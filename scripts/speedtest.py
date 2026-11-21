"""Bounded, real proxy-tunnel download tests using a pinned sing-box binary.

Only explicitly supported share-link forms are tested. Unsupported formats are
reported as skipped; they are never treated as successful or assigned fake Mbps.
"""
import base64
import ipaddress
import json
import os
import secrets
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

try:
    from . import collector
except ImportError:  # direct execution from scripts/collector.py
    import collector

SPEED_TEST_LIMIT = 200
# 并行测速路数：每个节点各自起一个 sing-box 进程，互不干扰；并行让
# 一轮在同样的 10 分钟预算内测约 200 个节点（串行时只能测约 80 个）。
# 代价是同一出口带宽被分摊，Mbps 数值比串行略低——排名只作粗排，
# 通过/不通过的判定不受影响。
SPEED_TEST_WORKERS = 4
SPEED_TEST_TOTAL_SECONDS = 600
SPEED_TEST_BYTES = 262144
SPEED_TEST_SAMPLES = 2
SPEED_TEST_TIMEOUT = 12
# 单个节点的绝对截止（秒）：所有地址尝试、采样与出口探测共享这一份
# 预算，杜绝滴流节点把整轮测速拖死（审查整改，2026-11-21）。
NODE_TEST_DEADLINE_SECONDS = 45
DOWNLOAD_URL = f"https://speed.cloudflare.com/__down?bytes={SPEED_TEST_BYTES}"


class UnsupportedNode(ValueError):
    pass


def _query(parsed):
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)


def _first(query, *keys, default=""):
    for key in keys:
        values = query.get(key)
        if values:
            return values[0]
    return default


def _tls(query, host, security=""):
    if security not in ("tls", "reality"):
        return None
    result = {
        "enabled": True,
        "server_name": _first(query, "sni", "peer", default=host),
    }
    insecure = _first(query, "allowInsecure", "insecure")
    if insecure.lower() in ("1", "true", "yes"):
        result["insecure"] = True
    fingerprint = _first(query, "fp")
    if fingerprint:
        result["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        public_key = _first(query, "pbk", "publicKey")
        if not public_key:
            raise UnsupportedNode("Reality public key missing")
        reality = {"enabled": True, "public_key": public_key}
        short_id = _first(query, "sid", "shortId")
        if short_id:
            reality["short_id"] = short_id
        result["reality"] = reality
    alpn = _first(query, "alpn")
    if alpn:
        result["alpn"] = [part for part in alpn.split(",") if part]
    return result


def _transport(query):
    kind = _first(query, "type", "network", default="tcp").lower()
    if kind in ("", "tcp", "raw"):
        return None
    if kind == "ws":
        transport = {"type": "ws"}
        path = _first(query, "path")
        host = _first(query, "host")
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if kind in ("grpc", "gun"):
        return {"type": "grpc", "service_name": _first(query, "serviceName", "service_name")}
    if kind in ("httpupgrade", "http-upgrade"):
        transport = {"type": "httpupgrade"}
        path = _first(query, "path")
        host = _first(query, "host")
        if path:
            transport["path"] = path
        if host:
            transport["host"] = host
        return transport
    if kind in ("h2", "http"):
        transport = {"type": "http"}
        path = _first(query, "path")
        host = _first(query, "host")
        if path:
            transport["path"] = path
        if host:
            transport["host"] = [host]
        return transport
    # 已知但暂不支持的传输可以带名字（便于诊断）；不在已知集合里的
    # 一律固定文案——kind 来自节点链接的查询参数，是不受信文本，
    # 原样带出会进公开质量报告与 CI 日志（审查整改，2026-11-21）。
    if kind in ("xhttp", "splithttp", "h2", "quic", "httpupgrade"):
        raise UnsupportedNode(f"transport {kind} not yet supported")
    raise UnsupportedNode("unsupported transport")


def build_outbound(uri):
    protocol, host, port = collector.get_endpoint(uri)
    if not protocol:
        raise UnsupportedNode("invalid share URI")
    parsed = urllib.parse.urlsplit(uri)
    query = _query(parsed)
    outbound = {"tag": "proxy", "server": host, "server_port": port}

    if protocol == "vless":
        if not parsed.username:
            raise UnsupportedNode("VLESS UUID missing")
        outbound.update({"type": "vless", "uuid": urllib.parse.unquote(parsed.username)})
        flow = _first(query, "flow")
        if flow:
            outbound["flow"] = flow
        security = _first(query, "security", default="none").lower()
        tls = _tls(query, host, security)
        if tls:
            outbound["tls"] = tls
        transport = _transport(query)
        if transport:
            outbound["transport"] = transport
        return outbound

    if protocol == "trojan":
        password = urllib.parse.unquote(parsed.password or parsed.username or "")
        if not password:
            raise UnsupportedNode("Trojan password missing")
        outbound.update({"type": "trojan", "password": password})
        security = _first(query, "security", default="tls").lower()
        tls = _tls(query, host, security)
        if tls:
            outbound["tls"] = tls
        transport = _transport(query)
        if transport:
            outbound["transport"] = transport
        return outbound

    if protocol == "ss":
        if _first(query, "plugin"):
            raise UnsupportedNode("Shadowsocks plugins are not yet supported")
        userinfo = parsed.username or ""
        if parsed.password is not None:
            decoded = urllib.parse.unquote(userinfo) + ":" + urllib.parse.unquote(parsed.password)
        else:
            try:
                decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
            except Exception:
                decoded = urllib.parse.unquote(userinfo)
        if ":" not in decoded:
            raise UnsupportedNode("Shadowsocks method/password missing")
        method, password = decoded.split(":", 1)
        if not method or not password:
            raise UnsupportedNode("Shadowsocks method/password missing")
        outbound.update({"type": "shadowsocks", "method": method, "password": password})
        return outbound

    if protocol == "vmess":
        raw = collector.decode_base64(uri[8:].split("#", 1)[0].split("?", 1)[0])
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            raise UnsupportedNode("invalid VMess JSON")
        if not isinstance(data, dict) or not data.get("id"):
            raise UnsupportedNode("VMess UUID missing")
        try:
            alter_id = int(data.get("aid", 0) or 0)
        except (TypeError, ValueError):
            raise UnsupportedNode("VMess alter_id is not a number")
        outbound.update({
            "type": "vmess",
            "uuid": str(data["id"]),
            "alter_id": alter_id,
            "security": str(data.get("scy") or "auto"),
        })
        network = str(data.get("net") or "tcp").lower()
        vmess_query = {"type": [network]}
        if data.get("path"):
            vmess_query["path"] = [str(data["path"])]
        if data.get("host"):
            vmess_query["host"] = [str(data["host"])]
        transport = _transport(vmess_query)
        if transport:
            outbound["transport"] = transport
        security = str(data.get("tls") or "").lower()
        tls_query = {"sni": [str(data.get("sni") or data.get("host") or host)]}
        if data.get("fp"):
            tls_query["fp"] = [str(data["fp"])]
        tls = _tls(tls_query, host, "tls" if security in ("tls", "reality") else "")
        if tls:
            outbound["tls"] = tls
        return outbound

    if protocol in ("hysteria2", "hy2"):
        password = urllib.parse.unquote(parsed.password or parsed.username or "")
        if not password:
            raise UnsupportedNode("Hysteria2 password missing")
        outbound.update({"type": "hysteria2", "password": password})
        tls = _tls(query, host, _first(query, "security", default="tls").lower())
        if not tls:
            tls = {"enabled": True, "server_name": _first(query, "sni", default=host)}
        outbound["tls"] = tls
        obfs = _first(query, "obfs")
        if obfs:
            outbound["obfs"] = {"type": obfs, "password": _first(query, "obfs-password", "obfs_password")}
        return outbound

    if protocol == "tuic":
        uuid = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")
        if not uuid or not password:
            raise UnsupportedNode("TUIC UUID/password missing")
        outbound.update({
            "type": "tuic",
            "uuid": uuid,
            "password": password,
            "congestion_control": _first(query, "congestion_control", default="bbr"),
            "udp_relay_mode": _first(query, "udp_relay_mode", default="native"),
        })
        tls = _tls(query, host, _first(query, "security", default="tls").lower())
        outbound["tls"] = tls or {"enabled": True, "server_name": _first(query, "sni", default=host)}
        return outbound

    if protocol == "hysteria":
        # Hysteria v1：sing-box 的 type=hysteria；auth 在查询参数里。
        outbound.update({"type": "hysteria"})
        auth = _first(query, "auth")
        if auth:
            outbound["auth_str"] = auth
        for field, key in (("upmbps", "up_mbps"), ("downmbps", "down_mbps")):
            raw_value = _first(query, field)
            if raw_value:
                try:
                    outbound[key] = int(float(raw_value))
                except ValueError:
                    pass
        obfs = _first(query, "obfsParam", "obfsparam")
        if obfs:
            outbound["obfs"] = obfs
        tls = {"enabled": True, "server_name": _first(query, "peer", "sni", default=host)}
        insecure = _first(query, "insecure", "allowInsecure")
        if insecure.lower() in ("1", "true", "yes"):
            tls["insecure"] = True
        outbound["tls"] = tls
        return outbound

    if protocol == "anytls":
        auth_secret = urllib.parse.unquote(parsed.username or "")
        if not auth_secret:
            raise UnsupportedNode("AnyTLS password missing")
        outbound.update({"type": "anytls", "password": auth_secret})
        outbound["tls"] = _tls(query, host, "tls") or {
            "enabled": True,
            "server_name": _first(query, "sni", default=host),
        }
        return outbound

    if protocol in ("http", "https"):
        outbound.update({"type": "http"})
        auth_user = urllib.parse.unquote(parsed.username or "")
        if auth_user:
            outbound.update({
                "username": auth_user,
                "password": urllib.parse.unquote(parsed.password or ""),
            })
        if protocol == "https":
            outbound["tls"] = {"enabled": True, "server_name": host}
        return outbound

    if protocol == "socks5":
        outbound.update({"type": "socks", "version": "5"})
        auth_user = urllib.parse.unquote(parsed.username or "")
        auth_secret = urllib.parse.unquote(parsed.password) if parsed.password else None
        if auth_secret is None and auth_user:
            # 米贝等分享把 user:pass 整体 base64 后放进 userinfo；
            # 解不出冒号分隔的凭据时按原样当用户名用。
            try:
                decoded = base64.urlsafe_b64decode(auth_user + "=" * (-len(auth_user) % 4)).decode()
            except Exception:
                decoded = ""
            if ":" in decoded:
                auth_user, _, auth_secret = decoded.partition(":")
        if auth_user:
            outbound.update({"username": auth_user, "password": auth_secret or ""})
        return outbound

    raise UnsupportedNode(f"{protocol} is not yet supported by the speed tester")


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_local(port, process):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _singbox_error_kind(output):
    """Return a coarse, non-sensitive diagnostic label; never publish raw sing-box output."""
    message = (output or "").lower()
    labels = (
        ("unknown_field", ("unknown field", "unknown key", "extra field")),
        ("unsupported_option", ("unsupported", "not supported")),
        ("tls_error", ("tls", "certificate", "x509")),
        ("reality_error", ("reality", "public key", "short id")),
        ("authentication_error", ("authentication", "unauthorized", "invalid user", "invalid password")),
        ("config_error", ("invalid", "parse", "decode", "configuration")),
        ("network_error", ("connection refused", "timeout", "network is unreachable", "no route")),
    )
    for label, needles in labels:
        if any(needle in message for needle in needles):
            return label
    return "no_detail"


def _exception_diagnostic(exc):
    """Expose safe error categories and numeric codes, never raw URLs or credentials."""
    import urllib.error

    reason = getattr(exc, "reason", None)
    nested = reason if isinstance(reason, BaseException) else exc
    errno = getattr(nested, "errno", None) or getattr(exc, "errno", None)
    detail = {"error_type": type(exc).__name__}
    if isinstance(exc, urllib.error.HTTPError):
        detail["http_status"] = int(exc.code)
        detail["reason"] = "http_error"
    elif isinstance(errno, int):
        detail["errno"] = errno
        detail["reason"] = {
            104: "connection_reset",
            111: "connection_refused",
            110: "connection_timeout",
            101: "network_unreachable",
            113: "no_route_to_host",
            99: "address_not_available",
        }.get(errno, "socket_error")
    elif isinstance(exc, (TimeoutError, socket.timeout)):
        detail["reason"] = "timeout"
    elif isinstance(exc, urllib.error.URLError):
        detail["reason"] = "proxy_or_tls_connection_error"
    else:
        detail["reason"] = type(exc).__name__.lower()
    return detail


EGRESS_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"


def _probe_egress_ip(opener) -> str | None:
    """经隧道读 Cloudflare trace 得到节点真实出口 IP；失败返回 None。

    只在测速成功后顺带做（sing-box 还开着），失败不影响测速结果。
    出口 IP 只用于内存中的质量分类与地区校验，不写进任何报告。
    """
    try:
        request = urllib.request.Request(
            EGRESS_TRACE_URL,
            headers={"User-Agent": "shadowrocket-auto-speedtest/1.0"},
        )
        with opener.open(request, timeout=4) as response:
            text = response.read(4096).decode("utf-8", "replace")
    except Exception:
        return None
    for line in text.splitlines():
        if line.startswith("ip="):
            candidate = line[3:].strip()
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                return None
    return None


def measure_node(uri, binary):
    """测一个节点：DNS 校验过的地址逐个尝试，直到连通或用完。

    每个节点有绝对截止 NODE_TEST_DEADLINE_SECONDS：单次 socket 超时
    只是空闲超时，慢慢滴数据的节点曾能把整轮测速拖到被工作流强杀；
    现在每阶段都用剩余时间收紧，过期即放弃。首个地址连不上时换下一
    个已校验地址（首地址 IPv6 不通、次地址可用的情况不再误杀）。
    """
    started = time.monotonic()
    deadline = started + NODE_TEST_DEADLINE_SECONDS
    try:
        outbound = build_outbound(uri)
    except UnsupportedNode as exc:
        return {"status": "unsupported", "stage": "build_outbound", "reason": str(exc)}

    try:
        _, original_host, _ = collector.get_endpoint(uri)
        addresses = collector.resolve_public_addresses(original_host)
    except Exception as exc:
        return {"status": "download_failed", "stage": "dns_validation",
                **_exception_diagnostic(exc)}
    if not addresses:
        return {"status": "dns_rejected", "stage": "dns_validation",
                "reason": "no_validated_public_address"}
    candidate_ips: list[str] = []
    for entry in addresses:
        ip = entry[4][0]
        if ip not in candidate_ips:
            candidate_ips.append(ip)
    last_result: dict = {}
    for ip in candidate_ips[:3]:
        if time.monotonic() >= deadline:
            return {"status": "download_failed", "stage": "node_deadline",
                    "reason": "node_deadline_exceeded"}
        attempt_outbound = dict(outbound)
        attempt_outbound["server"] = ip
        result = _attempt_download(uri, attempt_outbound, binary, started, deadline)
        if result.get("status") == "ok":
            return result
        last_result = result
        # 只有连接层失败才值得换地址重试；协议/内容层失败换地址也没用。
        if result.get("status") not in ("handshake_failed", "proxy_connect_failed"):
            return result
    return last_result


def _attempt_download(uri, outbound, binary, started, deadline):
    process = None
    stage = "config_check"
    try:
        port = _free_port()
        # 回环入站设随机凭据：防止本机其他进程（或抢占了端口的另一个
        # sing-box）冒充本节点出网，也避免测速结果张冠李戴。
        local_user = "sb" + secrets.token_hex(4)
        local_pass = secrets.token_hex(8)
        config = {
            "log": {"disabled": False, "level": "warn", "timestamp": False},
            "inbounds": [{
                "type": "mixed",
                "tag": "local-in",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"username": local_user, "password": local_pass}],
            }],
            "outbounds": [outbound],
            "route": {"final": "proxy"},
        }
        with tempfile.TemporaryDirectory(prefix="node-speed-") as directory:
            config_path = Path(directory) / "config.json"
            stderr_path = Path(directory) / "sing-box.stderr"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            os.chmod(config_path, 0o600)

            check = subprocess.run(
                [binary, "check", "-c", str(config_path)],
                capture_output=True, text=True, timeout=4,
            )
            if check.returncode != 0:
                return {
                    "status": "invalid_config",
                    "stage": stage,
                    "reason": _singbox_error_kind(check.stderr or check.stdout),
                }

            stage = "singbox_start"
            with stderr_path.open("w+", encoding="utf-8") as stderr_file:
                process = subprocess.Popen(
                    [binary, "run", "-c", str(config_path)],
                    stdout=subprocess.DEVNULL, stderr=stderr_file,
                )
                if not _wait_local(port, process) or process.poll() is not None:
                    stderr_file.flush()
                    stderr_file.seek(0)
                    diagnostic = _singbox_error_kind(stderr_file.read())
                    return {
                        "status": "handshake_failed",
                        "stage": stage,
                        "reason": diagnostic,
                    }

                proxy_url = (
                    f"http://{urllib.parse.quote(local_user, safe='')}:"
                    f"{urllib.parse.quote(local_pass, safe='')}@127.0.0.1:{port}"
                )
                proxy = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
                opener = urllib.request.build_opener(proxy)
                rates = []
                for sample_index in range(SPEED_TEST_SAMPLES):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return {"status": "download_failed", "stage": "node_deadline",
                                "reason": "node_deadline_exceeded"}
                    request = urllib.request.Request(
                        DOWNLOAD_URL,
                        headers={"User-Agent": "shadowrocket-auto-speedtest/1.0", "Cache-Control": "no-cache"},
                    )
                    sample_start = time.monotonic()
                    stage = "proxy_tunnel_connect"
                    try:
                        response = opener.open(request, timeout=min(SPEED_TEST_TIMEOUT, remaining))
                    except Exception as exc:
                        diagnostic = _exception_diagnostic(exc)
                        stderr_file.flush()
                        stderr_file.seek(0)
                        diagnostic["singbox_error"] = _singbox_error_kind(stderr_file.read())
                        return {
                            "status": "proxy_connect_failed",
                            "stage": stage,
                            "sample": sample_index + 1,
                            **diagnostic,
                        }
                    with response:
                        stage = "http_response"
                        if response.status != 200:
                            return {
                                "status": "http_status_failed",
                                "stage": stage,
                                "sample": sample_index + 1,
                                "http_status": int(response.status),
                            }
                        stage = "proxy_download_read"
                        payload = bytearray()
                        try:
                            while len(payload) <= SPEED_TEST_BYTES:
                                if time.monotonic() >= deadline:
                                    return {"status": "download_failed", "stage": "node_deadline",
                                            "reason": "node_deadline_exceeded"}
                                chunk = response.read(min(65536, SPEED_TEST_BYTES + 1 - len(payload)))
                                if not chunk:
                                    break
                                payload.extend(chunk)
                        except Exception as exc:
                            diagnostic = _exception_diagnostic(exc)
                            stderr_file.flush()
                            stderr_file.seek(0)
                            diagnostic["singbox_error"] = _singbox_error_kind(stderr_file.read())
                            return {
                                "status": "download_read_failed",
                                "stage": stage,
                                "sample": sample_index + 1,
                                **diagnostic,
                            }
                    elapsed = time.monotonic() - sample_start
                    if len(payload) != SPEED_TEST_BYTES or elapsed <= 0:
                        return {
                            "status": "incomplete_download",
                            "stage": "download_validation",
                            "sample": sample_index + 1,
                            "reason": "payload_size_mismatch",
                        }
                    rates.append((len(payload) * 8) / elapsed / 1_000_000)
                rates.sort()
                median = statistics.median(rates)
                egress_ip = _probe_egress_ip(opener)
                return {
                    "status": "ok",
                    "stage": "complete",
                    "download_mbps": round(median, 2),
                    "samples_mbps": [round(rate, 2) for rate in rates],
                    "elapsed_seconds": round(time.monotonic() - started, 2),
                    **({"egress_ip": egress_ip} if egress_ip else {}),
                }
    except Exception as exc:
        return {
            "status": "download_failed",
            "stage": stage,
            **_exception_diagnostic(exc),
        }
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def _balanced_speed_shortlist(nodes, limit):
    """Round-robin protocols so one popular protocol cannot consume every test slot."""
    buckets = {}
    unsupported = []
    for uri in nodes:
        try:
            build_outbound(uri)
        except (UnsupportedNode, ValueError, TypeError) as exc:
            # One malformed share link must never abort the whole round:
            # build_outbound historically leaked plain ValueError/TypeError
            # for bad fields (e.g. a non-numeric VMess alter_id).
            unsupported.append((uri, {
                "status": "unsupported",
                "stage": "preflight",
                "reason": str(exc) if isinstance(exc, UnsupportedNode) else "malformed share link",
            }))
            continue
        protocol = collector.get_endpoint(uri)[0] or "unknown"
        buckets.setdefault(protocol, []).append(uri)

    selected = []
    protocols = sorted(buckets)
    while len(selected) < limit and protocols:
        remaining = []
        for protocol in protocols:
            if buckets[protocol] and len(selected) < limit:
                selected.append(buckets[protocol].pop(0))
            if buckets[protocol]:
                remaining.append(protocol)
        protocols = remaining
    return selected, unsupported


def _report_result(result):
    if result.get("status") == "ok":
        print(f"[实测测速] {result['download_mbps']:.2f} Mbps")
    else:
        print(
            f"[测速失败] status={result.get('status')} "
            f"stage={result.get('stage', 'unknown')} "
            f"reason={result.get('reason', 'n/a')} "
            f"error_type={result.get('error_type', 'n/a')} "
            f"http_status={result.get('http_status', 'n/a')} "
            f"errno={result.get('errno', 'n/a')}"
        )


def rank_by_speed(nodes, binary, limit=SPEED_TEST_LIMIT, workers=SPEED_TEST_WORKERS):
    """Speed-test a bounded, protocol-balanced shortlist; return URI/result pairs.

    Nodes are measured in parallel (each spawns its own sing-box process);
    nodes not started before the round deadline are reported skipped_budget.
    """
    shortlist, results = _balanced_speed_shortlist(nodes, limit)
    results = list(results)
    deadline = time.monotonic() + SPEED_TEST_TOTAL_SECONDS
    queue = list(shortlist)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        in_flight = {}

        def submit(uri):
            in_flight[pool.submit(measure_node, uri, binary)] = uri

        while queue and len(in_flight) < max(1, workers) and time.monotonic() < deadline:
            submit(queue.pop(0))
        while in_flight:
            done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
            for future in done:
                uri = in_flight.pop(future)
                try:
                    result = future.result()
                except Exception as exc:  # measure_node should not raise; never lose a slot
                    result = {"status": "download_failed", "stage": "scheduler",
                              "reason": type(exc).__name__}
                results.append((uri, result))
                _report_result(result)
            while queue and len(in_flight) < max(1, workers) and time.monotonic() < deadline:
                submit(queue.pop(0))
    for uri in queue:
        results.append((uri, {"status": "skipped_budget", "stage": "scheduler", "reason": "round_budget_exhausted"}))
    successful = [(uri, result) for uri, result in results if result.get("status") == "ok"]
    successful.sort(key=lambda item: item[1]["download_mbps"], reverse=True)
    return successful, results
