"""Bounded, real proxy-tunnel download tests using a pinned sing-box binary.

Only explicitly supported share-link forms are tested. Unsupported formats are
reported as skipped; they are never treated as successful or assigned fake Mbps.
"""
import base64
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

from scripts import collector

SPEED_TEST_LIMIT = 15
SPEED_TEST_BYTES = 262144
SPEED_TEST_SAMPLES = 2
SPEED_TEST_TIMEOUT = 12
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
    raise UnsupportedNode(f"transport {kind} not yet supported")


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
        outbound.update({
            "type": "vmess",
            "uuid": str(data["id"]),
            "alter_id": int(data.get("aid", 0)),
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


def measure_node(uri, binary):
    started = time.monotonic()
    try:
        outbound = build_outbound(uri)
    except UnsupportedNode as exc:
        return {"status": "unsupported", "reason": str(exc)}

    port = _free_port()
    config = {
        "log": {"disabled": True},
        "inbounds": [{
            "type": "mixed",
            "tag": "local-in",
            "listen": "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": [outbound],
        "route": {"final": "proxy"},
    }
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="node-speed-") as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            os.chmod(config_path, 0o600)
            check = subprocess.run(
                [binary, "check", "-c", str(config_path)],
                capture_output=True, text=True, timeout=4,
            )
            if check.returncode != 0:
                return {"status": "invalid_config", "reason": "sing-box rejected generated config"}
            process = subprocess.Popen(
                [binary, "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if not _wait_local(port, process):
                return {"status": "handshake_failed", "reason": "local proxy did not start"}

            proxy = urllib.request.ProxyHandler({
                "http": f"http://127.0.0.1:{port}",
                "https": f"http://127.0.0.1:{port}",
            })
            opener = urllib.request.build_opener(proxy)
            rates = []
            for _ in range(SPEED_TEST_SAMPLES):
                request = urllib.request.Request(
                    DOWNLOAD_URL,
                    headers={"User-Agent": "shadowrocket-auto-speedtest/1.0", "Cache-Control": "no-cache"},
                )
                sample_start = time.monotonic()
                with opener.open(request, timeout=SPEED_TEST_TIMEOUT) as response:
                    if response.status != 200:
                        raise OSError(f"speed endpoint HTTP {response.status}")
                    payload = response.read(SPEED_TEST_BYTES + 1)
                elapsed = time.monotonic() - sample_start
                if len(payload) != SPEED_TEST_BYTES or elapsed <= 0:
                    raise OSError("incomplete speed-test payload")
                rates.append((len(payload) * 8) / elapsed / 1_000_000)
            rates.sort()
            median = rates[len(rates) // 2] if len(rates) % 2 else sum(rates) / 2
            return {
                "status": "ok",
                "download_mbps": round(median, 2),
                "samples_mbps": [round(rate, 2) for rate in rates],
                "elapsed_seconds": round(time.monotonic() - started, 2),
            }
    except Exception as exc:
        return {"status": "download_failed", "reason": type(exc).__name__}
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def rank_by_speed(nodes, binary, limit=SPEED_TEST_LIMIT):
    """Speed-test a bounded shortlist; return URI/result pairs in measured Mbps order."""
    results = []
    shortlist = nodes[:limit]
    for uri in shortlist:
        result = measure_node(uri, binary)
        results.append((uri, result))
        if result.get("status") == "ok":
            print(f"[实测测速] {result['download_mbps']:.2f} Mbps")
        else:
            print(f"[测速跳过/失败] {result.get('status')}")
    successful = [(uri, result) for uri, result in results if result.get("status") == "ok"]
    successful.sort(key=lambda item: item[1]["download_mbps"], reverse=True)
    return successful, results
