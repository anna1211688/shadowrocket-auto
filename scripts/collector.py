import base64
import ipaddress
import hashlib
import json
import os
import random
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "config" / "sources.txt"
OUTPUT = ROOT / "docs" / "shadowrocket.txt"
QUALITY_REPORT = ROOT / "docs" / "quality_report.json"

# ============ 可配置参数 ============
TIMEOUT = 3.0                 # TCP 连接超时（秒）
MAX_LATENCY = 2.5             # 最大可接受 TCP 建连延迟（秒）
TCP_SAMPLES = 3
MIN_SUCCESSFUL_SAMPLES = 2
MAX_NODES = 150               # 最终保留节点数
MAX_WORKERS = 30
NODE_DEADLINE = 5.0
DNS_TIMEOUT = 2.0
SOURCE_TIMEOUT = (4, 8)
SOURCE_DEADLINE = 20.0
SOURCE_RETRIES = 1
MAX_SOURCE_BYTES = 2_000_000
MAX_SOURCE_NODES = 5_000
MAX_TOTAL_NODES = 20_000
MAX_LINE_LENGTH = 8_192
MAX_SOURCES = 50
MAX_SOURCE_WORKERS = 10
MAX_TEST_CANDIDATES = 5_000
USER_AGENT = "shadowrocket-auto/1.0"

class DNSResolutionTimeout(Exception):
    """Raised when the external DNS lookup exceeds its hard deadline."""


# 协议优先级权重（数值越小越优先，同延迟时生效）
PROTOCOL_WEIGHT = {
    "vless": 0,
    "trojan": 1,
    "hysteria2": 1,
    "hy2": 1,
    "hysteria": 2,
    "tuic": 2,
    "vmess": 3,
    "ss": 4,
}
# ====================================


def atomic_write_text(path: Path, content: str) -> None:
    """Write a complete UTF-8 file beside its destination, then atomically replace it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def decode_base64(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_SOURCE_BYTES * 2:
        return ""
    value = value.strip()
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""


def decode_subscription(content: str) -> list[str]:
    content = content.strip()
    if not content:
        return []

    decoded = decode_base64(content)
    if decoded and ("://" in decoded or "\n" in decoded):
        content = decoded

    nodes = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and len(line) <= MAX_LINE_LENGTH:
            nodes.append(line)
            if len(nodes) >= MAX_SOURCE_NODES:
                break
    return nodes


def get_protocol(line: str) -> str | None:
    m = re.match(r"^(ss|vmess|vless|trojan|hysteria2?|hy2|tuic)://", line, re.I)
    return m.group(1).lower() if m else None


def normalize_dns_name(host: str) -> str | None:
    """Return a strict ASCII DNS name; reject malformed labels and option-like input."""
    if not isinstance(host, str) or not host or host.startswith("-"):
        return None
    name = host[:-1] if host.endswith(".") else host
    if not name or name.endswith("."):
        return None
    try:
        ascii_name = name.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(ascii_name) > 253:
        return None
    labels = ascii_name.split(".")
    if any(
        not label or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        return None
    return ascii_name


def resolve_public_addresses(host: str) -> list[tuple]:
    """解析主机并拒绝非公网结果；域名解析由可超时终止的 getent 子进程执行。"""
    if not isinstance(host, str) or not host or len(host) > 253 or any(ord(c) < 33 or ord(c) == 127 for c in host) or any(c in host for c in "/\\\\?#@"):
        return []
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            return []
        try:
            return socket.getaddrinfo(str(literal), None, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)
        except OSError:
            return []

    dns_name = normalize_dns_name(host)
    if not dns_name:
        return []

    try:
        # subprocess.run 会在 DNS_TIMEOUT 到期后终止并回收解析进程，避免永久卡住采集线程。
        completed = subprocess.run(
            ["getent", "ahosts", dns_name],
            check=False, capture_output=True, text=True, timeout=DNS_TIMEOUT,
        )
        if completed.returncode != 0:
            return []
        resolved = set()
        for line in completed.stdout.splitlines():
            fields = line.split()
            if fields:
                try:
                    address = ipaddress.ip_address(fields[0])
                except ValueError:
                    continue
                if not address.is_global:
                    return []
                resolved.add(str(address))
        if not resolved:
            return []
        results = []
        for address in sorted(resolved):
            results.extend(socket.getaddrinfo(address, None, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST))
        return results
    except subprocess.TimeoutExpired as exc:
        raise DNSResolutionTimeout(host) from exc
    except (OSError, UnicodeError, ValueError, TypeError):
        return []

def limit_candidates(candidates: list[str], stats: dict) -> list[str]:
    """Bound worst-case network work so scheduled runs finish within the job deadline."""
    skipped = max(0, len(candidates) - MAX_TEST_CANDIDATES)
    stats["skipped_limit"] = skipped
    return candidates[:MAX_TEST_CANDIDATES]


def is_public_ip(host: str) -> bool:
    """快速过滤明确的非公网 IP；域名在实际连接前只解析并验证一次。"""
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return isinstance(host, str) and bool(host) and len(host) <= 253
    except (TypeError, AttributeError):
        return False


REGION_KEYWORDS = {
    "HK": ("香港", "hong kong", "hongkong", "hkg", "🇭🇰"),
    "TW": ("台湾", "台灣", "taiwan", "taipei", "🇹🇼"),
    "JP": ("日本", "东京", "東京", "大阪", "japan", "tokyo", "osaka", "🇯🇵"),
    "SG": ("新加坡", "狮城", "singapore", "🇸🇬"),
    "KR": ("韩国", "韓國", "首尔", "首爾", "korea", "seoul", "🇰🇷"),
    "US": ("美国", "美國", "洛杉矶", "西雅图", "硅谷", "united states", "los angeles", "seattle", "🇺🇸"),
    "DE": ("德国", "德國", "germany", "frankfurt", "🇩🇪"),
    "GB": ("英国", "英國", "伦敦", "倫敦", "united kingdom", "london", "🇬🇧"),
}


def get_node_label(line: str) -> str:
    """提取节点备注及主机名，用于不依赖第三方服务的地区猜测。"""
    protocol = get_protocol(line)
    label = ""
    if protocol == "vmess":
        try:
            raw = decode_base64(line[8:].split("#", 1)[0].split("?", 1)[0])
            parsed = json.loads(raw)
            label = str(parsed.get("ps", "")) if isinstance(parsed, dict) else ""
        except (ValueError, TypeError):
            pass
    else:
        label = urllib.parse.unquote(urllib.parse.urlsplit(line).fragment)
    _, host, _ = get_endpoint(line)
    return f"{label} {host or ''}".lower()


def infer_region(line: str) -> str:
    """根据节点备注/主机名推测地区；无法判断时返回 OTHER，不调用外部地理定位服务。"""
    label = get_node_label(line)
    for region, keywords in REGION_KEYWORDS.items():
        if any(keyword.lower() in label for keyword in keywords):
            return region
    return "OTHER"


def write_quality_report(raw_count: int, candidate_count: int, stats: dict,
                         alive: list[tuple],
                         subscription_status: str = "preserved_previous",
                         speed_results: list[tuple] | None = None) -> None:
    """写入不包含节点地址/凭据的聚合质量报告。"""
    import datetime
    import statistics

    latencies = sorted(entry[1] * 1000 for entry in alive)
    jitters = sorted(entry[3] * 1000 for entry in alive if len(entry) > 3 and entry[3] is not None)
    protocol_counts: dict[str, int] = {}
    region_counts: dict[str, int] = {}
    for entry in alive:
        line, _, protocol = entry[:3]
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        region = infer_region(line)
        region_counts[region] = region_counts.get(region, 0) + 1

    def percentile(values: list[float], fraction: float):
        if not values:
            return None
        position = (len(values) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(values) - 1)
        return round(values[lower] + (values[upper] - values[lower]) * (position - lower), 1)

    speed_results = speed_results or []
    successful_speeds = [
        (uri, result) for uri, result in speed_results
        if result.get("status") == "ok" and isinstance(result.get("download_mbps"), (int, float))
    ]
    successful_speeds.sort(key=lambda item: item[1]["download_mbps"], reverse=True)
    speed_values = [float(result["download_mbps"]) for _, result in successful_speeds]
    failure_diagnostics = [
        result for _, result in speed_results if result.get("status") != "ok"
    ]
    diagnostic_counts = {
        "by_status": {},
        "by_stage": {},
        "by_reason": {},
        "by_error_type": {},
        "by_singbox_error": {},
    }
    for result in failure_diagnostics:
        for key, field in (
            ("by_status", "status"),
            ("by_stage", "stage"),
            ("by_reason", "reason"),
            ("by_error_type", "error_type"),
            ("by_singbox_error", "singbox_error"),
        ):
            value = str(result.get(field) or "unknown")
            diagnostic_counts[key][value] = diagnostic_counts[key].get(value, 0) + 1

    speed_nodes = []
    for uri, result in successful_speeds[:20]:
        protocol, _, _ = get_endpoint(uri)
        latency = next((entry[1] for entry in alive if entry[0] == uri), None)
        speed_nodes.append({
            "id": hashlib.sha256(uri.encode("utf-8")).hexdigest()[:12],
            "protocol": protocol,
            "download_mbps": round(float(result["download_mbps"]), 2),
            "tcp_latency_ms": round(latency * 1000, 1) if latency is not None else None,
        })

    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "measurement": "proxy_download_speed_mbps_with_tcp_latency_context",
        "ranking": "measured_proxy_download_mbps_descending",
        "speed_test": {
            "candidates_considered": len(speed_results),
            "tested": sum(1 for _, result in speed_results if result.get("status") != "unsupported"),
            "unsupported": sum(1 for _, result in speed_results if result.get("status") == "unsupported"),
            "successful": len(successful_speeds),
            "failed_or_unsupported": len(speed_results) - len(successful_speeds),
            "download_mbps": {
                "min": round(min(speed_values), 2) if speed_values else None,
                "average": round(statistics.mean(speed_values), 2) if speed_values else None,
                "p50": percentile(sorted(speed_values), 0.50),
                "p95": percentile(sorted(speed_values), 0.95),
            },
            "top_nodes": speed_nodes,
            "diagnostic_counts": diagnostic_counts,
            "failure_diagnostics": [
                {
                    "protocol": get_endpoint(uri)[0],
                    "status": result.get("status"),
                    "stage": result.get("stage", "unknown"),
                    "reason": result.get("reason", result.get("error_type", "unknown")),
                    **({"error_type": result["error_type"]} if result.get("error_type") else {}),
                    **({"http_status": result["http_status"]} if result.get("http_status") else {}),
                    **({"errno": result["errno"]} if result.get("errno") else {}),
                    **({"singbox_error": result["singbox_error"]} if result.get("singbox_error") else {}),
                    **({"sample": result["sample"]} if result.get("sample") else {}),
                }
                for uri, result in speed_results
                if result.get("status") != "ok"
            ][:25],
        },
        "note": "Subscription order is based on measured download Mbps through a sing-box proxy tunnel. Only supported URI formats with successful complete downloads are ranked; this is GitHub-runner egress performance, not a guarantee of client-side speed.",
        "subscription_status": subscription_status,
        "raw_nodes": raw_count,
        "unique_candidates": candidate_count,
        "tcp_reachable": len(alive),
        "udp_unverified": stats.get("udp_unverified", 0),
        "rejected": stats,
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "region_counts": dict(sorted(region_counts.items())),
        "latency_ms": {
            "min": round(latencies[0], 1) if latencies else None,
            "average": round(statistics.mean(latencies), 1) if latencies else None,
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "jitter_average": round(statistics.mean(jitters), 1) if jitters else None,
            "jitter_p95": percentile(jitters, 0.95),
        },
    }
    atomic_write_text(QUALITY_REPORT, json.dumps(report, ensure_ascii=False, indent=2) + "\n")


def get_dedup_key(line: str):
    """区分同端点但凭据/传输参数不同的节点，同时忽略节点备注。"""
    protocol, host, port = get_endpoint(line)
    if not protocol or not host or not port:
        return None

    try:
        if protocol == "vmess":
            raw = decode_base64(line[8:].split("#", 1)[0].split("?", 1)[0])
            data = json.loads(raw)
            if not isinstance(data, dict):
                return None
            for label in ("ps", "remark", "name"):
                data.pop(label, None)
            identity = json.dumps(data, sort_keys=True, separators=(",", ":"))
        else:
            parsed = urllib.parse.urlsplit(line)
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            query.sort()
            identity = json.dumps({
                "username": parsed.username,
                "password": parsed.password,
                "path": parsed.path,
                "query": query,
            }, sort_keys=True, separators=(",", ":"))
            # 旧式 SIP002/base64 SS URI 无法从 urlsplit 可靠拆分凭据，保留其完整主体。
            if protocol == "ss" and not parsed.hostname:
                identity = line.split("#", 1)[0].strip()
        return (protocol, host.lower(), int(port), identity)
    except (TypeError, ValueError, AttributeError, json.JSONDecodeError):
        return None


def get_endpoint(line: str):
    """返回 (protocol, host, port) 或 (None, None, None)"""
    line = line.strip()
    protocol = get_protocol(line)
    if not protocol:
        return None, None, None

    try:
        if protocol == "vmess":
            raw = decode_base64(line[8:].split("#")[0].split("?")[0])
            data = json.loads(raw)
            if not isinstance(data, dict):
                return None, None, None
            host = data.get("add") or data.get("host")
            raw_port = data.get("port")
            if not isinstance(host, str) or not host or len(host) > 253:
                return None, None, None
            if isinstance(raw_port, bool) or not str(raw_port).isdigit():
                return None, None, None
            port = int(raw_port)
            if not 1 <= port <= 65535:
                return None, None, None
            return protocol, host, port

        if protocol in ("vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic"):
            parsed = urllib.parse.urlsplit(line)
            host = parsed.hostname
            port = parsed.port
            if isinstance(host, str) and host and len(host) <= 253 and isinstance(port, int) and 1 <= port <= 65535:
                return protocol, host, port
            return None, None, None

        if protocol == "ss":
            body = line[5:].split("#")[0].split("?")[0]

            if "@" in body:
                _, endpoint = body.rsplit("@", 1)
            else:
                decoded = decode_base64(body)
                if "@" not in decoded:
                    return None, None, None
                _, endpoint = decoded.rsplit("@", 1)

            if endpoint.startswith("["):
                host_port = endpoint[1:].split("]")
                host = host_port[0]
                port = int(host_port[1].lstrip(":")) if len(host_port) > 1 else 0
            else:
                host, _, port_str = endpoint.rpartition(":")
                port = int(port_str) if port_str.isdigit() else 0

            if not isinstance(host, str) or not host or len(host) > 253 or not 1 <= port <= 65535:
                return None, None, None
            return protocol, host, port

    except (ValueError, TypeError, AttributeError, UnicodeError, json.JSONDecodeError):
        return None, None, None

    return None, None, None


def test_node(line: str):
    """TCP 节点多次采样；UDP 代理协议不冒充 TCP 可用节点。"""
    import statistics
    protocol, host, port = get_endpoint(line)
    if not protocol or not host or not port or not (1 <= port <= 65535):
        return "invalid", line, None, None, None
    if protocol in ("hysteria", "hysteria2", "hy2", "tuic"):
        return "udp_unverified", line, None, protocol, None
    try:
        addresses = resolve_public_addresses(host)
        if not addresses:
            return "private", line, None, protocol, None
        samples = []
        node_deadline = time.perf_counter() + NODE_DEADLINE
        for _ in range(TCP_SAMPLES):
            if node_deadline <= time.perf_counter():
                break
            for family, socktype, proto, _, sockaddr in addresses:
                remaining = node_deadline - time.perf_counter()
                if remaining <= 0:
                    break
                target = (sockaddr[0], port, *sockaddr[2:]) if family == socket.AF_INET6 else (sockaddr[0], port)
                try:
                    started = time.perf_counter()
                    with socket.socket(family, socktype, proto) as sock:
                        sock.settimeout(min(TIMEOUT, remaining))
                        sock.connect(target)
                    samples.append(time.perf_counter() - started)
                    break
                except OSError:
                    continue
        if len(samples) < MIN_SUCCESSFUL_SAMPLES:
            return "timeout", line, None, protocol, None
        latency = statistics.median(samples)
        jitter = max(samples) - min(samples)
        if latency > MAX_LATENCY:
            return "slow", line, latency, protocol, jitter
        return "ok", line, latency, protocol, jitter
    except (socket.timeout, TimeoutError, DNSResolutionTimeout):
        return "timeout", line, None, protocol, None
    except Exception:
        return "timeout", line, None, protocol, None

def is_allowed_source_url(url: str) -> bool:
    """仅允许可信的 raw GitHub 源，避免配置/重定向把采集器变成 SSRF 代理。"""
    if not isinstance(url, str) or len(url) > 2_048:
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "raw.githubusercontent.com"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        )
    except (ValueError, TypeError):
        return False


def fetch_source(url: str) -> list[str]:
    if not is_allowed_source_url(url):
        print('[源拒绝] 仅允许 HTTPS raw.githubusercontent.com')
        return []
    last_error = None
    # One deadline covers every attempt and the retry delay; retries never reset the budget.
    deadline = time.monotonic() + SOURCE_DEADLINE
    for attempt in range(1 + SOURCE_RETRIES):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last_error = "TimeoutError"
            break
        try:
            request_timeout = (min(SOURCE_TIMEOUT[0], remaining), min(SOURCE_TIMEOUT[1], remaining))
            with requests.get(url, timeout=request_timeout, headers={"User-Agent": USER_AGENT}, stream=True, allow_redirects=False) as resp:
                # Redirects are disabled above; accept only a successful full response.
                # raise_for_status() does not reject 3xx when redirects are disabled.
                if resp.status_code != 200:
                    raise ValueError(f"unexpected HTTP status: {resp.status_code}")
                length = resp.headers.get("Content-Length")
                if length and int(length) > MAX_SOURCE_BYTES:
                    raise ValueError("source too large")
                chunks, total = [], 0
                for chunk in resp.iter_content(chunk_size=16384):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("source deadline exceeded")
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_SOURCE_BYTES:
                        raise ValueError("source too large")
                    chunks.append(chunk)
                if time.monotonic() >= deadline:
                    raise TimeoutError("source deadline exceeded")
                return decode_subscription(b"".join(chunks).decode("utf-8-sig", errors="replace"))
        except (requests.RequestException, ValueError, UnicodeError, TimeoutError) as e:
            last_error = type(e).__name__
            if attempt < SOURCE_RETRIES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(1.0, remaining))
    print(f"[源失败] request failed or response limit exceeded ({last_error})")
    return []


def main():
    # 1. 读取源列表
    sources = []
    if SOURCES.exists():
        for line in SOURCES.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                sources.append(line)
                if len(sources) >= MAX_SOURCES:
                    break

    print(f"共 {len(sources)} 个订阅源")

    # 2. 拉取所有节点（带重试）
    raw_nodes: list[str] = []
    for offset in range(0, len(sources), MAX_SOURCE_WORKERS):
        batch = sources[offset:offset + MAX_SOURCE_WORKERS]
        with ThreadPoolExecutor(max_workers=MAX_SOURCE_WORKERS) as source_executor:
            for nodes in source_executor.map(fetch_source, batch):
                raw_nodes.extend(nodes[:max(0, MAX_TOTAL_NODES - len(raw_nodes))])
                if len(raw_nodes) >= MAX_TOTAL_NODES:
                    break
        if len(raw_nodes) >= MAX_TOTAL_NODES:
            break

    # 3. 初步过滤 + 按端点、凭据和传输参数去重
    stats = {"ok": 0, "slow": 0, "timeout": 0, "invalid": 0, "private": 0, "duplicate": 0, "udp_unverified": 0}
    candidates = []
    seen_keys = set()

    for line in raw_nodes:
        protocol, host, port = get_endpoint(line)
        if not protocol or not host or not port:
            stats["invalid"] += 1
            continue
        # 域名在 test_node 中做 DNS 公网校验；这里仅排除明确的非公网 IP 字面量。
        if not is_public_ip(host):
            stats["private"] += 1
            continue

        key = get_dedup_key(line)
        if key is None:
            stats["invalid"] += 1
            continue
        if key in seen_keys:
            stats["duplicate"] = stats.get("duplicate", 0) + 1
            continue
        seen_keys.add(key)
        candidates.append(line)

    unique_candidate_count = len(candidates)
    # 候选按源顺序排列时，测试上限会固定切掉排在后面的源（实测 11k 候选
    # 只测前 5k，后加的源永远轮不到）。按小时种子打散，让每小时一轮的
    # 覆盖范围轮换，长期每个源都有机会被测到。
    random.Random(int(time.time() // 3600)).shuffle(candidates)
    candidates = limit_candidates(candidates, stats)
    print(
        f"去重后候选节点: {unique_candidate_count}；"
        f"本轮最多检测 {len(candidates)} 个（超出上限跳过 {stats['skipped_limit']} 个）"
    )

    # 4. 并行测试 + 分类统计
    print(f"开始并行 TCP 多次采样（每节点 {TCP_SAMPLES} 次，至少成功 {MIN_SUCCESSFUL_SAMPLES} 次；UDP 协议单独标记未验证）...")

    alive: list[tuple] = []  # (line, median_latency, protocol, jitter)
    udp_candidates: list[str] = []
    if candidates:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(test_node, line) for line in candidates]
            for future in as_completed(futures):
                try:
                    status, line, latency, protocol, jitter = future.result()
                except Exception:
                    stats["timeout"] += 1
                    continue
                stats[status] = stats.get(status, 0) + 1
                if status == "ok":
                    alive.append((line, latency, protocol, jitter))
                elif status == "udp_unverified":
                    udp_candidates.append(line)

    if not candidates:
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous")
        print(f"质量报告已更新: {QUALITY_REPORT}")
        print("没有可用候选节点，保留旧订阅。")
        return

    print("-" * 46)
    print("测试结果统计:")
    print(f"  ✅ 合格节点       : {stats['ok']}")
    print(f"  🐢 延迟过高过滤   : {stats['slow']}  (>{MAX_LATENCY}s)")
    print(f"  ⏰ 超时/不可达    : {stats['timeout']}  (>{TIMEOUT}s 或连接失败)")
    print(f"  🔒 私有IP过滤     : {stats['private']}")
    print(f"  ↪ UDP待协议验证   : {stats['udp_unverified']}")
    print(f"  ❌ 解析失败       : {stats['invalid']}")
    print("-" * 46)

    if not alive and not udp_candidates:
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous")
        print(f"质量报告已更新: {QUALITY_REPORT}")
        print("没有可进行协议级测速的节点，保留旧订阅。")
        return

    # 5. TCP 延迟只用于缩小候选范围；最终订阅严格按真实代理隧道下载 Mbps 排名。
    alive.sort(key=lambda x: (x[1], x[3], PROTOCOL_WEIGHT.get(x[2], 9)))
    # Give the speed tester a wider pool; it preflights unsupported formats and
    # selects a round-robin sample across protocols instead of testing VLESS only.
    protocol_buckets: dict[str, list[tuple]] = {}
    for entry in alive:
        protocol_buckets.setdefault(entry[2], []).append(entry)
    tcp_shortlist = []
    protocol_order = sorted(protocol_buckets)
    while len(tcp_shortlist) < 80 and protocol_order:
        remaining_protocols = []
        for protocol in protocol_order:
            if protocol_buckets[protocol] and len(tcp_shortlist) < 80:
                tcp_shortlist.append(protocol_buckets[protocol].pop(0)[0])
            if protocol_buckets[protocol]:
                remaining_protocols.append(protocol)
        protocol_order = remaining_protocols
    udp_shortlist = udp_candidates[:20]
    speed_shortlist = tcp_shortlist + udp_shortlist

    import shutil
    try:
        from speedtest import rank_by_speed  # python scripts/collector.py
    except ImportError:  # package-style execution
        from .speedtest import rank_by_speed
    binary = os.environ.get("SING_BOX_PATH") or shutil.which("sing-box")
    if not binary:
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous")
        raise RuntimeError("sing-box binary unavailable; refusing to publish a latency-only ranking")

    print(f"开始真实代理隧道下载测速：TCP {len(tcp_shortlist)} 个，UDP {len(udp_shortlist)} 个")
    successful_speed_nodes, speed_results = rank_by_speed(speed_shortlist, binary)
    stats["proxy_speed_candidates_considered"] = len(speed_results)
    stats["proxy_speed_unsupported"] = sum(
        1 for _, result in speed_results if result.get("status") == "unsupported"
    )
    stats["proxy_speed_tested"] = sum(
        1 for _, result in speed_results if result.get("status") != "unsupported"
    )
    stats["proxy_speed_ok"] = len(successful_speed_nodes)
    stats["udp_speed_verified"] = sum(
        1 for uri, result in successful_speed_nodes
        if get_endpoint(uri)[0] in ("hysteria2", "hy2", "tuic")
    )
    stats["udp_unverified"] = max(0, stats.get("udp_unverified", 0) - stats["udp_speed_verified"])
    stats["proxy_speed_failed_or_unsupported"] = len(speed_results) - len(successful_speed_nodes)

    if not successful_speed_nodes:
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous", speed_results)
        print("没有节点通过实际代理下载测试，保留上一版订阅。")
        return

    selected = [uri for uri, _ in successful_speed_nodes[:MAX_NODES]]
    print("实测下载速度排名（Mbps）:")
    for rank, (uri, result) in enumerate(successful_speed_nodes[:10], 1):
        protocol, host, port = get_endpoint(uri)
        print(f"  #{rank} {result['download_mbps']:.2f} Mbps  {protocol}://{host}:{port}")

    # 6. 只发布已完成代理隧道下载测试的节点；订阅按实测 Mbps 降序。
    content = base64.b64encode("\n".join(selected).encode("utf-8")).decode("ascii")
    atomic_write_text(OUTPUT, content + "\n")
    write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "updated", speed_results)
    print(f"质量报告已更新: {QUALITY_REPORT}")

    print(f"\n已生成真实测速节点: {len(selected)} 个")
    print(f"  → {OUTPUT}")
    print("订阅仅包含已通过实际代理下载测试的节点，按 Mbps 从高到低排序；不会提交节点 URI。")
    print(f"  → {QUALITY_REPORT} (仅含哈希节点 ID 与聚合测速数据)")


if __name__ == "__main__":
    main()
