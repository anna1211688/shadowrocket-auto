import base64
import ipaddress
import json
import re
import socket
import subprocess
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
MAX_LATENCY = 2.5             # 最大可接受延迟（秒）
MAX_NODES = 150               # 最终保留节点数
MAX_WORKERS = 30
NODE_DEADLINE = 5.0
DNS_TIMEOUT = 2.0
SOURCE_TIMEOUT = (4, 8)
SOURCE_RETRIES = 1
MAX_SOURCE_BYTES = 2_000_000
MAX_SOURCE_NODES = 5_000
MAX_TOTAL_NODES = 20_000
MAX_LINE_LENGTH = 8_192
MAX_SOURCES = 100
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

    try:
        # subprocess.run 会在 DNS_TIMEOUT 到期后终止并回收解析进程，避免永久卡住采集线程。
        completed = subprocess.run(
            ["getent", "ahosts", host],
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
                         alive: list[tuple[str, float, str]],
                         subscription_status: str = "preserved_previous") -> None:
    """写入不包含节点地址/凭据的聚合质量报告。"""
    import datetime
    import statistics

    latencies = sorted(latency * 1000 for _, latency, _ in alive)
    protocol_counts: dict[str, int] = {}
    region_counts: dict[str, int] = {}
    for line, _, protocol in alive:
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

    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "measurement": "tcp_connect_only",
        "note": "TCP reachability is not proof that proxy authentication or tunneling works.",
        "subscription_status": subscription_status,
        "raw_nodes": raw_count,
        "unique_candidates": candidate_count,
        "tcp_reachable": len(alive),
        "rejected": stats,
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "region_counts": dict(sorted(region_counts.items())),
        "latency_ms": {
            "min": round(latencies[0], 1) if latencies else None,
            "average": round(statistics.mean(latencies), 1) if latencies else None,
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
        },
    }
    QUALITY_REPORT.parent.mkdir(parents=True, exist_ok=True)
    QUALITY_REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
    """
    返回:
      ("ok", line, latency, protocol)
      ("slow", line, latency, protocol)
      ("timeout", line, None, protocol)
      ("invalid", line, None, None)
      ("private", line, None, protocol)
    """
    protocol, host, port = get_endpoint(line)
    if not protocol or not host or not port or not (1 <= port <= 65535):
        return "invalid", line, None, None

    try:
        addresses = resolve_public_addresses(host)
        if not addresses:
            return "private", line, None, protocol
        start = time.perf_counter()
        deadline = start + NODE_DEADLINE
        connected = False
        for family, socktype, proto, _, sockaddr in addresses:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return "timeout", line, None, protocol
            target = (sockaddr[0], port, *sockaddr[2:]) if family == socket.AF_INET6 else (sockaddr[0], port)
            try:
                with socket.socket(family, socktype, proto) as sock:
                    sock.settimeout(min(TIMEOUT, remaining))
                    sock.connect(target)
                connected = True
                break
            except OSError:
                continue
        if not connected:
            return "timeout", line, None, protocol
        latency = time.perf_counter() - start
        if latency > MAX_LATENCY:
            return "slow", line, latency, protocol
        return "ok", line, latency, protocol
    except (socket.timeout, TimeoutError, DNSResolutionTimeout):
        return "timeout", line, None, protocol
    except Exception:
        return "timeout", line, None, protocol


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
    for attempt in range(1 + SOURCE_RETRIES):
        try:
            with requests.get(url, timeout=SOURCE_TIMEOUT, headers={"User-Agent": USER_AGENT}, stream=True, allow_redirects=False) as resp:
                resp.raise_for_status()
                length = resp.headers.get("Content-Length")
                if length and int(length) > MAX_SOURCE_BYTES:
                    raise ValueError("source too large")
                chunks, total = [], 0
                for chunk in resp.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_SOURCE_BYTES:
                        raise ValueError("source too large")
                    chunks.append(chunk)
                return decode_subscription(b"".join(chunks).decode("utf-8-sig", errors="replace"))
        except (requests.RequestException, ValueError, UnicodeError) as e:
            last_error = type(e).__name__
            if attempt < SOURCE_RETRIES:
                time.sleep(1)
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
    for url in sources:
        nodes = fetch_source(url)
        raw_nodes.extend(nodes[:max(0, MAX_TOTAL_NODES - len(raw_nodes))])
        if len(raw_nodes) >= MAX_TOTAL_NODES:
            break

    # 3. 初步过滤 + 按端点、凭据和传输参数去重
    stats = {"ok": 0, "slow": 0, "timeout": 0, "invalid": 0, "private": 0, "duplicate": 0}
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

    print(f"去重后候选节点: {len(candidates)}")

    # 4. 并行测试 + 分类统计
    print(f"开始并行 TCP 连通性测试（并发 {MAX_WORKERS}，超时 {TIMEOUT}s，最大延迟 {MAX_LATENCY}s）...")

    alive: list[tuple[str, float, str]] = []  # (line, latency, protocol)
    if candidates:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(test_node, line) for line in candidates]
            for future in as_completed(futures):
                try:
                    status, line, latency, protocol = future.result()
                except Exception:
                    stats["timeout"] += 1
                    continue
                stats[status] = stats.get(status, 0) + 1
                if status == "ok":
                    alive.append((line, latency, protocol))

    subscription_status = "updated" if alive else "preserved_previous"
    write_quality_report(len(raw_nodes), len(candidates), stats, alive, subscription_status)
    print(f"质量报告已更新: {QUALITY_REPORT}")

    if not candidates:
        print("没有可用候选节点，保留旧订阅。")
        return

    print("-" * 46)
    print("测试结果统计:")
    print(f"  ✅ 合格节点       : {stats['ok']}")
    print(f"  🐢 延迟过高过滤   : {stats['slow']}  (>{MAX_LATENCY}s)")
    print(f"  ⏰ 超时/不可达    : {stats['timeout']}  (>{TIMEOUT}s 或连接失败)")
    print(f"  🔒 私有IP过滤     : {stats['private']}")
    print(f"  ❌ 解析失败       : {stats['invalid']}")
    print("-" * 46)

    if not alive:
        print("没有检测到可建立 TCP 连接的节点，保留旧订阅。")
        return

    # 5. 排序：先按延迟，再按协议权重
    alive.sort(key=lambda x: (x[1], PROTOCOL_WEIGHT.get(x[2], 9)))
    selected = [line for line, _, _ in alive[:MAX_NODES]]

    print("延迟最低的 8 个节点:")
    for line, lat, proto in alive[:8]:
        _, host, port = get_endpoint(line)
        print(f"  {lat*1000:.0f}ms  {proto}://{host}:{port}")

    # 6. 写入文件
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # base64 订阅（给客户端用）
    content = base64.b64encode("\n".join(selected).encode("utf-8")).decode("ascii")
    OUTPUT.write_text(content + "\n", encoding="utf-8")

    print(f"\n已发布节点: {len(selected)} 个")
    print(f"  → {OUTPUT}")
    print("仅生成 Base64 订阅；不会写出明文节点文件。")
    print(f"  → {QUALITY_REPORT} (聚合质量报告)")


if __name__ == "__main__":
    main()
