import base64
import ipaddress
import json
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "config" / "sources.txt"
OUTPUT = ROOT / "docs" / "shadowrocket.txt"
OUTPUT_PLAIN = ROOT / "docs" / "shadowrocket_plain.txt"  # 明文调试用

# ============ 可配置参数 ============
TIMEOUT = 3.0                 # TCP 连接超时（秒）
MAX_LATENCY = 2.5             # 最大可接受延迟（秒）
MAX_NODES = 150               # 最终保留节点数
MAX_WORKERS = 50              # 并发测试数量
SOURCE_TIMEOUT = 12           # 拉取订阅源超时
SOURCE_RETRIES = 1            # 源拉取失败后重试次数
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

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
    value = value.strip()
    value += "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value).decode("utf-8", errors="ignore")
    except Exception:
        try:
            return base64.b64decode(value).decode("utf-8", errors="ignore")
        except Exception:
            return ""


def decode_subscription(content: str) -> list[str]:
    content = content.strip()
    if not content:
        return []

    decoded = decode_base64(content)
    if decoded and ("://" in decoded or "\n" in decoded):
        content = decoded

    return [line.strip() for line in content.splitlines() if line.strip()]


def get_protocol(line: str) -> str | None:
    m = re.match(r"^(ss|vmess|vless|trojan|hysteria2?|hy2|tuic)://", line, re.I)
    return m.group(1).lower() if m else None


def is_public_ip(host: str) -> bool:
    """过滤私有、回环、保留地址"""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        # 域名视为可用（后续 TCP 测试会验证）
        return True


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
            host = data.get("add") or data.get("host")
            port = int(data.get("port", 0))
            return protocol, host, port

        if protocol in ("vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic"):
            parsed = urllib.parse.urlsplit(line)
            host = parsed.hostname
            port = parsed.port
            if host and port:
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

            return protocol, host, port

    except Exception:
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

    if not is_public_ip(host):
        return "private", line, None, protocol

    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            latency = time.perf_counter() - start
            if latency > MAX_LATENCY:
                return "slow", line, latency, protocol
            return "ok", line, latency, protocol
    except (socket.timeout, TimeoutError):
        return "timeout", line, None, protocol
    except Exception:
        return "timeout", line, None, protocol


def fetch_source(url: str) -> list[str]:
    last_error = None
    for attempt in range(1 + SOURCE_RETRIES):
        try:
            resp = requests.get(
                url,
                timeout=SOURCE_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )
            resp.raise_for_status()
            return decode_subscription(resp.text)
        except Exception as e:
            last_error = e
            if attempt < SOURCE_RETRIES:
                time.sleep(1)
    print(f"[源失败] {url} -> {last_error}")
    return []


def main():
    # 1. 读取源列表
    sources = []
    if SOURCES.exists():
        for line in SOURCES.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                sources.append(line)

    print(f"共 {len(sources)} 个订阅源")

    # 2. 拉取所有节点（带重试）
    raw_nodes: list[str] = []
    for url in sources:
        nodes = fetch_source(url)
        print(f"  拉取到 {len(nodes)} 条: {url}")
        raw_nodes.extend(nodes)

    # 3. 初步过滤 + 按 (protocol, host, port) 去重
    candidates = []
    seen_keys = set()

    for line in raw_nodes:
        protocol, host, port = get_endpoint(line)
        if not protocol or not host or not port:
            continue
        if not is_public_ip(host):
            continue

        key = (protocol, host.lower(), port)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        candidates.append(line)

    print(f"去重后候选节点: {len(candidates)}")

    if not candidates:
        print("没有可用候选节点，保留旧订阅。")
        return

    # 4. 并行测试 + 分类统计
    print(f"开始并行测试（并发 {MAX_WORKERS}，超时 {TIMEOUT}s，最大延迟 {MAX_LATENCY}s）...")

    alive: list[tuple[str, float, str]] = []  # (line, latency, protocol)
    stats = {"ok": 0, "slow": 0, "timeout": 0, "invalid": 0, "private": 0}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_node, line) for line in candidates]
        for future in as_completed(futures):
            status, line, latency, protocol = future.result()
            stats[status] = stats.get(status, 0) + 1
            if status == "ok":
                alive.append((line, latency, protocol))

    print("-" * 46)
    print("测试结果统计:")
    print(f"  ✅ 合格节点       : {stats['ok']}")
    print(f"  🐢 延迟过高过滤   : {stats['slow']}  (>{MAX_LATENCY}s)")
    print(f"  ⏰ 超时/不可达    : {stats['timeout']}  (>{TIMEOUT}s 或连接失败)")
    print(f"  🔒 私有IP过滤     : {stats['private']}")
    print(f"  ❌ 解析失败       : {stats['invalid']}")
    print("-" * 46)

    if not alive:
        print("没有检测到合格节点，保留旧订阅。")
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

    # 明文版本（方便调试，可不提交到 git 也可提交）
    OUTPUT_PLAIN.write_text("\n".join(selected) + "\n", encoding="utf-8")

    print(f"\n已发布节点: {len(selected)} 个")
    print(f"  → {OUTPUT}")
    print(f"  → {OUTPUT_PLAIN} (明文调试)")


if __name__ == "__main__":
    main()
