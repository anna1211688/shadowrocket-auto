import base64
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

# ============ 可配置参数 ============
TIMEOUT = 3.0                 # TCP 连接超时（秒）——超过此时间视为超时节点，直接丢弃
MAX_LATENCY = 2.5             # 最大可接受延迟（秒）——即使连通，超过此延迟也过滤掉
MAX_NODES = 150               # 最终保留节点数
MAX_WORKERS = 50              # 并发测试数量
SOURCE_TIMEOUT = 12           # 拉取订阅源超时
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
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
                # IPv6
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
    测试节点可达性。
    返回:
      ("ok", line, latency)     — 连通且延迟合格
      ("slow", line, latency)   — 连通但延迟过高
      ("timeout", line, None)   — 超时或连接失败
      ("invalid", line, None)   — 解析失败
    """
    protocol, host, port = get_endpoint(line)
    if not host or not port or not (1 <= port <= 65535):
        return "invalid", line, None

    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            latency = time.perf_counter() - start
            if latency > MAX_LATENCY:
                return "slow", line, latency
            return "ok", line, latency
    except (socket.timeout, TimeoutError):
        return "timeout", line, None
    except Exception:
        return "timeout", line, None


def fetch_source(url: str) -> list[str]:
    try:
        resp = requests.get(
            url,
            timeout=SOURCE_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        return decode_subscription(resp.text)
    except Exception as e:
        print(f"[源失败] {url} -> {e}")
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

    # 2. 拉取所有节点
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

    alive: list[tuple[str, float]] = []
    stats = {"ok": 0, "slow": 0, "timeout": 0, "invalid": 0}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_node, line) for line in candidates]
        for future in as_completed(futures):
            status, line, latency = future.result()
            stats[status] += 1
            if status == "ok":
                alive.append((line, latency))

    print("-" * 40)
    print(f"测试结果统计:")
    print(f"  ✅ 合格节点     : {stats['ok']}")
    print(f"  🐢 延迟过高过滤 : {stats['slow']}  (>{MAX_LATENCY}s)")
    print(f"  ⏰ 超时/不可达  : {stats['timeout']}  (>{TIMEOUT}s 或连接失败)")
    print(f"  ❌ 解析失败     : {stats['invalid']}")
    print("-" * 40)

    if not alive:
        print("没有检测到合格节点，保留旧订阅。")
        return

    # 5. 按延迟排序，取前 MAX_NODES
    alive.sort(key=lambda x: x[1])
    selected = [line for line, _ in alive[:MAX_NODES]]

    print(f"延迟最低的 8 个节点:")
    for line, lat in alive[:8]:
        proto, host, port = get_endpoint(line)
        print(f"  {lat*1000:.0f}ms  {proto}://{host}:{port}")

    # 6. 写入 base64 订阅
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    content = base64.b64encode("\n".join(selected).encode("utf-8")).decode("ascii")
    OUTPUT.write_text(content + "\n", encoding="utf-8")

    print(f"\n已发布节点: {len(selected)} 个 → {OUTPUT}")


if __name__ == "__main__":
    main()
