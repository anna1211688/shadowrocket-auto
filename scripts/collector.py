import base64
import datetime
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


def cn_tier(line: str) -> int:
    """大陆可用性档位：0=A（优先）/ 1=B / 2=C。

    面向主要在大陆使用的客户端：VLESS Reality 与 443 端口的 TLS 伪装
    最难被识别和封锁；SS、hy2 等明文特征或 UDP 协议在大陆成功率最低。
    注意这只是按协议/传输/端口的启发式排序，节点 IP 本身是否已被封锁
    无法从境外测量得知。
    """
    protocol, _, port = get_endpoint(line)
    if not protocol:
        return 2
    if protocol == "vless":
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(line).query))
        security = str(query.get("security", "")).lower()
        if security == "reality":
            return 0
        if security == "tls":
            return 0 if port == 443 else 1
        return 2
    if protocol == "trojan":
        return 0 if port == 443 else 1
    if protocol == "vmess":
        try:
            raw = decode_base64(line[8:].split("#", 1)[0].split("?", 1)[0])
            data = json.loads(raw)
            if isinstance(data, dict) and str(data.get("tls", "")).lower() == "tls" \
                    and str(data.get("port")) == "443":
                return 1
        except (ValueError, TypeError):
            pass
        return 2
    return 2


_CF_IPV4_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "188.114.96.0/20",
        "162.158.0.0/15", "198.41.128.0/17", "162.159.0.0/16",
    )
]
_CF_IPV6_NETWORK = ipaddress.ip_network("2606:4700::/32")


def cdn_fronted(line: str) -> bool:
    """节点端点是否由 Cloudflare 前置（CDN 中转）。

    2026-11-20 深圳实测教训：直连 IP 的 Reality/TLS 节点（A 档）订阅
    31 个在大陆仍全部超时——公开服务器 IP 早被名单收录，按 IP 封锁
    与协议伪装无关。经 Cloudflare 前置的节点对外端点是 CF 的 anycast
    地址、真实服务器藏在后面，CF 地址段承载海量正常站点、极少被整段
    封锁，是公开池里从大陆连通率最高的一类，故单列最高优先级。
    """
    _, host, _ = get_endpoint(line)
    if not host:
        return False
    host = str(host).lower()
    if host.endswith(("workers.dev", "pages.dev")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        return address in _CF_IPV6_NETWORK
    return any(address in network for network in _CF_IPV4_NETWORKS)


# 大陆优化模式（2026-11-20 迭代）：测速分组按优先级——CF 前置 A/B
# 100、直连 A 40、直连 B 20、C 档（SS 等）40。C 档回放的原因是深圳
# 实测：唯一连上的恰是冷门 IP 段上的普通 SS，而被寄予厚望的
# Reality/CF 前置若出自已被编目的服务/IP 段照样全灭——决定生死的是
# 「这家服务、这个 IP 段有没有被收录」，不是协议本身。故订阅端再加
# 两道多样性闸门（见 dedupe_for_subscription）：按服务去重、按 /24
# 网段限额，逼订阅分散到几十家不同来源，靠分散存活而非押注单一
# 类型。某轮若全部未通过，沿用「保留上一版订阅」逻辑。
# 每组名单按小时种子轮换切片，让候选都有被测到的机会。
FRONTED_TCP_QUOTA = 100
TIER_TCP_QUOTAS = {0: 40, 1: 20, 2: 40}
SPEED_TCP_LIMIT = 200
SPEED_UDP_LIMIT = 0

# 存活时长信号（2026-11-20 晚定）：深圳实测对照显示，小而稳定的
# Pawdroid 订阅 9 个节点有 6 个可用，而我们每小时按「刚测速通过」
# 新选的 30 个只有 1 个——公开池的新面孔多是短命诱饵，长期存活的
# 节点才是真服务。历史随质量报告一同提交回仓库（工作流只提交该
# 文件），跨轮累积每个节点被 TCP 测活/测速通过的轮次与首见时间；
# 「老兵」＝首见 ≥24 小时且至少 6 个轮次 TCP 测活。选测速名单时
# 每组先保老兵、余量再轮换抽新面孔；订阅排序同组内老兵靠前。
VETERAN_MIN_AGE_HOURS = 24
VETERAN_MIN_ALIVE_ROUNDS = 6
HISTORY_PRUNE_DAYS = 7
HISTORY_MAX_ENTRIES = 20000


def history_key(line: str) -> str:
    """节点在历史中的身份：用去重键（忽略备注名）的哈希。"""
    key = get_dedup_key(line)
    if key is None:
        protocol, host, port = get_endpoint(line)
        key = (protocol, str(host).lower(), port)
    return hashlib.sha256(repr(key).encode("utf-8")).hexdigest()[:16]


def _history_age_hours(entry: dict, now: datetime.datetime) -> float:
    try:
        first = datetime.datetime.fromisoformat(entry["f"])
    except (KeyError, TypeError, ValueError):
        return 0.0
    if first.tzinfo is None:
        first = first.replace(tzinfo=datetime.timezone.utc)
    return max(0.0, (now - first).total_seconds() / 3600.0)


def is_veteran(entry: dict | None, now: datetime.datetime) -> bool:
    if not entry:
        return False
    return (_history_age_hours(entry, now) >= VETERAN_MIN_AGE_HOURS
            and entry.get("a", 0) >= VETERAN_MIN_ALIVE_ROUNDS)


def load_node_history() -> dict:
    """从上一轮质量报告读回节点历史（报告由工作流提交回仓库）。"""
    try:
        report = json.loads(QUALITY_REPORT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    history = report.get("node_history")
    return history if isinstance(history, dict) else {}


def update_node_history(history: dict, alive_lines, passed_lines, now: datetime.datetime) -> dict:
    """累积本轮结果并修剪：条目 {f:首见, l:最近见, a:测活轮次, p:测通轮次}。"""
    stamp = now.isoformat()
    updated = {key: dict(entry) for key, entry in history.items() if isinstance(entry, dict)}
    for line in set(alive_lines):
        key = history_key(line)
        entry = updated.setdefault(key, {"f": stamp, "l": stamp, "a": 0, "p": 0})
        entry["l"] = stamp
        entry["a"] = entry.get("a", 0) + 1
    for line in set(passed_lines):
        entry = updated.get(history_key(line))
        if entry is not None:
            entry["p"] = entry.get("p", 0) + 1
    cutoff = now - datetime.timedelta(days=HISTORY_PRUNE_DAYS)
    pruned = {}
    for key, entry in updated.items():
        try:
            last = datetime.datetime.fromisoformat(entry["l"])
        except (KeyError, TypeError, ValueError):
            continue
        if last.tzinfo is None:
            last = last.replace(tzinfo=datetime.timezone.utc)
        if last >= cutoff:
            pruned[key] = entry
    if len(pruned) > HISTORY_MAX_ENTRIES:
        by_recent = sorted(pruned.items(), key=lambda item: item[1]["l"], reverse=True)
        pruned = dict(by_recent[:HISTORY_MAX_ENTRIES])
    return pruned


def _round_robin_by_protocol(entries: list[tuple], limit: int) -> list[str]:
    protocol_buckets: dict[str, list[tuple]] = {}
    for entry in entries:
        protocol_buckets.setdefault(entry[2], []).append(entry)
    selected: list[str] = []
    protocol_order = sorted(protocol_buckets)
    while len(selected) < limit and protocol_order:
        remaining = []
        for protocol in protocol_order:
            if protocol_buckets[protocol] and len(selected) < limit:
                selected.append(protocol_buckets[protocol].pop(0)[0])
            if protocol_buckets[protocol]:
                remaining.append(protocol)
        protocol_order = remaining
    return selected


def _rotate(entries: list, rng: random.Random) -> list:
    """按随机偏移旋转列表：切片随种子变化，切片内相对顺序不变。"""
    if len(entries) < 2:
        return list(entries)
    offset = rng.randrange(len(entries))
    return entries[offset:] + entries[:offset]


def select_speed_shortlist(alive: list[tuple], udp_candidates: list[str], seed: int | None = None,
                           history: dict | None = None, now: datetime.datetime | None = None):
    """按组配额选 TCP 测速名单（CF 前置 A/B → 直连 A → 直连 B → C 档）。

    某组不足时，剩余名额按组优先级补位。
    组内先保「老兵」（见 is_veteran，按历史测通轮次、测活轮次排序），
    余量再按小时种子轮换抽取：alive 已按延迟排序，轮换让每小时被测的
    是不同切片（切片内仍按延迟优先），避免长期只测同一批新面孔。
    """
    if seed is None:
        seed = int(time.time() // 3600)
    rng = random.Random(seed)
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    history = history or {}
    # 分组（优先级从高到低）：CF 前置的 A/B → 直连 A → 直连 B → C 档。
    groups: list[tuple[list[tuple], int]] = []
    fronted = [e for e in alive if cn_tier(e[0]) <= 1 and cdn_fronted(e[0])]
    direct_a = [e for e in alive if cn_tier(e[0]) == 0 and not cdn_fronted(e[0])]
    direct_b = [e for e in alive if cn_tier(e[0]) == 1 and not cdn_fronted(e[0])]
    tier_c = [e for e in alive if cn_tier(e[0]) == 2 and not cdn_fronted(e[0])]
    groups = [(fronted, FRONTED_TCP_QUOTA), (direct_a, TIER_TCP_QUOTAS[0]),
              (direct_b, TIER_TCP_QUOTAS[1]), (tier_c, TIER_TCP_QUOTAS[2])]
    tcp_shortlist: list[str] = []
    leftovers: list[list[tuple]] = []
    for entries, quota in groups:
        veterans = [e for e in entries if is_veteran(history.get(history_key(e[0])), now)]
        veterans.sort(key=lambda e: (-history[history_key(e[0])].get("p", 0),
                                     -history[history_key(e[0])].get("a", 0)))
        veteran_lines = {e[0] for e in veterans}
        others = [e for e in entries if e[0] not in veteran_lines]
        rotated = _rotate(others, rng)
        picked_veterans = [e[0] for e in veterans[:quota]]
        picked = picked_veterans + _round_robin_by_protocol(rotated, quota - len(picked_veterans))
        tcp_shortlist.extend(picked)
        picked_lines = set(picked)
        leftover_ordered = [e for e in veterans if e[0] not in picked_lines]
        leftover_ordered += [entry for entry in rotated if entry[0] not in picked_lines]
        leftovers.append(leftover_ordered)
    # 补位按组优先级进行，前组不足时由后组补满，反之亦然。
    for leftover in leftovers:
        if len(tcp_shortlist) >= SPEED_TCP_LIMIT:
            break
        tcp_shortlist.extend(
            _round_robin_by_protocol(leftover, SPEED_TCP_LIMIT - len(tcp_shortlist))
        )
    return tcp_shortlist, _rotate(udp_candidates, rng)[:SPEED_UDP_LIMIT]


def dedupe_by_endpoint(nodes: list[tuple]) -> list[tuple]:
    """同一服务器（host:端口）只保留第一条。

    输入须已按期望顺序排好（档位、再 Mbps）：公开池里同一台服务器常
    以多个密码出现多次，对客户端那是同一台机器——IP 被封会成片失效，
    订阅里只留最快的一条，其余丢弃。返回 (保留列表, 丢弃数)。
    """
    seen: set[tuple] = set()
    kept: list[tuple] = []
    dropped = 0
    for uri, result in nodes:
        _, host, port = get_endpoint(uri)
        key = (str(host).lower(), port)
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        kept.append((uri, result))
    return kept, dropped


def service_key(line: str) -> tuple:
    """识别节点背后的「服务」：同一服务的多个入口应视为一个来源。

    前置节点用 (协议, 凭据, 源站域名, 端口)：CF 边缘 IP 只是门牌，
    同一 UUID+源站换多少个 CF IP 都是同一家（实测一例：8 个 CF IP
    实为同一节点）。直连节点再带上服务器地址，剩下的同服务多 IP
    由 network_key 的网段限额兜底。无凭据可取时退回端点键。
    """
    protocol, host, port = get_endpoint(line)
    credential = ""
    origin = ""
    if protocol == "vmess":
        try:
            raw = decode_base64(line[8:].split("#", 1)[0].split("?", 1)[0])
            data = json.loads(raw)
            if isinstance(data, dict):
                credential = str(data.get("id", ""))
                origin = str(data.get("host") or data.get("sni") or "")
        except (ValueError, TypeError):
            pass
    elif protocol in ("vless", "trojan", "ss", "hysteria2", "hy2", "tuic"):
        parts = urllib.parse.urlsplit(line)
        credential = parts.username or ""
        if protocol in ("vless", "trojan"):
            query = dict(urllib.parse.parse_qsl(parts.query))
            origin = query.get("host") or query.get("sni") or ""
    if credential:
        if cdn_fronted(line):
            return (protocol, credential, origin.lower(), port)
        return (protocol, credential, origin.lower(), str(host).lower(), port)
    return (protocol, str(host).lower(), port)


def network_key(host: str) -> tuple:
    """节点端点所在的网段：IPv4 按 /24、IPv6 按 /48、域名按自身。"""
    name = str(host).lower()
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return ("host", name)
    if isinstance(address, ipaddress.IPv4Address):
        return ("net", str(ipaddress.ip_network(f"{name}/24", strict=False)))
    return ("net", str(ipaddress.ip_network(f"{name}/48", strict=False)))


MAX_PER_SERVICE = 2
MAX_PER_NETWORK = 3


def dedupe_for_subscription(nodes: list[tuple]) -> tuple[list[tuple], int]:
    """多样性闸门：同一服务最多留 MAX_PER_SERVICE 个入口，同一网段
    最多留 MAX_PER_NETWORK 个节点。输入须已按期望顺序排好。

    依据 2026-11-20 深圳实测：订阅的死活取决于来源是否分散——曾有
    一轮 33 个节点实际只来自个位数服务/网段，被编目的那几家一倒
    就是整表超时。分散到几十家后，个别来源被封不影响其余。
    """
    service_counts: dict[tuple, int] = {}
    network_counts: dict[tuple, int] = {}
    kept: list[tuple] = []
    dropped = 0
    for uri, result in nodes:
        skey = service_key(uri)
        _, host, _ = get_endpoint(uri)
        nkey = network_key(host)
        if service_counts.get(skey, 0) >= MAX_PER_SERVICE or network_counts.get(nkey, 0) >= MAX_PER_NETWORK:
            dropped += 1
            continue
        service_counts[skey] = service_counts.get(skey, 0) + 1
        network_counts[nkey] = network_counts.get(nkey, 0) + 1
        kept.append((uri, result))
    return kept, dropped


def write_quality_report(raw_count: int, candidate_count: int, stats: dict,
                         alive: list[tuple],
                         subscription_status: str = "preserved_previous",
                         speed_results: list[tuple] | None = None,
                         selected: list[str] | None = None,
                         history: dict | None = None) -> None:
    """写入不包含节点地址/凭据的聚合质量报告。"""
    import datetime
    import statistics

    latencies = sorted(entry[1] * 1000 for entry in alive)
    jitters = sorted(entry[3] * 1000 for entry in alive if len(entry) > 3 and entry[3] is not None)
    protocol_counts: dict[str, int] = {}
    region_counts: dict[str, int] = {}
    tier_counts: dict[str, int] = {}
    for entry in alive:
        line, _, protocol = entry[:3]
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        region = infer_region(line)
        region_counts[region] = region_counts.get(region, 0) + 1
        tier = "ABC"[cn_tier(line)]
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

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

    report_now = datetime.datetime.now(datetime.timezone.utc)
    report = {
        "generated_at": report_now.isoformat(),
        "measurement": "proxy_download_speed_mbps_with_tcp_latency_context",
        "ranking": "cdn_fronted_then_cn_tier_then_measured_proxy_download_mbps_descending",
        "cn_tier_counts": dict(sorted(tier_counts.items())),
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
        "note": "Mainland-China optimised subscription: Cloudflare-fronted and tier A/B nodes are preferred, tier C (SS etc.) is included under diversity caps - field tests from Shenzhen showed survival depends on how un-catalogued a node's service/IP range is, not on protocol alone. Subscription enforces per-service (max 2) and per-/24 (max 3) caps so no single provider dominates. Selection also weights node longevity: a cross-round history (node_history, hash keys only) tracks how long each node has kept appearing and passing, and veterans (>=24h old, alive in >=6 rounds) get shortlist priority and rank ahead within their tier - a small stable subscription in the same pool field-tested far better than freshly picked nodes. Order is fronted first, then tier, then veteran status, then measured download Mbps through a sing-box proxy tunnel. Only supported URI formats with successful complete downloads are ranked; this is GitHub-runner egress performance, not a guarantee of client-side speed or reachability.",
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
    if selected is not None:
        selected_tiers: dict[str, int] = {}
        for line in selected:
            tier = "ABC"[cn_tier(line)]
            selected_tiers[tier] = selected_tiers.get(tier, 0) + 1
        report["subscription"] = {
            "nodes": len(selected),
            "cdn_fronted": sum(1 for line in selected if cdn_fronted(line)),
            "tier_counts": dict(sorted(selected_tiers.items())),
            "distinct_services": len({service_key(line) for line in selected}),
            "distinct_networks": len({network_key(get_endpoint(line)[1]) for line in selected}),
            "veterans": sum(1 for line in selected
                            if is_veteran((history or {}).get(history_key(line)), report_now)),
        }
    if history is not None:
        # 历史只存哈希键与计数/时间戳，不含地址或凭据；随报告提交回
        # 仓库，供下一轮累积（工作流只提交本文件）。
        report["node_history"] = history
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
    run_now = datetime.datetime.now(datetime.timezone.utc)
    history = load_node_history()
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
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous",
                             history=update_node_history(history, [], [], run_now))
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
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous",
                             history=update_node_history(history, [], [], run_now))
        print(f"质量报告已更新: {QUALITY_REPORT}")
        print("没有可进行协议级测速的节点，保留旧订阅。")
        return

    # 5. TCP 延迟只用于缩小候选范围；测速名单按档位配额选（见
    # select_speed_shortlist），订阅排序先档位、再实测 Mbps。
    alive.sort(key=lambda x: (x[1], x[3], PROTOCOL_WEIGHT.get(x[2], 9)))
    tcp_shortlist, udp_shortlist = select_speed_shortlist(alive, udp_candidates, history=history, now=run_now)
    veteran_picks = sum(1 for line in tcp_shortlist if is_veteran(history.get(history_key(line)), run_now))
    print(f"本轮历史条目 {len(history)} 个，测速名单含老兵节点 {veteran_picks} 个")
    speed_shortlist = tcp_shortlist + udp_shortlist

    import shutil
    try:
        from speedtest import rank_by_speed  # python scripts/collector.py
    except ImportError:  # package-style execution
        from .speedtest import rank_by_speed
    binary = os.environ.get("SING_BOX_PATH") or shutil.which("sing-box")
    if not binary:
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous",
                             history=update_node_history(history, [e[0] for e in alive], [], run_now))
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
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous", speed_results,
                             history=update_node_history(history, [e[0] for e in alive], [], run_now))
        print("没有节点通过实际代理下载测试，保留上一版订阅。")
        return

    # 本轮结果并入历史（订阅排序与报告的老兵判定都用更新后的历史）。
    history = update_node_history(history, [e[0] for e in alive],
                                  [uri for uri, _ in successful_speed_nodes], run_now)
    # 订阅排序：CF 前置优先，再按档位、同档内老兵靠前、再实测 Mbps；
    # 然后按服务器去重，只留独立节点。
    successful_speed_nodes.sort(key=lambda item: (0 if cdn_fronted(item[0]) else 1, cn_tier(item[0]),
                                                  0 if is_veteran(history.get(history_key(item[0])), run_now) else 1,
                                                  -item[1]["download_mbps"]))
    ranked_nodes, dropped_dupes = dedupe_by_endpoint(successful_speed_nodes)
    if dropped_dupes:
        print(f"按服务器去重：丢弃同 host:端口 的重复节点 {dropped_dupes} 个，保留 {len(ranked_nodes)} 个独立节点")
    ranked_nodes, dropped_concentrated = dedupe_for_subscription(ranked_nodes)
    if dropped_concentrated:
        print(f"多样性闸门：丢弃同服务/同网段超额节点 {dropped_concentrated} 个，保留 {len(ranked_nodes)} 个分散节点")
    selected = [uri for uri, _ in ranked_nodes[:MAX_NODES]]
    print("订阅排序（前置 / 档位 / Mbps）:")
    for rank, (uri, result) in enumerate(ranked_nodes[:10], 1):
        protocol, host, port = get_endpoint(uri)
        fronted_mark = "CF前置 " if cdn_fronted(uri) else ""
        print(f"  #{rank} {fronted_mark}{'ABC'[cn_tier(uri)]}档 {result['download_mbps']:.2f} Mbps  {protocol}://{host}:{port}")

    # 6. 只发布已完成代理隧道下载测试的节点；订阅按档位、再按 Mbps 排序。
    content = base64.b64encode("\n".join(selected).encode("utf-8")).decode("ascii")
    atomic_write_text(OUTPUT, content + "\n")
    write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "updated", speed_results, selected=selected, history=history)
    print(f"质量报告已更新: {QUALITY_REPORT}")

    print(f"\n已生成真实测速节点: {len(selected)} 个")
    print(f"  → {OUTPUT}")
    print("订阅仅包含已通过实际代理下载测试的节点，CF 前置优先、再按档位和 Mbps 排序；不会提交节点 URI。")
    print(f"  → {QUALITY_REPORT} (仅含哈希节点 ID 与聚合测速数据)")


if __name__ == "__main__":
    main()
