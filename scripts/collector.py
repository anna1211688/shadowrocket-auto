import base64
import datetime
import ipaddress
import hashlib
import html
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
PRIORITY_SOURCES = ROOT / "config" / "priority_sources.txt"
FIELD_VERIFIED_NETWORKS = ROOT / "config" / "field_verified_networks.txt"
DISCOVERY_CONFIG = ROOT / "config" / "discovery.json"
OUTPUT = ROOT / "docs" / "shadowrocket.txt"
CLASH_OUTPUT = ROOT / "docs" / "clash.yaml"
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
    "socks5": 5,
    "anytls": 1,
    "http": 6,
    "https": 6,
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

    # Clash YAML 订阅（proxies: 结构）：转成 URI 列表再走统一管线。
    if "proxies:" in content:
        yaml_uris = clash_yaml_to_uris(content)
        if yaml_uris:
            return yaml_uris

    nodes = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and len(line) <= MAX_LINE_LENGTH:
            nodes.append(line)
            if len(nodes) >= MAX_SOURCE_NODES:
                break
    return nodes


def clash_proxy_to_uri(proxy) -> str | None:
    """单个 Clash 代理条目转分享 URI；不支持或字段不全返回 None。

    只转换管线能测速的协议（ss/vmess/vless/trojan/hysteria2/tuic/
    socks5/http）；SSR、Snell 等 sing-box 不支持的跳过，带插件的
    SS（obfs/v2ray-plugin）也跳过——宁缺毋滥，错误转换只会污染池子。
    """
    if not isinstance(proxy, dict):
        return None
    ptype = str(proxy.get("type") or "").lower()
    server, port = proxy.get("server"), proxy.get("port")
    if not server or not port:
        return None
    host_port = f"{server}:{port}"
    frag = urllib.parse.quote(str(proxy.get("name") or ""))

    def params(**kw):
        clean = {k: v for k, v in kw.items() if v not in (None, "")}
        return urllib.parse.urlencode(clean)

    def transport_params(base: dict) -> dict:
        network = str(proxy.get("network") or "").lower()
        if network in ("ws", "grpc"):
            base["type"] = network
        if network == "ws":
            opts = proxy.get("ws-opts") or {}
            if opts.get("path"):
                base["path"] = opts["path"]
            headers = opts.get("headers") or {}
            if headers.get("Host"):
                base["host"] = headers["Host"]
        if network == "grpc":
            opts = proxy.get("grpc-opts") or {}
            if opts.get("grpc-service-name"):
                base["serviceName"] = opts["grpc-service-name"]
        return base

    if ptype == "ss":
        if proxy.get("plugin"):
            return None
        cipher, pw = proxy.get("cipher"), proxy.get("password")
        if not cipher or pw is None:
            return None
        userinfo = base64.b64encode(f"{cipher}:{pw}".encode()).decode()
        return f"ss://{userinfo}@{host_port}#{frag}"
    if ptype in ("socks5", "socks", "http"):
        user, pw = proxy.get("username"), proxy.get("password")
        auth = ""
        if user:
            auth = urllib.parse.quote(str(user))
            if pw is not None:
                auth += ":" + urllib.parse.quote(str(pw))
            auth += "@"
        scheme = "socks5" if ptype in ("socks5", "socks") else (
            "https" if proxy.get("tls") else "http")
        return f"{scheme}://{auth}{host_port}#{frag}"
    if ptype == "trojan":
        pw = proxy.get("password")
        if pw is None:
            return None
        query = transport_params({"sni": proxy.get("sni") or proxy.get("servername")})
        return f"trojan://{urllib.parse.quote(str(pw))}@{host_port}?{params(**query)}#{frag}"
    if ptype == "vless":
        uuid = proxy.get("uuid")
        if not uuid:
            return None
        reality = proxy.get("reality-opts") or {}
        query = {"encryption": "none",
                 "security": "reality" if reality else ("tls" if proxy.get("tls") else "none"),
                 "sni": proxy.get("servername") or proxy.get("sni"),
                 "flow": proxy.get("flow"),
                 "fp": proxy.get("client-fingerprint"),
                 "pbk": reality.get("public-key"),
                 "sid": reality.get("short-id")}
        query = transport_params(query)
        if "type" not in query:
            query["type"] = str(proxy.get("network") or "tcp")
        return f"vless://{uuid}@{host_port}?{params(**query)}#{frag}"
    if ptype == "vmess":
        uuid = proxy.get("uuid")
        if not uuid:
            return None
        ws_opts = proxy.get("ws-opts") or {}
        headers = ws_opts.get("headers") or {}
        doc = {"v": "2", "ps": str(proxy.get("name") or ""), "add": str(server),
               "port": str(port), "id": str(uuid),
               "aid": str(proxy.get("alterId") or 0),
               "scy": str(proxy.get("cipher") or "auto"),
               "net": str(proxy.get("network") or "tcp"),
               "type": str(proxy.get("headerType") or "none"),
               "host": str(headers.get("Host") or proxy.get("ws-headers", {}).get("Host") or ""),
               "path": str(ws_opts.get("path") or ""),
               "tls": "tls" if proxy.get("tls") else "",
               "sni": str(proxy.get("servername") or proxy.get("sni") or "")}
        encoded = base64.b64encode(
            json.dumps(doc, ensure_ascii=False).encode()).decode()
        return f"vmess://{encoded}"
    if ptype in ("hysteria2", "hy2"):
        pw = proxy.get("password")
        if pw is None:
            return None
        query = {"sni": proxy.get("sni") or proxy.get("servername"),
                 "insecure": "1" if proxy.get("skip-cert-verify") else None,
                 "obfs": proxy.get("obfs"),
                 "obfs-password": proxy.get("obfs-password")}
        return f"hysteria2://{urllib.parse.quote(str(pw))}@{host_port}?{params(**query)}#{frag}"
    if ptype == "hysteria":
        # Hysteria v1：测速器期望 auth/peer/upmbps 等查询参数格式。
        def _mbps(value):
            if value is None:
                return None
            try:
                return str(int(float(str(value).split()[0])))
            except (ValueError, IndexError):
                return None
        query = {"auth": proxy.get("auth_str") or proxy.get("auth-str"),
                 "peer": proxy.get("sni") or proxy.get("servername"),
                 "upmbps": _mbps(proxy.get("up")),
                 "downmbps": _mbps(proxy.get("down")),
                 "obfsParam": proxy.get("obfs"),
                 "insecure": "1" if proxy.get("skip-cert-verify") else None}
        return f"hysteria://{host_port}?{params(**query)}#{frag}"
    if ptype == "anytls":
        pw = proxy.get("password")
        if pw is None:
            return None
        query = {"sni": proxy.get("sni") or proxy.get("servername")}
        return f"anytls://{urllib.parse.quote(str(pw))}@{host_port}?{params(**query)}#{frag}"
    if ptype == "tuic":
        uuid, pw = proxy.get("uuid"), proxy.get("password")
        if not uuid or pw is None:
            return None
        query = {"sni": proxy.get("sni") or proxy.get("servername"),
                 "congestion_control": proxy.get("congestion-controller"),
                 "alpn": ",".join(proxy.get("alpn") or []) or None}
        return f"tuic://{uuid}:{urllib.parse.quote(str(pw))}@{host_port}?{params(**query)}#{frag}"
    return None


def clash_yaml_to_uris(content: str) -> list[str]:
    """Clash YAML 订阅转 URI 列表（go4sharing 等 YAML-only 源）。

    PyYAML 懒加载：缺库或解析失败返回空列表，绝不让单个源的格式
    问题拖垮整轮采集。safe_load 不执行任意标签。
    """
    try:
        import yaml
    except ImportError:
        return []
    try:
        data = yaml.safe_load(content)
    except Exception:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        return []
    uris = []
    for proxy in data["proxies"]:
        uri = clash_proxy_to_uri(proxy)
        if uri:
            uris.append(uri)
            if len(uris) >= MAX_SOURCE_NODES:
                break
    return uris

def extract_display_name(line: str) -> str:
    """从已改名的发布 URI 里取显示名（vmess 读 ps，其余读 # 备注）。"""
    if get_protocol(line) == "vmess":
        try:
            raw = decode_base64(line[8:].split("#", 1)[0].split("?", 1)[0])
            data = json.loads(raw)
            if isinstance(data, dict) and data.get("ps"):
                return str(data["ps"])
        except (ValueError, TypeError):
            pass
    return urllib.parse.unquote(urllib.parse.urlsplit(line).fragment) or ""


def _clash_query(line: str) -> dict:
    parsed_qs = urllib.parse.parse_qs(urllib.parse.urlsplit(line).query)

    def first(*keys, default=""):
        for key in keys:
            values = parsed_qs.get(key)
            if values:
                return values[0]
        return default

    return first


def uri_to_clash_proxy(line: str, name: str | None = None) -> dict | None:
    """单个分享 URI 转 Mihomo/Clash proxy 条目；不支持或字段不全返回 None。

    与 clash_proxy_to_uri 互为逆向：覆盖测速器支持的协议。SS 插件、
    xhttp 等 Mihomo 表达不了/未验证的形式跳过，宁缺毋滥。
    """
    protocol, host, port = get_endpoint(line)
    if not protocol or not host or not port:
        return None
    parsed = urllib.parse.urlsplit(line)
    q = _clash_query(line)
    proxy: dict = {
        "name": name or extract_display_name(line) or f"{protocol}-{host}-{port}",
        "server": host,
        "port": port,
    }

    def insecure() -> bool:
        return q("allowInsecure", "insecure").lower() in ("1", "true", "yes")

    def apply_transport(proxy: dict) -> bool:
        network = q("type", "network", default="tcp").lower()
        if network in ("", "tcp", "raw"):
            return True
        if network == "ws":
            proxy["network"] = "ws"
            opts: dict = {}
            if q("path"):
                opts["path"] = q("path")
            if q("host"):
                opts["headers"] = {"Host": q("host")}
            if opts:
                proxy["ws-opts"] = opts
            return True
        if network in ("grpc", "gun"):
            proxy["network"] = "grpc"
            if q("serviceName", "service_name"):
                proxy["grpc-opts"] = {"grpc-service-name": q("serviceName", "service_name")}
            return True
        if network in ("http", "h2"):
            proxy["network"] = "http"
            opts = {}
            if q("path"):
                opts["path"] = [q("path")]
            if q("host"):
                opts["host"] = [q("host")]
            if opts:
                proxy["http-opts"] = opts
            return True
        if network in ("httpupgrade", "http-upgrade"):
            proxy["network"] = "httpupgrade"
            opts = {}
            if q("path"):
                opts["path"] = q("path")
            if q("host"):
                opts["host"] = q("host")
            if opts:
                proxy["httpupgrade-opts"] = opts
            return True
        return False

    if protocol == "ss":
        if q("plugin"):
            return None
        method = password = None
        if parsed.hostname:
            userinfo = urllib.parse.unquote(parsed.username or "")
            if parsed.password is not None:
                method, _, password = (userinfo + ":" + urllib.parse.unquote(parsed.password)).partition(":")
            else:
                decoded = decode_base64(userinfo)
                method, _, password = (decoded or userinfo).partition(":")
        else:
            decoded = decode_base64(line[5:].split("#")[0].split("?")[0])
            creds, _, _ = decoded.rpartition("@")
            method, _, password = creds.partition(":")
        if not method or not password:
            return None
        proxy.update({"type": "ss", "cipher": method, "password": password, "udp": True})
        return proxy
    if protocol == "vless":
        uuid = urllib.parse.unquote(parsed.username or "")
        if not uuid:
            return None
        proxy.update({"type": "vless", "uuid": uuid, "udp": True})
        if q("flow"):
            proxy["flow"] = q("flow")
        security = q("security", default="none").lower()
        if security in ("tls", "reality"):
            proxy["tls"] = True
        sni = q("sni", "peer")
        if sni:
            proxy["servername"] = sni
        if q("fp"):
            proxy["client-fingerprint"] = q("fp")
        if security == "reality":
            if not q("pbk", "publicKey"):
                return None
            reality = {"public-key": q("pbk", "publicKey")}
            if q("sid", "shortId"):
                reality["short-id"] = q("sid", "shortId")
            proxy["reality-opts"] = reality
        if insecure():
            proxy["skip-cert-verify"] = True
        if q("alpn"):
            proxy["alpn"] = [p for p in q("alpn").split(",") if p]
        return proxy if apply_transport(proxy) else None
    if protocol == "trojan":
        password = urllib.parse.unquote(parsed.password or parsed.username or "")
        if not password:
            return None
        proxy.update({"type": "trojan", "password": password, "udp": True})
        sni = q("sni", "peer")
        if sni:
            proxy["sni"] = sni
        if insecure():
            proxy["skip-cert-verify"] = True
        if q("alpn"):
            proxy["alpn"] = [p for p in q("alpn").split(",") if p]
        return proxy if apply_transport(proxy) else None
    if protocol == "vmess":
        try:
            data = json.loads(decode_base64(line[8:].split("#", 1)[0].split("?", 1)[0]))
        except (ValueError, TypeError):
            return None
        if not isinstance(data, dict) or not data.get("id"):
            return None
        try:
            alter_id = int(data.get("aid", 0) or 0)
        except (TypeError, ValueError):
            return None
        proxy.update({"type": "vmess", "uuid": str(data["id"]), "alterId": alter_id,
                      "cipher": str(data.get("scy") or "auto"), "udp": True})
        network = str(data.get("net") or "tcp").lower()
        if network == "ws":
            proxy["network"] = "ws"
            opts = {}
            if data.get("path"):
                opts["path"] = str(data["path"])
            if data.get("host"):
                opts["headers"] = {"Host": str(data["host"])}
            if opts:
                proxy["ws-opts"] = opts
        elif network in ("grpc", "gun"):
            proxy["network"] = "grpc"
        elif network not in ("", "tcp"):
            return None
        if str(data.get("tls") or "").lower() == "tls":
            proxy["tls"] = True
            sni = str(data.get("sni") or data.get("host") or "")
            if sni:
                proxy["servername"] = sni
        return proxy
    if protocol in ("hysteria2", "hy2"):
        password = urllib.parse.unquote(parsed.password or parsed.username or "")
        if not password:
            return None
        proxy.update({"type": "hysteria2", "password": password})
        sni = q("sni", "peer")
        if sni:
            proxy["sni"] = sni
        if insecure():
            proxy["skip-cert-verify"] = True
        if q("obfs"):
            proxy["obfs"] = q("obfs")
        if q("obfs-password", "obfs_password"):
            proxy["obfs-password"] = q("obfs-password", "obfs_password")
        if q("alpn"):
            proxy["alpn"] = [p for p in q("alpn").split(",") if p]
        return proxy
    if protocol == "hysteria":
        proxy.update({"type": "hysteria"})
        if q("auth"):
            proxy["auth-str"] = q("auth")
        sni = q("peer", "sni")
        if sni:
            proxy["sni"] = sni
        if insecure():
            proxy["skip-cert-verify"] = True
        if q("obfsParam", "obfsparam"):
            proxy["obfs"] = q("obfsParam", "obfsparam")
        for src, dst in (("upmbps", "up"), ("downmbps", "down")):
            if q(src):
                try:
                    proxy[dst] = f"{int(float(q(src)))} Mbps"
                except ValueError:
                    pass
        return proxy
    if protocol == "tuic":
        uuid = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")
        if not uuid or not password:
            return None
        proxy.update({"type": "tuic", "uuid": uuid, "password": password, "udp": True})
        sni = q("sni", "peer")
        if sni:
            proxy["sni"] = sni
        if q("congestion_control"):
            proxy["congestion-controller"] = q("congestion_control")
        if q("alpn"):
            proxy["alpn"] = [p for p in q("alpn").split(",") if p]
        if insecure():
            proxy["skip-cert-verify"] = True
        return proxy
    if protocol == "anytls":
        password = urllib.parse.unquote(parsed.username or "")
        if not password:
            return None
        proxy.update({"type": "anytls", "password": password, "udp": True})
        sni = q("sni", "peer")
        if sni:
            proxy["sni"] = sni
        if insecure():
            proxy["skip-cert-verify"] = True
        return proxy
    if protocol == "socks5":
        proxy.update({"type": "socks5", "udp": True})
        user = urllib.parse.unquote(parsed.username or "")
        secret = urllib.parse.unquote(parsed.password) if parsed.password else None
        if secret is None and user:
            decoded = decode_base64(user)
            if ":" in decoded:
                user, _, secret = decoded.partition(":")
        if user:
            proxy["username"] = user
            proxy["password"] = secret or ""
        return proxy
    if protocol in ("http", "https"):
        proxy.update({"type": "http"})
        if protocol == "https":
            proxy["tls"] = True
        user = urllib.parse.unquote(parsed.username or "")
        if user:
            proxy["username"] = user
            proxy["password"] = urllib.parse.unquote(parsed.password or "")
        return proxy
    return None


# ---- Clash 分流（与 Shadowrocket-Traffic-Shunting-Configuration 的
# lazy_group_optimized.conf 对齐）----
# 地区组过滤与 .conf 的 policy-regex-filter 逐字一致，作用在发布节点的
# 展示名上；服务组与规则集一一对应，规则集改用上游 blackmatrix7 的
# Clash 版（rule/Clash/<Name>/<Name>.list，classical 行为），AI 用
# iab0x00 的 AI.txt（内容为无策略的 classical 行，可直接作规则集）。
# .conf 里 PROXY（内置入口）对应这里的「🚀 节点选择」；各服务组的默认
# 选项按 .conf 的 policy-select-name 放在第一位（Mihomo 默认选第一项）。

CLASH_REGION_FILTERS = {
    "香港节点": r"🇭🇰|(^|[^A-Za-z])(HK|HKG)([^A-Za-z]|$)|Hong Kong|HongKong|hong kong|hongkong|香港|深港|沪港|京港",
    "台湾节点": r"🇹🇼|(^|[^A-Za-z])(TW|TWN)([^A-Za-z]|$)|Taiwan|taiwan|Taipei|taipei|台湾|台灣|台北|台中|新北|彰化",
    "日本节点": r"🇯🇵|(^|[^A-Za-z])(JP|JPN)([^A-Za-z]|$)|Japan|japan|Tokyo|tokyo|Osaka|osaka|日本|东京|東京|大阪|京日|苏日|沪日|上日|川日|深日|广日",
    "新加坡节点": r"🇸🇬|(^|[^A-Za-z])(SG|SGP)([^A-Za-z]|$)|Singapore|singapore|新加坡|狮城|沪新|京新|深新|杭新|广新",
    "韩国节点": r"🇰🇷|(^|[^A-Za-z])(KR|KOR)([^A-Za-z]|$)|Korea|korea|Seoul|seoul|韩国|首尔|春川",
    "美国节点": r"🇺🇸|(^|[^A-Za-z])(US|USA)([^A-Za-z]|$)|United States|united states|America|america|Phoenix|phoenix|Los Angeles|los angeles|Seattle|seattle|Chicago|chicago|New York|new york|美国|凤凰城|洛杉矶|西雅图|芝加哥|纽约|沪美",
}

# 与 .conf 的「自动前置」一致：全场自动最快，300 秒一测。
CLASH_FRONT_FILTER = (
    "🇭🇰|🇹🇼|🇯🇵|🇸🇬|🇰🇷|🇺🇸|🇬🇧|🇩🇪|🇫🇷|🇳🇱|🇨🇦|🇦🇺|🇮🇳|🇹🇭|🇻🇳|🇲🇾|🇮🇩|🇵🇭|🇷🇺|🇹🇷|🇦🇷|🇧🇷|🇲🇽|🇮🇹|🇪🇸|🇨🇭|🇸🇪|🇳🇿"
    "|香港|台湾|台灣|日本|新加坡|韩国|美国|英国|德国|法国|荷兰|加拿大|澳洲|澳大利亚|印度|泰国|越南|马来|印尼|菲律宾|俄罗斯|土耳其|意大利|西班牙|瑞士|瑞典|新西兰"
)

_BLACKMATRIX7_CLASH = (
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
    "master/rule/Clash/{name}/{name}.list"
)

# provider 名 -> 规则集 URL（blackmatrix7 的目录名大小写按上游原样）
CLASH_RULE_PROVIDERS = {
    "ai": "https://raw.githubusercontent.com/iab0x00/ProxyRules/main/Rule/AI.txt",
    "youtube": _BLACKMATRIX7_CLASH.format(name="YouTube"),
    "netflix": _BLACKMATRIX7_CLASH.format(name="Netflix"),
    "disney": _BLACKMATRIX7_CLASH.format(name="Disney"),
    "hbo": _BLACKMATRIX7_CLASH.format(name="HBO"),
    "spotify": _BLACKMATRIX7_CLASH.format(name="Spotify"),
    "telegram": _BLACKMATRIX7_CLASH.format(name="Telegram"),
    "paypal": _BLACKMATRIX7_CLASH.format(name="PayPal"),
    "twitter": _BLACKMATRIX7_CLASH.format(name="Twitter"),
    "facebook": _BLACKMATRIX7_CLASH.format(name="Facebook"),
    "amazon": _BLACKMATRIX7_CLASH.format(name="Amazon"),
    "sony": _BLACKMATRIX7_CLASH.format(name="Sony"),
    "nintendo": _BLACKMATRIX7_CLASH.format(name="Nintendo"),
    "epic": _BLACKMATRIX7_CLASH.format(name="Epic"),
    "steamcn": _BLACKMATRIX7_CLASH.format(name="SteamCN"),
    "steam": _BLACKMATRIX7_CLASH.format(name="Steam"),
    "game": _BLACKMATRIX7_CLASH.format(name="Game"),
    "github": _BLACKMATRIX7_CLASH.format(name="GitHub"),
    "microsoft": _BLACKMATRIX7_CLASH.format(name="Microsoft"),
    "google": _BLACKMATRIX7_CLASH.format(name="Google"),
    "apple": _BLACKMATRIX7_CLASH.format(name="Apple"),
    "bilibili": _BLACKMATRIX7_CLASH.format(name="BiliBili"),
    "netease": _BLACKMATRIX7_CLASH.format(name="NetEaseMusic"),
    "baidu": _BLACKMATRIX7_CLASH.format(name="Baidu"),
    "douban": _BLACKMATRIX7_CLASH.format(name="DouBan"),
    "wechat": _BLACKMATRIX7_CLASH.format(name="WeChat"),
    "sina": _BLACKMATRIX7_CLASH.format(name="Sina"),
    "zhihu": _BLACKMATRIX7_CLASH.format(name="Zhihu"),
    "xiaohongshu": _BLACKMATRIX7_CLASH.format(name="XiaoHongShu"),
    "douyin": _BLACKMATRIX7_CLASH.format(name="DouYin"),
    "tiktok": _BLACKMATRIX7_CLASH.format(name="TikTok"),
    "global": _BLACKMATRIX7_CLASH.format(name="Global"),
    "china": _BLACKMATRIX7_CLASH.format(name="China"),
    "lan": _BLACKMATRIX7_CLASH.format(name="Lan"),
}

# 服务组：组名 -> 成员（默认项在第一位；REGIONS 在构建时展开为六个地区组）
_CLASH_REGIONS = ["香港节点", "台湾节点", "日本节点", "新加坡节点", "韩国节点", "美国节点"]
CLASH_SERVICE_GROUPS = {
    # AI 默认跟随节点选择（.conf 注释：避免地区组为空时 AI 分流失效）
    "AI": ["🚀 节点选择", "日本节点", "香港节点", "台湾节点", "新加坡节点", "韩国节点", "美国节点"],
    "YOUTUBE": ["🚀 节点选择", *_CLASH_REGIONS],
    "NETFLIX": ["🚀 节点选择", *_CLASH_REGIONS],
    "DISNEY+": ["🚀 节点选择", *_CLASH_REGIONS],
    "MAX": ["🚀 节点选择", *_CLASH_REGIONS],
    "TIKTOK": ["🚀 节点选择", *_CLASH_REGIONS],
    "SPOTIFY": ["🚀 节点选择", "DIRECT", *_CLASH_REGIONS],
    "TELEGRAM": ["🚀 节点选择", *_CLASH_REGIONS],
    "TWITTER": ["🚀 节点选择", *_CLASH_REGIONS],
    "FACEBOOK": ["🚀 节点选择", *_CLASH_REGIONS],
    "PAYPAL": ["🚀 节点选择", "DIRECT", *_CLASH_REGIONS],
    "AMAZON": ["🚀 节点选择", "DIRECT", *_CLASH_REGIONS],
    "苹果服务": ["DIRECT", "🚀 节点选择", *_CLASH_REGIONS],
    "谷歌服务": ["🚀 节点选择", *_CLASH_REGIONS],
    "微软服务": ["🚀 节点选择", "DIRECT", *_CLASH_REGIONS],
    "哔哩哔哩": ["DIRECT", "🚀 节点选择", "香港节点", "台湾节点"],
    "游戏平台": ["🚀 节点选择", "DIRECT", *_CLASH_REGIONS],
}

# 规则顺序与 .conf 的 [Rule] 一致（从上到下匹配）
CLASH_RULES = [
    "DOMAIN-SUFFIX,deepseek.com,AI",
    "DOMAIN-SUFFIX,generativelanguage.googleapis.com,AI",
    "DOMAIN-SUFFIX,aiplatform.googleapis.com,AI",
    "DOMAIN-SUFFIX,googleapis.com,谷歌服务",
    "RULE-SET,ai,AI",
    "RULE-SET,youtube,YOUTUBE",
    "RULE-SET,netflix,NETFLIX",
    "RULE-SET,disney,DISNEY+",
    "DOMAIN-SUFFIX,litix.io,MAX",
    "DOMAIN-SUFFIX,discomax.com,MAX",
    "DOMAIN-SUFFIX,brightline.tv,MAX",
    "RULE-SET,hbo,MAX",
    "RULE-SET,spotify,SPOTIFY",
    "RULE-SET,telegram,TELEGRAM",
    "RULE-SET,paypal,PAYPAL",
    "RULE-SET,twitter,TWITTER",
    "RULE-SET,facebook,FACEBOOK",
    "RULE-SET,amazon,AMAZON",
    "RULE-SET,sony,游戏平台",
    "RULE-SET,nintendo,游戏平台",
    "RULE-SET,epic,游戏平台",
    "RULE-SET,steamcn,游戏平台",
    "RULE-SET,steam,游戏平台",
    "RULE-SET,game,游戏平台",
    "RULE-SET,github,🚀 节点选择",
    "RULE-SET,microsoft,微软服务",
    "RULE-SET,google,谷歌服务",
    "RULE-SET,apple,苹果服务",
    "RULE-SET,bilibili,哔哩哔哩",
    "RULE-SET,netease,DIRECT",
    "RULE-SET,baidu,DIRECT",
    "RULE-SET,douban,DIRECT",
    "RULE-SET,wechat,DIRECT",
    "RULE-SET,sina,DIRECT",
    "RULE-SET,zhihu,DIRECT",
    "RULE-SET,xiaohongshu,DIRECT",
    "RULE-SET,douyin,DIRECT",
    "RULE-SET,tiktok,TIKTOK",
    "RULE-SET,global,🚀 节点选择",
    "RULE-SET,china,DIRECT",
    "RULE-SET,lan,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "GEOIP,CN,DIRECT",
    "MATCH,🐟 漏网之鱼",
]


def build_clash_config(lines: list[str]) -> dict | None:
    """已改名的发布 URI 列表转 Mihomo/Clash 完整配置；无可用节点返回 None。

    与 Shadowrocket 订阅共用同一批节点，只是格式不同：FIClash 等
    Clash 系客户端只认 YAML 里的 proxies + 策略组 + 规则。分组与规则
    与 Shadowrocket 的 lazy_group_optimized.conf 分流对齐（见上方
    CLASH_* 常量），两边行为尽量一致。
    """
    proxies = []
    seen_names: dict[str, int] = {}
    for line in lines:
        proxy = uri_to_clash_proxy(line)
        if not proxy:
            continue
        base_name = proxy["name"]
        seen_names[base_name] = seen_names.get(base_name, 0) + 1
        if seen_names[base_name] > 1:
            proxy["name"] = f"{base_name} #{seen_names[base_name]}"
        proxies.append(proxy)
    if not proxies:
        return None
    names = [proxy["name"] for proxy in proxies]
    test_url = "http://www.gstatic.com/generate_204"
    groups: list[dict] = [
        {"name": "🚀 节点选择", "type": "select",
         "proxies": ["♻️ 自动选择", "自动前置", *_CLASH_REGIONS, "DIRECT", *names]},
        {"name": "♻️ 自动选择", "type": "url-test", "url": test_url,
         "interval": 300, "tolerance": 50, "proxies": names},
        {"name": "自动前置", "type": "url-test", "url": test_url,
         "interval": 300, "tolerance": 50, "proxies": names,
         "filter": CLASH_FRONT_FILTER},
    ]
    for region in _CLASH_REGIONS:
        groups.append({
            "name": region, "type": "url-test", "url": test_url,
            "interval": 900, "tolerance": 50, "proxies": names,
            "filter": CLASH_REGION_FILTERS[region],
        })
    for group_name, members in CLASH_SERVICE_GROUPS.items():
        groups.append({"name": group_name, "type": "select", "proxies": members})
    groups.append({"name": "🐟 漏网之鱼", "type": "select",
                   "proxies": ["🚀 节点选择", "DIRECT"]})
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": ["223.5.5.5", "1.1.1.1"],
            "fallback": ["8.8.8.8", "https://dns.google/dns-query"],
        },
        "proxies": proxies,
        "proxy-groups": groups,
        "rule-providers": {
            name: {
                "type": "http",
                "behavior": "classical",
                "url": url,
                "path": f"./ruleset/{name}.list",
                "interval": 86400,
            }
            for name, url in CLASH_RULE_PROVIDERS.items()
        },
        "rules": list(CLASH_RULES),
    }


def dump_clash_config(lines: list[str]) -> str | None:
    """build_clash_config 的 YAML 文本；无可用节点或缺 PyYAML 返回 None。"""
    config = build_clash_config(lines)
    if not config:
        return None
    try:
        import yaml
    except ImportError:
        return None
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False)


def get_protocol(line: str) -> str | None:
    m = re.match(r"^(ss|vmess|vless|trojan|hysteria2?|hy2|tuic|socks5?|anytls|https?)://", line, re.I)
    if not m:
        return None
    protocol = m.group(1).lower()
    # socks 与 socks5 是同一种分享格式，统一记为 socks5。
    return "socks5" if protocol in ("socks", "socks5") else protocol


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
    "NZ": ("新西兰", "新西蘭", "new zealand", "auckland", "🇳🇿"),
    "CA": ("加拿大", "canada", "toronto", "vancouver", "🇨🇦"),
    "FR": ("法国", "法國", "france", "paris", "🇫🇷"),
    "NL": ("荷兰", "荷蘭", "netherlands", "amsterdam", "🇳🇱"),
    "AU": ("澳大利亚", "澳洲", "australia", "sydney", "🇦🇺"),
    "ID": ("印尼", "印度尼西亚", "indonesia", "jakarta", "🇮🇩"),
    "IN": ("印度", "india", "mumbai", "🇮🇳"),
    "RU": ("俄罗斯", "俄羅斯", "russia", "moscow", "🇷🇺"),
    "TR": ("土耳其", "turkey", "türkiye", "istanbul", "🇹🇷"),
    "BR": ("巴西", "brazil", "🇧🇷"),
    "NG": ("尼日利亚", "nigeria", "🇳🇬"),
    "SC": ("塞舌尔", "seychelles", "🇸🇨"),
    "FI": ("芬兰", "芬蘭", "finland", "helsinki", "🇫🇮"),
    "EE": ("爱沙尼亚", "estonia", "🇪🇪"),
    "ES": ("西班牙", "spain", "madrid", "🇪🇸"),
    "IT": ("意大利", "italy", "milan", "🇮🇹"),
    "PL": ("波兰", "波蘭", "poland", "warsaw", "🇵🇱"),
    "UA": ("乌克兰", "烏克蘭", "ukraine", "kyiv", "🇺🇦"),
    "VN": ("越南", "vietnam", "🇻🇳"),
    "TH": ("泰国", "泰國", "thailand", "bangkok", "🇹🇭"),
    "MY": ("马来西亚", "馬來西亞", "malaysia", "🇲🇾"),
    "PH": ("菲律宾", "菲律賓", "philippines", "🇵🇭"),
    "CN": ("中国", "中國", "china", "beijing", "shanghai", "shenzhen", "🇨🇳"),
    "CH": ("瑞士", "switzerland", "zurich", "🇨🇭"),
    "SE": ("瑞典", "sweden", "stockholm", "🇸🇪"),
    "NO": ("挪威", "norway", "🇳🇴"),
    "DK": ("丹麦", "丹麥", "denmark", "🇩🇰"),
    "IE": ("爱尔兰", "愛爾蘭", "ireland", "🇮🇪"),
    "AT": ("奥地利", "austria", "vienna", "🇦🇹"),
    "AR": ("阿根廷", "argentina", "🇦🇷"),
    "MX": ("墨西哥", "mexico", "🇲🇽"),
    "ZA": ("南非", "south africa", "🇿🇦"),
    "AE": ("阿联酋", "迪拜", "dubai", "uae", "emirates", "🇦🇪"),
    "IL": ("以色列", "israel", "🇮🇱"),
    "KZ": ("哈萨克斯坦", "kazakhstan", "🇰🇿"),
}

REGION_ZH = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡", "KR": "韩国",
    "US": "美国", "DE": "德国", "GB": "英国", "NZ": "新西兰", "CA": "加拿大",
    "FR": "法国", "NL": "荷兰", "AU": "澳大利亚", "ID": "印尼", "IN": "印度",
    "RU": "俄罗斯", "TR": "土耳其", "BR": "巴西", "NG": "尼日利亚", "SC": "塞舌尔",
    "FI": "芬兰", "EE": "爱沙尼亚", "ES": "西班牙", "IT": "意大利", "PL": "波兰",
    "UA": "乌克兰", "VN": "越南", "TH": "泰国", "MY": "马来西亚", "PH": "菲律宾",
    "CN": "中国", "CH": "瑞士", "SE": "瑞典", "NO": "挪威", "DK": "丹麦",
    "IE": "爱尔兰", "AT": "奥地利", "AR": "阿根廷", "MX": "墨西哥", "ZA": "南非",
    "AE": "阿联酋", "IL": "以色列", "KZ": "哈萨克斯坦", "OTHER": "未知地区",
}

REGION_FLAGS = {
    "HK": "🇭🇰", "TW": "🇹🇼", "JP": "🇯🇵", "SG": "🇸🇬", "KR": "🇰🇷",
    "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "NZ": "🇳🇿", "CA": "🇨🇦",
    "FR": "🇫🇷", "NL": "🇳🇱", "AU": "🇦🇺", "ID": "🇮🇩", "IN": "🇮🇳",
    "RU": "🇷🇺", "TR": "🇹🇷", "BR": "🇧🇷", "NG": "🇳🇬", "SC": "🇸🇨",
    "FI": "🇫🇮", "EE": "🇪🇪", "ES": "🇪🇸", "IT": "🇮🇹", "PL": "🇵🇱",
    "UA": "🇺🇦", "VN": "🇻🇳", "TH": "🇹🇭", "MY": "🇲🇾", "PH": "🇵🇭",
    "CN": "🇨🇳", "CH": "🇨🇭", "SE": "🇸🇪", "NO": "🇳🇴", "DK": "🇩🇰",
    "IE": "🇮🇪", "AT": "🇦🇹", "AR": "🇦🇷", "MX": "🇲🇽", "ZA": "🇿🇦",
    "AE": "🇦🇪", "IL": "🇮🇱", "KZ": "🇰🇿", "OTHER": "🌐",
}

_PROTOCOL_DISPLAY = {"hysteria2": "HY2", "hy2": "HY2", "hysteria": "Hysteria", "anytls": "AnyTLS"}


def rename_node(line: str, name: str) -> str:
    """把节点的显示名换成 name（vmess 改 JSON 里的 ps，其余改 # 备注）。

    只动显示名：端点、凭据、传输参数不变，去重键与历史键都不受影响。
    """
    protocol = get_protocol(line)
    if protocol == "vmess":
        try:
            rest = line[8:].split("#", 1)[0]
            body, sep, suffix = rest.partition("?")
            data = json.loads(decode_base64(body))
            if not isinstance(data, dict):
                return line
            data["ps"] = name
            encoded = base64.b64encode(
                json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            return "vmess://" + encoded + (sep + suffix if sep else "")
        except (ValueError, TypeError):
            return line
    base = line.split("#", 1)[0]
    return base + "#" + urllib.parse.quote(name, safe="")


EGRESS_TYPE_ZH = {
    "residential": "住宅",
    "datacenter": "机场",
    "mobile": "移动",
    "proxy": "代理",
}


def label_subscription(lines: list[str], egress_regions: dict | None = None,
                       egress_types: dict | None = None) -> list[str]:
    """发布前统一命名：旗帜 + 中文地区 + 协议 + 同组序号。

    源站自带的名字多是广告或乱码（如 vless-1863464818），客户端根本
    分不清节点在哪。地区按 resolve_region 推测：先看原名/主机名/SNI，
    直连节点仍推不出时按端点 IP 查归属地，都不行的标「未知地区」。
    序号按（地区, 协议）分别计数。
    """
    counters: dict[tuple, int] = {}
    labelled = []
    geo_budget = {"used": 0}
    for line in lines:
        # 出口国家是实测真值，优先于一切名字/归属地推测（意大利误标
        # 新西兰的教训）；没有出口数据时才走推测链。
        egress_region = (egress_regions or {}).get(get_dedup_key(line))
        if egress_region and egress_region != "OTHER":
            region = egress_region
        else:
            region = resolve_region(line, geo_budget=geo_budget)
        protocol = get_protocol(line)
        display = _PROTOCOL_DISPLAY.get(protocol, protocol.upper())
        key = (region, display)
        counters[key] = counters.get(key, 0) + 1
        name = f"{REGION_FLAGS.get(region, '🌐')} {REGION_ZH.get(region, '未知地区')} {display} {counters[key]:02d}"
        # 出口类型备注：住宅 IP 稀缺且常更耐封，与机场（机房）IP 分开标。
        egress_type = (egress_types or {}).get(get_dedup_key(line))
        if egress_type in EGRESS_TYPE_ZH:
            name += f" · {EGRESS_TYPE_ZH[egress_type]}"
        labelled.append(rename_node(line, name))
    return labelled


def get_node_label(line: str) -> str:
    """提取节点备注、主机名与 SNI/源站提示，用于地区猜测。

    CF 前置节点的端点只是边缘 IP，真正的地区线索常在 SNI/Host 里
    （如 jp3.yohototo.top），一并纳入推断文本。
    """
    protocol = get_protocol(line)
    label = ""
    hints = ""
    if protocol == "vmess":
        try:
            raw = decode_base64(line[8:].split("#", 1)[0].split("?", 1)[0])
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                label = str(parsed.get("ps", ""))
                hints = f"{parsed.get('host', '')} {parsed.get('sni', '')}"
        except (ValueError, TypeError):
            pass
    else:
        label = urllib.parse.unquote(urllib.parse.urlsplit(line).fragment)
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(line).query))
        hints = f"{query.get('host', '')} {query.get('sni', '')}"
    _, host, _ = get_endpoint(line)
    return f"{label} {host or ''} {hints}".lower()


# 裸国家代码按词元匹配（如「DE SS-34 | free-nodes」）；排除与英文
# 单词/编号写法冲突的代码：IN/IT 是常用词、NO 常见于「No.1」编号、
# AT 是介词，裸代码出现时歧义太大，宁可标未知。
_CODE_TOKEN_EXCLUDE = {"IN", "IT", "NO", "AT"}
_CODE_TOKEN_ALIASES = {"uk": "GB", "usa": "US"}


def infer_region(line: str) -> str:
    """根据节点备注/主机名推测地区；无法判断时返回 OTHER，不调用外部地理定位服务。"""
    label = get_node_label(line)
    for region, keywords in REGION_KEYWORDS.items():
        if any(keyword.lower() in label for keyword in keywords):
            return region
    tokens = set(re.split(r"[^a-z]+", label))
    for token, region in _CODE_TOKEN_ALIASES.items():
        if token in tokens:
            return region
    for region in REGION_KEYWORDS:
        if region not in _CODE_TOKEN_EXCLUDE and region.lower() in tokens:
            return region
    return "OTHER"


# --- IP 归属地兜底（仅发布改名阶段、关键词推不出地区时使用） ---
GEOIP_ENDPOINT = "http://ip-api.com/json/{ip}?fields=status,countryCode"
GEOIP_TIMEOUT = (3, 5)
GEOIP_MAX_LOOKUPS = 40
_geoip_cache: dict[str, str] = {}


def region_for_country_code(code) -> str | None:
    """ISO 国家代码映射到本项目的地区键；表里没有的返回 None。"""
    if not isinstance(code, str) or not code:
        return None
    normalized = code.strip().upper()
    if normalized == "UK":
        normalized = "GB"
    return normalized if normalized in REGION_FLAGS else None


def lookup_region_by_ip(ip_text: str) -> str:
    """查公网 IP 的归属国家；任何失败都返回 OTHER，绝不中断发布。

    ip-api 免费端点限速且为 HTTP，因此只查公网 IP、结果按 IP 缓存、
    超时短；调用方另有每轮次数上限（GEOIP_MAX_LOOKUPS）。
    """
    try:
        ip = ipaddress.ip_address(str(ip_text))
    except ValueError:
        return "OTHER"
    if not ip.is_global:
        return "OTHER"
    key = str(ip)
    if key in _geoip_cache:
        return _geoip_cache[key]
    region = "OTHER"
    try:
        with requests.get(
            GEOIP_ENDPOINT.format(ip=key),
            timeout=GEOIP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        ) as resp:
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and data.get("status") == "success":
                    region = region_for_country_code(data.get("countryCode")) or "OTHER"
    except Exception:
        region = "OTHER"
    _geoip_cache[key] = region
    return region


EGRESS_BATCH_API = "http://ip-api.com/batch?fields=status,countryCode,proxy,hosting,mobile,query"


# 出口类型在订阅排序中的优先级（越小越靠前）：住宅出口在深圳实测
# 中存活最好，移动次之；未测到的居中；机房（机场）IP 段最易被编目；
# 已知代理出口垫底。
EGRESS_RANK = {"residential": 0, "mobile": 1, "datacenter": 3, "proxy": 4}
EGRESS_RANK_UNKNOWN = 2


def egress_rank(result: dict) -> int:
    """按测速结果里的出口类型给排序权重；未分类返回中位。"""
    return EGRESS_RANK.get(result.get("egress_type"), EGRESS_RANK_UNKNOWN)


def classify_egress_ips(ips) -> dict:
    """批量分类出口 IP：{ip: {"region": 地区键|None, "type": 分类}}。

    分类口径：hosting→datacenter、proxy→proxy（已知代理出口）、
    mobile→mobile、其余→residential。一次批量请求（上限 100 个），
    任何失败返回 {}。原始出口 IP 只在内存中使用，不写入报告——
    报告只记聚合计数与国家级信息。
    """
    unique: list[str] = []
    seen: set[str] = set()
    for value in ips:
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if ip.is_global and str(ip) not in seen:
            seen.add(str(ip))
            unique.append(str(ip))
    if not unique:
        return {}
    try:
        with requests.post(
            EGRESS_BATCH_API,
            json=unique[:100],
            timeout=(5, 15),
            headers={"User-Agent": USER_AGENT},
        ) as resp:
            if resp.status_code != 200:
                return {}
            data = resp.json()
    except Exception:
        return {}
    classified: dict[str, dict] = {}
    if not isinstance(data, list):
        return classified
    for item in data:
        if not isinstance(item, dict) or item.get("status") != "success":
            continue
        ip = item.get("query")
        if not isinstance(ip, str):
            continue
        if item.get("hosting"):
            egress_type = "datacenter"
        elif item.get("proxy"):
            egress_type = "proxy"
        elif item.get("mobile"):
            egress_type = "mobile"
        else:
            egress_type = "residential"
        classified[ip] = {
            "region": region_for_country_code(item.get("countryCode")),
            "type": egress_type,
        }
    return classified


def resolve_region(line: str, *, geo_budget: dict | None = None) -> str:
    """发布用地区：先关键词推断；仍未知且非 CF 前置时按端点 IP 查归属地。

    CF 前置节点的端点是 Cloudflare anycast 边缘 IP，查归属地只会得到
    错误国家，因此跳过（其线索已在 SNI/源站推断里用尽）。
    """
    region = infer_region(line)
    if region != "OTHER" or cdn_fronted(line):
        return region
    if geo_budget is not None:
        if geo_budget.get("used", 0) >= GEOIP_MAX_LOOKUPS:
            return region
        geo_budget["used"] = geo_budget.get("used", 0) + 1
    _, host, _ = get_endpoint(line)
    if not host:
        return region
    try:
        addresses = resolve_public_addresses(host)
    except Exception:
        return region
    if not addresses:
        return region
    return lookup_region_by_ip(addresses[0][4][0])


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
    if protocol in ("trojan", "anytls"):
        # AnyTLS 同为 TLS 承载，伪装特性与 Trojan 相近，同档处理。
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
# UDP 曾为 0（2026-11-20 停用，当时判定验证通过率极低）；审查发现这让
# HY2/TUIC 永远进不了订阅、每轮上百个 UDP 候选白白流过（2026-11-21
# 整改开启 40 个名额，先看真实入选与深圳实测再调整）。
SPEED_UDP_LIMIT = 40

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


def _is_vless_vision_or_grpc(uri: str) -> bool:
    """VLESS 是否为 Vision 直连或 GRPC 传输（与白名单口径一致）。"""
    if get_protocol(uri) != "vless":
        return False
    try:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)
    except ValueError:
        return False
    flow = (query.get("flow") or [""])[0].lower()
    transport = (query.get("type") or [""])[0].lower()
    return "vision" in flow or transport == "grpc"


# 大陆实测整形参数（2026-11-21/22 两晚深圳实测的量化结论）。
VISION_EXPLORATION_SLOTS = 3   # 未达标 Vision/GRPC 每轮保留的探索位
SS_EXPLORATION_SLOTS = 3       # 未认证 SS 每轮保留的探索位
HY2_SUBSCRIPTION_CAP = 3       # HY2 在订阅中的封顶（认证网段不占名额）


def apply_field_evidence_shaping(ranked_nodes, field_networks=None):
    """按大陆实测证据整形发布名单，返回 (保留名单, 统计)。

    两晚深圳实测（2026-11-21/22）的两条规律，只作用于发布选择，
    采集/测速/历史不动：
    1. VLESS Vision/GRPC：活下来的全部出自认证网段；「住宅/移动
       出口」豁免曾保留过五晚，段外住宅 Vision 累计约 1/13——
       2026-11-22 第五晚后取消豁免，未认证者不论出口类型只留
       排序最靠前的 VISION_EXPLORATION_SLOTS 个探索位；
    2. HY2：四晚合计存活约 3/42，是白名单类型里唯一持续整批
       超时的——封顶 HY2_SUBSCRIPTION_CAP 个（探索位级别），
       认证网段内的不占名额（实测证明能活的段不受误伤）；
    3. SS：存活者全部出自认证网段，未认证 SS 四晚合计约 1/23
       （含住宅出口，照样整批超时）——未认证者只留排序最靠前的
       SS_EXPLORATION_SLOTS 个探索位。SOCKS5 不动：四晚约 12/13
       存活且不挑网段，是唯一不需要门槛的类别。
    """
    kept = []
    vision_explore_used = 0
    ss_explore_used = 0
    hy2_kept = 0
    stats = {"vision_exploration_dropped": 0, "hy2_capped": 0,
             "ss_exploration_dropped": 0}
    for uri, result in ranked_nodes:
        if _is_vless_vision_or_grpc(uri):
            qualified = is_field_verified(uri, field_networks)
            if qualified:
                kept.append((uri, result))
            elif vision_explore_used < VISION_EXPLORATION_SLOTS:
                vision_explore_used += 1
                kept.append((uri, result))
            else:
                stats["vision_exploration_dropped"] += 1
            continue
        if get_protocol(uri) in ("hysteria2", "hy2"):
            if is_field_verified(uri, field_networks):
                kept.append((uri, result))
            elif hy2_kept < HY2_SUBSCRIPTION_CAP:
                hy2_kept += 1
                kept.append((uri, result))
            else:
                stats["hy2_capped"] += 1
            continue
        if get_protocol(uri) == "ss":
            if is_field_verified(uri, field_networks):
                kept.append((uri, result))
            elif ss_explore_used < SS_EXPLORATION_SLOTS:
                ss_explore_used += 1
                kept.append((uri, result))
            else:
                stats["ss_exploration_dropped"] += 1
            continue
        kept.append((uri, result))
    return kept, stats

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


def load_priority_sources() -> set:
    """优先源名单（config/priority_sources.txt）：小型精选订阅。

    优先源的节点每轮保送进候选（不受候选上限抽签影响），并在测速
    名单里与老兵同列优先——像 Pawdroid 这种 9 个节点的小文件，节点
    在普通源的大池子里出勤率太低，存活资历永远攒不起来。只放节点
    少而精的源，滥用会挤占测速预算。
    """
    urls = set()
    if PRIORITY_SOURCES.exists():
        for line in PRIORITY_SOURCES.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.add(line)
    return urls


def load_field_verified_networks() -> list:
    """深圳实测认证网段（config/field_verified_networks.txt）。

    用户在深圳逐个实测连通过的服务所在 /24 网段：两晚实测证明决定
    节点生死的是服务/IP 段是否被封锁编目，这些段是被实测证明未被
    编目的。网段内节点在测速名单与订阅排序中优先保位。登记只来自
    真实实测，不凭猜测添加；后续实测整批超时的网段应移除。
    """
    networks = []
    if FIELD_VERIFIED_NETWORKS.exists():
        for line in FIELD_VERIFIED_NETWORKS.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    continue
    return networks


def is_field_verified(line: str, networks: list | None) -> bool:
    """节点端点 IP 是否落在深圳实测认证网段内（域名端点不匹配）。"""
    if not networks:
        return False
    _, host, _ = get_endpoint(line)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in network for network in networks)

def collect_candidates(priority_raw_nodes: list[str], raw_nodes: list[str], stats: dict):
    """校验并去重，返回 (优先候选, 普通候选)；两列共用一套去重键，
    优先源节点先占位，普通源里的同一节点算重复。"""
    seen_keys: set = set()

    def take(lines: list[str]) -> list[str]:
        kept = []
        for line in lines:
            protocol, host, port = get_endpoint(line)
            if not protocol or not host or not port:
                stats["invalid"] += 1
                continue
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
            kept.append(line)
        return kept

    return take(priority_raw_nodes), take(raw_nodes)


def load_node_history() -> dict:
    """从上一轮质量报告读回节点历史（报告由工作流提交回仓库）。"""
    try:
        report = json.loads(QUALITY_REPORT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    history = report.get("node_history")
    return history if isinstance(history, dict) else {}


# 发现源的状态同样保存在质量报告里跨轮累积（工作流只提交该文件）。
DISCOVERED_PRUNE_DAYS = 7
DISCOVERED_MAX_STORED = 50
DISCOVERED_MAX_FETCH = 40
DISCOVERED_MAX_EMPTY = 3


def load_discovery_config() -> dict:
    try:
        config = json.loads(DISCOVERY_CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return config if isinstance(config, dict) else {}


def load_discovered_sources() -> dict:
    """从上一轮质量报告读回发现源状态 {url: {f, l, ok, empty}}。"""
    try:
        report = json.loads(QUALITY_REPORT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    stored = report.get("discovered_sources")
    return stored if isinstance(stored, dict) else {}


def update_discovered_sources(stored: dict, fetch_results: dict, rediscovered: set,
                              now: datetime.datetime) -> dict:
    """累积发现源状态并修剪：连续 3 轮无产出或 7 天未见即淘汰。

    发现到的订阅地址先过源白名单才会被抓取（见 main），存活下来的
    升为常驻发现源每轮自动抓取，不必等渠道再次发现。
    """
    stamp = now.isoformat()
    updated = {url: dict(entry) for url, entry in stored.items() if isinstance(entry, dict)}
    for url in rediscovered:
        # 只有新建条目给时间戳；已存条目的 l 只由真实抓取刷新——此前
        # 「被再次发现」也刷新 l，没被抓取额度选中的源永远不会过期，
        # 还会挤占新发现源的抓取位置（审查整改，2026-11-21）。
        updated.setdefault(url, {"f": stamp, "l": stamp, "ok": 0, "empty": 0})
    for url, count in fetch_results.items():
        entry = updated.setdefault(url, {"f": stamp, "l": stamp, "ok": 0, "empty": 0})
        entry["l"] = stamp
        if count > 0:
            entry["ok"] = entry.get("ok", 0) + 1
            entry["empty"] = 0
        else:
            entry["empty"] = entry.get("empty", 0) + 1
    cutoff = now - datetime.timedelta(days=DISCOVERED_PRUNE_DAYS)
    kept = {}
    for url, entry in updated.items():
        try:
            last = datetime.datetime.fromisoformat(entry.get("l", ""))
        except ValueError:
            continue
        if last < cutoff or entry.get("empty", 0) >= DISCOVERED_MAX_EMPTY:
            continue
        kept[url] = entry
    if len(kept) > DISCOVERED_MAX_STORED:
        kept = dict(
            sorted(kept.items(), key=lambda item: -item[1].get("ok", 0))[:DISCOVERED_MAX_STORED]
        )
    return kept


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
        # 通过测速的节点直接建条目：UDP 节点不走 TCP 测活、没有 alive
        # 记录，此前永远建不了条目、攒不了老兵资格（审查整改）。
        entry = updated.setdefault(
            history_key(line), {"f": stamp, "l": stamp, "a": 0, "p": 0}
        )
        entry["l"] = stamp
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
                           history: dict | None = None, now: datetime.datetime | None = None,
                           priority_keys: set | None = None,
                           field_networks: list | None = None):
    """按组配额选 TCP 测速名单（CF 前置 A/B → 直连 A → 直连 B → C 档）。

    某组不足时，剩余名额按组优先级补位。
    组内先保优先节点——「老兵」（见 is_veteran）与优先源节点，按历史
    测通轮次、测活轮次排序；余量再按小时种子轮换抽取：alive 已按
    延迟排序，轮换让每小时被测的是不同切片（切片内仍按延迟优先），
    避免长期只测同一批新面孔。
    """
    if seed is None:
        seed = int(time.time() // 3600)
    rng = random.Random(seed)
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    history = history or {}
    priority_keys = priority_keys or set()
    # 分组（优先级从高到低）：CF 前置的 A/B → 直连 A → 直连 B → C 档。
    # 单趟计算档位与前置标记（此前每条要重复算 3 次档位、2 次前置）。
    fronted: list[tuple] = []
    direct_a: list[tuple] = []
    direct_b: list[tuple] = []
    tier_c: list[tuple] = []
    for entry in alive:
        tier = cn_tier(entry[0])
        if cdn_fronted(entry[0]):
            if tier <= 1:
                fronted.append(entry)
            continue
        if tier == 0:
            direct_a.append(entry)
        elif tier == 1:
            direct_b.append(entry)
        else:
            tier_c.append(entry)
    groups = [(fronted, FRONTED_TCP_QUOTA), (direct_a, TIER_TCP_QUOTAS[0]),
              (direct_b, TIER_TCP_QUOTAS[1]), (tier_c, TIER_TCP_QUOTAS[2])]
    tcp_shortlist: list[str] = []
    leftovers: list[list[tuple]] = []
    for entries, quota in groups:
        def pref_rank(entry: tuple) -> tuple:
            record = history.get(history_key(entry[0])) or {}
            return (-record.get("p", 0), -record.get("a", 0))

        preferred = [e for e in entries
                     if history_key(e[0]) in priority_keys
                     or is_veteran(history.get(history_key(e[0])), now)
                     or is_field_verified(e[0], field_networks)
                     or get_protocol(e[0]) == "socks5"]
        preferred.sort(key=pref_rank)
        preferred_lines = {e[0] for e in preferred}
        others = [e for e in entries if e[0] not in preferred_lines]
        rotated = _rotate(others, rng)
        picked_preferred = [e[0] for e in preferred[:quota]]
        picked = picked_preferred + _round_robin_by_protocol(rotated, quota - len(picked_preferred))
        tcp_shortlist.extend(picked)
        picked_lines = set(picked)
        leftover_ordered = [e for e in preferred if e[0] not in picked_lines]
        leftover_ordered += [entry for entry in rotated if entry[0] not in picked_lines]
        leftovers.append(leftover_ordered)
    # 补位按组优先级进行，前组不足时由后组补满，反之亦然。
    for leftover in leftovers:
        if len(tcp_shortlist) >= SPEED_TCP_LIMIT:
            break
        tcp_shortlist.extend(
            _round_robin_by_protocol(leftover, SPEED_TCP_LIMIT - len(tcp_shortlist))
        )
    # UDP 名单：保送源节点与老兵优先（与 TCP 侧同一存活逻辑），其余
    # 按小时种子轮换，让新面孔也有被测到的机会。
    def udp_pref_rank(line: str) -> tuple:
        record = history.get(history_key(line)) or {}
        return (-record.get("p", 0), -record.get("a", 0))

    udp_preferred = [
        line for line in udp_candidates
        if history_key(line) in priority_keys
        or is_veteran(history.get(history_key(line)), now)
        or is_field_verified(line, field_networks)
    ]
    udp_preferred.sort(key=udp_pref_rank)
    udp_preferred_lines = set(udp_preferred)
    udp_rest = [line for line in udp_candidates if line not in udp_preferred_lines]
    udp_shortlist = (udp_preferred + _rotate(udp_rest, rng))[:SPEED_UDP_LIMIT]
    return tcp_shortlist, udp_shortlist


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
    elif protocol in ("vless", "trojan", "ss", "hysteria2", "hy2", "tuic", "socks5", "anytls", "http", "https", "hysteria"):
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
MAX_PER_NETWORK_PRIORITY = 8


def shenzhen_publishable(line: str) -> bool:
    """深圳实测白名单（2026-11-21 晚实测后收紧，仅作用于订阅发布）。

    当晚订阅 70 个只有 14 个能用。实测能活的只有：SS 裸协议、
    Hysteria2、SOCKS5、VLESS Vision 直连、VLESS GRPC；WebSocket
    传输全灭（第三次验证）、Trojan 全灭、其余类型未证明能活。故发
    布只放行这五类，WS 传输不分协议一律排除。采集、测速与历史积
    累不受影响——其他类型继续攒数据，实测口径变了随时放回来。
    """
    protocol = get_protocol(line)
    try:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(line).query)
    except ValueError:
        query = {}

    def q(key: str) -> str:
        values = query.get(key)
        return values[0].lower() if values else ""

    # WS 排除优先于白名单（不分协议）。
    if q("type") in ("ws", "websocket"):
        return False
    if protocol in ("ss", "hysteria2", "hy2", "socks5", "socks"):
        return True
    if protocol == "vless":
        if "vision" in q("flow"):
            return True
        if q("type") == "grpc":
            return True
    return False


def dedupe_for_subscription(nodes: list[tuple], priority_keys: set | None = None) -> tuple[list[tuple], int]:
    """多样性闸门：同一服务最多留 MAX_PER_SERVICE 个入口，同一网段
    最多留 MAX_PER_NETWORK 个节点。输入须已按期望顺序排好。

    依据 2026-11-20 深圳实测：订阅的死活取决于来源是否分散——曾有
    一轮 33 个节点实际只来自个位数服务/网段，被编目的那几家一倒
    就是整表超时。分散到几十家后，个别来源被封不影响其余。
    例外（同日晚经用户批准）：保送源节点的网段限额放宽到
    MAX_PER_NETWORK_PRIORITY——v2rayfree 那批德国 SS 同网段十几个
    在深圳整段可连，限额 3 会把已验证可用的节点误伤挡下；网段计数
    仍与普通节点共享，只是保送节点用更高的准入阈值。
    """
    priority_keys = priority_keys or set()
    service_counts: dict[tuple, int] = {}
    network_counts: dict[tuple, int] = {}
    kept: list[tuple] = []
    dropped = 0
    for uri, result in nodes:
        skey = service_key(uri)
        _, host, _ = get_endpoint(uri)
        nkey = network_key(host)
        network_cap = MAX_PER_NETWORK_PRIORITY if history_key(uri) in priority_keys else MAX_PER_NETWORK
        if service_counts.get(skey, 0) >= MAX_PER_SERVICE or network_counts.get(nkey, 0) >= network_cap:
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
                         history: dict | None = None,
                         discovered: dict | None = None,
                         discovery_stats: dict | None = None,
                         egress_summary: dict | None = None) -> None:
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
            # 出口质量（国家级信息＋分类，不含原始出口 IP）。
            **({"egress_region": result["egress_region"]} if result.get("egress_region") else {}),
            **({"egress_type": result["egress_type"]} if result.get("egress_type") else {}),
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
            **({"egress": egress_summary} if egress_summary is not None else {}),
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
    if discovered is not None:
        # 发现源是公开订阅地址（非凭据），可明文保存以便跨轮累积。
        report["discovered_sources"] = discovered
    if discovery_stats is not None:
        report["discovery"] = discovery_stats
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

        if protocol in ("vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "socks5", "anytls", "http", "https"):
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

# 例外白名单：个别经用户逐个批准的非 GitHub 源主机。保持逐个批准、
# 不开放通配或子域，避免采集器被任意 URL 滥用（SSRF 面不变）。
# aa.mibei77.com：米贝订阅，2026-11-20 用户批准加入（其节点深圳实测
# 大批可连）；链接为按月目录的快照地址，失效后该源自然无产出。
# freeclashnode 两主机：2026-11-22 用户批准加入（普通源）。其节点
# 文件链接带日期、每日更换，由 resolve_freeclashnode_sources 解析。
EXTRA_SOURCE_HOSTS = {"aa.mibei77.com", "tian.zmxoo.xyz",
                      "node.freeclashnode.com", "www.freeclashnode.com",
                      "blog.banyunxiaoxi.icu", "t.me"}


def is_allowed_source_url(url: str) -> bool:
    """仅允许 raw GitHub 源与逐个批准的例外主机，避免把采集器变成 SSRF 代理。"""
    if not isinstance(url, str) or len(url) > 2_048:
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        return (
            parsed.scheme == "https"
            and (parsed.hostname == "raw.githubusercontent.com" or parsed.hostname in EXTRA_SOURCE_HOSTS)
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        )
    except (ValueError, TypeError):
        return False


def fetch_source(url: str) -> list[str]:
    if not is_allowed_source_url(url):
        print('[源拒绝] 仅允许 HTTPS 白名单源（raw.githubusercontent.com 及批准的例外）')
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


FREECLASHNODE_LISTING = "https://www.freeclashnode.com/free-node/"
# 列表页里的文章链接是相对路径（/free-node/日期-...htm），匹配路径后拼主机。
_FCN_POST_RE = re.compile(
    r"/free-node/\d{4}-\d{2}-\d{2}-free-node-subscribe-links\.htm")
_FCN_FILE_RE = re.compile(r"https://node\.freeclashnode\.com/uploads/[\w./-]+\.txt")


def _fetch_text(url: str) -> str | None:
    """按与 fetch_source 相同的安全纪律抓一个文本页（白名单主机、
    不跟随重定向、2MB 上限、总时限），失败返回 None。"""
    if not is_allowed_source_url(url):
        return None
    deadline = time.monotonic() + SOURCE_DEADLINE
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        request_timeout = (min(SOURCE_TIMEOUT[0], remaining), min(SOURCE_TIMEOUT[1], remaining))
        with requests.get(url, timeout=request_timeout, headers={"User-Agent": USER_AGENT},
                          stream=True, allow_redirects=False) as resp:
            if resp.status_code != 200:
                return None
            chunks, total = [], 0
            for chunk in resp.iter_content(chunk_size=16384):
                if time.monotonic() >= deadline:
                    return None
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    return None
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", "replace")
    except Exception:
        return None


def extract_freeclashnode_file_urls(html: str) -> list[str]:
    """从 FreeClashNode 文章页提取 V2ray 文本订阅链接（只要 .txt，
    YAML/JSON 格式管线不解析），去重保序并过源白名单。"""
    urls = []
    for url in _FCN_FILE_RE.findall(html or ""):
        if url not in urls and is_allowed_source_url(url):
            urls.append(url)
    return urls


def freeclashnode_fallback_urls(day: datetime.date) -> list[str]:
    """按日期规律拼当天的节点文件地址（文章页抓不到时的兜底）：
    uploads/{年}/{月}/{序号}-{年月日}.txt，序号 0..4。"""
    return [
        f"https://node.freeclashnode.com/uploads/{day:%Y}/{day:%m}/{i}-{day:%Y%m%d}.txt"
        for i in range(5)
    ]


def resolve_freeclashnode_sources(now: datetime.datetime) -> list[str]:
    """解析 FreeClashNode 当天发布的节点文件链接（普通源）。

    该站每天发一篇文章、文件链接带日期，静态地址写不进配置：
    先抓列表页找最新文章、再从文章页提取 .txt 链接；任一步失败
    则按日期规律拼今天与昨天的地址兜底（不存在的文件抓取时自然
    无产出）。整体失败返回空列表，不影响主流程。
    """
    try:
        listing = _fetch_text(FREECLASHNODE_LISTING)
        posts = []
        if listing:
            for path in _FCN_POST_RE.findall(listing):
                url = "https://www.freeclashnode.com" + path
                if url not in posts:
                    posts.append(url)
        for post in posts[:2]:
            html = _fetch_text(post)
            urls = extract_freeclashnode_file_urls(html) if html else []
            if urls:
                return urls[:10]
        urls = []
        for delta in (0, 1):
            day = (now - datetime.timedelta(days=delta)).date()
            urls.extend(freeclashnode_fallback_urls(day))
        return urls
    except Exception:
        return []


# 小汐搬运（Telegram @byxiaoxi，2026-11-22 用户批准，普通源）：节点
# 不在订阅文件里，而是嵌在它博客的每日帖子 HTML 中。解析路径：频道
# 公开页找最新帖子地址 → 抓帖子正文 → 剥标签后提取节点 URI。
BYXIAOXI_CHANNEL_URL = "https://t.me/s/byxiaoxi"
_BYXIAOXI_POST_RE = re.compile(
    r"https://blog\.banyunxiaoxi\.icu/\d{4}/\d{2}/\d{2}/[^\s\"'<>]+")
_PROXY_URI_RE = re.compile(
    r"(?:ss|vmess|vless|trojan|hysteria2|hy2|tuic|anytls|socks5)"
    r"://[^\s<>\"']+")


def extract_byxiaoxi_post_urls(channel_html: str) -> list[str]:
    """从频道页提取博客帖子地址（新到旧、去重，最多 2 篇）。"""
    posts: list[str] = []
    for url in _BYXIAOXI_POST_RE.findall(channel_html or ""):
        # 不能剥尾部斜杠：WordPress 固定链接少了它会 301，而抓取器
        # 按纪律不跟随重定向。频道页按时间正序排列，最新在末尾。
        url = url.rstrip(".,)")
        if url not in posts:
            posts.append(url)
    return posts[-2:][::-1]


def byxiaoxi_post_to_uris(post_html: str) -> list[str]:
    """博客帖子 HTML → 节点 URI：先剥标签、还原实体，再按协议提取。

    同一节点会在帖子里按客户端分区分重复列示，这里先去重；
    有效性与端点去重由后续统一管线负责。
    """
    text = html.unescape(re.sub(r"<[^>]+>", "\n", post_html or ""))
    uris: list[str] = []
    for uri in _PROXY_URI_RE.findall(text):
        uri = uri.rstrip(".,;)")
        if uri and uri not in uris:
            uris.append(uri)
            if len(uris) >= MAX_SOURCE_NODES:
                break
    return uris


def resolve_byxiaoxi_nodes(now: datetime.datetime) -> list[str]:
    """定位小汐搬运最新帖子并提取节点；任何一步失败返回已得部分。

    顶层异常兜底与 FreeClashNode 解析器对齐：解析器内部任何未预料
    的错误都不许冒泡进主流程、拖垮整轮采集。
    """
    try:
        return _resolve_byxiaoxi_nodes(now)
    except Exception:
        return []


def _resolve_byxiaoxi_nodes(now: datetime.datetime) -> list[str]:
    channel_html = _fetch_text(BYXIAOXI_CHANNEL_URL)
    if not channel_html:
        return []
    uris: list[str] = []
    for post_url in extract_byxiaoxi_post_urls(channel_html):
        if not is_allowed_source_url(post_url):
            continue
        post_html = _fetch_text(post_url)
        if post_html:
            for uri in byxiaoxi_post_to_uris(post_html):
                if uri not in uris:
                    uris.append(uri)
    return uris


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

    # 1b. 源发现：从公开渠道找新订阅地址与散装节点；发现到的订阅地址
    # 仍须过源白名单才抓取，存活下来的发现源跨轮保存在质量报告里。
    discovered_state = load_discovered_sources()
    # 与正式源/保送源重复的发现源条目直接剔除：此前 Pawdroid 同时以
    # 正式源和发现源身份被重复抓取、占一份抓取额度（审查整改）。
    configured_urls = set(sources) | load_priority_sources()
    discovered_state = {
        url: entry for url, entry in discovered_state.items()
        if url not in configured_urls
    }
    discovery_stats: dict = {}
    discovered_uris: list[str] = []
    fetch_urls: list[str] = []
    allowed_urls: list[str] = []
    discovery_config = load_discovery_config()
    if discovery_config.get("enable"):
        try:
            from discovery import run_discovery  # python scripts/collector.py
        except ImportError:  # 作为包导入时
            from .discovery import run_discovery
        found = run_discovery(discovery_config)
        discovered_uris = found["uris"]
        allowed_urls = [
            url for url in found["urls"]
            if is_allowed_source_url(url) and url not in configured_urls
        ]
        stored_urls = sorted(
            discovered_state, key=lambda url: -discovered_state[url].get("ok", 0)
        )
        # 本轮新发现的源排在前面先抓：此前老源按 ok 排序长期霸占抓取
        # 额度，新源排不进来、又因未抓取无法证明自己（审查整改）。
        fresh_urls = [url for url in allowed_urls if url not in discovered_state]
        fetch_urls = list(
            dict.fromkeys(fresh_urls + stored_urls + allowed_urls)
        )[:DISCOVERED_MAX_FETCH]
        sources.extend(fetch_urls)
        discovery_stats = {
            "channels": found["channels"],
            "urls_found": len(found["urls"]),
            "urls_allowlisted": len(allowed_urls),
            "uris_found": len(discovered_uris),
            "sources_fetched": len(fetch_urls),
        }
        print(f"源发现: {discovery_stats}")

    # 1c. FreeClashNode 每日源（普通源，2026-11-22 用户批准）：链接
    # 带日期每日更换，先解析出当天的文件地址再并入源列表。
    fcn_urls = [url for url in resolve_freeclashnode_sources(run_now)
                if url not in configured_urls]
    if fcn_urls:
        sources.extend(fcn_urls)
        print(f"FreeClashNode 每日源: 解析到 {len(fcn_urls)} 个文件")

    # 2. 拉取所有节点（带重试）；优先源单独收集，不受总量截断影响。
    priority_urls = load_priority_sources()
    raw_nodes: list[str] = []
    priority_raw_nodes: list[str] = []
    fetched_counts: dict[str, int] = {}
    for offset in range(0, len(sources), MAX_SOURCE_WORKERS):
        batch = sources[offset:offset + MAX_SOURCE_WORKERS]
        with ThreadPoolExecutor(max_workers=MAX_SOURCE_WORKERS) as source_executor:
            for source_url, nodes in zip(batch, source_executor.map(fetch_source, batch)):
                fetched_counts[source_url] = len(nodes)
                if source_url in priority_urls:
                    priority_raw_nodes.extend(nodes)
                else:
                    raw_nodes.extend(nodes[:max(0, MAX_TOTAL_NODES - len(raw_nodes))])
    if discovered_uris:
        raw_nodes.extend(discovered_uris)
    # 小汐搬运（普通源）：解析器直接给 URI，合并进候选池。
    byx_uris = resolve_byxiaoxi_nodes(run_now)
    if byx_uris:
        raw_nodes.extend(byx_uris)
        print(f"小汐搬运: 提取到 {len(byx_uris)} 个节点")
    if discovery_config.get("enable"):
        discovered_state = update_discovered_sources(
            discovered_state,
            {url: fetched_counts.get(url, 0) for url in fetch_urls},
            set(allowed_urls),
            run_now,
        )

    # 3. 初步过滤 + 按端点、凭据和传输参数去重；优先候选不受上限约束。
    stats = {"ok": 0, "slow": 0, "timeout": 0, "invalid": 0, "private": 0, "duplicate": 0, "udp_unverified": 0}
    stats["freeclashnode_sources"] = len(fcn_urls)
    stats["byxiaoxi_nodes"] = len(byx_uris)
    priority_candidates, other_candidates = collect_candidates(priority_raw_nodes, raw_nodes, stats)
    priority_keys = {history_key(line) for line in priority_candidates}

    unique_candidate_count = len(priority_candidates) + len(other_candidates)
    # 候选按源顺序排列时，测试上限会固定切掉排在后面的源（实测 11k 候选
    # 只测前 5k，后加的源永远轮不到）。按小时种子打散，让每小时一轮的
    # 覆盖范围轮换，长期每个源都有机会被测到。
    random.Random(int(time.time() // 3600)).shuffle(other_candidates)
    candidates = priority_candidates + limit_candidates(other_candidates, stats)
    print(
        f"去重后候选节点: {unique_candidate_count}（优先源保送 {len(priority_candidates)} 个）；"
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
                             history=update_node_history(history, [], [], run_now),
                             discovered=discovered_state, discovery_stats=discovery_stats)
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
                             history=update_node_history(history, [], [], run_now),
                             discovered=discovered_state, discovery_stats=discovery_stats)
        print(f"质量报告已更新: {QUALITY_REPORT}")
        print("没有可进行协议级测速的节点，保留旧订阅。")
        return

    # 5. TCP 延迟只用于缩小候选范围；测速名单按档位配额选（见
    # select_speed_shortlist），订阅排序先档位、再实测 Mbps。
    alive.sort(key=lambda x: (x[1], x[3], PROTOCOL_WEIGHT.get(x[2], 9)))
    field_networks = load_field_verified_networks()
    tcp_shortlist, udp_shortlist = select_speed_shortlist(alive, udp_candidates, history=history, now=run_now,
                                                          priority_keys=priority_keys,
                                                          field_networks=field_networks)
    veteran_picks = sum(1 for line in tcp_shortlist if is_veteran(history.get(history_key(line)), run_now))
    priority_picks = sum(1 for line in tcp_shortlist if history_key(line) in priority_keys)
    print(f"本轮历史条目 {len(history)} 个，测速名单含老兵节点 {veteran_picks} 个、优先源节点 {priority_picks} 个")
    speed_shortlist = tcp_shortlist + udp_shortlist

    import shutil
    try:
        from speedtest import rank_by_speed  # python scripts/collector.py
    except ImportError:  # package-style execution
        from .speedtest import rank_by_speed
    binary = os.environ.get("SING_BOX_PATH") or shutil.which("sing-box")
    if not binary:
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous",
                             history=update_node_history(history, [e[0] for e in alive], [], run_now),
                             discovered=discovered_state, discovery_stats=discovery_stats)
        raise RuntimeError("sing-box binary unavailable; refusing to publish a latency-only ranking")

    print(f"开始真实代理隧道下载测速：TCP {len(tcp_shortlist)} 个，UDP {len(udp_shortlist)} 个")
    # limit 显式放行整份短名单：rank_by_speed 的默认上限 200 且带协
    # 议均衡重排，TCP 200 + UDP 40 的名单会被它砍掉尾部并打乱配额
    # （审查整改，2026-11-21）。
    successful_speed_nodes, speed_results = rank_by_speed(
        speed_shortlist, binary, limit=len(speed_shortlist)
    )
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
        if get_endpoint(uri)[0] in ("hysteria", "hysteria2", "hy2", "tuic")
    )
    stats["udp_unverified"] = max(0, stats.get("udp_unverified", 0) - stats["udp_speed_verified"])
    stats["proxy_speed_failed_or_unsupported"] = len(speed_results) - len(successful_speed_nodes)

    # 出口 IP 质量检测：测速时经隧道实测到的出口 IP 在此批量分类
    # （数据中心/住宅/移动/已知代理出口＋出口国家）。原始出口 IP 只在
    # 本进程内使用，标注完立即从结果里抹掉，绝不写入公开报告。
    egress_classified = classify_egress_ips(
        result.get("egress_ip") for _, result in successful_speed_nodes
    )
    egress_regions: dict[str, str] = {}
    egress_types: dict[str, str] = {}
    egress_by_type: dict[str, int] = {}
    egress_checked = 0
    label_mismatch = 0
    for uri, result in successful_speed_nodes:
        egress_ip = result.pop("egress_ip", None)
        if not egress_ip:
            continue
        egress_checked += 1
        info = egress_classified.get(egress_ip)
        if not info:
            continue
        egress_by_type[info["type"]] = egress_by_type.get(info["type"], 0) + 1
        egress_types[get_dedup_key(uri)] = info["type"]
        if info["region"]:
            result["egress_region"] = info["region"]
            result["egress_type"] = info["type"]
            egress_regions[get_dedup_key(uri)] = info["region"]
            inferred = infer_region(uri)
            if inferred != "OTHER" and inferred != info["region"]:
                label_mismatch += 1
    egress_summary = {
        "checked": egress_checked,
        "classified": sum(egress_by_type.values()),
        "by_type": egress_by_type,
        "label_region_mismatch": label_mismatch,
    }

    if not successful_speed_nodes:
        write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "preserved_previous", speed_results,
                             history=update_node_history(history, [e[0] for e in alive], [], run_now),
                             discovered=discovered_state, discovery_stats=discovery_stats, egress_summary=egress_summary)
        print("没有节点通过实际代理下载测试，保留上一版订阅。")
        return

    # 本轮结果并入历史（订阅排序与报告的老兵判定都用更新后的历史）。
    history = update_node_history(history, [e[0] for e in alive],
                                  [uri for uri, _ in successful_speed_nodes], run_now)
    # 订阅排序：CF 前置优先，深圳实测认证网段靠前，再按档位、同档
    # 内老兵靠前、再按出口
    # 类型（住宅>移动>未测>机场>代理——深圳实测住宅出口最耐活，出口
    # 类型测速时已顺带测得）、最后实测 Mbps；然后按服务器去重。
    successful_speed_nodes.sort(key=lambda item: (0 if cdn_fronted(item[0]) else 1,
                                                  0 if is_field_verified(item[0], field_networks) else 1,
                                                  cn_tier(item[0]),
                                                  0 if is_veteran(history.get(history_key(item[0])), run_now) else 1,
                                                  egress_rank(item[1]),
                                                  -item[1]["download_mbps"]))
    ranked_nodes, dropped_dupes = dedupe_by_endpoint(successful_speed_nodes)
    if dropped_dupes:
        print(f"按服务器去重：丢弃同 host:端口 的重复节点 {dropped_dupes} 个，保留 {len(ranked_nodes)} 个独立节点")
    ranked_nodes, dropped_concentrated = dedupe_for_subscription(ranked_nodes, priority_keys=priority_keys)
    if dropped_concentrated:
        print(f"多样性闸门：丢弃同服务/同网段超额节点 {dropped_concentrated} 个，保留 {len(ranked_nodes)} 个分散节点")
    # 深圳实测白名单：只作用于发布选择，采集/测速/历史照常积累。
    before_whitelist = len(ranked_nodes)
    ranked_nodes = [(uri, result) for uri, result in ranked_nodes if shenzhen_publishable(uri)]
    stats["shenzhen_filtered"] = before_whitelist - len(ranked_nodes)
    if stats["shenzhen_filtered"]:
        print(f"深圳实测白名单：滤除未实测验证类型 {stats['shenzhen_filtered']} 个，保留 {len(ranked_nodes)} 个")
    # 大陆实测整形：Vision 出口门槛 + HY2 封顶（见整形函数的实测依据）。
    ranked_nodes, shaping_stats = apply_field_evidence_shaping(ranked_nodes, field_networks)
    stats.update(shaping_stats)
    if any(shaping_stats.values()):
        print(f"大陆实测整形：未达标 Vision 超探索位滤除 {shaping_stats['vision_exploration_dropped']} 个、"
              f"HY2 超封顶滤除 {shaping_stats['hy2_capped']} 个、"
              f"未认证 SS 超探索位滤除 {shaping_stats['ss_exploration_dropped']} 个，保留 {len(ranked_nodes)} 个")
    selected = [uri for uri, _ in ranked_nodes[:MAX_NODES]]
    stats["field_verified"] = sum(1 for uri in selected if is_field_verified(uri, field_networks))
    print("订阅排序（前置 / 档位 / Mbps）:")
    for rank, (uri, result) in enumerate(ranked_nodes[:10], 1):
        protocol, host, port = get_endpoint(uri)
        fronted_mark = "CF前置 " if cdn_fronted(uri) else ""
        print(f"  #{rank} {fronted_mark}{'ABC'[cn_tier(uri)]}档 {result['download_mbps']:.2f} Mbps  {protocol}://{host}:{port}")

    # 6. 只发布已完成代理隧道下载测试的节点；发布名统一为中文地区标记。
    labelled = label_subscription(selected, egress_regions=egress_regions, egress_types=egress_types)
    content = base64.b64encode("\n".join(labelled).encode("utf-8")).decode("ascii")
    atomic_write_text(OUTPUT, content + "\n")
    # 同一批节点同步生成 Clash YAML（FIClash 等 Mihomo 客户端用）；
    # 转不出任何节点时不覆盖旧文件，与订阅保留逻辑一致。
    clash_config = build_clash_config(labelled)
    stats["clash_proxies"] = len(clash_config["proxies"]) if clash_config else 0
    clash_text = dump_clash_config(labelled)
    if clash_text:
        atomic_write_text(CLASH_OUTPUT, clash_text)
        print(f"  → {CLASH_OUTPUT} (Clash YAML, {stats['clash_proxies']} 个节点)")
    write_quality_report(len(raw_nodes), unique_candidate_count, stats, alive, "updated", speed_results, selected=selected, history=history, discovered=discovered_state, discovery_stats=discovery_stats, egress_summary=egress_summary)
    print(f"质量报告已更新: {QUALITY_REPORT}")

    print(f"\n已生成真实测速节点: {len(selected)} 个")
    print(f"  → {OUTPUT}")
    print("订阅仅包含已通过实际代理下载测试的节点，CF 前置优先、再按档位和 Mbps 排序；不会提交节点 URI。")
    print(f"  → {QUALITY_REPORT} (仅含哈希节点 ID 与聚合测速数据)")


if __name__ == "__main__":
    main()
