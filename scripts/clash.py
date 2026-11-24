"""Clash <-> URI 互转与 Clash 配置生成（2026-11-25 自 collector.py 抽出）。

collector 在自身命名空间 re-export 本模块全部公开名字，既有导入
（from scripts import collector 后用 collector.build_clash_config 等）
与行为保持不变。URI 解析原语来自 scripts.uri_parse；订阅摄入上限
MAX_SOURCE_NODES 仍属 collector 的可调常量，经 collector_module()
在调用时读取，测试 patch 语义不变。
"""
import base64
import json
import urllib.parse

try:
    from .uri_parse import (
        collector_module,
        decode_base64,
        first_query_value,
        get_endpoint,
        get_protocol,
    )
except ImportError:  # 以脚本方式运行（scripts 目录在 sys.path 上）
    from uri_parse import (
        collector_module,
        decode_base64,
        first_query_value,
        get_endpoint,
        get_protocol,
    )


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
        # SIP002：userinfo 用 base64url 且去掉 = 填充；标准 base64 的
        # / 与 + 会破坏 URL 结构，含这类字符的密码此前转出的链接不可用。
        userinfo = base64.urlsafe_b64encode(
            f"{cipher}:{pw}".encode()).decode().rstrip("=")
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
                 "insecure": None,  # 整改：不把 Clash 的 skip-cert-verify 透传为节点 insecure 标记（保持证书校验）
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
                 "insecure": None}  # 同上：不透传 skip-cert-verify
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
            if len(uris) >= collector_module().MAX_SOURCE_NODES:
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
        return first_query_value(parsed_qs, *keys, default=default)

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
        # 整改：不再透传节点自带的 allowInsecure/insecure 标记。
        # 节点是不可信输入，让它自行关闭证书校验会使客户端到节点的
        # TLS 可被中间人冒充；一律保持校验，故此处恒为 False，
        # 下游的 skip-cert-verify 字段因此不再输出。
        return False

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
