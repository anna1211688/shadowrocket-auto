"""URI 解析原语：从 collector.py 抽出的无状态基础函数（2026-11-25 重构）。

包含 Base64 解码、协议识别、端点解析 (get_endpoint) 与去重键
(get_dedup_key)——collector / clash / speedtest 三方共用同一份实现，
collector 再把全部名字 re-export 出去，保持既有导入与测试 patch
边界不变。

本模块不 import collector（避免循环导入）；个别函数需要 collector
的可调常量（如 MAX_SOURCE_BYTES，测试会在 collector 模块上改它）
时，通过 collector_module() 在调用时延迟读取，保证 patch 语义不变。
"""
import base64
import functools
import json
import re
import urllib.parse

_collector_module_cache = None


def collector_module():
    """延迟导入 collector 模块（缓存），供读取其可调常量。"""
    global _collector_module_cache
    if _collector_module_cache is None:
        try:
            from . import collector as _collector
        except ImportError:  # 以脚本方式运行（scripts 目录在 sys.path 上）
            import collector as _collector
        _collector_module_cache = _collector
    return _collector_module_cache


def first_query_value(query: dict, *keys: str, default: str = "") -> str:
    """parse_qs 结果按 key 顺序取第一个非空值列表的首项。

    collector._clash_query 与 speedtest._first 原先各写了一份相同
    逻辑，统一到这里（一份实现，两处调用）。
    """
    for key in keys:
        values = query.get(key)
        if values:
            return values[0]
    return default


def decode_base64(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > collector_module().MAX_SOURCE_BYTES * 2:
        return ""
    value = value.strip()
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""


def get_protocol(line: str) -> str | None:
    m = re.match(r"^(ss|vmess|vless|trojan|hysteria2?|hy2|tuic|socks5?|anytls|https?)://", line, re.I)
    if not m:
        return None
    protocol = m.group(1).lower()
    # socks 与 socks5 是同一种分享格式，统一记为 socks5。
    return "socks5" if protocol in ("socks", "socks5") else protocol


def get_dedup_key(line: str):
    """区分同端点但凭据/传输参数不同的节点，同时忽略节点备注。"""
    if isinstance(line, str):
        return _get_dedup_key_cached(line)
    return _get_dedup_key_impl(line)


@functools.lru_cache(maxsize=16384)
def _get_dedup_key_cached(line: str):
    return _get_dedup_key_impl(line)


def _get_dedup_key_impl(line: str):
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
    if isinstance(line, str):
        return _get_endpoint_cached(line)
    return _get_endpoint_impl(line)


@functools.lru_cache(maxsize=16384)
def _get_endpoint_cached(line: str):
    return _get_endpoint_impl(line)


def _get_endpoint_impl(line: str):
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
