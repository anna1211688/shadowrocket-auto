"""源发现：从公开渠道寻找新的订阅地址与散装节点链接。

与固定源名单互补：名单靠人工维护（慢但可信），发现靠自动爬取公开
渠道（快但嘈杂）。发现到的订阅地址仍必须通过 collector 的源白名单
才会被抓取；散装节点链接只是数据，直接进入候选池走同一套测活/
测速筛选。因此发现层不需要、也不会放宽既有的 SSRF 防护：本模块
只访问固定的几个站点（api.github.com、t.me、www.google.com、
www.youtube.com、syndication.twitter.com），不抓取搜索结果里的
任意链接。

各渠道彼此独立且永不抛异常：某个渠道被封或结构变化时只在统计里
留下一条 error，其余渠道照常工作。整体有总时限，避免拖垮每小时
一轮的主流程。
"""

import base64
import html as html_module
import json
import os
import re
import subprocess
import time
import urllib.parse

import requests

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
REQUEST_TIMEOUT = (5, 12)
MAX_TEXT_BYTES = 2_000_000
MAX_URLS_PER_CHANNEL = 60
MAX_URIS_PER_CHANNEL = 400

# 链接本体只含 ASCII（分享链接的备注都是 URL 编码的）；排除非 ASCII
# 可避免中文标点把正文粘进链接里（如「ss://…#名，订阅 https://…」）。
# 大小写只对协议头用 (?i:...) 局部忽略：全局 IGNORECASE 会让否定字符
# 类 [^\x7f-…] 连带排除字母 i/I（其折叠伙伴 ı/İ 落在该区间内）。
_URI_RE = re.compile(
    r"(?i:ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic|socks5|socks)://[^\s\"'<>\\\x7f-\uffff]+"
)
_URL_RE = re.compile(r"(?i:https?)://[^\s\"'<>\\\x7f-\uffff]+")
_TRAILING_JUNK = "\"'<>，。；、）】」』)]}>&"


def _clean_token(token: str) -> str:
    token = html_module.unescape(token)
    while token and token[-1] in _TRAILING_JUNK:
        token = token[:-1]
    return token


def extract_candidates(text: str) -> tuple[list[str], list[str]]:
    """从任意文本里提取 (节点链接, 普通 URL)，各自去重保序。"""
    if not text:
        return [], []
    uris: list[str] = []
    seen_uris: set[str] = set()
    for match in _URI_RE.finditer(text):
        uri = _clean_token(match.group(0))
        if uri and uri not in seen_uris:
            seen_uris.add(uri)
            uris.append(uri)
    urls: list[str] = []
    seen_urls: set[str] = set()
    for match in _URL_RE.finditer(text):
        url = _clean_token(match.group(0))
        if not url or url in seen_uris or url in seen_urls:
            continue
        seen_urls.add(url)
        urls.append(url)
    return uris, urls


def _get_text(url: str, headers: dict | None = None) -> str | None:
    """带上限地抓取一个固定站点的页面文本；失败返回 None。"""
    try:
        with requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, **(headers or {})},
            allow_redirects=True,
        ) as resp:
            if resp.status_code != 200:
                return None
            chunks, total = [], 0
            for chunk in resp.iter_content(chunk_size=16384, decode_unicode=True):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_TEXT_BYTES:
                    break
                chunks.append(chunk)
            return "".join(chunks)
    except Exception:
        return None


def _get_json(url: str, headers: dict | None = None):
    try:
        with requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, **(headers or {})},
        ) as resp:
            if resp.status_code != 200:
                return None
            return resp.json()
    except Exception:
        return None


def github_token() -> str | None:
    """GitHub 令牌：环境变量优先；Actions 里尝试 checkout 持久化的凭据。

    工作流文件无法由本项目修改（无 workflows 权限），checkout 动作会把
    令牌存进本地 git 配置的 extraheader，这里只读解析、失败即放弃。
    """
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value.strip()
    try:
        # 不能用 --local：checkout 把凭据放在 RUNNER_TEMP 的独立配置文件里，
        # 本地配置只有一条 include.path 指向它，必须让 git 跟随 include 解析。
        completed = subprocess.run(
            ["git", "config", "--get-all", "http.https://github.com/.extraheader"],
            check=False, capture_output=True, text=True, timeout=5,
        )
        header = completed.stdout.strip().splitlines()[-1].strip() if completed.stdout.strip() else ""
        if header.lower().startswith("authorization: basic "):
            decoded = base64.b64decode(header.split(" ", 2)[-1]).decode("utf-8", "replace")
            if ":" in decoded:
                return decoded.split(":", 1)[1].strip() or None
    except Exception:
        pass
    return None


def _github_headers(token: str | None) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def crawl_github(config: dict, token: str | None) -> dict:
    """GitHub 渠道：代码搜索找含节点链接的文件 + 仓库搜索读 README。

    代码搜索需要令牌；无令牌时只做仓库搜索（未授权速率较低但够用）。
    含节点链接的文件其 raw 地址即为候选订阅源。
    """
    uris: list[str] = []
    urls: list[str] = []
    notes: list[str] = []
    headers = _github_headers(token)
    if token:
        for query in config.get("code_queries", [])[:4]:
            data = _get_json(
                "https://api.github.com/search/code?per_page=20&q="
                + urllib.parse.quote(query),
                headers,
            )
            if not data or "items" not in data:
                notes.append("code search failed")
                continue
            for item in data["items"][:20]:
                html_url = item.get("html_url", "")
                if "/blob/" in html_url:
                    raw_url = html_url.replace(
                        "https://github.com/", "https://raw.githubusercontent.com/"
                    ).replace("/blob/", "/", 1)
                    urls.append(raw_url)
    else:
        notes.append("no token: code search skipped")
    for query in config.get("repo_queries", [])[:4]:
        data = _get_json(
            "https://api.github.com/search/repositories?per_page=8&q="
            + urllib.parse.quote(query),
            headers,
        )
        if not data or "items" not in data:
            notes.append("repo search failed")
            continue
        for repo in data["items"][:8]:
            branch = repo.get("default_branch") or "main"
            readme = _get_text(
                f"https://raw.githubusercontent.com/{repo['full_name']}/{branch}/README.md"
            )
            if readme:
                found_uris, found_urls = extract_candidates(readme)
                uris.extend(found_uris)
                urls.extend(found_urls)
    return {"uris": uris, "urls": urls, "notes": notes}


def crawl_telegram(config: dict) -> dict:
    """Telegram 渠道：公开频道的网页预览 t.me/s/<频道>，无需登录。"""
    uris: list[str] = []
    urls: list[str] = []
    notes: list[str] = []
    for channel in config.get("channels", [])[:12]:
        page = _get_text(f"https://t.me/s/{channel}")
        if not page:
            notes.append(f"{channel}: fetch failed")
            continue
        found_uris, found_urls = extract_candidates(page)
        uris.extend(found_uris)
        urls.extend(found_urls)
    return {"uris": uris, "urls": urls, "notes": notes}


def crawl_google(config: dict) -> dict:
    """Google 渠道：抓搜索结果页外链。机房 IP 常被拦截，失败即跳过。"""
    uris: list[str] = []
    urls: list[str] = []
    notes: list[str] = []
    for query in config.get("queries", [])[:4]:
        page = _get_text(
            "https://www.google.com/search?num=20&q=" + urllib.parse.quote(query)
        )
        if not page:
            notes.append("fetch failed")
            continue
        if "/sorry/" in page or "unusual traffic" in page:
            notes.append("blocked by google")
            continue
        for href in re.findall(r'href="([^"]+)"', page):
            link = html_module.unescape(href)
            if link.startswith("/url?q="):
                link = urllib.parse.unquote(link[len("/url?q="):].split("&", 1)[0])
            if not link.startswith("http"):
                continue
            host = urllib.parse.urlsplit(link).hostname or ""
            if not host or "google." in host:
                continue
            urls.append(link)
        found_uris, _ = extract_candidates(page)
        uris.extend(found_uris)
    return {"uris": uris, "urls": urls, "notes": notes}


def crawl_youtube(config: dict) -> dict:
    """YouTube 渠道：搜索页找视频，视频页简介里常有订阅链接。"""
    uris: list[str] = []
    urls: list[str] = []
    notes: list[str] = []
    max_videos = int(config.get("max_videos_per_query", 3))
    for query in config.get("queries", [])[:3]:
        page = _get_text(
            "https://www.youtube.com/results?search_query=" + urllib.parse.quote(query)
        )
        if not page:
            notes.append("search failed")
            continue
        video_ids = []
        for video_id in re.findall(r'"videoId":"([\w-]{11})"', page):
            if video_id not in video_ids:
                video_ids.append(video_id)
        for video_id in video_ids[:max_videos]:
            watch = _get_text(f"https://www.youtube.com/watch?v={video_id}")
            if not watch:
                continue
            found_uris, found_urls = extract_candidates(watch)
            uris.extend(found_uris)
            urls.extend(found_urls)
    return {"uris": uris, "urls": urls, "notes": notes}


def crawl_x(config: dict) -> dict:
    """X 渠道：配置的公开账号走 syndication 时间线（免登录）；未配置则跳过。"""
    uris: list[str] = []
    urls: list[str] = []
    notes: list[str] = []
    users = config.get("users", [])[:6]
    if not users:
        return {"uris": [], "urls": [], "notes": ["no users configured"]}
    for user in users:
        data = _get_json(
            f"https://syndication.twitter.com/srv/timeline-profile/screen-name/{user}"
        )
        if not data:
            notes.append(f"{user}: fetch failed")
            continue
        found_uris, found_urls = extract_candidates(json.dumps(data, ensure_ascii=False))
        uris.extend(found_uris)
        urls.extend(found_urls)
    return {"uris": uris, "urls": urls, "notes": notes}


_CHANNELS = {
    "github": crawl_github,
    "telegram": crawl_telegram,
    "google": crawl_google,
    "youtube": crawl_youtube,
    "x": crawl_x,
}


def _url_priority(url: str) -> int:
    """订阅地址优先排序：频道一页能带回大量站点链接，截断前先保住像
    订阅的（raw GitHub 地址最优先，其次路径含 sub 或订阅文件后缀）。
    野生链接格式千奇百怪，解析失败的一律排最后。"""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        path = parsed.path.lower()
    except ValueError:
        return 2
    if host == "raw.githubusercontent.com":
        return 0
    if "sub" in path or path.endswith((".txt", ".yaml", ".yml", ".json")):
        return 1
    return 2


def run_discovery(config: dict, deadline_seconds: int = 180) -> dict:
    """按配置跑全部启用渠道，返回 {uris, urls, channels: 每渠道统计}。"""
    started = time.monotonic()
    all_uris: list[str] = []
    all_urls: list[str] = []
    channel_stats: dict[str, dict] = {}
    token = github_token()
    for name, crawler in _CHANNELS.items():
        channel_config = config.get(name) or {}
        if not channel_config.get("enable", False):
            channel_stats[name] = {"skipped": "disabled"}
            continue
        if time.monotonic() - started > deadline_seconds:
            channel_stats[name] = {"skipped": "deadline"}
            continue
        try:
            if name == "github":
                result = crawler(channel_config, token)
            else:
                result = crawler(channel_config)
        except Exception as exc:  # 渠道实现 bug 也不许拖垮主流程
            channel_stats[name] = {"error": type(exc).__name__}
            continue
        uris = list(dict.fromkeys(result.get("uris", [])))[:MAX_URIS_PER_CHANNEL]
        urls = sorted(
            dict.fromkeys(result.get("urls", [])), key=_url_priority
        )[:MAX_URLS_PER_CHANNEL]
        all_uris.extend(uris)
        all_urls.extend(urls)
        channel_stats[name] = {
            "uris": len(uris),
            "urls": len(urls),
            "notes": result.get("notes", [])[:4],
        }
    return {
        "uris": list(dict.fromkeys(all_uris)),
        "urls": list(dict.fromkeys(all_urls)),
        "channels": channel_stats,
    }
