import datetime
import unittest
from unittest.mock import patch

from scripts import collector, discovery


class ExtractCandidatesTests(unittest.TestCase):
    def test_extracts_uris_and_urls_with_cleanup(self):
        text = (
            '节点 ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#n1，'
            '订阅 https://raw.githubusercontent.com/a/b/main/sub.txt&amp;x '
            '重复 ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#n1 '
            '页面 https://example.com/page)。'
        )
        uris, urls = discovery.extract_candidates(text)
        self.assertEqual(uris, ["ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#n1"])
        self.assertIn("https://raw.githubusercontent.com/a/b/main/sub.txt&x", urls)
        self.assertIn("https://example.com/page", urls)

    def test_empty_text(self):
        self.assertEqual(discovery.extract_candidates(""), ([], []))


class ChannelTests(unittest.TestCase):
    @patch("scripts.discovery._get_text")
    def test_telegram_channel_extracts(self, mocked_get):
        mocked_get.return_value = (
            '<div class="tgme_widget_message_text">'
            'vless://uuid@host.example:443?security=tls#n '
            'https://raw.githubusercontent.com/x/y/main/sub</div>'
        )
        result = discovery.crawl_telegram({"channels": ["somechan"]})
        self.assertEqual(len(result["uris"]), 1)
        self.assertIn("https://raw.githubusercontent.com/x/y/main/sub", result["urls"])

    @patch("scripts.discovery._get_text", return_value=None)
    def test_telegram_channel_failure_is_noted(self, mocked_get):
        result = discovery.crawl_telegram({"channels": ["gone"]})
        self.assertEqual(result["uris"], [])
        self.assertTrue(result["notes"])

    @patch("scripts.discovery._get_text")
    @patch("scripts.discovery._get_json")
    def test_github_repo_search_without_token(self, mocked_json, mocked_text):
        mocked_json.return_value = {
            "items": [{"full_name": "owner/repo", "default_branch": "main"}]
        }
        mocked_text.return_value = "see https://raw.githubusercontent.com/o/r/main/nodes.txt"
        result = discovery.crawl_github({"repo_queries": ["free nodes"]}, None)
        self.assertIn("https://raw.githubusercontent.com/o/r/main/nodes.txt", result["urls"])
        self.assertTrue(any("no token" in note for note in result["notes"]))

    @patch("scripts.discovery._get_json")
    def test_github_code_search_builds_raw_urls(self, mocked_json):
        mocked_json.return_value = {
            "items": [{"html_url": "https://github.com/o/r/blob/main/lists/sub.txt"}]
        }
        result = discovery.crawl_github({"code_queries": ["vless://"]}, "token123")
        self.assertIn(
            "https://raw.githubusercontent.com/o/r/main/lists/sub.txt", result["urls"]
        )

    def test_x_channel_without_users_skips(self):
        result = discovery.crawl_x({"users": []})
        self.assertEqual(result["uris"], [])
        self.assertIn("no users configured", result["notes"])

    def test_url_priority_prefers_subscription_like_urls(self):
        self.assertEqual(
            discovery._url_priority("https://raw.githubusercontent.com/a/b/main/sub"), 0
        )
        self.assertEqual(discovery._url_priority("https://example.com/sub/abc"), 1)
        self.assertEqual(discovery._url_priority("https://example.com/list.txt"), 1)
        self.assertEqual(discovery._url_priority("https://example.com/about"), 2)

    def test_run_discovery_all_disabled(self):
        result = discovery.run_discovery({})
        self.assertEqual(result["uris"], [])
        self.assertTrue(all("skipped" in stats for stats in result["channels"].values()))


class DiscoveredSourceStateTests(unittest.TestCase):
    NOW = datetime.datetime(2026, 11, 21, tzinfo=datetime.timezone.utc)

    def test_new_source_recorded_and_ok_increments(self):
        state = collector.update_discovered_sources(
            {}, {"https://a.example/sub": 12}, {"https://a.example/sub"}, self.NOW
        )
        entry = state["https://a.example/sub"]
        self.assertEqual(entry["ok"], 1)
        self.assertEqual(entry["empty"], 0)

    def test_empty_rounds_prune_after_three(self):
        url = "https://a.example/sub"
        state = {url: {"f": self.NOW.isoformat(), "l": self.NOW.isoformat(), "ok": 2, "empty": 2}}
        state = collector.update_discovered_sources(state, {url: 0}, set(), self.NOW)
        self.assertNotIn(url, state)

    def test_stale_source_pruned(self):
        url = "https://a.example/sub"
        old = (self.NOW - datetime.timedelta(days=8)).isoformat()
        state = {url: {"f": old, "l": old, "ok": 5, "empty": 0}}
        state = collector.update_discovered_sources(state, {}, set(), self.NOW)
        self.assertNotIn(url, state)


if __name__ == "__main__":
    unittest.main()


class NewSchemeExtractionTests(unittest.TestCase):
    """审查整改：发现层补齐 collector 已支持的协议提取。"""

    def test_hysteria_and_anytls_loose_uris(self):
        uris, _ = discovery.extract_candidates(
            "hysteria://auth@h1.example:443?peer=sni.example#n1 "
            "anytls://pw@h2.example:8443?sni=s.example#n2"
        )
        self.assertEqual(len(uris), 2)

    def test_http_proxy_shape_goes_to_uris_not_urls(self):
        uris, urls = discovery.extract_candidates(
            "节点 http://user:pass@192.0.2.5:8080 订阅 https://example.com/sub.txt "
            "裸代理 https://192.0.2.6:8443"
        )
        self.assertIn("http://user:pass@192.0.2.5:8080", uris)
        self.assertIn("https://192.0.2.6:8443", uris)
        self.assertEqual(urls, ["https://example.com/sub.txt"])


class _FakeResp:
    def __init__(self, status=200, chunks=()):
        self.status_code = status
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size=16384):
        yield from self._chunks


class FetchGuardTests(unittest.TestCase):
    """审查整改：不跟随重定向；JSON 与文本共用字节上限。"""

    def test_redirect_is_not_followed(self):
        with unittest.mock.patch.object(
            discovery.requests, "get", return_value=_FakeResp(status=301)
        ):
            self.assertIsNone(discovery._get_text("https://t.me/s/x"))

    def test_oversized_json_rejected(self):
        big = b"x" * (discovery.MAX_TEXT_BYTES + 1)
        with unittest.mock.patch.object(
            discovery.requests, "get", return_value=_FakeResp(chunks=[big])
        ):
            self.assertIsNone(discovery._get_json("https://api.github.com/x"))

    def test_small_json_ok(self):
        with unittest.mock.patch.object(
            discovery.requests, "get",
            return_value=_FakeResp(chunks=[b'{"a": 1}']),
        ):
            self.assertEqual(discovery._get_json("https://api.github.com/x"), {"a": 1})

    def test_oversized_text_is_truncated_not_dropped(self):
        big = b"y" * (discovery.MAX_TEXT_BYTES + 100)
        with unittest.mock.patch.object(
            discovery.requests, "get", return_value=_FakeResp(chunks=[big])
        ):
            text = discovery._get_text("https://t.me/s/x")
        self.assertTrue(text)
        self.assertEqual(len(text), discovery.MAX_TEXT_BYTES)
