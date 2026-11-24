"""整改回归测试（全部离线：网络/DNS 均用 mock）。"""
import os
import unittest
from unittest.mock import patch

from scripts import collector, discovery, speedtest


class HttpsEndpointsTests(unittest.TestCase):
    def test_ip_api_endpoints_use_https(self):
        self.assertTrue(collector.GEOIP_ENDPOINT.startswith("https://"), collector.GEOIP_ENDPOINT)
        self.assertTrue(collector.EGRESS_BATCH_API.startswith("https://"), collector.EGRESS_BATCH_API)
        self.assertNotIn("http://ip-api.com", collector.GEOIP_ENDPOINT)
        self.assertNotIn("http://ip-api.com", collector.EGRESS_BATCH_API)

    @patch("scripts.collector.requests.get")
    def test_lookup_region_uses_no_redirects(self, mocked_get):
        collector._geoip_cache.clear()
        resp = mocked_get.return_value.__enter__.return_value
        resp.status_code = 200
        resp.headers = {}
        resp.content = b"{}"
        resp.json.return_value = {"status": "success", "countryCode": "JP"}
        collector._geoip_cache.clear()
        self.assertEqual(collector.lookup_region_by_ip("8.8.8.8"), "JP")
        self.assertFalse(mocked_get.call_args.kwargs.get("allow_redirects", True))


class DiscoveryEncodingTests(unittest.TestCase):
    @patch("scripts.discovery._get_text", return_value="")
    def test_telegram_channel_is_url_quoted(self, mocked_get):
        discovery.crawl_telegram({"channels": ["a/b?c d"]})
        called_url = mocked_get.call_args.args[0]
        self.assertEqual(called_url, "https://t.me/s/a%2Fb%3Fc%20d")

    @patch("scripts.discovery._get_json", return_value=None)
    def test_x_user_is_url_quoted(self, mocked_json):
        discovery.crawl_x({"users": ["a/b?c"]})
        called_url = mocked_json.call_args.args[0]
        self.assertIn("screen-name/a%2Fb%3Fc", called_url)

    @patch("scripts.discovery._get_text", return_value="")
    @patch("scripts.discovery._get_json")
    def test_github_full_name_segments_are_quoted(self, mocked_json, mocked_text):
        mocked_json.return_value = {"items": [{"full_name": "own er/re po", "default_branch": "ma in"}]}
        discovery.crawl_github({"repo_queries": ["q"]}, None)
        called_url = mocked_text.call_args.args[0]
        self.assertEqual(
            called_url,
            "https://raw.githubusercontent.com/own%20er/re%20po/ma%20in/README.md",
        )

    def test_github_token_only_from_env(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(discovery.github_token())
        with patch.dict(os.environ, {"GH_TOKEN": "  tok123 "}, clear=True):
            self.assertEqual(discovery.github_token(), "tok123")
        # No git-config fallback remains in the source.
        import inspect
        self.assertNotIn("subprocess", inspect.getsource(discovery.github_token))
        self.assertNotIn("--get-all", inspect.getsource(discovery.github_token))


class InsecureNotPropagatedTests(unittest.TestCase):
    def test_speedtest_tls_ignores_insecure_flag(self):
        outbound = speedtest.build_outbound(
            "vless://uuid@example.com:443?security=tls&sni=example.com&allowInsecure=1"
        )
        self.assertNotIn("insecure", outbound["tls"])

    def test_speedtest_hysteria_ignores_insecure_flag(self):
        outbound = speedtest.build_outbound(
            "hysteria://example.com:443?auth=secret&peer=sni.example&insecure=1"
        )
        self.assertNotIn("insecure", outbound["tls"])

    def test_clash_conversion_does_not_output_skip_cert_verify(self):
        proxy = collector.uri_to_clash_proxy(
            "trojan://secret@example.com:443?allowInsecure=1&sni=example.com"
        )
        self.assertIsNotNone(proxy)
        self.assertNotIn("skip-cert-verify", proxy)

    def test_speedtest_samples_is_three(self):
        self.assertEqual(speedtest.SPEED_TEST_SAMPLES, 3)


class SourceDnsValidationTests(unittest.TestCase):
    @patch("scripts.collector.resolve_public_addresses", return_value=[(2, 1, 6, "", ("8.8.8.8", 0))])
    def test_public_host_passes(self, mocked_resolve):
        self.assertTrue(collector.source_host_is_public("https://raw.githubusercontent.com/a/b/c.txt"))
        mocked_resolve.assert_called_once_with("raw.githubusercontent.com")

    @patch("scripts.collector.resolve_public_addresses", return_value=[])
    def test_unresolved_or_private_host_rejected(self, mocked_resolve):
        self.assertFalse(collector.source_host_is_public("https://t.me/s/x"))

    @patch("scripts.collector.resolve_public_addresses", side_effect=RuntimeError("dns boom"))
    def test_resolver_error_rejected(self, mocked_resolve):
        self.assertFalse(collector.source_host_is_public("https://t.me/s/x"))

    @patch.object(collector, "source_host_is_public", return_value=False)
    @patch("scripts.collector.requests.get")
    def test_fetch_source_rejected_before_request_when_dns_bad(self, mocked_get, mocked_dns):
        self.assertEqual(
            collector.fetch_source("https://raw.githubusercontent.com/owner/repo/main/list.txt"),
            [],
        )
        mocked_get.assert_not_called()


class CacheConsistencyTests(unittest.TestCase):
    def test_history_key_cached_and_consistent(self):
        a = "vless://uuid@example.com:443?type=ws#NameA"
        b = "vless://uuid@example.com:443?type=ws#NameB"
        self.assertEqual(collector.history_key(a), collector.history_key(a))
        self.assertEqual(collector.history_key(a), collector.history_key(b))

    def test_get_endpoint_and_dedup_key_repeatable(self):
        line = "trojan://secret@example.com:443?type=tcp#x"
        self.assertEqual(collector.get_endpoint(line), collector.get_endpoint(line))
        self.assertEqual(collector.get_dedup_key(line), collector.get_dedup_key(line))

    @patch("scripts.collector.subprocess.run")
    def test_domain_resolution_cached_single_getent(self, mocked_run):
        collector._resolve_domain_cached.cache_clear()
        mocked_run.return_value = type(
            "Result", (), {"returncode": 0, "stdout": "8.8.4.4 STREAM cache.example\n"}
        )()
        with patch("scripts.collector.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.4.4", 0))]):
            first = collector.resolve_public_addresses("cache.example")
            second = collector.resolve_public_addresses("cache.example")
        self.assertEqual(first, second)
        self.assertEqual(mocked_run.call_count, 1)
        collector._resolve_domain_cached.cache_clear()


class SourceFailureCountsTests(unittest.TestCase):
    def test_failure_counts_aggregate(self):
        collector.SOURCE_FAILURE_COUNTS.clear()
        collector._record_source_failure("https://raw.githubusercontent.com/a/b.txt", "Timeout")
        collector._record_source_failure("https://raw.githubusercontent.com/a/c.txt", "Timeout")
        counts = collector.get_source_failure_counts()
        self.assertEqual(counts[("raw.githubusercontent.com", "Timeout")], 2)
        counts[("x", "y")] = 99  # returned dict is a copy
        self.assertNotIn(("x", "y"), collector.get_source_failure_counts())
        collector.SOURCE_FAILURE_COUNTS.clear()


if __name__ == "__main__":
    unittest.main()
