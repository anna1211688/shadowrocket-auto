import base64
import json
import socket
import urllib.parse
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import collector


class SubscriptionParsingTests(unittest.TestCase):
    def test_decodes_base64_subscription(self):
        payload = "vless://user@example.com:443#edge"
        encoded = base64.b64encode(payload.encode()).decode()
        self.assertEqual(collector.decode_subscription(encoded), [payload])

    def test_parses_vless_endpoint(self):
        self.assertEqual(
            collector.get_endpoint("vless://uuid@example.com:443?encryption=none#Tokyo"),
            ("vless", "example.com", 443),
        )

    def test_parses_vmess_endpoint(self):
        config = {"add": "example.com", "port": "8443", "id": "uuid"}
        encoded = base64.urlsafe_b64encode(json.dumps(config).encode()).decode()
        self.assertEqual(
            collector.get_endpoint(f"vmess://{encoded}"),
            ("vmess", "example.com", 8443),
        )


class DeduplicationTests(unittest.TestCase):
    def test_ignores_node_name_fragment(self):
        first = "vless://uuid@example.com:443?type=ws&security=tls#Tokyo"
        second = "vless://uuid@example.com:443?security=tls&type=ws#Osaka"
        self.assertEqual(collector.get_dedup_key(first), collector.get_dedup_key(second))

    def test_preserves_different_credentials(self):
        first = "vless://uuid-one@example.com:443?type=ws#A"
        second = "vless://uuid-two@example.com:443?type=ws#B"
        self.assertNotEqual(collector.get_dedup_key(first), collector.get_dedup_key(second))

    def test_preserves_different_transport_parameters(self):
        first = "trojan://secret@example.com:443?type=ws#A"
        second = "trojan://secret@example.com:443?type=tcp#B"
        self.assertNotEqual(collector.get_dedup_key(first), collector.get_dedup_key(second))


class PublicAddressValidationTests(unittest.TestCase):
    @patch("scripts.collector.socket.getaddrinfo")
    @patch("scripts.collector.subprocess.run")
    def test_rejects_domain_resolving_to_loopback(self, mocked_run, mocked_getaddrinfo):
        mocked_run.return_value = type("Result", (), {"returncode": 0, "stdout": "127.0.0.1 STREAM internal.example\n"})()
        self.assertEqual(collector.resolve_public_addresses("internal.example"), [])

    @patch("scripts.collector.socket.getaddrinfo")
    @patch("scripts.collector.subprocess.run")
    def test_accepts_domain_resolving_to_public_ip(self, mocked_run, mocked_getaddrinfo):
        expected = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
        mocked_run.return_value = type("Result", (), {"returncode": 0, "stdout": "8.8.8.8 STREAM dns.example\n"})()
        mocked_getaddrinfo.return_value = expected
        self.assertEqual(collector.resolve_public_addresses("dns.example"), expected)

    @patch("scripts.collector.subprocess.run")
    def test_rejects_malformed_dns_names_before_lookup(self, mocked_run):
        for host in ("-f.example", "bad..example", "bad_name.example", "name;id.example"):
            self.assertEqual(collector.resolve_public_addresses(host), [])
        mocked_run.assert_not_called()

    @patch("scripts.collector.subprocess.run")
    def test_rejects_mixed_public_and_private_dns_answers(self, mocked_run):
        mocked_run.return_value = type("Result", (), {"returncode": 0, "stdout": "8.8.8.8 STREAM mixed.example\n10.0.0.5 STREAM mixed.example\n"})()
        self.assertEqual(collector.resolve_public_addresses("mixed.example"), [])

    def test_rejects_private_ip_literal(self):
        self.assertEqual(collector.resolve_public_addresses("192.168.1.10"), [])

    def test_accepts_public_ip_literal(self):
        self.assertTrue(collector.resolve_public_addresses("8.8.8.8"))



class RegionAndQualityReportTests(unittest.TestCase):
    def test_infers_japan_from_node_remark(self):
        self.assertEqual(
            collector.infer_region("vless://uuid@example.com:443#Tokyo-01"),
            "JP",
        )

    def test_infers_hong_kong_from_chinese_remark(self):
        self.assertEqual(
            collector.infer_region("trojan://secret@example.com:443#香港中转"),
            "HK",
        )

    def test_unknown_region_is_other(self):
        self.assertEqual(
            collector.infer_region("vless://uuid@example.com:443#node-01"),
            "OTHER",
        )

    def test_domain_is_deferred_to_connection_time_validation(self):
        with patch("scripts.collector.subprocess.run") as mocked:
            self.assertTrue(collector.is_public_ip("node.example"))
            mocked.assert_not_called()

    def test_report_aggregates_without_node_addresses(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "quality_report.json"
            with patch.object(collector, "QUALITY_REPORT", report_path):
                collector.write_quality_report(
                    5, 3,
                    {"ok": 2, "slow": 1, "timeout": 0, "invalid": 0, "private": 0},
                    [
                        ("vless://uuid@203.0.113.1:443#Tokyo", 0.1, "vless"),
                        ("trojan://secret@203.0.113.2:443#HongKong", 0.2, "trojan"),
                    ],
                    "updated",
                    [("vless://uuid@203.0.113.1:443#Tokyo", {"status": "ok", "download_mbps": 12.5})],
                )
            data = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(data["tcp_reachable"], 2)
            self.assertEqual(data["speed_test"]["successful"], 1)
            self.assertEqual(data["speed_test"]["top_nodes"][0]["download_mbps"], 12.5)
            self.assertNotIn("example.com", report_path.read_text(encoding="utf-8"))
            self.assertEqual(data["region_counts"], {"HK": 1, "JP": 1})
            self.assertEqual(data["protocol_counts"], {"trojan": 1, "vless": 1})
            self.assertEqual(data["measurement"], "proxy_download_speed_mbps_with_tcp_latency_context")
            self.assertNotIn("203.0.113.1", report_path.read_text(encoding="utf-8"))

class ProtocolAwareProbeTests(unittest.TestCase):
    def test_udp_protocols_are_not_misreported_as_tcp_reachable(self):
        for uri in (
            "hysteria2://password@example.com:443#udp",
            "hy2://password@example.com:443#udp",
            "tuic://uuid:password@example.com:443#udp",
        ):
            with patch("scripts.collector.resolve_public_addresses") as resolver:
                result = collector.test_node(uri)
                resolver.assert_not_called()
            self.assertEqual(result[0], "udp_unverified")
            self.assertIsNone(result[2])

class GeoRegionTests(unittest.TestCase):
    def test_sni_hint_infers_region_for_fronted_node(self):
        node = "vless://uuid@104.21.0.87:443?security=reality&sni=jp3.yohototo.top&type=tcp#x"
        self.assertEqual(collector.infer_region(node), "JP")

    def test_country_code_mapping(self):
        self.assertEqual(collector.region_for_country_code("NZ"), "NZ")
        self.assertEqual(collector.region_for_country_code("uk"), "GB")
        self.assertIsNone(collector.region_for_country_code("XX"))
        self.assertIsNone(collector.region_for_country_code(""))

    @patch("scripts.collector.requests.get")
    def test_lookup_region_by_ip_success_and_failure(self, mocked_get):
        collector._geoip_cache.clear()
        resp = mocked_get.return_value.__enter__.return_value
        resp.status_code = 200
        resp.json.return_value = {"status": "success", "countryCode": "NZ"}
        self.assertEqual(collector.lookup_region_by_ip("202.50.253.90"), "NZ")
        resp.json.return_value = {"status": "fail"}
        self.assertEqual(collector.lookup_region_by_ip("202.50.253.91"), "OTHER")

    @patch("scripts.collector.requests.get")
    def test_lookup_region_by_ip_skips_non_global(self, mocked_get):
        self.assertEqual(collector.lookup_region_by_ip("203.0.113.5"), "OTHER")
        self.assertEqual(collector.lookup_region_by_ip("192.168.1.1"), "OTHER")
        mocked_get.assert_not_called()

    @patch("scripts.collector.lookup_region_by_ip", return_value="NZ")
    def test_resolve_region_uses_geo_for_direct_unknown(self, mocked_lookup):
        node = "ss://YWVzLTI1Ni1nY206cGFzcw==@202.50.253.90:19999#x"
        self.assertEqual(collector.resolve_region(node), "NZ")

    @patch("scripts.collector.lookup_region_by_ip", return_value="US")
    def test_resolve_region_skips_geo_for_fronted(self, mocked_lookup):
        node = "vless://uuid@104.21.0.87:443?security=reality&sni=example.com&type=tcp#x"
        self.assertEqual(collector.resolve_region(node), "OTHER")
        mocked_lookup.assert_not_called()

    @patch("scripts.collector.lookup_region_by_ip", return_value="NZ")
    def test_label_subscription_uses_geo_region(self, mocked_lookup):
        lines = ["ss://YWVzLTI1Ni1nY206cGFzcw==@202.50.253.90:19999#x"]
        labelled = collector.label_subscription(lines)
        name = urllib.parse.unquote(labelled[0].split("#", 1)[1])
        self.assertEqual(name, "🇳🇿 新西兰 SS 01")


class SourceUrlSecurityTests(unittest.TestCase):
    def test_allows_only_https_raw_github_sources(self):
        self.assertTrue(collector.is_allowed_source_url(
            "https://raw.githubusercontent.com/owner/repo/main/list.txt"
        ))
        # 逐个批准的例外主机（米贝订阅，2026-11-20 用户批准）。
        self.assertTrue(collector.is_allowed_source_url(
            "https://aa.mibei77.com/202611/11.2064bagtq.txt"
        ))
        # 逐个批准的例外主机（zmxoo 订阅，2026-11-21 用户批准）。
        self.assertTrue(collector.is_allowed_source_url(
            "https://tian.zmxoo.xyz/linkapi"
        ))
        for url in (
            "http://raw.githubusercontent.com/owner/repo/main/list.txt",
            "https://github.com/owner/repo",
            "https://raw.githubusercontent.com.evil.example/list",
            "https://user:pass@raw.githubusercontent.com/owner/repo/file",
            "https://raw.githubusercontent.com:8443/owner/repo/file",
            "file:///etc/passwd",
            "https://127.0.0.1/private",
            "https://mibei77.com/202611/11.2064bagtq.txt",
            "https://sub.aa.mibei77.com/202611/11.2064bagtq.txt",
            "http://aa.mibei77.com/202611/11.2064bagtq.txt",
            "https://zmxoo.xyz/linkapi",
            "https://sub.tian.zmxoo.xyz/linkapi",
            "http://tian.zmxoo.xyz/linkapi",
        ):
            self.assertFalse(collector.is_allowed_source_url(url), url)

    @patch("scripts.collector.SOURCE_RETRIES", 0)
    @patch("scripts.collector.requests.get")
    def test_rejects_redirect_response_without_following_it(self, mocked_get):
        response = mocked_get.return_value.__enter__.return_value
        response.status_code = 302
        response.headers = {}
        response.iter_content.return_value = []
        self.assertEqual(
            collector.fetch_source("https://raw.githubusercontent.com/owner/repo/main/list.txt"),
            [],
        )
        mocked_get.assert_called_once()
        self.assertFalse(mocked_get.call_args.kwargs.get("allow_redirects", True))

    def test_source_download_has_total_deadline(self):
        response = type("Response", (), {
            "status_code": 200,
            "headers": {},
            "iter_content": lambda self, chunk_size: [b"vless://id@example.org:443"],
        })()
        manager = type("Manager", (), {
            "__enter__": lambda self: response,
            "__exit__": lambda self, *args: None,
        })()
        with patch.object(collector, "SOURCE_RETRIES", 0), \
             patch("scripts.collector.requests.get", return_value=manager), \
             patch("scripts.collector.time.monotonic", side_effect=[0.0, 0.0, collector.SOURCE_DEADLINE + 1]):
            self.assertEqual(
                collector.fetch_source("https://raw.githubusercontent.com/owner/repo/main/list.txt"),
                [],
            )

    @patch("scripts.collector.time.sleep")
    @patch("scripts.collector.time.monotonic", side_effect=[0.0, 0.0, 0.0, collector.SOURCE_DEADLINE + 1])
    @patch("scripts.collector.requests.get", side_effect=collector.requests.Timeout("temporary timeout"))
    def test_retries_share_one_total_deadline(self, mocked_get, mocked_monotonic, mocked_sleep):
        self.assertEqual(
            collector.fetch_source("https://raw.githubusercontent.com/owner/repo/main/list.txt"),
            [],
        )
        mocked_get.assert_called_once()
        mocked_sleep.assert_called_once_with(1.0)

    @patch("scripts.collector.requests.get")
    def test_rejects_untrusted_source_before_network_request(self, mocked_get):
        self.assertEqual(collector.fetch_source("http://127.0.0.1/secret"), [])
        mocked_get.assert_not_called()


class AtomicFileWriteTests(unittest.TestCase):
    def test_atomically_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.txt"
            target.write_text("old", encoding="utf-8")
            collector.atomic_write_text(target, "new")
            self.assertEqual(target.read_text(encoding="utf-8"), "new")
            self.assertEqual(list(Path(directory).glob(".artifact.txt.*.tmp")), [])

    def test_failed_replace_preserves_previous_file_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.txt"
            target.write_text("old", encoding="utf-8")
            with patch("scripts.collector.os.replace", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    collector.atomic_write_text(target, "new")
            self.assertEqual(target.read_text(encoding="utf-8"), "old")
            self.assertEqual(list(Path(directory).glob(".artifact.txt.*.tmp")), [])


class AdversarialInputTests(unittest.TestCase):
    def test_candidate_work_is_bounded(self):
        stats = {}
        candidates = [f"vless://id@node{i}.example:443" for i in range(collector.MAX_TEST_CANDIDATES + 25)]
        limited = collector.limit_candidates(candidates, stats)
        self.assertEqual(len(limited), collector.MAX_TEST_CANDIDATES)
        self.assertEqual(stats["skipped_limit"], 25)
        self.assertEqual(limited, candidates[:collector.MAX_TEST_CANDIDATES])

    def test_vmess_non_string_host_and_bad_ports_are_rejected(self):
        for host in (123, [], {}, None):
            raw = json.dumps({"add": host, "port": 443}).encode()
            uri = "vmess://" + base64.urlsafe_b64encode(raw).decode()
            self.assertEqual(collector.get_endpoint(uri), (None, None, None))
        for port in (0, -1, 65536, True, "nope"):
            raw = json.dumps({"add": "example.org", "port": port}).encode()
            uri = "vmess://" + base64.urlsafe_b64encode(raw).decode()
            self.assertEqual(collector.get_endpoint(uri), (None, None, None))

    @patch("scripts.collector.socket.getaddrinfo", side_effect=OSError("resolver error"))
    def test_literal_ip_socket_error_is_contained(self, mocked):
        self.assertEqual(collector.resolve_public_addresses("8.8.8.8"), [])

    @patch("scripts.collector.subprocess.run", side_effect=collector.subprocess.TimeoutExpired(cmd="getent", timeout=collector.DNS_TIMEOUT))
    def test_dns_timeout_is_contained(self, mocked):
        with self.assertRaises(collector.DNSResolutionTimeout):
            collector.resolve_public_addresses("unresolved.example")
        mocked.assert_called_once()

    def test_single_bad_node_does_not_raise(self):
        with patch("scripts.collector.resolve_public_addresses", side_effect=TypeError("bad input")):
            self.assertEqual(collector.test_node("vless://uuid@example.org:443")[0], "timeout")

    def test_subscription_input_caps_lines_and_length(self):
        old_count, old_length = collector.MAX_SOURCE_NODES, collector.MAX_LINE_LENGTH
        try:
            collector.MAX_SOURCE_NODES = 2
            collector.MAX_LINE_LENGTH = 9
            self.assertEqual(collector.decode_subscription("vless://a\nvless://b\nvless://c"), ["vless://a", "vless://b"])
        finally:
            collector.MAX_SOURCE_NODES, collector.MAX_LINE_LENGTH = old_count, old_length


class CnTierTests(unittest.TestCase):
    def test_vless_reality_is_tier_a(self):
        self.assertEqual(collector.cn_tier("vless://uuid@example.com:443?security=reality&pbk=key"), 0)

    def test_vless_tls_443_is_tier_a_other_tls_is_b(self):
        self.assertEqual(collector.cn_tier("vless://uuid@example.com:443?security=tls"), 0)
        self.assertEqual(collector.cn_tier("vless://uuid@example.com:8443?security=tls"), 1)

    def test_vless_without_tls_is_tier_c(self):
        self.assertEqual(collector.cn_tier("vless://uuid@example.com:80"), 2)

    def test_trojan_tiers_follow_port(self):
        self.assertEqual(collector.cn_tier("trojan://secret@example.com:443"), 0)
        self.assertEqual(collector.cn_tier("trojan://secret@example.com:8443"), 1)

    def test_vmess_tls_443_is_tier_b_plain_is_c(self):
        tls443 = "vmess://" + base64.urlsafe_b64encode(
            json.dumps({"add": "example.com", "port": "443", "id": "uuid", "tls": "tls"}).encode()
        ).decode()
        plain = "vmess://" + base64.urlsafe_b64encode(
            json.dumps({"add": "example.com", "port": "80", "id": "uuid", "tls": ""}).encode()
        ).decode()
        self.assertEqual(collector.cn_tier(tls443), 1)
        self.assertEqual(collector.cn_tier(plain), 2)

    @staticmethod
    def _entry(line, protocol):
        return (line, 0.1, protocol, 0.01)

    def test_cdn_fronted_detection(self):
        self.assertTrue(collector.cdn_fronted("vless://uuid@104.16.10.22:443?security=tls"))
        self.assertTrue(collector.cdn_fronted("vless://uuid@172.64.150.43:443?security=tls"))
        self.assertTrue(collector.cdn_fronted("vless://uuid@host.workers.dev:443?security=tls"))
        self.assertTrue(collector.cdn_fronted("vless://uuid@host.pages.dev:443?security=tls"))
        self.assertTrue(collector.cdn_fronted("vless://uuid@[2606:4700::1]:443?security=tls"))
        self.assertFalse(collector.cdn_fronted("vless://uuid@8.8.8.8:443?security=tls"))
        self.assertFalse(collector.cdn_fronted("trojan://secret@example.com:443"))

    def test_shortlist_respects_tier_quotas(self):
        alive = []
        for i in range(110):
            alive.append(self._entry(f"vless://uuid@104.16.10.{i % 250 + 1}:443?security=tls", "vless"))
        for i in range(50):
            alive.append(self._entry(f"vless://uuid@a{i}.example:443?security=reality&pbk=k", "vless"))
        for i in range(30):
            alive.append(self._entry(f"trojan://secret@b{i}.example:8443", "trojan"))
        ss_userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode().rstrip("=")
        for i in range(50):
            alive.append(self._entry(f"ss://{ss_userinfo}@c{i}.example:8388", "ss"))
        udp = [f"hy2://secret@u{i}.example:443" for i in range(25)]
        tcp, udp_short = collector.select_speed_shortlist(alive, udp, seed=1)
        tiers = [collector.cn_tier(line) for line in tcp]
        self.assertEqual(len(tcp), 200)
        self.assertEqual(sum(1 for line in tcp if collector.cdn_fronted(line)), 100)
        self.assertEqual(tiers.count(0), 140)
        self.assertEqual(tiers.count(1), 20)
        self.assertEqual(tiers.count(2), 40)
        # UDP 名额已开启（SPEED_UDP_LIMIT=40）：25 个候选应全部入选。
        self.assertEqual(len(udp_short), 25)

    def test_shortlist_backfills_from_c_when_ab_short(self):
        alive = []
        for i in range(5):
            alive.append(self._entry(f"vless://uuid@a{i}.example:443?security=reality&pbk=k", "vless"))
        ss_userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode().rstrip("=")
        for i in range(100):
            alive.append(self._entry(f"ss://{ss_userinfo}@c{i}.example:8388", "ss"))
        tcp, _ = collector.select_speed_shortlist(alive, [], seed=1)
        tiers = [collector.cn_tier(line) for line in tcp]
        self.assertEqual(len(tcp), 105)
        self.assertEqual(tiers.count(0), 5)
        self.assertEqual(tiers.count(2), 100)

    def test_history_update_and_veteran_threshold(self):
        import datetime as dt
        now = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
        line = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=") + "@203.0.113.7:19999"
        history = {}
        for hours in range(0, 30, 5):
            history = collector.update_node_history(history, [line], [line], now - dt.timedelta(hours=30 - hours))
        entry = history[collector.history_key(line)]
        self.assertEqual(entry["a"], 6)
        self.assertEqual(entry["p"], 6)
        self.assertTrue(collector.is_veteran(entry, now))
        young = collector.update_node_history({}, [line], [], now)
        self.assertFalse(collector.is_veteran(young[collector.history_key(line)], now))

    def test_history_prunes_stale_entries(self):
        import datetime as dt
        now = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
        line = "trojan://pw@198.51.100.9:443"
        history = collector.update_node_history({}, [line], [], now - dt.timedelta(days=8))
        self.assertIn(collector.history_key(line), history)
        history = collector.update_node_history(history, [], [], now)
        self.assertNotIn(collector.history_key(line), history)

    def test_history_key_ignores_remark(self):
        a = "trojan://pw@198.51.100.9:443#name-one"
        b = "trojan://pw@198.51.100.9:443#name-two"
        self.assertEqual(collector.history_key(a), collector.history_key(b))

    def test_shortlist_prioritises_veterans_within_group(self):
        import datetime as dt
        now = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
        ss_userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode().rstrip("=")
        alive = []
        veteran_lines = []
        for i in range(5):
            line = f"ss://{ss_userinfo}@vet{i}.example:8388"
            veteran_lines.append(line)
            alive.append(self._entry(line, "ss"))
        for i in range(100):
            alive.append(self._entry(f"ss://{ss_userinfo}@c{i}.example:8388", "ss"))
        history = {}
        for line in veteran_lines:
            history[collector.history_key(line)] = {
                "f": (now - dt.timedelta(days=3)).isoformat(),
                "l": now.isoformat(), "a": 30, "p": 10,
            }
        tcp, _ = collector.select_speed_shortlist(alive, [], seed=1, history=history, now=now)
        for line in veteran_lines:
            self.assertIn(line, tcp)

    def test_classify_egress_ips(self):
        payload = [
            {"status": "success", "query": "193.32.10.7", "countryCode": "IT", "hosting": True, "proxy": False, "mobile": False},
            {"status": "success", "query": "103.20.5.9", "countryCode": "JP", "hosting": False, "proxy": False, "mobile": False},
            {"status": "success", "query": "45.148.10.5", "countryCode": "US", "hosting": False, "proxy": True, "mobile": False},
        ]

        class FakeResponse:
            status_code = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def json(self):
                return payload

        with unittest.mock.patch.object(collector.requests, "post", return_value=FakeResponse()) as post:
            classified = collector.classify_egress_ips(["193.32.10.7", "103.20.5.9", "45.148.10.5", "10.0.0.1"])
        self.assertEqual(classified["193.32.10.7"], {"region": "IT", "type": "datacenter"})
        self.assertEqual(classified["103.20.5.9"], {"region": "JP", "type": "residential"})
        self.assertEqual(classified["45.148.10.5"]["type"], "proxy")
        self.assertNotIn("10.0.0.1", classified)
        sent = post.call_args.kwargs["json"]
        self.assertNotIn("10.0.0.1", sent)

    def test_label_subscription_marks_egress_type(self):
        line = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#node"
        key = collector.get_dedup_key(line)
        residential = collector.label_subscription([line], egress_types={key: "residential"})
        self.assertIn("住宅", urllib.parse.unquote(residential[0].split("#", 1)[1]))
        datacenter = collector.label_subscription([line], egress_types={key: "datacenter"})
        self.assertIn("机场", urllib.parse.unquote(datacenter[0].split("#", 1)[1]))
        plain = collector.label_subscription([line])
        self.assertNotIn("住宅", urllib.parse.unquote(plain[0].split("#", 1)[1]))

    def test_label_subscription_prefers_egress_region(self):
        line = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@nz.example.com:8388#nz-node"
        key = collector.get_dedup_key(line)
        labelled = collector.label_subscription([line], egress_regions={key: "IT"})
        name = urllib.parse.unquote(labelled[0].split("#", 1)[1])
        self.assertIn("意大利", name)

    def test_new_protocols_recognised(self):
        self.assertEqual(collector.get_protocol("hysteria://h:443?auth=x"), "hysteria")
        self.assertEqual(collector.get_protocol("anytls://p@h:443"), "anytls")
        self.assertEqual(collector.get_protocol("http://u:p@h:8080"), "http")
        self.assertEqual(collector.get_protocol("https://h:8443"), "https")
        self.assertEqual(collector.get_endpoint("anytls://p@example.com:443")[1:], ("example.com", 443))
        # AnyTLS 是 TLS 承载：443 端口按 A 档，其余按 B 档（同 Trojan）。
        self.assertEqual(collector.cn_tier("anytls://p@example.com:443"), 0)
        self.assertEqual(collector.cn_tier("anytls://p@example.com:8443"), 1)
        self.assertEqual(collector.cn_tier("http://u:p@example.com:8080"), 2)
        self.assertEqual(collector.cn_tier("hysteria://example.com:443?auth=x"), 2)

    def test_socks5_recognised_as_tcp_tier_c(self):
        line = "socks://MTIzOjEyMw@example.com:8888#ES node"
        self.assertEqual(collector.get_protocol(line), "socks5")
        self.assertEqual(collector.get_protocol("socks5://user:pass@example.com:1080"), "socks5")
        self.assertEqual(collector.get_endpoint(line)[1:], ("example.com", 8888))
        self.assertEqual(collector.cn_tier(line), 2)

    def test_infer_region_extended(self):
        self.assertEqual(collector.infer_region("ss://eA@202.50.253.90:19999#%E6%96%B0%E8%A5%BF%E5%85%B0%20NZ"), "NZ")
        self.assertEqual(collector.infer_region("trojan://pw@h.example:443#Canada 01"), "CA")
        self.assertEqual(collector.infer_region("vless://u@h.example:443#Indonesia Jakarta"), "ID")
        self.assertEqual(collector.infer_region("vless://u@h.example:443#India Mumbai"), "IN")
        self.assertEqual(collector.infer_region("vless://u@h.example:443#random-name"), "OTHER")

    def test_infer_region_bare_country_codes(self):
        self.assertEqual(collector.infer_region("ss://eA@h.example:8388#DE SS-34 | free-nodes"), "DE")
        self.assertEqual(collector.infer_region("vless://u@h.example:443#US VLESS-01 | free-nodes"), "US")
        self.assertEqual(collector.infer_region("vless://u@h.example:443#UK London relay"), "GB")
        self.assertEqual(collector.infer_region("vless://u@h.example:443#No.1 fast node"), "OTHER")
        self.assertEqual(collector.infer_region("ss://eA@h.example:8388#NZ SS-02"), "NZ")

    def test_rename_node_keeps_identity(self):
        line = "trojan://pw@h.example:443#old-name"
        renamed = collector.rename_node(line, "🇭🇰 香港 TROJAN 01")
        self.assertEqual(collector.get_endpoint(renamed), collector.get_endpoint(line))
        self.assertEqual(collector.history_key(renamed), collector.history_key(line))
        self.assertIn("香港", urllib.parse.unquote(urllib.parse.urlsplit(renamed).fragment))

    def test_label_subscription_chinese_names(self):
        ss_userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=")
        lines = [
            f"ss://{ss_userinfo}@202.50.253.90:19999#新西兰 NZ 1",
            f"ss://{ss_userinfo}@202.50.253.27:19999#新西兰 NZ 2",
        ]
        labelled = collector.label_subscription(lines)
        names = [urllib.parse.unquote(urllib.parse.urlsplit(l).fragment) for l in labelled]
        self.assertEqual(names, ["🇳🇿 新西兰 SS 01", "🇳🇿 新西兰 SS 02"])

    def test_label_subscription_vmess_ps(self):
        payload = {"v": "2", "ps": "old", "add": "h.example", "port": "443", "id": "uuid",
                   "aid": "0", "net": "ws", "type": "none", "host": "", "path": "/", "tls": "tls"}
        line = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
        (labelled,) = collector.label_subscription([line])
        data = json.loads(collector.decode_base64(labelled[8:]))
        self.assertTrue(data["ps"].endswith("VMESS 01"))
        self.assertEqual(collector.history_key(labelled), collector.history_key(line))

    def test_collect_candidates_priority_first_and_shared_dedup(self):
        stats = {"invalid": 0, "private": 0, "duplicate": 0}
        shared = "trojan://pw@shared.example:443"
        priority_raw = [shared, "ss://" + base64.urlsafe_b64encode(b"aes-128-gcm:pw").decode().rstrip("=") + "@prio.example:8388"]
        regular_raw = [shared, "trojan://pw2@other.example:443", "not-a-node"]
        priority, regular = collector.collect_candidates(priority_raw, regular_raw, stats)
        self.assertEqual(len(priority), 2)
        self.assertEqual(regular, ["trojan://pw2@other.example:443"])
        self.assertEqual(stats["duplicate"], 1)
        self.assertEqual(stats["invalid"], 1)

    def test_shortlist_priority_key_gets_seat(self):
        ss_userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode().rstrip("=")
        alive = []
        priority_line = f"ss://{ss_userinfo}@prio.example:8388"
        alive.append(self._entry(priority_line, "ss"))
        for i in range(100):
            alive.append(self._entry(f"ss://{ss_userinfo}@c{i}.example:8388", "ss"))
        tcp, _ = collector.select_speed_shortlist(
            alive, [], seed=1, priority_keys={collector.history_key(priority_line)})
        self.assertIn(priority_line, tcp)

    def test_dedupe_for_subscription_caps_same_fronted_service(self):
        nodes = [
            (f"vless://same-uuid@104.16.10.{i}:443?security=tls&host=origin.example&sni=origin.example&type=ws", {"download_mbps": 9.0})
            for i in range(1, 6)
        ]
        kept, dropped = collector.dedupe_for_subscription(nodes)
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, 3)

    def test_dedupe_for_subscription_caps_same_network(self):
        nodes = [
            (f"trojan://pass{i}@10.9.8.{i}:443", {"download_mbps": 9.0})
            for i in range(1, 7)
        ]
        kept, dropped = collector.dedupe_for_subscription(nodes)
        self.assertEqual(len(kept), 3)
        self.assertEqual(dropped, 3)

    def test_dedupe_for_subscription_priority_network_cap_8(self):
        nodes = [
            (f"trojan://pass{i}@10.9.8.{i}:443", {"download_mbps": 9.0})
            for i in range(1, 11)
        ]
        priority_keys = {collector.history_key(uri) for uri, _ in nodes}
        kept, dropped = collector.dedupe_for_subscription(nodes, priority_keys=priority_keys)
        self.assertEqual(len(kept), 8)
        self.assertEqual(dropped, 2)
        kept_regular, _ = collector.dedupe_for_subscription(nodes)
        self.assertEqual(len(kept_regular), 3)

    def test_dedupe_for_subscription_keeps_distinct_sources(self):
        nodes = [
            ("trojan://pass1@10.1.1.1:443", {"download_mbps": 9.0}),
            ("vless://uuid-2@20.2.2.2:443?security=reality&pbk=k", {"download_mbps": 8.0}),
            ("ss://" + base64.urlsafe_b64encode(b"aes-128-gcm:pw").decode().rstrip("=") + "@30.3.3.3:8388", {"download_mbps": 7.0}),
        ]
        kept, dropped = collector.dedupe_for_subscription(nodes)
        self.assertEqual(len(kept), 3)
        self.assertEqual(dropped, 0)

    def test_shortlist_backfills_between_included_tiers(self):
        alive = []
        for i in range(10):
            alive.append(self._entry(f"vless://uuid@a{i}.example:443?security=reality&pbk=k", "vless"))
        for i in range(150):
            alive.append(self._entry(f"trojan://secret@b{i}.example:8443", "trojan"))
        tcp, _ = collector.select_speed_shortlist(alive, [], seed=1)
        tiers = [collector.cn_tier(line) for line in tcp]
        self.assertEqual(len(tcp), 160)
        self.assertEqual(tiers.count(0), 10)
        self.assertEqual(tiers.count(1), 150)

    def test_shortlist_rotates_with_seed(self):
        alive = [
            self._entry(f"vless://uuid@a{i}.example:443?security=reality&pbk=k", "vless")
            for i in range(300)
        ]
        tcp1, _ = collector.select_speed_shortlist(alive, [], seed=1)
        tcp1_again, _ = collector.select_speed_shortlist(alive, [], seed=1)
        tcp2, _ = collector.select_speed_shortlist(alive, [], seed=2)
        self.assertEqual(tcp1, tcp1_again)
        self.assertEqual(len(tcp1), 200)
        self.assertNotEqual(set(tcp1), set(tcp2))

    def test_dedupe_by_endpoint_keeps_first_per_server(self):
        nodes = [
            ("trojan://pass1@Example.com:443", {"download_mbps": 9.0}),
            ("trojan://pass2@example.com:443", {"download_mbps": 8.0}),
            ("trojan://pass3@example.com:8443", {"download_mbps": 7.0}),
            ("vless://uuid@other.com:443?security=reality&pbk=k", {"download_mbps": 6.0}),
        ]
        kept, dropped = collector.dedupe_by_endpoint(nodes)
        self.assertEqual(dropped, 1)
        self.assertEqual([uri for uri, _ in kept], [nodes[0][0], nodes[2][0], nodes[3][0]])

    def test_ss_and_hy2_are_tier_c(self):
        userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode().rstrip("=")
        self.assertEqual(collector.cn_tier(f"ss://{userinfo}@example.com:8388"), 2)
        self.assertEqual(collector.cn_tier("hy2://secret@example.com:443"), 2)


if __name__ == "__main__":
    unittest.main()
