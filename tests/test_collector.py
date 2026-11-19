import base64
import json
import socket
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
    def test_rejects_domain_resolving_to_loopback(self, mocked_getaddrinfo):
        mocked_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        ]
        self.assertEqual(collector.resolve_public_addresses("internal.example"), [])

    @patch("scripts.collector.socket.getaddrinfo")
    def test_accepts_domain_resolving_to_public_ip(self, mocked_getaddrinfo):
        expected = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))
        ]
        mocked_getaddrinfo.return_value = expected
        self.assertEqual(collector.resolve_public_addresses("dns.example"), expected)

    @patch("scripts.collector.socket.getaddrinfo")
    def test_rejects_mixed_public_and_private_dns_answers(self, mocked_getaddrinfo):
        mocked_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
        ]
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
        with patch("scripts.collector.socket.getaddrinfo") as mocked:
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
                )
            data = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(data["tcp_reachable"], 2)
            self.assertEqual(data["region_counts"], {"HK": 1, "JP": 1})
            self.assertEqual(data["protocol_counts"], {"trojan": 1, "vless": 1})
            self.assertEqual(data["measurement"], "tcp_connect_only")
            self.assertNotIn("203.0.113.1", report_path.read_text(encoding="utf-8"))

class AdversarialInputTests(unittest.TestCase):
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

    @patch("scripts.collector.socket.getaddrinfo", side_effect=socket.gaierror("no answer"))
    def test_dns_error_is_contained(self, mocked):
        self.assertEqual(collector.resolve_public_addresses("unresolved.example"), [])

    def test_single_bad_node_does_not_raise(self):
        with patch("scripts.collector.resolve_public_addresses", side_effect=TypeError("bad input")):
            self.assertEqual(collector.test_node("vless://uuid@example.org:443")[0], "timeout")

    def test_subscription_input_caps_lines_and_length(self):
        old_count, old_length = collector.MAX_SOURCE_NODES, collector.MAX_LINE_LENGTH
        try:
            collector.MAX_SOURCE_NODES = 2
            collector.MAX_LINE_LENGTH = 8
            self.assertEqual(collector.decode_subscription("vless://a\nvless://b\nvless://c"), ["vless://a", "vless://b"])
        finally:
            collector.MAX_SOURCE_NODES, collector.MAX_LINE_LENGTH = old_count, old_length


if __name__ == "__main__":
    unittest.main()
