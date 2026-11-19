import base64
import json
import unittest
import urllib.error

from scripts import speedtest


class SingBoxOutboundTests(unittest.TestCase):
    def test_vless_reality_websocket_conversion(self):
        node = "vless://12345678-1234-1234-1234-123456789012@example.com:443?encryption=none&security=reality&sni=cdn.example&fp=chrome&pbk=publickey&sid=abcd&type=ws&host=cdn.example&path=%2Fedge#test"
        outbound = speedtest.build_outbound(node)
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["uuid"], "12345678-1234-1234-1234-123456789012")
        self.assertEqual(outbound["tls"]["reality"]["public_key"], "publickey")
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertEqual(outbound["transport"]["headers"]["Host"], "cdn.example")

    def test_trojan_tls_grpc_conversion(self):
        outbound = speedtest.build_outbound("trojan://secret@example.com:443?security=tls&sni=example.com&type=grpc&serviceName=proxy")
        self.assertEqual(outbound["type"], "trojan")
        self.assertEqual(outbound["password"], "secret")
        self.assertEqual(outbound["transport"], {"type": "grpc", "service_name": "proxy"})

    def test_hysteria2_conversion(self):
        outbound = speedtest.build_outbound("hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=pass")
        self.assertEqual(outbound["type"], "hysteria2")
        self.assertEqual(outbound["obfs"]["password"], "pass")
        self.assertTrue(outbound["tls"]["enabled"])

    def test_tuic_conversion(self):
        outbound = speedtest.build_outbound("tuic://uuid:secret@example.com:443?sni=example.com&congestion_control=bbr")
        self.assertEqual(outbound["type"], "tuic")
        self.assertEqual(outbound["uuid"], "uuid")
        self.assertEqual(outbound["password"], "secret")

    def test_shadowsocks_sip002_conversion(self):
        userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode().rstrip("=")
        outbound = speedtest.build_outbound(f"ss://{userinfo}@example.com:8388")
        self.assertEqual(outbound["type"], "shadowsocks")
        self.assertEqual(outbound["method"], "aes-128-gcm")
        self.assertEqual(outbound["password"], "secret")

    def test_vmess_conversion(self):
        raw = json.dumps({"add":"example.com","port":"443","id":"uuid","aid":"0","net":"ws","tls":"tls","host":"cdn.example","path":"/edge"}).encode()
        uri = "vmess://" + base64.urlsafe_b64encode(raw).decode()
        outbound = speedtest.build_outbound(uri)
        self.assertEqual(outbound["type"], "vmess")
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertEqual(outbound["tls"]["enabled"], True)

    def test_unknown_transport_is_skipped_not_guessed(self):
        with self.assertRaises(speedtest.UnsupportedNode):
            speedtest.build_outbound("vless://uuid@example.com:443?type=kcp")

    def test_singbox_error_diagnostics_are_classified_without_raw_output(self):
        self.assertEqual(
            speedtest._singbox_error_kind("tls: failed to verify certificate"),
            "tls_error",
        )
        self.assertEqual(
            speedtest._singbox_error_kind("unknown field \\"server_name\\""),
            "unknown_field",
        )

    def test_exception_diagnostics_keep_http_status_without_url(self):
        error = urllib.error.HTTPError(
            "https://user:secret@example.com/private", 403, "Forbidden", {}, None
        )
        diagnostic = speedtest._exception_diagnostic(error)
        self.assertEqual(diagnostic, {"error_type": "HTTPError", "http_status": 403})
        self.assertNotIn("secret", str(diagnostic))


if __name__ == "__main__":
    unittest.main()
