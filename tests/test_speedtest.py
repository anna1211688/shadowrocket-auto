import base64
import json
import unittest
import unittest.mock
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

    def test_hysteria_v1_conversion(self):
        outbound = speedtest.build_outbound(
            "hysteria://example.com:443?protocol=udp&auth=secret&peer=sni.example&insecure=1&upmbps=50&downmbps=200&obfsParam=obfsvalue"
        )
        self.assertEqual(outbound["type"], "hysteria")
        self.assertEqual(outbound["auth_str"], "secret")
        self.assertEqual(outbound["up_mbps"], 50)
        self.assertEqual(outbound["down_mbps"], 200)
        self.assertEqual(outbound["obfs"], "obfsvalue")
        self.assertEqual(outbound["tls"]["server_name"], "sni.example")
        # 整改后：节点自带的 insecure=1 不再透传，保持证书校验。
        self.assertNotIn("insecure", outbound["tls"])

    def test_anytls_conversion(self):
        outbound = speedtest.build_outbound("anytls://secret@example.com:443?sni=sni.example")
        self.assertEqual(outbound["type"], "anytls")
        self.assertEqual(outbound["password"], "secret")
        self.assertEqual(outbound["tls"]["server_name"], "sni.example")

    def test_http_proxy_conversion(self):
        outbound = speedtest.build_outbound("http://user:pass@example.com:8080")
        self.assertEqual(outbound["type"], "http")
        self.assertEqual(outbound["username"], "user")
        self.assertNotIn("tls", outbound)
        secure = speedtest.build_outbound("https://example.com:8443")
        self.assertEqual(secure["type"], "http")
        self.assertTrue(secure["tls"]["enabled"])

    def test_probe_egress_ip(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _size):
                return b"fl=1f1\nh=www.cloudflare.com\nip=203.0.113.7\nts=1\n"

        class FakeOpener:
            def open(self, request, timeout=None):
                return FakeResponse()

        self.assertEqual(speedtest._probe_egress_ip(FakeOpener()), "203.0.113.7")

        class BrokenOpener:
            def open(self, request, timeout=None):
                raise OSError("tunnel down")

        self.assertIsNone(speedtest._probe_egress_ip(BrokenOpener()))

    def test_socks5_base64_userinfo_conversion(self):
        userinfo = base64.b64encode(b"123:123").decode().rstrip("=")
        outbound = speedtest.build_outbound(f"socks://{userinfo}@example.com:8888")
        self.assertEqual(outbound["type"], "socks")
        self.assertEqual(outbound["version"], "5")
        self.assertEqual(outbound["username"], "123")
        self.assertEqual(outbound["password"], "123")
        self.assertEqual(outbound["server_port"], 8888)

    def test_socks5_plain_and_no_auth_conversion(self):
        outbound = speedtest.build_outbound("socks5://user:pass@example.com:1080")
        self.assertEqual(outbound["username"], "user")
        self.assertEqual(outbound["password"], "pass")
        open_outbound = speedtest.build_outbound("socks://Og@example.com:38182")
        self.assertNotIn("username", open_outbound)

    def test_vmess_conversion(self):
        raw = json.dumps({"add":"example.com","port":"443","id":"uuid","aid":"0","net":"ws","tls":"tls","host":"cdn.example","path":"/edge"}).encode()
        uri = "vmess://" + base64.urlsafe_b64encode(raw).decode()
        outbound = speedtest.build_outbound(uri)
        self.assertEqual(outbound["type"], "vmess")
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertEqual(outbound["tls"]["enabled"], True)

    def test_vmess_non_numeric_alter_id_is_unsupported_not_a_crash(self):
        raw = json.dumps({"add":"example.com","port":"443","id":"uuid","aid":"abc","net":"tcp"}).encode()
        uri = "vmess://" + base64.urlsafe_b64encode(raw).decode()
        with self.assertRaises(speedtest.UnsupportedNode):
            speedtest.build_outbound(uri)

    def test_balanced_shortlist_survives_malformed_node(self):
        raw = json.dumps({"add":"example.com","port":"443","id":"uuid","aid":"abc","net":"tcp"}).encode()
        bad = "vmess://" + base64.urlsafe_b64encode(raw).decode()
        good = "trojan://secret@example.com:443"
        selected, unsupported = speedtest._balanced_speed_shortlist([bad, good], 10)
        self.assertEqual(selected, [good])
        self.assertEqual(len(unsupported), 1)

    def test_unknown_transport_is_skipped_not_guessed(self):
        with self.assertRaises(speedtest.UnsupportedNode):
            speedtest.build_outbound("vless://uuid@example.com:443?type=kcp")

    def test_singbox_error_diagnostics_are_classified_without_raw_output(self):
        self.assertEqual(
            speedtest._singbox_error_kind("tls: failed to verify certificate"),
            "tls_error",
        )
        self.assertEqual(
            speedtest._singbox_error_kind("unknown field server_name"),
            "unknown_field",
        )


    def test_xhttp_is_explicitly_unsupported_by_upstream_singbox(self):
        with self.assertRaisesRegex(speedtest.UnsupportedNode, "xhttp"):
            speedtest.build_outbound(
                "vless://uuid@example.com:443?security=tls&type=xhttp&path=%2Fedge"
            )

    def test_socket_reset_has_safe_reason_code(self):
        error = urllib.error.URLError(ConnectionResetError(104, "connection reset"))
        diagnostic = speedtest._exception_diagnostic(error)
        self.assertEqual(diagnostic["reason"], "connection_reset")
        self.assertEqual(diagnostic["errno"], 104)

    def test_balanced_shortlist_covers_protocols(self):
        nodes = [
            "vless://uuid1@example.com:443",
            "vless://uuid2@example.com:443",
            "trojan://secret@example.net:443",
            "vmess://" + __import__("base64").urlsafe_b64encode(
                b'{"add":"vmess.example","port":"443","id":"uuid","net":"tcp"}'
            ).decode(),
            "ss://" + base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode().rstrip("=") + "@ss.example:8388",
        ]
        selected, unsupported = speedtest._balanced_speed_shortlist(nodes, 4)
        protocols = {speedtest.collector.get_endpoint(uri)[0] for uri in selected}
        self.assertEqual(len(selected), 4)
        self.assertGreaterEqual(len(protocols), 3)
        self.assertEqual(unsupported, [])

    def test_exception_diagnostics_keep_http_status_without_url(self):
        error = urllib.error.HTTPError(
            "https://user:secret@example.com/private", 403, "Forbidden", {}, None
        )
        diagnostic = speedtest._exception_diagnostic(error)
        self.assertEqual(diagnostic["error_type"], "HTTPError")
        self.assertEqual(diagnostic["http_status"], 403)
        self.assertEqual(diagnostic["reason"], "http_error")
        self.assertNotIn("secret", str(diagnostic))


class ParallelRankTests(unittest.TestCase):
    def test_rank_by_speed_parallel_covers_all_nodes(self):
        nodes = [
            "vless://12345678-1234-1234-1234-123456789012@example.com:443?encryption=none&security=reality&sni=cdn.example&fp=chrome&pbk=publickey&sid=abcd&type=ws&host=cdn.example&path=%2Fedge#test",
            "trojan://secret@example.com:443#test",
            "hy2://secret@example.com:443#test",
        ]
        calls = []

        def fake_measure(uri, binary):
            calls.append(uri)
            return {"status": "ok", "stage": "complete", "download_mbps": 10.0, "samples_mbps": [10.0]}

        with unittest.mock.patch.object(speedtest, "measure_node", fake_measure):
            successful, results = speedtest.rank_by_speed(nodes, "sing-box", workers=3)
        self.assertEqual(sorted(calls), sorted(nodes))
        self.assertEqual(len(results), 3)
        self.assertEqual(len(successful), 3)


if __name__ == "__main__":
    unittest.main()


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._body):
            return b""
        if n is None or n < 0:
            n = len(self._body) - self._pos
        chunk = self._body[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeProcess:
    def __init__(self):
        self.terminated = False

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


class MeasureNodeMockTests(unittest.TestCase):
    """measure_node 的进程/网络全用替身：覆盖 DNS 拒绝、完整成功
    （含出口探测与进程回收）、首地址失败后故障转移到第二个地址。"""

    URI = "vless://12345678-1234-1234-1234-123456789012@node.example:443?security=tls#t"

    def _addr(self, ip):
        import socket as _socket
        return (_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, 443))

    def test_dns_rejected_when_no_public_address(self):
        with unittest.mock.patch(
            "scripts.collector.resolve_public_addresses", return_value=[]
        ):
            result = speedtest.measure_node(self.URI, "/fake/sing-box")
        self.assertEqual(result["status"], "dns_rejected")

    def _run_with_opener(self, opener, addresses, wait_local_results=None):
        processes = []

        def fake_popen(*args, **kwargs):
            proc = _FakeProcess()
            processes.append(proc)
            return proc

        wait_iter = iter(wait_local_results or [True])
        with unittest.mock.patch(
            "scripts.collector.resolve_public_addresses", return_value=addresses
        ), unittest.mock.patch.object(
            speedtest.subprocess, "run",
            return_value=unittest.mock.Mock(returncode=0, stderr="", stdout=""),
        ), unittest.mock.patch.object(
            speedtest.subprocess, "Popen", side_effect=fake_popen
        ), unittest.mock.patch.object(
            speedtest, "_wait_local", side_effect=lambda port, proc: next(wait_iter)
        ), unittest.mock.patch.object(
            speedtest.urllib.request, "build_opener", return_value=opener
        ):
            result = speedtest.measure_node(self.URI, "/fake/sing-box")
        return result, processes

    def test_successful_measurement_with_egress_probe(self):
        payload = b"x" * speedtest.SPEED_TEST_BYTES

        class Opener:
            def open(self, request, timeout=None):
                url = getattr(request, "full_url", str(request))
                if "cdn-cgi/trace" in url:
                    return _FakeResponse(b"ip=203.0.113.9\nloc=NL\n")
                return _FakeResponse(payload)

        result, processes = self._run_with_opener(Opener(), [self._addr("192.0.2.10")])
        self.assertEqual(result["status"], "ok")
        self.assertGreater(result["download_mbps"], 0)
        self.assertEqual(result["egress_ip"], "203.0.113.9")
        self.assertTrue(processes and processes[0].terminated)

    def test_failover_to_second_address(self):
        payload = b"x" * speedtest.SPEED_TEST_BYTES

        class Opener:
            def open(self, request, timeout=None):
                return _FakeResponse(payload)

        # 第一次 _wait_local 失败（handshake_failed，可重试）→ 换第二个地址成功。
        result, processes = self._run_with_opener(
            Opener(),
            [self._addr("192.0.2.10"), self._addr("192.0.2.11")],
            wait_local_results=[False, True],
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(processes), 2)
