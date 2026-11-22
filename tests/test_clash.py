"""Clash YAML 输出测试：URI -> Mihomo proxy 转换与完整配置结构。

与 Shadowrocket 订阅共用同一批发布节点；这里保证当前发布白名单
涉及的协议（SS、Hysteria2、SOCKS5、VLESS Vision/gRPC）转换正确，
且生成的 YAML 能被 PyYAML 读回、也能被仓库自己的 Clash 源解析器
（clash_yaml_to_uris）逆向读回同等数量的节点。
"""
import base64
import json
import unittest
import urllib.parse

import yaml

from scripts import collector

SS_USERINFO = base64.urlsafe_b64encode("aes-128-gcm:secret".encode()).decode().rstrip("=")
SS_LINE = f"ss://{SS_USERINFO}@103.152.69.9:8388#%E6%97%A5%E6%9C%AC%20SS%2001"
HY2_LINE = "hysteria2://passw0rd@hy2.example.com:443?sni=hy2.example.com#%E7%BE%8E%E5%9B%BD%20HY2%2001"
SOCKS_LINE = "socks5://user:pass@203.0.113.8:1080#SOCKS%2001"
VLESS_VISION = (
    "vless://11111111-2222-3333-4444-555555555555@vl.example.com:443"
    "?encryption=none&security=reality&sni=www.example.com&fp=chrome"
    "&pbk=PUBLICKEY&sid=ab12&flow=xtls-rprx-vision&type=tcp#VLESS%2001"
)
VLESS_GRPC = (
    "vless://11111111-2222-3333-4444-555555555555@vl2.example.com:443"
    "?encryption=none&security=tls&sni=vl2.example.com&type=grpc"
    "&serviceName=grpcsvc#VLESS%20GRPC"
)


class UriToClashProxyTests(unittest.TestCase):
    def test_ss(self):
        proxy = collector.uri_to_clash_proxy(SS_LINE)
        self.assertEqual(proxy["type"], "ss")
        self.assertEqual(proxy["cipher"], "aes-128-gcm")
        self.assertEqual(proxy["password"], "secret")
        self.assertEqual(proxy["server"], "103.152.69.9")
        self.assertEqual(proxy["port"], 8388)
        self.assertIn("日本", proxy["name"])

    def test_ss_with_plugin_is_skipped(self):
        line = SS_LINE.split("#")[0] + "?plugin=obfs-local%3Bobfs%3Dhttp#x"
        self.assertIsNone(collector.uri_to_clash_proxy(line))

    def test_hysteria2(self):
        proxy = collector.uri_to_clash_proxy(HY2_LINE)
        self.assertEqual(proxy["type"], "hysteria2")
        self.assertEqual(proxy["password"], "passw0rd")
        self.assertEqual(proxy["sni"], "hy2.example.com")

    def test_socks5_with_auth(self):
        proxy = collector.uri_to_clash_proxy(SOCKS_LINE)
        self.assertEqual(proxy["type"], "socks5")
        self.assertEqual(proxy["username"], "user")
        self.assertEqual(proxy["password"], "pass")

    def test_socks5_base64_userinfo(self):
        creds = base64.urlsafe_b64encode("bob:pw2".encode()).decode().rstrip("=")
        proxy = collector.uri_to_clash_proxy(f"socks5://{creds}@203.0.113.9:1081#s")
        self.assertEqual(proxy["username"], "bob")
        self.assertEqual(proxy["password"], "pw2")

    def test_vless_reality_vision(self):
        proxy = collector.uri_to_clash_proxy(VLESS_VISION)
        self.assertEqual(proxy["type"], "vless")
        self.assertEqual(proxy["flow"], "xtls-rprx-vision")
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["reality-opts"]["public-key"], "PUBLICKEY")
        self.assertEqual(proxy["reality-opts"]["short-id"], "ab12")
        self.assertEqual(proxy["client-fingerprint"], "chrome")

    def test_vless_grpc(self):
        proxy = collector.uri_to_clash_proxy(VLESS_GRPC)
        self.assertEqual(proxy["network"], "grpc")
        self.assertEqual(proxy["grpc-opts"]["grpc-service-name"], "grpcsvc")

    def test_vmess(self):
        doc = {"v": "2", "ps": "VMess 01", "add": "vm.example.com", "port": "443",
               "id": "11111111-2222-3333-4444-555555555555", "aid": "0",
               "scy": "auto", "net": "ws", "host": "cdn.example.com",
               "path": "/ws", "tls": "tls", "sni": "vm.example.com"}
        line = "vmess://" + base64.b64encode(json.dumps(doc).encode()).decode()
        proxy = collector.uri_to_clash_proxy(line)
        self.assertEqual(proxy["type"], "vmess")
        self.assertEqual(proxy["network"], "ws")
        self.assertEqual(proxy["ws-opts"]["headers"]["Host"], "cdn.example.com")
        self.assertTrue(proxy["tls"])

    def test_invalid_line_returns_none(self):
        self.assertIsNone(collector.uri_to_clash_proxy("not a uri"))
        self.assertIsNone(collector.uri_to_clash_proxy("ss://%%%"))


class BuildClashConfigTests(unittest.TestCase):
    LINES = [SS_LINE, HY2_LINE, SOCKS_LINE, VLESS_VISION, VLESS_GRPC]

    def test_config_structure(self):
        config = collector.build_clash_config(self.LINES)
        self.assertEqual(len(config["proxies"]), 5)
        names = [p["name"] for p in config["proxies"]]
        self.assertEqual(len(names), len(set(names)))
        groups = {g["name"]: g for g in config["proxy-groups"]}
        for name in names:
            self.assertIn(name, groups["♻️ 自动选择"]["proxies"])
            self.assertIn(name, groups["🚀 节点选择"]["proxies"])
        self.assertEqual(config["rules"][-1], "MATCH,🐟 漏网之鱼")

    def test_empty_or_unconvertible_returns_none(self):
        self.assertIsNone(collector.build_clash_config([]))
        self.assertIsNone(collector.dump_clash_config(["not a uri"]))

    def test_yaml_round_trip_through_own_parser(self):
        text = collector.dump_clash_config(self.LINES)
        self.assertIsNotNone(text)
        data = yaml.safe_load(text)
        self.assertEqual(len(data["proxies"]), 5)
        uris = collector.clash_yaml_to_uris(text)
        self.assertEqual(len(uris), 5)
        protocols = {collector.get_protocol(u) for u in uris}
        self.assertEqual(protocols, {"ss", "hysteria2", "socks5", "vless"})


if __name__ == "__main__":
    unittest.main()
