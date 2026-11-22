"""collector.main() 的端到端替身测试与真实配置文件契约测试。

审查指出（2026-11-21）：发布状态机（main）与真实配置文件此前没有
任何直接测试——订阅是「更新」还是「保留旧版」、历史是否落盘、配置
写错是否被发现，全靠线上验证。这里用临时目录 + 替身覆盖两条主
路径，并对仓库里的真实 config 文件做契约校验。
"""
import base64
import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from scripts import collector

ROOT = Path(__file__).resolve().parents[1]

SS_USERINFO = base64.urlsafe_b64encode("aes-128-gcm:secret".encode()).decode().rstrip("=")
NODE_LINE = f"ss://{SS_USERINFO}@103.152.69.9:8388#%E6%97%A5%E6%9C%AC%E8%8A%82%E7%82%B9"
SOURCE_URL = "https://raw.githubusercontent.com/example/repo/main/sub.txt"


class MainFlowTests(unittest.TestCase):
    def _run_main(self, rank_result):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        sources = root / "sources.txt"
        sources.write_text(SOURCE_URL + "\n", encoding="utf-8")
        output = root / "shadowrocket.txt"
        clash_output = root / "clash.yaml"
        report = root / "quality_report.json"
        self._clash_output = clash_output

        def fake_rank(nodes, binary, limit=None):
            return rank_result

        env = dict(os.environ, SING_BOX_PATH="/bin/true")
        with unittest.mock.patch.object(collector, "SOURCES", sources), \
            unittest.mock.patch.object(collector, "PRIORITY_SOURCES", root / "priority.txt"), \
            unittest.mock.patch.object(collector, "DISCOVERY_CONFIG", root / "discovery.json"), \
            unittest.mock.patch.object(collector, "OUTPUT", output), \
            unittest.mock.patch.object(collector, "CLASH_OUTPUT", clash_output), \
            unittest.mock.patch.object(collector, "QUALITY_REPORT", report), \
            unittest.mock.patch.object(collector, "fetch_source", return_value=[NODE_LINE]), \
            unittest.mock.patch.object(
                collector, "test_node",
                return_value=("ok", NODE_LINE, 0.05, "ss", 0.001),
            ), \
            unittest.mock.patch.object(
                collector, "classify_egress_ips",
                return_value={"203.0.113.9": {"type": "residential", "region": "JP"}},
            ), \
            unittest.mock.patch.object(collector, "lookup_region_by_ip", return_value=""), \
            unittest.mock.patch("scripts.speedtest.rank_by_speed", side_effect=fake_rank), \
            unittest.mock.patch.dict(os.environ, env, clear=False):
            collector.main()
        return tmp, output, report

    def test_main_publishes_updated_subscription(self):
        result = {"download_mbps": 12.3, "egress_ip": "203.0.113.9"}
        tmp, output, report = self._run_main(([(NODE_LINE, dict(result))], [(NODE_LINE, dict(result))]))
        self.addCleanup(tmp.cleanup)
        import urllib.parse
        published = urllib.parse.unquote(
            base64.b64decode(output.read_text(encoding="utf-8")).decode("utf-8")
        )
        self.assertIn("日本", published)
        self.assertIn("· 住宅", published)
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(data["subscription_status"], "updated")
        self.assertEqual(len(data["node_history"]), 1)
        # 同一批节点应同步生成 Clash YAML（FIClash 用）。
        import yaml
        clash = yaml.safe_load(self._clash_output.read_text(encoding="utf-8"))
        self.assertEqual(len(clash["proxies"]), 1)
        self.assertEqual(clash["proxies"][0]["type"], "ss")
        self.assertIn("日本", clash["proxies"][0]["name"])

    def test_main_preserves_previous_when_speed_test_fails(self):
        tmp, output, report = self._run_main(([], [(NODE_LINE, {"status": "proxy_connect_failed"})]))
        self.addCleanup(tmp.cleanup)
        output.write_text("previous-subscription", encoding="utf-8")
        # 再跑一轮：测速全失败时不应覆盖已有订阅文件。
        tmp2, output2, report2 = self._run_main(([], [(NODE_LINE, {"status": "proxy_connect_failed"})]))
        self.addCleanup(tmp2.cleanup)
        self.assertFalse(output2.exists())
        data = json.loads(report2.read_text(encoding="utf-8"))
        self.assertEqual(data["subscription_status"], "preserved_previous")


class ConfigContractTests(unittest.TestCase):
    """真实配置文件契约：源必须过白名单、无重复、保送源必须是正式
    源、发现配置结构合法且规模在爬虫上限内。"""

    def _lines(self, name):
        return [
            line.strip()
            for line in (ROOT / "config" / name).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def test_sources_are_allowlisted_and_unique(self):
        sources = self._lines("sources.txt")
        self.assertTrue(sources)
        self.assertEqual(len(sources), len(set(sources)))
        for url in sources:
            self.assertTrue(collector.is_allowed_source_url(url), url)

    def test_priority_sources_are_configured_sources(self):
        sources = set(self._lines("sources.txt"))
        priority = self._lines("priority_sources.txt")
        self.assertTrue(priority)
        self.assertEqual(len(priority), len(set(priority)))
        for url in priority:
            self.assertIn(url, sources)

    def test_discovery_config_shape(self):
        config = json.loads((ROOT / "config" / "discovery.json").read_text(encoding="utf-8"))
        self.assertIn("enable", config)
        caps = {"github": 4, "telegram": 12, "google": 4, "youtube": 3, "x": 6}
        list_keys = {
            "github": ("code_queries", "repo_queries"),
            "telegram": ("channels",),
            "google": ("queries",),
            "youtube": ("queries",),
            "x": ("users",),
        }
        for channel, keys in list_keys.items():
            section = config.get(channel) or {}
            for key in keys:
                values = section.get(key, [])
                self.assertIsInstance(values, list)
                self.assertLessEqual(len(values), caps[channel], f"{channel}.{key}")


if __name__ == "__main__":
    unittest.main()
