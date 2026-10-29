"""Tests for the urlscan ingestion feeder (urlscan_feeder).

All offline: the HTTP fetch and the sleep are injected, so 429/timeout/deleted
paths are exercised with no network and no real delay. Covers valid results,
missing fields, dedup, rate limits, timeouts, dry-run (writes nothing),
idempotency, and size-capped raw storage.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from collection import CollectionStore, artifact_key  # noqa: E402
from urlscan_result import ResultFetch  # noqa: E402
import urlscan_feeder as uf  # noqa: E402


def sample_payload(uuid="01a13d16-89c7-73da-b6b7-2c46fd09d971"):
    """A realistic urlscan Result shape with contacted infra + a delivered MSI."""
    return {
        "task": {"uuid": uuid, "time": "2026-10-14T12:00:00.000Z",
                 "url": "https://201.182.25.51/"},
        "page": {"url": "https://201.182.25.51/", "domain": "201.182.25.51",
                 "ip": "201.182.25.51", "asn": "AS262287", "asnname": "EvilHost",
                 "country": "BR"},
        "lists": {
            "domains": ["201.182.25.51", "cdn.evil-delivery.live"],
            "ips": ["201.182.25.51", "45.33.32.156", "192.168.1.10"],  # last is private
            "urls": ["https://201.182.25.51/", "https://cdn.evil-delivery.live/a.msi"],
            "hashes": ["h1", "h2"],
            "certificates": [{"subjectName": "evil", "issuer": "R3"}],
        },
        "data": {"requests": [
            {"request": {"request": {"url": "https://201.182.25.51/"}},
             "response": {"hash": "pagehash",
                          "response": {"mimeType": "text/html",
                                       "remoteIPAddress": "201.182.25.51"}}},
            {"request": {"request": {"url": "https://cdn.evil-delivery.live/a.msi"}},
             "response": {"hash": "msihash123",
                          "response": {"mimeType": "application/x-msi",
                                       "remoteIPAddress": "45.33.32.156"}}},
        ]},
    }


def fetch_ok(payload):
    return lambda uuid, cfg: ResultFetch(uuid, "ok", 200, payload=payload)


class FeederTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = CollectionStore(os.path.join(self.tmp, "collection.db"))
        self.raw = os.path.join(self.tmp, "raw")
        self.cfg = None  # feeder never touches cfg when fetcher is injected
        self.nosleep = lambda *_a, **_k: None

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def commit(self, payload=None, **kw):
        payload = payload if payload is not None else sample_payload()
        return uf.ingest_scan(self.store, self.cfg, payload["task"]["uuid"],
                              raw_dir=self.raw, dry_run=False,
                              fetcher=fetch_ok(payload), sleeper=self.nosleep, **kw)


class TestParsing(unittest.TestCase):
    def test_extract_full(self):
        obs = uf.extract_observations(sample_payload(), "01a13d16-89c7-73da-b6b7-2c46fd09d971")
        self.assertEqual(obs.task_url, "https://201.182.25.51/")
        self.assertIn("cdn.evil-delivery.live", obs.domains)
        # private IP filtered, public ones kept
        self.assertIn("45.33.32.156", obs.ips)
        self.assertNotIn("192.168.1.10", obs.ips)
        self.assertEqual(obs.ips["201.182.25.51"]["asn"], 262287)
        # DNS resolution for the MSI CDN observed via request remoteIPAddress
        self.assertIn(("cdn.evil-delivery.live", "A", "45.33.32.156"), obs.dns)
        # the MSI is an artifact with urlscan's body hash, available-in-TI
        msi = [a for a in obs.artifacts if a["type"] == "msi"]
        self.assertEqual(len(msi), 1)
        self.assertEqual(msi[0]["sha256"], "msihash123")
        self.assertEqual(msi[0]["status"], "available_in_ti")

    def test_missing_fields_no_fabrication(self):
        obs = uf.extract_observations({}, "u")
        self.assertEqual(obs.plan_counts(), {"domains": 0, "ips": 0, "dns_records": 0, "artifacts": 0})
        self.assertIsNone(obs.task_url)

    def test_html_page_is_not_an_artifact(self):
        # a text/html response must never be recorded as a payload artifact
        obs = uf.extract_observations(sample_payload(), "u")
        self.assertFalse(any(a["type"] == "download" and a["url"].endswith("/") for a in obs.artifacts))

    def test_benign_asset_mislabeled_octet_stream_is_not_payload(self):
        # a CDN font served as application/octet-stream must NOT become an artifact
        self.assertIsNone(uf._payload_type(
            "https://cdnjs.cloudflare.com/.../fa-brands-400.woff2", "application/octet-stream"))
        self.assertIsNone(uf._payload_type("https://x/app.css", "application/octet-stream"))
        # a real installer served as octet-stream still is a payload
        self.assertEqual(uf._payload_type("https://x/setup.msi", "application/octet-stream"), "msi")
        self.assertEqual(uf._payload_type("https://x/get?id=1", "application/octet-stream"), "download")

    def test_payload_with_benign_mislabeled_asset_in_requests(self):
        p = sample_payload()
        p["data"]["requests"].append(
            {"request": {"request": {"url": "https://cdn.x/fonts/fa-brands-400.woff2"}},
             "response": {"hash": "fonthash",
                          "response": {"mimeType": "application/octet-stream",
                                       "remoteIPAddress": "45.33.32.156"}}})
        obs = uf.extract_observations(p, "u")
        self.assertFalse(any("woff2" in (a["url"] or "") for a in obs.artifacts))
        # the genuine MSI is still captured
        self.assertTrue(any(a["type"] == "msi" for a in obs.artifacts))


class TestCommitAndProvenance(FeederTestBase):
    def test_commit_inserts_with_provenance(self):
        res = self.commit()
        self.assertFalse(res["dry_run"])
        st = self.store.stats()
        self.assertEqual(st["domains"], 2)
        self.assertEqual(st["ips"], 2)                 # two public; private dropped
        self.assertGreaterEqual(st["dns_records"], 1)
        self.assertEqual(st["artifacts"], 1)           # just the MSI
        msi = self.store.artifact(artifact_key("msihash123"))
        self.assertEqual(msi["acquisition_status"], "available_in_ti")
        self.assertEqual(msi["served_by_domain"], "cdn.evil-delivery.live")
        # every observation carries the scan UUID as provenance source
        src = self.store.infra_for_payload(artifact_key("msihash123"))[0]["source"]
        self.assertTrue(src.endswith("01a13d16-89c7-73da-b6b7-2c46fd09d971"))

    def test_raw_json_stored_atomically(self):
        res = self.commit()
        self.assertTrue(res["raw"]["stored"])
        path = res["raw"]["path"]
        self.assertTrue(os.path.isfile(path))
        self.assertFalse(os.path.isfile(path + ".tmp"))
        with open(path) as fh:
            json.load(fh)  # valid JSON round-trips

    def test_raw_oversize_is_skipped_not_truncated(self):
        res = uf.ingest_scan(self.store, self.cfg, "01a13d16-89c7-73da-b6b7-2c46fd09d971",
                             raw_dir=self.raw, dry_run=False, max_raw_bytes=10,
                             fetcher=fetch_ok(sample_payload()), sleeper=self.nosleep)
        self.assertFalse(res["raw"]["stored"])
        self.assertEqual(res["raw"]["reason"], "oversize")
        self.assertFalse(os.path.isdir(self.raw) and os.listdir(self.raw))


class TestDryRun(FeederTestBase):
    def test_dry_run_writes_nothing(self):
        res = uf.ingest_scan(self.store, self.cfg, "01a13d16-89c7-73da-b6b7-2c46fd09d971",
                             raw_dir=self.raw, dry_run=True,
                             fetcher=fetch_ok(sample_payload()), sleeper=self.nosleep)
        self.assertTrue(res["dry_run"])
        self.assertEqual(res["would_insert"]["artifacts"], 1)
        # nothing persisted: DB empty, no raw dir, no markers
        st = self.store.stats()
        self.assertEqual(st["domains"], 0)
        self.assertEqual(st["artifacts"], 0)
        self.assertEqual(st["enrichment_runs"], 0)
        self.assertFalse(os.path.isdir(self.raw))


class TestFailureModes(FeederTestBase):
    def _fetch(self, rf):
        return lambda uuid, cfg: rf

    def test_deleted_scan_404_invents_nothing(self):
        res = uf.ingest_scan(self.store, self.cfg, "01a13d16-89c7-73da-b6b7-2c46fd09d971",
                             raw_dir=self.raw, dry_run=False,
                             fetcher=self._fetch(ResultFetch("u", "not_found", 404,
                                                             note="scan_unavailable_or_deleted")),
                             sleeper=self.nosleep)
        self.assertFalse(res["fetched"])
        self.assertEqual(res["status"], "not_found")
        self.assertEqual(self.store.stats()["domains"], 0)
        # the outcome is recorded, not invented as empty data
        self.assertEqual(
            self.store.last_enrichment("scan", "01a13d16-89c7-73da-b6b7-2c46fd09d971",
                                       "urlscan_fetch")["status"], "not_found")

    def test_rate_limit_retries_then_gives_up_as_quota(self):
        calls = {"n": 0}
        def fetcher(uuid, cfg):
            calls["n"] += 1
            return ResultFetch(uuid, "rate_limited", 429, retry_after=1)
        slept = []
        res = uf.ingest_scan(self.store, self.cfg, "01a13d16-89c7-73da-b6b7-2c46fd09d971",
                             raw_dir=self.raw, dry_run=False, fetcher=fetcher,
                             sleeper=lambda d: slept.append(d), max_retries=3)
        self.assertEqual(calls["n"], 4)          # initial + 3 retries
        self.assertEqual(slept, [1, 1, 1])       # honoured Retry-After each time
        self.assertEqual(res["status"], "quota")
        self.assertFalse(res["fetched"])

    def test_rate_limit_then_success(self):
        seq = [ResultFetch("u", "rate_limited", 429, retry_after=1),
               ResultFetch("u", "ok", 200, payload=sample_payload())]
        def fetcher(uuid, cfg):
            return seq.pop(0)
        res = uf.ingest_scan(self.store, self.cfg, "01a13d16-89c7-73da-b6b7-2c46fd09d971",
                             raw_dir=self.raw, dry_run=False, fetcher=fetcher,
                             sleeper=self.nosleep)
        self.assertTrue(res["fetched"])
        self.assertEqual(self.store.stats()["artifacts"], 1)

    def test_timeout_backoff_exponential(self):
        slept = []
        res = uf.ingest_scan(self.store, self.cfg, "01a13d16-89c7-73da-b6b7-2c46fd09d971",
                             raw_dir=self.raw, dry_run=False,
                             fetcher=lambda u, c: ResultFetch(u, "timeout", note="request_timeout"),
                             sleeper=lambda d: slept.append(d), max_retries=3, base_backoff=2.0)
        self.assertEqual(slept, [2.0, 4.0, 8.0])  # exponential backoff
        self.assertEqual(res["status"], "timeout")

    def test_no_api_key_records_outcome(self):
        res = uf.ingest_scan(self.store, self.cfg, "01a13d16-89c7-73da-b6b7-2c46fd09d971",
                             raw_dir=self.raw, dry_run=False,
                             fetcher=lambda u, c: ResultFetch(u, "no_api_key",
                                                              note="result_unavailable:no_api_key"),
                             sleeper=self.nosleep)
        self.assertEqual(res["status"], "no_api_key")
        self.assertEqual(self.store.stats()["domains"], 0)


class TestDeduplicationAndIdempotency(FeederTestBase):
    def test_second_commit_is_noop(self):
        first = self.commit()
        before = self.store.stats()
        second = self.commit()
        after = self.store.stats()
        self.assertFalse(first["skipped"])
        self.assertTrue(second["skipped"])
        self.assertEqual(before, after)

    def test_counters_not_inflated_on_reingest(self):
        self.commit()
        dom = self.store.domain("cdn.evil-delivery.live")
        seen = dom["times_seen"]
        self.commit()  # skipped
        self.assertEqual(self.store.domain("cdn.evil-delivery.live")["times_seen"], seen)

    def test_force_reingest_bumps_counter_no_new_rows(self):
        self.commit()
        res = self.commit(force=True)
        self.assertFalse(res["skipped"])
        self.assertEqual(self.store.stats()["domains"], 2)      # no new rows
        self.assertEqual(self.store.domain("cdn.evil-delivery.live")["times_seen"], 2)

    def test_within_scan_duplicate_values_collapse(self):
        # same domain/ip appearing in lists AND requests must not double-count
        obs = uf.extract_observations(sample_payload(), "u")
        self.assertEqual(len([d for d in obs.domains if d == "cdn.evil-delivery.live"]), 1)


if __name__ == "__main__":
    unittest.main()
