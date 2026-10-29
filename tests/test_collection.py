"""Passive collection-store tests.

Lock in the identity/dedup rules of collection.CollectionStore: one row per
domain / IP / DNS tuple, WHOIS and TLS kept as history on content change,
payload artifacts keyed by hash-or-URL (so an undownloaded URL and its later
acquisition collapse to one identity), provenance edges deduplicated, and the
enrichment log driving re-query decisions. Uses a temp DB file (not :memory:)
so the WAL/pragma open path is exercised as in production.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from collection import CollectionStore, artifact_key  # noqa: E402


class CollectionTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = CollectionStore(os.path.join(self.tmp, "collection.db"))

    def tearDown(self):
        self.store.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestDomainsAndIps(CollectionTestBase):
    def test_domain_upsert_dedups_and_counts(self):
        row, is_new = self.store.upsert_domain("Evil.Example.COM.", apex_domain="example.com")
        self.assertTrue(is_new)
        self.assertEqual(row["fqdn"], "evil.example.com")  # normalised
        self.assertEqual(row["times_seen"], 1)
        row2, is_new2 = self.store.upsert_domain("evil.example.com")
        self.assertFalse(is_new2)
        self.assertEqual(row2["times_seen"], 2)

    def test_domain_fields_fill_without_clobber(self):
        self.store.upsert_domain("d.com", source="urlscan")
        # a later sighting supplies status but must not wipe the original source
        row, _ = self.store.upsert_domain("d.com", status="sinkholed", source="cape")
        self.assertEqual(row["source"], "urlscan")
        self.assertEqual(row["status"], "sinkholed")

    def test_ip_version_inferred_and_sinkhole_toggle(self):
        v4, _ = self.store.upsert_ip("8.8.8.8", is_sinkhole=True, source="pcap")
        self.assertEqual(v4["version"], 4)
        self.assertEqual(v4["is_sinkhole"], 1)
        v6, _ = self.store.upsert_ip("2001:4860:4860::8888")
        self.assertEqual(v6["version"], 6)
        # a later sighting without is_sinkhole must not clear the flag
        again, is_new = self.store.upsert_ip("8.8.8.8")
        self.assertFalse(is_new)
        self.assertEqual(again["is_sinkhole"], 1)
        self.assertEqual(again["times_seen"], 2)


class TestConsumedUrls(CollectionTestBase):
    def test_records_dedups_and_counts_by_source(self):
        self.store.record_consumed("https://a.com/x", "urlscan", "a.com")
        self.store.record_consumed("http://1.2.3.4/p", "urlhaus", "1.2.3.4")
        self.store.record_consumed("https://b.top/", "gist", "b.top")
        self.store.record_consumed("https://a.com/x", "urlscan", "a.com")  # repeat
        counts = {r["source"]: (r["urls"], r["sightings"]) for r in self.store.consumed_counts()}
        self.assertEqual(counts["urlscan"], (1, 2))   # 1 distinct url, seen twice
        self.assertEqual(counts["urlhaus"], (1, 1))
        self.assertEqual(counts["gist"], (1, 1))
        recent = self.store.consumed_recent(10)
        self.assertEqual({r["url"] for r in recent},
                         {"https://a.com/x", "http://1.2.3.4/p", "https://b.top/"})

    def test_blank_url_ignored(self):
        self.store.record_consumed("", "urlscan")
        self.assertEqual(self.store.consumed_counts(), [])


class TestRecoveryLedger(CollectionTestBase):
    def test_records_every_outcome_and_dedups(self):
        # a skipped macOS bash lure is now kept (not dropped)
        self.store.record_recovery(sha256="a" * 64, domain="mac.example", source="browser",
                                   decision="skipped_unclassified", command="/bin/bash -c curl|bash")
        # a submitted Windows payload
        self.store.record_recovery(sha256="b" * 64, domain="win.example", source="live:urlhaus",
                                   package="ps1", decision="submitted", cape_task_id=42,
                                   command="powershell -nop -c iex(...)")
        # same command+domain again -> bump, not a new row; decision refreshed
        self.store.record_recovery(sha256="a" * 64, domain="mac.example",
                                   decision="skipped_unclassified")
        decs = {r["decision"]: (r["n"], r["sightings"]) for r in self.store.recovery_decisions()}
        self.assertEqual(decs["skipped_unclassified"], (1, 2))   # 1 distinct, seen twice
        self.assertEqual(decs["submitted"], (1, 1))
        recent = self.store.recoveries_recent(10)
        self.assertEqual(len(recent), 2)
        got = {r["domain"]: r["decision"] for r in recent}
        self.assertEqual(got["mac.example"], "skipped_unclassified")
        self.assertEqual(got["win.example"], "submitted")


class TestDns(CollectionTestBase):
    def test_a_record_mirrors_ip_and_dedups(self):
        row, is_new = self.store.record_dns("evil.com", "a", "1.2.3.4", source="urlscan")
        self.assertTrue(is_new)
        self.assertEqual(row["ip"], "1.2.3.4")
        self.assertEqual(row["record_type"], "A")
        _, is_new2 = self.store.record_dns("evil.com", "A", "1.2.3.4")
        self.assertFalse(is_new2)
        self.assertEqual(self.store.ips_for_domain("evil.com")[0]["times_seen"], 2)

    def test_pivots_both_directions(self):
        self.store.record_dns("a.com", "A", "9.9.9.9")
        self.store.record_dns("b.com", "A", "9.9.9.9")
        domains = [r["domain"] for r in self.store.domains_for_ip("9.9.9.9")]
        self.assertEqual(sorted(domains), ["a.com", "b.com"])


class TestWhois(CollectionTestBase):
    def test_identical_whois_is_one_snapshot(self):
        _, new1 = self.store.record_whois("evil.com", raw_text="registrar: ACME\ncreated: 2026")
        _, new2 = self.store.record_whois("evil.com", raw_text="registrar: ACME\ncreated: 2026")
        self.assertTrue(new1)
        self.assertFalse(new2)
        self.assertEqual(len(self.store.whois_history("evil.com")), 1)

    def test_changed_registration_keeps_history(self):
        self.store.record_whois("evil.com", registrar="ACME", name_servers=["ns1.acme"])
        self.store.record_whois("evil.com", registrar="EVILREG", name_servers=["ns1.evil"])
        hist = self.store.whois_history("evil.com")
        self.assertEqual(len(hist), 2)
        self.assertEqual(self.store.latest_whois("evil.com")["registrar"], "EVILREG")


class TestPayloadArtifacts(CollectionTestBase):
    def test_url_only_artifact_defaults_to_not_acquired(self):
        row, is_new = self.store.upsert_payload_artifact(
            url="https://i-like-ele-phants-verification.live/iamchallenge/verification/UserID7383526",
            artifact_type="msi", served_by_domain="i-like-ele-phants-verification.live",
            source="cape:76",
        )
        self.assertTrue(is_new)
        self.assertIsNone(row["sha256"])
        self.assertEqual(row["acquisition_status"], "not_acquired")
        self.assertTrue(row["artifact_key"].startswith("url:"))

    def test_acquiring_backfills_hash_onto_url_row(self):
        url = "https://evil.com/a.msi"
        self.store.upsert_payload_artifact(url=url, artifact_type="msi")
        # later we obtain the body: same URL + a hash must not create a 2nd row
        row, is_new = self.store.upsert_payload_artifact(
            sha256="ABCD1234", url=url, acquisition_status="acquired",
        )
        self.assertFalse(is_new)
        self.assertEqual(row["sha256"], "abcd1234")
        self.assertEqual(row["acquisition_status"], "acquired")
        self.assertEqual(self.store.stats()["artifacts"], 1)

    def test_hash_keyed_artifact_identity(self):
        self.store.upsert_payload_artifact(sha256="DEAD", artifact_type="exe")
        self.assertEqual(self.store.artifact(artifact_key("DEAD"))["artifact_type"], "exe")

    def test_requires_sha_or_url(self):
        with self.assertRaises(ValueError):
            self.store.upsert_payload_artifact(artifact_type="exe")


class TestProvenanceAndPivots(CollectionTestBase):
    def test_source_edges_dedup_and_pivot(self):
        key = artifact_key(url="https://evil.com/a.msi")
        self.store.upsert_payload_artifact(url="https://evil.com/a.msi", served_by_domain="evil.com")
        _, n1 = self.store.link_artifact_source(key, domain="evil.com", source="cape:76")
        _, n2 = self.store.link_artifact_source(key, domain="evil.com", source="cape:76")
        _, n3 = self.store.link_artifact_source(key, domain="evil.com", source="urlscan:abc")
        self.assertTrue(n1)
        self.assertFalse(n2)  # identical edge collapses
        self.assertTrue(n3)   # different source is a new edge
        self.assertEqual(len(self.store.infra_for_payload(key)), 2)
        found = [r["artifact_key"] for r in self.store.payloads_for_domain("evil.com")]
        self.assertIn(key, found)


class TestEnrichmentLog(CollectionTestBase):
    def test_quota_outcome_suppresses_requery_within_window(self):
        self.store.record_enrichment("url", "https://evil.com/a.msi", "vt", "quota",
                                     detail="QuotaExceededError")
        self.assertFalse(
            self.store.needs_enrichment("url", "https://evil.com/a.msi", "vt", min_age_hours=24)
        )
        self.assertEqual(
            self.store.last_enrichment("url", "https://evil.com/a.msi", "vt")["status"], "quota"
        )

    def test_error_or_never_means_retry(self):
        self.assertTrue(self.store.needs_enrichment("domain", "evil.com", "whois"))
        self.store.record_enrichment("domain", "evil.com", "whois", "error", detail="timeout")
        self.assertTrue(self.store.needs_enrichment("domain", "evil.com", "whois"))


class TestStatsAndReopen(CollectionTestBase):
    def test_stats_and_reopen_in_place(self):
        self.store.upsert_domain("evil.com")
        self.store.upsert_ip("1.2.3.4")
        self.store.record_dns("evil.com", "A", "1.2.3.4")
        self.store.upsert_payload_artifact(url="https://evil.com/a.msi")
        path = self.store.db_path
        self.store.close()
        reopened = CollectionStore(path)  # schema is idempotent; data persists
        st = reopened.stats()
        self.assertEqual(st["domains"], 1)
        self.assertEqual(st["ips"], 1)
        self.assertEqual(st["dns_records"], 1)
        self.assertEqual(st["artifacts_not_acquired"], 1)
        reopened.close()
        self.store = CollectionStore(path)  # restore for tearDown


class TestSchemaMigration(unittest.TestCase):
    """A pre-enrichment collection.db (no ct_logs, no statuses/abuse_contact on
    whois_records) must upgrade in place on open WITHOUT losing existing rows."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "old.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_upgrade_preserves_rows_and_adds_schema(self):
        import sqlite3
        # Hand-build an OLD-shape DB: whois_records lacking the new columns, and
        # no ct_logs table, plus some existing data.
        c = sqlite3.connect(self.path)
        c.executescript(
            "CREATE TABLE domains (id INTEGER PRIMARY KEY AUTOINCREMENT, fqdn TEXT UNIQUE NOT NULL,"
            " apex_domain TEXT, registrable TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,"
            " times_seen INTEGER NOT NULL DEFAULT 1, status TEXT, source TEXT, tags TEXT, notes TEXT);"
            "CREATE TABLE whois_records (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,"
            " kind TEXT NOT NULL, registrar TEXT, created TEXT, updated TEXT, expires TEXT,"
            " registrant_org TEXT, name_servers TEXT, asn INTEGER, cidr TEXT, raw_sha256 TEXT NOT NULL,"
            " first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, times_seen INTEGER NOT NULL DEFAULT 1,"
            " source TEXT, UNIQUE (target, raw_sha256));"
            "INSERT INTO domains (fqdn, first_seen, last_seen, source) VALUES"
            " ('old.example', 't', 't', 'cape:1');"
            "INSERT INTO whois_records (target, kind, registrar, raw_sha256, first_seen, last_seen)"
            " VALUES ('old.example', 'domain', 'OldReg', 'deadbeef', 't', 't');"
        )
        c.commit()
        c.close()

        # Opening via CollectionStore must create the missing table/columns and
        # keep the pre-existing rows intact.
        store = CollectionStore(self.path)
        cols = {r["name"] for r in store._conn.execute("PRAGMA table_info(whois_records)")}
        self.assertIn("statuses", cols)
        self.assertIn("abuse_contact", cols)
        self.assertIsNotNone(store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ct_logs'").fetchone())
        self.assertEqual(store.domain("old.example")["source"], "cape:1")
        w = store.latest_whois("old.example")
        self.assertEqual(w["registrar"], "OldReg")
        self.assertIsNone(w["abuse_contact"])  # new column defaults NULL, old data intact
        # and the upgraded store is fully usable (write a new-column value)
        store.record_whois("old.example", registrar="OldReg", abuse_contact="abuse@x",
                           statuses=["active"], source="rdap:test")
        self.assertEqual(len(store.whois_history("old.example")), 2)
        store.close()


if __name__ == "__main__":
    unittest.main()
