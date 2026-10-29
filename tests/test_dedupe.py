"""Deduplication tests.

urlscan issues a fresh scan UUID on every rescan, so UUID dedup alone lets the
same lure through repeatedly. A live 100-result poll measured 100 UUIDs but
only 54 unique URLs across 51 domains, with one URL appearing 14 times. These
tests lock in each dedup layer.
"""

import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import pipeline  # noqa: E402
from config import Config  # noqa: E402
from state import ClickfixStore, now_iso  # noqa: E402
from urlnorm import normalize_url, url_parts  # noqa: E402


class TestUrlNormalization(unittest.TestCase):
    def test_case_and_default_port_collapse(self):
        self.assertEqual(
            normalize_url("https://WWVV.info:443/path"),
            normalize_url("https://wwvv.info/path"),
        )

    def test_trailing_slash_collapse(self):
        self.assertEqual(
            normalize_url("https://x.invalid/woo/"), normalize_url("https://x.invalid/woo")
        )

    def test_fragment_ignored(self):
        self.assertEqual(
            normalize_url("https://x.invalid/a#one"), normalize_url("https://x.invalid/a#two")
        )

    def test_tracking_params_dropped(self):
        self.assertEqual(
            normalize_url("https://x.invalid/a?utm_source=tw&fbclid=9"),
            normalize_url("https://x.invalid/a"),
        )

    def test_meaningful_params_preserved(self):
        # ?c= selects content on a real observed lure -- must NOT collapse.
        self.assertNotEqual(
            normalize_url("https://wwvv.info/m.com?c=%2F"),
            normalize_url("https://wwvv.info/m.com"),
        )

    def test_param_order_does_not_matter(self):
        self.assertEqual(
            normalize_url("https://x.invalid/a?b=2&a=1"),
            normalize_url("https://x.invalid/a?a=1&b=2"),
        )

    def test_duplicate_slashes_collapse(self):
        self.assertEqual(
            normalize_url("https://x.invalid/a//b"), normalize_url("https://x.invalid/a/b")
        )

    def test_malformed_url_does_not_raise(self):
        self.assertIsInstance(normalize_url("not a url at all"), str)
        self.assertEqual(normalize_url(""), "")

    def test_apex_domain(self):
        self.assertEqual(url_parts("https://a.b.evil.com/x")[1], "evil.com")


class DedupeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clickfix-dedupe-")
        cfg = Config()
        cfg.pipeline.db_path = os.path.join(self.tmp, "t.db")
        self.cfg = cfg
        self.store = ClickfixStore(cfg.pipeline.db_path)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sight(self, url, uuid):
        norm = normalize_url(url)
        domain, apex = url_parts(url)
        return self.store.record_url_sighting(norm, url, domain, apex, uuid)


class TestUrlSightings(DedupeTestCase):
    def test_repeat_sighting_does_not_add_a_row(self):
        for i in range(14):
            self.sight("https://wwvv.info/m.com?c=%2F", f"uuid-{i}")
        self.assertEqual(self.store.dedup_stats()["unique_urls"], 1)
        self.assertEqual(self.store.dedup_stats()["url_sightings"], 14)

    def test_cosmetic_variants_are_one_url(self):
        self.sight("https://X.invalid/a/", "u1")
        self.sight("https://x.invalid:443/a", "u2")
        self.sight("https://x.invalid/a#frag", "u3")
        self.assertEqual(self.store.dedup_stats()["unique_urls"], 1)

    def test_times_seen_counter(self):
        for i in range(5):
            row = self.sight("https://x.invalid/a", f"u{i}")
        self.assertEqual(row["times_seen"], 5)

    def test_distinct_urls_are_separate_rows(self):
        self.sight("https://a.invalid/", "u1")
        self.sight("https://b.invalid/", "u2")
        self.assertEqual(self.store.dedup_stats()["unique_urls"], 2)


class TestDedupDecision(DedupeTestCase):
    def test_first_sighting_is_analysed(self):
        row = self.sight("https://x.invalid/a", "u1")
        ok, reason = pipeline._dedup_decision(self.cfg, self.store, row)
        self.assertTrue(ok)
        self.assertEqual(reason, "new")

    def test_recently_analysed_url_is_skipped(self):
        row = self.sight("https://x.invalid/a", "u1")
        self.store.mark_url_analyzed(row["id"], "reported")
        row = self.sight("https://x.invalid/a", "u2")
        ok, reason = pipeline._dedup_decision(self.cfg, self.store, row)
        self.assertFalse(ok)
        self.assertIn("duplicate_url", reason)

    def test_url_is_revisited_after_the_window(self):
        # Lure domains do swap payloads, so dedup must expire.
        row = self.sight("https://x.invalid/a", "u1")
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        self.store._conn.execute(
            "UPDATE urls SET last_analyzed_at = ? WHERE id = ?", (old, row["id"])
        )
        self.store._conn.commit()
        row = self.sight("https://x.invalid/a", "u2")
        ok, _ = pipeline._dedup_decision(self.cfg, self.store, row)
        self.assertTrue(ok)

    def test_sighted_but_never_analysed_is_retried(self):
        # A fetch failure must not permanently blacklist the URL.
        self.sight("https://x.invalid/a", "u1")
        row = self.sight("https://x.invalid/a", "u2")
        ok, _ = pipeline._dedup_decision(self.cfg, self.store, row)
        self.assertTrue(ok)

    def test_domain_cooldown_blocks_sibling_url(self):
        self.cfg.pipeline.domain_cooldown_hours = 24
        first = self.sight("https://evil.com/a", "u1")
        self.store.mark_url_analyzed(first["id"], "reported")
        second = self.sight("https://evil.com/b", "u2")
        ok, reason = pipeline._dedup_decision(self.cfg, self.store, second)
        self.assertFalse(ok)
        self.assertIn("domain_cooldown", reason)

    def test_domain_cooldown_disabled_by_default(self):
        first = self.sight("https://evil.com/a", "u1")
        self.store.mark_url_analyzed(first["id"], "reported")
        second = self.sight("https://evil.com/b", "u2")
        ok, _ = pipeline._dedup_decision(self.cfg, self.store, second)
        self.assertTrue(ok)

    def test_different_domains_are_independent(self):
        self.cfg.pipeline.domain_cooldown_hours = 24
        first = self.sight("https://evil.com/a", "u1")
        self.store.mark_url_analyzed(first["id"], "reported")
        other = self.sight("https://other.com/a", "u2")
        ok, _ = pipeline._dedup_decision(self.cfg, self.store, other)
        self.assertTrue(ok)


class TestRealWorldDistribution(DedupeTestCase):
    """Replay the duplicate distribution measured from a live urlscan poll."""

    DISTRIBUTION = [
        ("https://wwvv.info/mghirealty.com?c=%2F", 14),
        ("https://suiperior-laundry.com/woo/", 9),
        ("https://comericafixsrvc.com/", 6),
        ("https://uniparkpay.shop/", 6),
        ("https://moregoonsrue.com/", 3),
    ]

    def test_measured_distribution_collapses(self):
        uuid_n = 0
        analysed = 0
        for url, count in self.DISTRIBUTION:
            for _ in range(count):
                uuid_n += 1
                row = self.sight(url, f"uuid-{uuid_n}")
                ok, _ = pipeline._dedup_decision(self.cfg, self.store, row)
                if ok:
                    self.store.mark_url_analyzed(row["id"], "reported")
                    analysed += 1

        total = sum(c for _, c in self.DISTRIBUTION)
        self.assertEqual(total, 38)
        # 38 scan results collapse to 5 page fetches.
        self.assertEqual(analysed, 5)
        stats = self.store.dedup_stats()
        self.assertEqual(stats["unique_urls"], 5)
        self.assertEqual(stats["url_sightings"], 38)
        self.assertEqual(stats["fetches_avoided"], 33)


class TestCommandLevelDedup(DedupeTestCase):
    def test_command_hash_dedup_still_applies(self):
        # Layer 3: different URLs, identical payload (campaign spray).
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        rid = self.store.insert_discovered("urlscan", "u1", "https://a.invalid/")
        self.store.update(rid, command_sha256="a" * 64, status="submitted")
        hit = self.store.recent_submission_for_hash("a" * 64, since)
        self.assertIsNotNone(hit)

    def test_unrelated_hash_is_not_a_duplicate(self):
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        self.assertIsNone(self.store.recent_submission_for_hash("b" * 64, since))


class TestIndexesExist(DedupeTestCase):
    def test_dedup_columns_are_indexed(self):
        names = {
            r[0]
            for r in self.store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }
        for expected in ("idx_urls_domain", "idx_urls_apex", "idx_pages_url_norm", "idx_pages_sha"):
            self.assertIn(expected, names)

    def test_url_norm_is_unique(self):
        import sqlite3

        self.sight("https://x.invalid/a", "u1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._conn.execute(
                "INSERT INTO urls (url_norm, url_original, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?)",
                (normalize_url("https://x.invalid/a"), "x", now_iso(), now_iso()),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
