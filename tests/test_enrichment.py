"""Offline tests for passive infrastructure enrichment (enrichment.py).

The HTTP getter and the sleep are injected, so RDAP/CT/passive-DNS and every
failure mode (not_found, forbidden, 429->quota, timeout, not_configured) run
with no network and no real delay. Covers success, missing fields, failures,
deduplication, historical snapshots, cache/idempotency, dry-run, and provenance.
"""

import datetime
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from collection import CollectionStore  # noqa: E402
from config import EnrichmentConfig  # noqa: E402
import enrichment as en  # noqa: E402
from enrichment import HttpResult  # noqa: E402

RDAP_DOMAIN = {
    "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
               {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"}],
    "status": ["client transfer prohibited", "active"],
    "nameservers": [{"ldhName": "NS1.EVIL.COM"}, {"ldhName": "NS2.EVIL.COM"}],
    "entities": [
        {"roles": ["registrar"],
         "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "EvilRegistrar LLC"]]],
         "entities": [{"roles": ["abuse"],
                       "vcardArray": ["vcard", [["email", {}, "text", "abuse@evilreg.com"]]]}]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["org", {}, "text", "Privacy Inc"]]]},
    ],
}
RDAP_IP = {
    "cidr0_cidrs": [{"v4prefix": "45.33.32.0", "length": 19}],
    "name": "LINODE-US", "country": "US", "status": ["active"],
    "entities": [{"roles": ["abuse"],
                  "vcardArray": ["vcard", [["email", {}, "text", "abuse@linode.com"]]]}],
}
CT_ROWS = [
    {"id": 111, "issuer_name": "CN=R3", "common_name": "evil.com",
     "name_value": "evil.com\nwww.evil.com", "not_before": "2026-01-01", "not_after": "2026-04-01",
     "serial_number": "ab", "entry_timestamp": "2026-01-01T01:00:00"},
    {"id": 222, "issuer_name": "CN=R3", "common_name": "evil.com", "name_value": "evil.com",
     "not_before": "2026-02-01", "not_after": "2026-05-01", "serial_number": "cd",
     "entry_timestamp": "2026-02-01"},
]


def getter_for(mapping, calls=None, kwargs_sink=None):
    """Build a fake getter dispatching by substring of the URL. Accepts and
    (optionally) records the per-request options the providers forward."""
    def getter(url, headers=None, params=None, auth=None, timeout=20, **kwargs):
        if calls is not None:
            calls.append(url)
        if kwargs_sink is not None:
            kwargs_sink.append({"url": url, "timeout": timeout, **kwargs})
        for key, res in mapping.items():
            if key in url:
                return res if not callable(res) else res()
        return HttpResult("not_found", 404)
    return getter


def ok(data=None, text=None):
    return HttpResult("ok", 200, data=data, text=text)


class EnrichTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = CollectionStore(os.path.join(self.tmp, "c.db"))
        self.cfg = EnrichmentConfig(base_backoff=1.0)  # ct on, pdns off
        self.slept = []
        self.sleeper = lambda d: self.slept.append(d)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestRdapDomain(EnrichTestBase):
    def getter(self, calls=None):
        return getter_for({"/domain/": ok(RDAP_DOMAIN), "crt.sh": ok([])}, calls)

    def test_parses_and_commits_with_provenance(self):
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False,
                               lookups=["rdap"], getter=self.getter(), sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "ok")
        w = self.store.latest_whois("evil.com")
        self.assertEqual(w["registrar"], "EvilRegistrar LLC")
        self.assertEqual(w["created"], "2020-01-01T00:00:00Z")
        self.assertEqual(w["expires"], "2027-01-01T00:00:00Z")
        self.assertEqual(w["abuse_contact"], "abuse@evilreg.com")
        self.assertIn("NS1.EVIL.COM", w["name_servers"])
        self.assertEqual(w["registrant_org"], "Privacy Inc")
        self.assertIn("client transfer prohibited", w["statuses"])
        self.assertEqual(w["source"], "rdap:rdap.org")

    def test_missing_fields_do_not_crash_or_fabricate(self):
        res = en.enrich_entity(self.store, self.cfg, "bare.com", dry_run=False, lookups=["rdap"],
                               getter=getter_for({"/domain/": ok({"events": [
                                   {"eventAction": "registration", "eventDate": "2021-05-05"}]})}),
                               sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "ok")
        w = self.store.latest_whois("bare.com")
        self.assertEqual(w["created"], "2021-05-05")
        self.assertIsNone(w["registrar"])      # absent -> stays NULL, not invented
        self.assertIsNone(w["abuse_contact"])


class TestRdapIp(EnrichTestBase):
    def test_ip_cidr_org_country_abuse(self):
        res = en.enrich_entity(self.store, self.cfg, "45.33.32.156", dry_run=False,
                               lookups=["rdap"],
                               getter=getter_for({"/ip/": ok(RDAP_IP)}), sleeper=self.sleeper)
        self.assertEqual(res["entity_type"], "ip")
        w = self.store.latest_whois("45.33.32.156")
        self.assertEqual(w["kind"], "ip")
        self.assertEqual(w["cidr"], "45.33.32.0/19")
        self.assertEqual(w["registrant_org"], "LINODE-US")
        self.assertEqual(w["abuse_contact"], "abuse@linode.com")
        ip = self.store.ip("45.33.32.156")
        self.assertEqual(ip["as_org"], "LINODE-US")
        self.assertEqual(ip["country"], "US")


class TestCt(EnrichTestBase):
    def test_ct_rows_ingested_and_deduped(self):
        g = getter_for({"crt.sh": ok(CT_ROWS), "/domain/": ok({})})
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["ct"],
                         getter=g, sleeper=self.sleeper)
        rows = self.store.ct_logs_for("evil.com")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["source"], "ct:crt.sh")
        self.assertIn("www.evil.com", rows[0]["name_value"])
        # re-run with force: same CT ids must dedup, not duplicate
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["ct"],
                         force=True, getter=g, sleeper=self.sleeper)
        self.assertEqual(len(self.store.ct_logs_for("evil.com")), 2)

    def test_ct_accepts_jsonless_text_body(self):
        import json as _json
        g = getter_for({"crt.sh": HttpResult("ok", 200, data=None, text=_json.dumps(CT_ROWS))})
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["ct"],
                         getter=g, sleeper=self.sleeper)
        self.assertEqual(len(self.store.ct_logs_for("evil.com")), 2)


class TestPassiveDns(EnrichTestBase):
    def test_not_configured_is_explicit(self):
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["pdns"],
                               getter=getter_for({}), sleeper=self.sleeper)
        # pdns disabled by default -> lookup not selected at all
        self.assertEqual(res["lookups"], [])

    def test_configured_jsonl_ingested_as_dns(self):
        cfg = EnrichmentConfig(pdns_enabled=True, pdns_base="https://pdns.example/q",
                               pdns_provider="circl")
        jsonl = ('{"rrname":"evil.com","rrtype":"A","rdata":"45.33.32.156"}\n'
                 '{"rrname":"evil.com","rrtype":"A","rdata":"203.0.113.9"}\n')
        g = getter_for({"pdns.example": HttpResult("ok", 200, data=None, text=jsonl)})
        res = en.enrich_entity(self.store, cfg, "evil.com", dry_run=False, lookups=["pdns"],
                               getter=g, sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "ok")
        got = {(r["record_type"], r["value"]) for r in self.store._conn.execute(
            "SELECT record_type, value FROM dns_records WHERE source='pdns:circl'")}
        self.assertIn(("A", "45.33.32.156"), got)
        self.assertEqual(len([r for r in self.store._conn.execute(
            "SELECT 1 FROM dns_records WHERE source='pdns:circl'")]), 2)


class TestFailureModes(EnrichTestBase):
    def test_not_found_records_no_rows(self):
        res = en.enrich_entity(self.store, self.cfg, "gone.com", dry_run=False, lookups=["rdap"],
                               getter=getter_for({"/domain/": HttpResult("not_found", 404)}),
                               sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "not_found")
        self.assertIsNone(self.store.latest_whois("gone.com"))
        self.assertEqual(
            self.store.last_enrichment("domain", "gone.com", "rdap")["status"], "not_found")

    def test_forbidden(self):
        res = en.enrich_entity(self.store, self.cfg, "x.com", dry_run=False, lookups=["rdap"],
                               getter=getter_for({"/domain/": HttpResult("forbidden", 403)}),
                               sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "forbidden")

    def test_rate_limit_becomes_quota_after_backoff(self):
        calls = []
        g = getter_for({"/domain/": HttpResult("rate_limited", 429, retry_after=1)}, calls)
        res = en.enrich_entity(self.store, self.cfg, "x.com", dry_run=False, lookups=["rdap"],
                               getter=g, sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "quota")
        self.assertEqual(len([c for c in calls if "/domain/" in c]), 4)  # initial + 3 retries
        self.assertEqual(self.slept, [1, 1, 1])

    def test_timeout_exponential_backoff(self):
        g = getter_for({"/domain/": HttpResult("timeout", note="request_timeout")})
        res = en.enrich_entity(self.store, self.cfg, "x.com", dry_run=False, lookups=["rdap"],
                               getter=g, sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "timeout")
        self.assertEqual(self.slept, [1.0, 2.0, 4.0])  # base_backoff=1 -> 1,2,4


class TestDryRunAndCache(EnrichTestBase):
    def getter(self):
        return getter_for({"/domain/": ok(RDAP_DOMAIN), "crt.sh": ok(CT_ROWS)})

    def test_dry_run_writes_nothing(self):
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=True,
                               getter=self.getter(), sleeper=self.sleeper)
        self.assertTrue(res["dry_run"])
        self.assertIsNone(self.store.latest_whois("evil.com"))
        self.assertEqual(self.store.stats()["ct_logs"], 0)
        self.assertEqual(self.store.stats()["enrichment_runs"], 0)  # no cache markers either

    def test_commit_then_cached_is_idempotent(self):
        first = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False,
                                 getter=self.getter(), sleeper=self.sleeper)
        before = self.store.stats()
        second = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False,
                                  getter=self.getter(), sleeper=self.sleeper)
        after = self.store.stats()
        self.assertTrue(all(l["status"] == "ok" for l in first["lookups"]))
        self.assertTrue(all(l["status"] == "cached" for l in second["lookups"]))
        self.assertEqual(before, after)  # cache suppressed all re-writes

    def test_force_reruns_but_history_dedups(self):
        g = self.getter()
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, getter=g, sleeper=self.sleeper)
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, force=True, getter=g,
                         sleeper=self.sleeper)
        # identical RDAP content -> still one whois snapshot; CT dedups to 2
        self.assertEqual(len(self.store.whois_history("evil.com")), 1)
        self.assertEqual(len(self.store.ct_logs_for("evil.com")), 2)

    def test_history_grows_on_registration_change(self):
        g1 = getter_for({"/domain/": ok(RDAP_DOMAIN), "crt.sh": ok([])})
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                         getter=g1, sleeper=self.sleeper)
        changed = dict(RDAP_DOMAIN)
        changed["entities"] = [{"roles": ["registrar"],
                                "vcardArray": ["vcard", [["fn", {}, "text", "NEW REGISTRAR"]]]}]
        g2 = getter_for({"/domain/": ok(changed)})
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                         force=True, getter=g2, sleeper=self.sleeper)
        hist = self.store.whois_history("evil.com")
        self.assertEqual(len(hist), 2)  # prior snapshot preserved, not overwritten
        self.assertEqual(self.store.latest_whois("evil.com")["registrar"], "NEW REGISTRAR")


class TestSelectionScoping(EnrichTestBase):
    def test_only_source_keeps_page_deps_separate(self):
        # payload infra vs urlscan page dependency, distinguished by source
        self.store.upsert_domain("i-like-ele-phants.live", source="cape:76")
        self.store.upsert_domain("cdnjs.cloudflare.com", source="urlscan:abc")
        enriched = []
        g = getter_for({"/domain/": ok(RDAP_DOMAIN), "crt.sh": ok([])})
        def spy(store, cfg, entity, **kw):
            enriched.append(entity)
            return {"entity": entity, "lookups": []}
        orig = en.enrich_entity
        en.enrich_entity = spy
        try:
            en.enrich_many(self.store, self.cfg, which="domains", only_source="cape:76",
                           dry_run=True, getter=g, sleeper=self.sleeper)
        finally:
            en.enrich_entity = orig
        self.assertEqual(enriched, ["i-like-ele-phants.live"])  # cloudflare excluded


class TestResponseSizeCap(unittest.TestCase):
    def test_read_capped_stops_at_limit(self):
        body, trunc = en._read_capped([b"a" * 10, b"b" * 10], 100)
        self.assertEqual(len(body), 20)
        self.assertFalse(trunc)

    def test_read_capped_truncates_oversize(self):
        body, trunc = en._read_capped([b"x" * 50, b"x" * 60, b"x" * 60], 100)
        self.assertTrue(trunc)
        self.assertEqual(len(body), 100)  # never materialises beyond the cap


class TestRdapBootstrap(EnrichTestBase):
    BOOT_DNS = {"services": [[["live", "com"], ["https://rdap.registry.example/"]]]}
    BOOT_V4 = {"services": [[["45.33.0.0/16"], ["https://rdap.linode.example/"]]]}

    def test_domain_resolves_authoritative_registry(self):
        g = getter_for({"dns.json": ok(self.BOOT_DNS),
                        "rdap.registry.example": ok(RDAP_DOMAIN)})
        res = en.enrich_entity(self.store, self.cfg, "evil.live", dry_run=False, lookups=["rdap"],
                               getter=g, sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "ok")
        # provenance reflects the authoritative registry, not rdap.org
        self.assertEqual(self.store.latest_whois("evil.live")["source"], "rdap:rdap.registry.example")

    def test_ip_resolves_authoritative_registry(self):
        g = getter_for({"ipv4.json": ok(self.BOOT_V4), "rdap.linode.example": ok(RDAP_IP)})
        en.enrich_entity(self.store, self.cfg, "45.33.32.156", dry_run=False, lookups=["rdap"],
                         getter=g, sleeper=self.sleeper)
        self.assertEqual(self.store.latest_whois("45.33.32.156")["source"], "rdap:rdap.linode.example")

    def test_falls_back_to_rdap_org_when_bootstrap_unavailable(self):
        # dns.json 404s -> no bootstrap entry -> fall back to the configured base
        g = getter_for({"dns.json": HttpResult("not_found", 404), "/domain/": ok(RDAP_DOMAIN)})
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                               getter=g, sleeper=self.sleeper)
        self.assertEqual(self.store.latest_whois("evil.com")["source"], "rdap:rdap.org")
        self.assertEqual(res["lookups"][0]["note"], "bootstrap_fallback")

    def test_bootstrap_longest_suffix_match(self):
        bs = en.RdapBootstrap(self.cfg)
        g = getter_for({"dns.json": ok({"services": [
            [["uk"], ["https://a/"]], [["co.uk"], ["https://b/"]]]})})
        # the more specific co.uk must win over uk
        self.assertEqual(bs.domain_base("x.co.uk", g, self.sleeper), "https://b/")


class TestMalformedRdap(EnrichTestBase):
    def test_200_bad_json_is_error_not_empty(self):
        # a 200 whose body is not a JSON object -> transient error, NOT "empty"
        g = getter_for({"/domain/": HttpResult("ok", 200, data=None, text="<html>nope</html>")})
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                               getter=g, sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "error")
        self.assertIsNone(self.store.latest_whois("evil.com"))


class TestTransientCacheTtl(EnrichTestBase):
    def _insert_run(self, etype, entity, lookup, status, hours_ago):
        ran = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(hours=hours_ago)).isoformat()
        self.store._conn.execute(
            "INSERT INTO enrichment_runs (entity_type, entity_value, lookup, status, detail, ran_at)"
            " VALUES (?,?,?,?,?,?)", (etype, entity, lookup, status, None, ran))
        self.store._conn.commit()

    def test_quota_retried_after_transient_window(self):
        # a 429 recorded 2h ago, transient_ttl=1h -> no longer fresh -> re-enrich
        self.cfg.transient_ttl_hours = 1.0
        self._insert_run("domain", "evil.com", "rdap", "quota", hours_ago=2)
        self.assertFalse(en._is_fresh(self.store, "domain", "evil.com", "rdap", self.cfg))

    def test_timeout_is_transient_not_week_long(self):
        self.cfg.transient_ttl_hours = 1.0
        self._insert_run("domain", "evil.com", "rdap", "timeout", hours_ago=2)
        self.assertFalse(en._is_fresh(self.store, "domain", "evil.com", "rdap", self.cfg))

    def test_success_cached_for_full_ttl(self):
        # an 'ok' 2h ago, cache_ttl=168h -> still fresh -> skip
        self._insert_run("domain", "evil.com", "rdap", "ok", hours_ago=2)
        self.assertTrue(en._is_fresh(self.store, "domain", "evil.com", "rdap", self.cfg))

    def test_quota_still_fresh_within_transient_window(self):
        self.cfg.transient_ttl_hours = 6.0
        self._insert_run("domain", "evil.com", "rdap", "quota", hours_ago=2)
        self.assertTrue(en._is_fresh(self.store, "domain", "evil.com", "rdap", self.cfg))


class TestOnlySourceBoundary(EnrichTestBase):
    def test_cape76_does_not_match_cape760(self):
        self.store.upsert_domain("payload.live", source="cape:76")
        self.store.upsert_domain("sibling.live", source="cape:760")        # different task
        self.store.upsert_domain("cdn.cloudflare.com", source="urlscan:abc")
        got = {r["fqdn"] for r in self.store.list_domains("cape:76")}
        self.assertEqual(got, {"payload.live"})                             # NOT sibling.live

    def test_bare_prefix_matches_all_segments(self):
        self.store.upsert_domain("a.live", source="cape:76")
        self.store.upsert_domain("b.live", source="cape:760")
        got = {r["fqdn"] for r in self.store.list_domains("cape")}
        self.assertEqual(got, {"a.live", "b.live"})

    def test_ips_same_boundary_rule(self):
        self.store.upsert_ip("8.8.8.8", source="cape:76")
        self.store.upsert_ip("9.9.9.9", source="cape:760")
        got = {r["ip"] for r in self.store.list_ips("cape:76")}
        self.assertEqual(got, {"8.8.8.8"})


def ok_raw(obj):
    """An 'ok' HttpResult carrying parsed data, text, AND exact raw bytes."""
    blob = json.dumps(obj).encode("utf-8")
    return HttpResult("ok", 200, data=obj, text=blob.decode("utf-8"), raw_bytes=blob)


class TestRdapEvidence(EnrichTestBase):
    def setUp(self):
        super().setUp()
        self.cfg.rdap_raw_dir = os.path.join(self.tmp, "rdap_raw")
        self.rdap_payload = RDAP_DOMAIN
        self.raw_blob = json.dumps(self.rdap_payload).encode("utf-8")
        self.raw_sha = hashlib.sha256(self.raw_blob).hexdigest()

    def _getter(self, payload=None):
        return getter_for({"/domain/": ok_raw(payload if payload is not None else self.rdap_payload)})

    def test_evidence_written_and_linked(self):
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                         getter=self._getter(), sleeper=self.sleeper)
        ev = self.store.rdap_evidence_for("evil.com")
        self.assertEqual(len(ev), 1)
        row = ev[0]
        # entity / provider / endpoint / time all linked
        self.assertEqual(row["entity"], "evil.com")
        self.assertEqual(row["provider"], "rdap:rdap.org")
        self.assertIn("/domain/evil.com", row["endpoint"])
        self.assertTrue(row["first_seen"])
        # hash of the stored raw bytes matches
        self.assertEqual(row["raw_sha256"], self.raw_sha)
        self.assertEqual(row["byte_len"], len(self.raw_blob))
        # raw bytes round-trip EXACTLY from the on-disk file
        with open(row["raw_path"], "rb") as fh:
            disk = fh.read()
        self.assertEqual(disk, self.raw_blob)
        self.assertEqual(hashlib.sha256(disk).hexdigest(), row["raw_sha256"])
        # traceable to the normalized whois row (same lookup)
        w = self.store.latest_whois("evil.com")
        self.assertEqual(row["whois_raw_sha256"], w["raw_sha256"])

    def test_repeated_identical_lookup_dedups(self):
        g = self._getter()
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                         getter=g, sleeper=self.sleeper)
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                         force=True, getter=g, sleeper=self.sleeper)
        ev = self.store.rdap_evidence_for("evil.com")
        self.assertEqual(len(ev), 1)              # one row...
        self.assertEqual(ev[0]["times_seen"], 2)  # ...with a bumped counter

    def test_changed_body_keeps_history(self):
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                         getter=self._getter(), sleeper=self.sleeper)
        changed = dict(RDAP_DOMAIN)
        changed["status"] = ["active"]            # different body -> different raw hash
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                         force=True, getter=self._getter(changed), sleeper=self.sleeper)
        self.assertEqual(len(self.store.rdap_evidence_for("evil.com")), 2)

    def test_failure_records_no_evidence(self):
        en.enrich_entity(self.store, self.cfg, "gone.com", dry_run=False, lookups=["rdap"],
                         getter=getter_for({"/domain/": HttpResult("not_found", 404)}),
                         sleeper=self.sleeper)
        self.assertEqual(self.store.rdap_evidence_for("gone.com"), [])

    def test_invalid_json_records_no_evidence(self):
        # a 200 that isn't JSON -> bad_json -> no whois, no evidence
        en.enrich_entity(self.store, self.cfg, "bad.com", dry_run=False, lookups=["rdap"],
                         getter=getter_for({"/domain/": HttpResult("bad_json", 200,
                                                                   text="<html/>", note="non_json_body")}),
                         sleeper=self.sleeper)
        self.assertEqual(self.store.rdap_evidence_for("bad.com"), [])
        self.assertIsNone(self.store.latest_whois("bad.com"))

    def test_dry_run_writes_no_evidence(self):
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=True, lookups=["rdap"],
                         getter=self._getter(), sleeper=self.sleeper)
        self.assertEqual(self.store.rdap_evidence_for("evil.com"), [])
        self.assertFalse(os.path.isdir(self.cfg.rdap_raw_dir))

    def test_oversize_body_recorded_without_file(self):
        self.cfg.rdap_max_raw_bytes = 10        # tiny cap
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap"],
                         getter=self._getter(), sleeper=self.sleeper)
        ev = self.store.rdap_evidence_for("evil.com")
        self.assertEqual(len(ev), 1)
        self.assertIsNone(ev[0]["raw_path"])     # body too big to persist...
        self.assertEqual(ev[0]["raw_sha256"], self.raw_sha)  # ...but still hashed+sized
        self.assertEqual(ev[0]["byte_len"], len(self.raw_blob))

    def test_ip_evidence_kind(self):
        en.enrich_entity(self.store, self.cfg, "45.33.32.156", dry_run=False, lookups=["rdap"],
                         getter=getter_for({"/ip/": ok_raw(RDAP_IP)}), sleeper=self.sleeper)
        ev = self.store.rdap_evidence_for("45.33.32.156")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["kind"], "ip")


class TestEvidenceOnlyBackfill(EnrichTestBase):
    """Backfill raw RDAP evidence WITHOUT mutating the normalized whois row."""

    def setUp(self):
        super().setUp()
        self.cfg.rdap_raw_dir = os.path.join(self.tmp, "rdap_raw")
        self.getter = getter_for({"/domain/": ok_raw(RDAP_DOMAIN)})
        self.bs = en.RdapBootstrap(self.cfg)

    def _seed_existing_whois(self, entity="evil.com", payload=None):
        """Create the pre-existing whois row exactly as a prior enrichment commit
        would have (same parse -> same canonical hash)."""
        g = getter_for({"/domain/": ok_raw(payload if payload is not None else RDAP_DOMAIN)})
        oc = en.rdap_domain(entity, self.cfg, g, self.sleeper, bootstrap=self.bs)
        self.store.record_whois(entity, kind="domain", source=oc.source, **oc.whois)
        return dict(self.store.latest_whois(entity))

    def test_hash_basis_reused_exactly(self):
        # the hash computed from an outcome equals the hash record_whois stored
        oc = en.rdap_domain("evil.com", self.cfg, self.getter, self.sleeper, bootstrap=self.bs)
        self.store.record_whois("evil.com", kind="domain", source=oc.source, **oc.whois)
        stored = self.store.latest_whois("evil.com")["raw_sha256"]
        self.assertEqual(en._whois_hash_for_outcome(self.store, oc), stored)

    def test_match_writes_evidence_and_leaves_whois_byte_for_byte(self):
        before = self._seed_existing_whois("evil.com")
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False,
                               evidence_only=True, getter=self.getter, sleeper=self.sleeper)
        look = res["lookups"][0]
        self.assertTrue(res["evidence_only"])
        self.assertEqual(look["status"], "evidence_written")
        self.assertTrue(look["evidence_written"])
        # evidence present and linked to the existing row
        ev = self.store.rdap_evidence_for("evil.com")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["whois_raw_sha256"], before["raw_sha256"])
        # the raw evidence round-trips + hash matches
        with open(ev[0]["raw_path"], "rb") as fh:
            disk = fh.read()
        self.assertEqual(hashlib.sha256(disk).hexdigest(), ev[0]["raw_sha256"])
        # the whois row is byte-for-byte / logically UNCHANGED (incl times_seen/last_seen)
        after = dict(self.store.latest_whois("evil.com"))
        self.assertEqual(after, before)
        self.assertEqual(len(self.store.whois_history("evil.com")), 1)

    def test_mismatch_writes_neither_evidence_nor_whois(self):
        before = self._seed_existing_whois("evil.com")
        changed = dict(RDAP_DOMAIN); changed["status"] = ["active"]   # different -> different hash
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, evidence_only=True,
                               getter=getter_for({"/domain/": ok_raw(changed)}), sleeper=self.sleeper)
        look = res["lookups"][0]
        self.assertEqual(look["status"], "evidence_skipped_stale_whois")
        self.assertFalse(look["evidence_written"])
        self.assertEqual(self.store.rdap_evidence_for("evil.com"), [])
        self.assertEqual(dict(self.store.latest_whois("evil.com")), before)   # untouched
        self.assertEqual(len(self.store.whois_history("evil.com")), 1)        # no new snapshot

    def test_no_existing_row_skips(self):
        res = en.enrich_entity(self.store, self.cfg, "nowhois.com", dry_run=False, evidence_only=True,
                               getter=self.getter, sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "evidence_skipped_stale_whois")
        self.assertEqual(self.store.rdap_evidence_for("nowhois.com"), [])
        self.assertIsNone(self.store.latest_whois("nowhois.com"))

    def test_dry_run_match_writes_nothing(self):
        before = self._seed_existing_whois("evil.com")
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=True, evidence_only=True,
                               getter=self.getter, sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "match")
        self.assertFalse(res["lookups"][0]["evidence_written"])
        self.assertEqual(self.store.rdap_evidence_for("evil.com"), [])
        self.assertEqual(dict(self.store.latest_whois("evil.com")), before)

    def test_fetch_failure_skips(self):
        self._seed_existing_whois("evil.com")
        res = en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, evidence_only=True,
                               getter=getter_for({"/domain/": HttpResult("not_found", 404)}),
                               sleeper=self.sleeper)
        self.assertEqual(res["lookups"][0]["status"], "not_found")
        self.assertFalse(res["lookups"][0]["evidence_written"])
        self.assertEqual(self.store.rdap_evidence_for("evil.com"), [])


class TestShowEvidence(EnrichTestBase):
    """Read-only inspection of stored RDAP evidence (inspect_evidence / --show-evidence)."""

    def setUp(self):
        super().setUp()
        self.cfg.rdap_raw_dir = os.path.join(self.tmp, "rdap_raw")
        os.makedirs(self.cfg.rdap_raw_dir, exist_ok=True)
        self.bs = en.RdapBootstrap(self.cfg)

    def _seed(self, entity="evil.com", *, write_file=True, byte_len=None, sha=None,
              whois_hash=None, make_whois=True):
        """Seed a whois row + an rdap_evidence row (+ optional raw file) for tests."""
        g = getter_for({"/domain/": ok_raw(RDAP_DOMAIN)})
        oc = en.rdap_domain(entity, self.cfg, g, self.sleeper, bootstrap=self.bs)
        wh = None
        if make_whois:
            self.store.record_whois(entity, kind="domain", source=oc.source, **oc.whois)
            wh = self.store.latest_whois(entity)["raw_sha256"]
        raw = oc.raw
        real_sha = hashlib.sha256(raw).hexdigest()
        path = None
        if write_file:
            path = os.path.join(self.cfg.rdap_raw_dir, real_sha + ".json")
            with open(path, "wb") as fh:
                fh.write(raw)
        self.store.record_rdap_evidence(
            entity, kind="domain", provider=oc.source, endpoint=oc.endpoint,
            raw_sha256=sha if sha is not None else real_sha,
            byte_len=byte_len if byte_len is not None else len(raw),
            raw_path=path, whois_raw_sha256=whois_hash if whois_hash is not None else wh)
        return {"raw": raw, "real_sha": real_sha, "whois_hash": wh, "path": path}

    def test_valid_evidence_verifies_clean(self):
        self._seed("evil.com")
        out = en.inspect_evidence(self.store, "evil.com")
        self.assertEqual(out["count"], 1)
        item = out["evidence"][0]
        self.assertEqual(item["file_status"], "ok")
        self.assertTrue(item["size_ok"] and item["sha_ok"])
        self.assertTrue(item["whois_linked"])
        self.assertTrue(item["whois_hash_matches_evidence"])
        self.assertTrue(item["whois_stored_hash_ok"])
        self.assertEqual(item["actual_sha256"], item["stored_sha256"])

    def test_missing_file_reported(self):
        s = self._seed("evil.com", write_file=False)
        # record_rdap_evidence stored a raw_path of None (write_file False) -> metadata_only;
        # instead point at a non-existent path to exercise 'missing'
        self.store._conn.execute("UPDATE rdap_evidence SET raw_path=? WHERE entity='evil.com'",
                                 (os.path.join(self.cfg.rdap_raw_dir, "does_not_exist.json"),))
        self.store._conn.commit()
        item = en.inspect_evidence(self.store, "evil.com")["evidence"][0]
        self.assertEqual(item["file_status"], "missing")

    def test_metadata_only_when_no_path(self):
        self._seed("evil.com", write_file=False)  # raw_path stays None
        item = en.inspect_evidence(self.store, "evil.com")["evidence"][0]
        self.assertEqual(item["file_status"], "metadata_only")

    def test_byte_length_mismatch(self):
        self._seed("evil.com", byte_len=999999)  # wrong stored length
        item = en.inspect_evidence(self.store, "evil.com")["evidence"][0]
        self.assertFalse(item["size_ok"])
        self.assertEqual(item["file_status"], "mismatch")

    def test_raw_sha_mismatch(self):
        self._seed("evil.com", sha="0" * 64)  # wrong stored hash
        item = en.inspect_evidence(self.store, "evil.com")["evidence"][0]
        self.assertFalse(item["sha_ok"])
        self.assertEqual(item["file_status"], "mismatch")

    def test_absent_whois_linkage(self):
        self._seed("evil.com", whois_hash="deadbeef", make_whois=True)
        item = en.inspect_evidence(self.store, "evil.com")["evidence"][0]
        self.assertFalse(item["whois_linked"])
        self.assertIsNone(item["whois_snapshot_hash"])
        self.assertFalse(item["whois_hash_matches_evidence"])

    def test_whois_stored_hash_tamper_detected(self):
        # evidence links to a whois row whose stored raw_sha256 no longer matches
        # the canonical hash of its own fields (simulated tamper)
        self._seed("evil.com")
        self.store._conn.execute(
            "UPDATE whois_records SET registrar='TAMPERED' WHERE target='evil.com'")
        self.store._conn.commit()
        item = en.inspect_evidence(self.store, "evil.com")["evidence"][0]
        # link still resolves by the OLD hash, but recomputed != stored -> flagged
        self.assertTrue(item["whois_linked"])
        self.assertFalse(item["whois_stored_hash_ok"])

    def test_inspect_performs_no_writes(self):
        self._seed("evil.com")
        before = self.store.stats()
        before_ev = [dict(r) for r in self.store.rdap_evidence_for("evil.com")]
        en.inspect_evidence(self.store, "evil.com")
        en.inspect_evidence(self.store, "evil.com")  # twice, to be sure
        self.assertEqual(self.store.stats(), before)
        self.assertEqual([dict(r) for r in self.store.rdap_evidence_for("evil.com")], before_ev)

    def test_cli_show_evidence_no_writes_no_enrichment(self):
        import io, contextlib
        self._seed("evil.com")
        before = self.store.stats()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = en.main(["evil.com", "--show-evidence", "--db", self.store.db_path])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("show_evidence", payload)
        self.assertEqual(payload["show_evidence"]["evidence"][0]["file_status"], "ok")
        # reopening confirms nothing changed (no enrichment, no writes)
        from collection import CollectionStore as CS
        reopened = CS(self.store.db_path)
        self.assertEqual(reopened.stats(), before)
        reopened.close()


class TestLimitWiring(EnrichTestBase):
    def test_providers_forward_configured_limits(self):
        self.cfg.max_response_bytes = 4242
        self.cfg.max_redirects = 2
        sink = []
        g = getter_for({"/domain/": ok(RDAP_DOMAIN), "crt.sh": ok([]), "dns.json": ok({})},
                       kwargs_sink=sink)
        en.enrich_entity(self.store, self.cfg, "evil.com", dry_run=False, lookups=["rdap", "ct"],
                         getter=g, sleeper=self.sleeper)
        self.assertTrue(sink, "getter was never called")
        for call in sink:
            self.assertEqual(call["max_bytes"], 4242)     # cfg, not the module default
            self.assertEqual(call["max_redirects"], 2)
            self.assertEqual(call["timeout"], self.cfg.timeout)

    def test_pdns_opts_out_of_json_expectation(self):
        cfg = EnrichmentConfig(pdns_enabled=True, pdns_base="https://pdns.example/q",
                               pdns_provider="circl")
        sink = []
        g = getter_for({"pdns.example": HttpResult("ok", 200, data=None, text="")},
                       kwargs_sink=sink)
        en.enrich_entity(self.store, cfg, "evil.com", dry_run=False, lookups=["pdns"],
                         getter=g, sleeper=self.sleeper)
        self.assertEqual([c["expect_json"] for c in sink], [False])


class _FakeResp:
    """A streamed response stand-in. `raise_at` lets a chunk read raise mid-stream."""
    def __init__(self, status=200, chunks=(b"{}",), headers=None, encoding="utf-8",
                 raise_at=None):
        self.status_code = status
        self._chunks = list(chunks)
        self.headers = headers or {}
        self.encoding = encoding
        self.url = ""
        self.closed = False
        self._raise_at = raise_at

    def iter_content(self, n):
        for i, c in enumerate(self._chunks):
            if self._raise_at is not None and i == self._raise_at:
                raise self._raise_at_exc
            yield c

    def close(self):
        self.closed = True


class _FakeSession:
    """Stand-in for requests.Session recording each GET (url, headers, auth)."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.log = []
        self.max_redirects = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.closed = True
        return False

    def get(self, url, headers=None, params=None, auth=None, timeout=None, stream=None,
            allow_redirects=None):
        self.log.append({"url": url, "headers": dict(headers or {}), "auth": auth,
                         "allow_redirects": allow_redirects})
        assert self._responses, f"unexpected extra request to {url}"
        return self._responses.pop(0)


def _redirect(status, location):
    return _FakeResp(status, chunks=(), headers={"Location": location})


class TestGetterHardening(unittest.TestCase):
    """Drive the real requests_getter with a mocked `requests` (offline). Proves
    manual redirect validation happens BEFORE the next host is contacted, plus
    size-cap / mid-stream-exception / classification behaviour."""

    def run_getter(self, responses, url="https://rdap.example/domain/x", **kw):
        import types
        import requests as real_requests
        sess = _FakeSession(responses)
        fake = types.SimpleNamespace(
            Session=lambda: sess,
            Timeout=real_requests.Timeout,
            TooManyRedirects=real_requests.TooManyRedirects,
            RequestException=real_requests.RequestException,
        )
        import unittest.mock as mock
        with mock.patch.dict(sys.modules, {"requests": fake}):
            res = en.requests_getter(url, **kw)
        return res, sess

    def test_single_request_no_duplicate(self):
        r, sess = self.run_getter([_FakeResp(200, chunks=(b'{"ok":1}',))])
        self.assertEqual(r.status, "ok")
        self.assertEqual(len(sess.log), 1)                 # exactly one request
        self.assertTrue(sess.closed)                       # session closed

    def test_downgrade_blocked_BEFORE_contacting_http(self):
        # 302 https -> http. The HTTP destination must NEVER be requested.
        r, sess = self.run_getter(
            [_redirect(302, "http://downgraded.example/x"),
             _FakeResp(200, chunks=(b'{"a":1}',))],          # would be used only if followed
            url="https://rdap.example/domain/x")
        self.assertEqual(r.status, "request_failed")
        self.assertEqual(r.note, "insecure_redirect")
        self.assertEqual([c["url"] for c in sess.log], ["https://rdap.example/domain/x"])
        self.assertFalse(any(c["url"].startswith("http://") for c in sess.log))

    def test_bad_redirect_scheme_rejected(self):
        r, sess = self.run_getter([_redirect(302, "file:///etc/passwd")])
        self.assertEqual((r.status, r.note), ("request_failed", "bad_redirect_scheme"))
        self.assertEqual(len(sess.log), 1)

    def test_redirect_loop_detected(self):
        r, sess = self.run_getter([_redirect(302, "https://rdap.example/domain/x")])
        self.assertEqual((r.status, r.note), ("request_failed", "redirect_loop"))
        self.assertEqual(len(sess.log), 1)

    def test_redirect_limit_enforced(self):
        # three successive https redirects with max_redirects=2 -> stop before the 4th hop
        r, sess = self.run_getter(
            [_redirect(302, "https://a.example/1"),
             _redirect(302, "https://b.example/2"),
             _redirect(302, "https://c.example/3"),
             _FakeResp(200, chunks=(b"{}",))],
            max_redirects=2)
        self.assertEqual((r.status, r.note), ("request_failed", "too_many_redirects"))
        self.assertEqual(len(sess.log), 3)                 # origin + 2 follows, never the 4th

    def test_credentials_dropped_on_cross_host_redirect(self):
        r, sess = self.run_getter(
            [_redirect(302, "https://other.example/x"), _FakeResp(200, chunks=(b"{}",))],
            url="https://rdap.example/domain/x",
            headers={"Authorization": "Bearer SECRET", "X-Keep": "1"},
            auth=("user", "pass"))
        self.assertEqual(r.status, "ok")
        first, second = sess.log[0], sess.log[1]
        self.assertEqual(first["auth"], ("user", "pass"))
        self.assertIn("Authorization", first["headers"])
        self.assertIsNone(second["auth"])                  # basic auth not forwarded
        self.assertNotIn("Authorization", second["headers"])  # header stripped cross-host
        self.assertIn("X-Keep", second["headers"])         # non-sensitive header retained

    def test_credentials_dropped_on_same_host_different_port(self):
        # same hostname, different port => different trust boundary => drop creds
        r, sess = self.run_getter(
            [_redirect(302, "https://rdap.example:8443/x"), _FakeResp(200, chunks=(b"{}",))],
            url="https://rdap.example/domain/x",
            headers={"Authorization": "Bearer SECRET"}, auth=("u", "p"))
        self.assertEqual(r.status, "ok")
        self.assertIsNone(sess.log[1]["auth"])
        self.assertNotIn("Authorization", sess.log[1]["headers"])

    def test_scheme_relative_cross_host_downgrade_blocked(self):
        # scheme-relative Location resolves to https (origin scheme) -> cross-host, creds dropped
        r, sess = self.run_getter(
            [_redirect(302, "//other.example/x"), _FakeResp(200, chunks=(b"{}",))],
            url="https://rdap.example/domain/x",
            headers={"Authorization": "x"}, auth=("u", "p"))
        self.assertEqual(r.status, "ok")
        self.assertEqual(sess.log[1]["url"], "https://other.example/x")
        self.assertIsNone(sess.log[1]["auth"])

    def test_default_port_equals_bare_host_keeps_creds(self):
        # explicit :443 is the same effective origin as the bare host -> creds kept
        r, sess = self.run_getter(
            [_redirect(302, "https://rdap.example:443/x/v2"), _FakeResp(200, chunks=(b"{}",))],
            url="https://rdap.example/domain/x", auth=("u", "p"))
        self.assertEqual(r.status, "ok")
        self.assertEqual(sess.log[1]["auth"], ("u", "p"))

    def test_credentials_kept_on_same_host_redirect(self):
        r, sess = self.run_getter(
            [_redirect(302, "https://rdap.example/domain/x/v2"), _FakeResp(200, chunks=(b"{}",))],
            url="https://rdap.example/domain/x",
            headers={"Authorization": "Bearer SECRET"}, auth=("u", "p"))
        self.assertEqual(r.status, "ok")
        self.assertEqual(sess.log[1]["auth"], ("u", "p"))
        self.assertIn("Authorization", sess.log[1]["headers"])

    def test_oversize_streamed_stops_without_content_length(self):
        big = [b"x" * 1000] * 50          # 50 KB streamed in chunks, no Content-Length
        r, _ = self.run_getter([_FakeResp(200, chunks=big)], max_bytes=1000)
        self.assertEqual((r.status, r.note), ("http_error", "oversize_response"))

    def test_mid_stream_exception_classified(self):
        import requests as real_requests
        resp = _FakeResp(200, chunks=(b"{", b"bad", b"more"), raise_at=1)
        resp._raise_at_exc = real_requests.exceptions.ChunkedEncodingError("boom")
        r, _ = self.run_getter([resp])
        self.assertEqual(r.status, "request_failed")        # not an unhandled crash

    def test_ok_parses_json(self):
        r, _ = self.run_getter([_FakeResp(200, chunks=(b'{"a":1}',))])
        self.assertEqual((r.status, r.data), ("ok", {"a": 1}))

    def test_bad_json_200_classified(self):
        r, _ = self.run_getter([_FakeResp(200, chunks=(b"<html>no</html>",))])
        self.assertEqual(r.status, "bad_json")

    def test_non_json_ok_when_not_expecting_json(self):
        r, _ = self.run_getter([_FakeResp(200, chunks=(b"line1\nline2",))], expect_json=False)
        self.assertEqual((r.status, r.text), ("ok", "line1\nline2"))


if __name__ == "__main__":
    unittest.main()
