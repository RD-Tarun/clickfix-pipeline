"""Centralised ClickFix pattern library.

Modelled on ClickGrab's `CommonPatterns` approach (MHaggis/ClickGrab,
Apache-2.0): keeping the campaign-specific signatures in one place, separate
from the extraction machinery, so they can be retuned as lure wording drifts
without touching decode logic.

Two distinct jobs live here:

  * `normalize_for_detection()` -- fold homoglyphs and invisible characters so
    that scoring and marker matching see the ASCII a defender expects. This is
    for DETECTION ONLY. The command submitted to CAPE keeps its original
    bytes: a lure that really does paste Cyrillic characters produces a
    command that really does fail that way in the guest, and the report should
    reflect that truthfully.

  * `clickfix_instruction_score()` -- confirm the page is actually a ClickFix
    lure by looking for the Win+R / Ctrl+V / "paste" instruction sequence,
    which is far more reliable than matching on page title.
"""

import re
from typing import List, Tuple

# Cyrillic/Greek/Armenian lookalikes used to break naive keyword matching --
# "роwershell" with a Cyrillic 'о' and 'р' reads identically to a victim but
# matches none of our markers.
HOMOGLYPHS = {
    "А": "A", "Α": "A", "а": "a", "α": "a", "ɑ": "a",
    "В": "B", "Β": "B", "Ь": "b", "Ƅ": "b",
    "С": "C", "Ϲ": "C", "с": "c",
    "Ѕ": "S", "ѕ": "s",
    "Е": "E", "Ε": "E", "е": "e",
    "Н": "H", "Η": "H",
    "І": "I", "Ι": "I", "Ⅰ": "I", "і": "i",
    "К": "K", "Κ": "K",
    "М": "M", "Μ": "M",
    "О": "O", "Ο": "O", "о": "o", "ο": "o", "օ": "o",
    "Р": "P", "Ρ": "P", "р": "p", "ρ": "p",
    "Т": "T", "Τ": "T",
    "Х": "X", "Χ": "X", "х": "x",
    "У": "Y", "Υ": "Y", "у": "y",
    "Ⅴ": "V", "ν": "v", "Ѵ": "V",
    "ⅅ": "D",
    "н": "n", "η": "n", "ո": "n",
    "г": "r", "ɾ": "r",
    "һ": "h",
    "ɡ": "g",
    "ł": "l", "Ӏ": "l",
    "є": "e",
    "ӏ": "l",
}

# Invisible characters used to make the visible preview differ from the
# clipboard payload, or simply to break substring matching.
_INVISIBLE_RE = re.compile(
    r"[​‌‍‎‏⁠⁡⁢⁣⁤"
    r"﻿­᠎؜ᅟᅠㅤﾠ]"
)

# The social-engineering instruction sequence. Presence of these is the single
# most reliable confirmation that a page is a ClickFix lure rather than a
# genuine captcha.
CLICKFIX_INSTRUCTION_PATTERNS: Tuple[Tuple[str, str, int], ...] = (
    (r"\bwin(?:dows)?\s*(?:key)?\s*\+\s*r\b", "win_r", 3),
    (r"\b(?:press|hit|tap)\s+(?:the\s+)?windows\s+(?:logo\s+)?key", "win_key", 2),
    (r"\bctrl\s*\+\s*v\b", "ctrl_v", 2),
    (r"\bcommand\s*\+\s*v\b", "cmd_v", 2),
    (r"\b(?:press|hit)\s+ctrl\s*\+\s*v\b", "ctrl_v_press", 2),
    (r"\bpaste\b.{0,40}\b(?:run|terminal|powershell|dialog|box)\b", "paste_run", 2),
    (r"\b(?:run|terminal)\s+dialog\b", "run_dialog", 2),
    (r"\bpress\s+enter\b", "press_enter", 1),
    (r"\bverification\s+(?:code|id|step)\b", "verification_step", 1),
    (r"\bi\s*am\s*not\s*a\s*robot\b", "not_a_robot", 1),
    (r"\bverify\s+(?:you\s+are\s+)?(?:a\s+)?human\b", "verify_human", 1),
    (r"\bproof\s+you\s+are\s+human\b", "proof_human", 1),
    (r"&#\d{2,5};", "html_entity_obfuscation", 1),
)

_COMPILED_INSTRUCTIONS = tuple(
    (re.compile(pat, re.IGNORECASE | re.DOTALL), name, weight)
    for pat, name, weight in CLICKFIX_INSTRUCTION_PATTERNS
)

# javascript-obfuscator style identifiers, common in packed lure bundles.
OBFUSCATED_IDENTIFIER_RE = re.compile(r"_0x[a-f0-9]{2,8}")


def strip_invisible(text: str) -> str:
    return _INVISIBLE_RE.sub("", text)


def fold_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def normalize_for_detection(text: str) -> str:
    """Fold a string to the ASCII form a defender's keyword list expects.

    DETECTION ONLY -- never write the result of this to the .ps1 that gets
    submitted to the sandbox.
    """
    return fold_homoglyphs(strip_invisible(text))


def contains_homoglyphs(text: str) -> bool:
    return any(ch in HOMOGLYPHS for ch in text)


def clickfix_instruction_score(html: str) -> Tuple[int, List[str]]:
    """Score how strongly a page reads as a ClickFix lure.

    Returns (score, matched_pattern_names). Used to distinguish a real lure
    from an ordinary captcha page when the extracted command is weak.
    """
    normalized = normalize_for_detection(html)
    score = 0
    hits: List[str] = []
    for regex, name, weight in _COMPILED_INSTRUCTIONS:
        if regex.search(normalized):
            score += weight
            hits.append(name)
    return score, hits


def looks_obfuscated(text: str) -> bool:
    """Heuristic: packed/obfuscated JS bundle rather than a hand-written lure."""
    return len(OBFUSCATED_IDENTIFIER_RE.findall(text)) >= 3
