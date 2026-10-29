"""Heuristic scoring + human-review gate for extracted commands.

CAPE's sandbox is where the command actually runs, so this stage isn't
about making the command "safe" -- it's about (a) filtering out extraction
noise/false positives before spending an analysis slot, and (b) requiring a
human look at anything the heuristics aren't confident about before it gets
submitted, since these come from live attacker infrastructure.
"""

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import List, Tuple

from config import SanitizeConfig
from lurepatterns import contains_homoglyphs, normalize_for_detection

_STRONG_MARKERS = (
    "invoke-expression",
    "iex(",
    "iex (",
    "downloadstring",
    "downloadfile",
    "-enc ",
    "-encodedcommand",
    "-w hidden",
    "-windowstyle hidden",
    "bitsadmin",
    "certutil -decode",
    "mshta http",
)
_WEAK_MARKERS = (
    "powershell",
    "pwsh",
    "curl ",
    "irm ",
    "iwr ",
    "invoke-webrequest",
    "cmd.exe /c",
    "cmd /c",
    "start-process",
)


@dataclass
class SanitizeResult:
    normalized_text: str
    sha256: str
    score: int
    reasons: List[str]
    auto_approve: bool
    homoglyphs_detected: bool = False


def _strip_invisible(text: str) -> str:
    # Zero-width/formatting characters some lures use to make the visible
    # copy preview differ from what actually gets pasted. We keep the
    # command byte-for-byte otherwise -- CAPE should see what a victim
    # would actually paste -- but these categories are never legitimately
    # part of a PowerShell command.
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cf",) or ch in "\n\r\t")


def evaluate(raw_text: str, cfg: SanitizeConfig) -> SanitizeResult:
    text = _strip_invisible(raw_text).strip()
    # Score against the homoglyph-folded form so a lure using Cyrillic
    # lookalikes cannot score zero. `text` -- what actually gets submitted --
    # keeps its original characters, so the sandbox sees what a victim would
    # really paste and the report stays truthful.
    lowered = normalize_for_detection(text).lower()
    homoglyphs = contains_homoglyphs(text)

    reasons: List[str] = []
    score = 0

    for marker in _STRONG_MARKERS:
        if marker in lowered:
            score += 2
            reasons.append(f"strong:{marker.strip()}")
    for marker in _WEAK_MARKERS:
        if marker in lowered:
            score += 1
            reasons.append(f"weak:{marker.strip()}")

    if homoglyphs:
        reasons.append("homoglyphs_present")

    length_ok = cfg.min_length <= len(text) <= cfg.max_length
    if not length_ok:
        reasons.append(f"length_out_of_range:{len(text)}")

    sha256 = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    auto_approve = length_ok and score >= cfg.auto_approve_threshold

    return SanitizeResult(
        normalized_text=text,
        sha256=sha256,
        score=score,
        reasons=reasons,
        auto_approve=auto_approve,
        homoglyphs_detected=homoglyphs,
    )


def defang_preview(text: str, max_len: int = 300) -> str:
    preview = text[:max_len]
    preview = preview.replace("http://", "hxxp://").replace("https://", "hxxps://")
    preview = re.sub(r"\.(?=[a-zA-Z]{2,}(?:[/:\s]|$))", "[.]", preview)
    if len(text) > max_len:
        preview += " ...[truncated]"
    return preview
