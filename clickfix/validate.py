"""Pre-submission payload validation.

The extraction gate (extractor.is_plausible_command) decides whether a
candidate is worth keeping. This is the stricter, final gate: it runs
immediately before a payload can become a CAPE task, and its job is to make
sure we never detonate something that is not actually a command.

Every rejection carries a named reason so the dry-run statistics can separate
"this page was never a ClickFix lure" from "our extractor mangled a real
payload" -- those two failures demand completely different fixes.

Fails closed: anything it cannot positively vouch for is rejected.
"""

import re
from dataclasses import dataclass, field
from typing import List

from lurepatterns import normalize_for_detection

# --- rejection reasons -----------------------------------------------------
R_EMPTY = "empty"
R_TOO_SHORT = "too_short"
R_TOO_LONG = "too_long"
R_UNRESOLVED_TEMPLATE = "unresolved_template_expression"
R_JS_SOURCE = "javascript_source"
R_HTML_MARKUP = "html_markup"
R_FUNCTION_DECL = "function_declaration"
R_INCOMPLETE_DECODER = "incomplete_decoder_expression"
R_TRUNCATED = "truncated_payload"
R_UI_PROSE = "ui_prose_not_a_command"
R_NO_SYNTAX = "no_command_syntax"
R_UNRESOLVED_CONCAT = "unresolved_concatenation_template"
R_PLACEHOLDER = "unsubstituted_server_side_placeholder"

_TEMPLATE_RE = re.compile(r"\$\{[^}]*\}?")
# Server-side templates: the lure kit ships a payload skeleton and the page
# substitutes the real C2 host/id at delivery time. Detonating the skeleton
# fetches a literal "REPLACE_SERVER/..." and yields an empty report, so it
# must be rejected as firmly as an unresolved ${...}.
_PLACEHOLDER_RE = re.compile(
    r"\b(?:REPLACE|PLACEHOLDER|INSERT|CHANGE|YOUR|TEMPLATE|__[A-Z]+__)[_A-Z]{2,}\b|"
    r"\{\{\s*\w+\s*\}\}|"
    r"<<[A-Z_]{3,}>>|"
    r"%%[A-Z_]{3,}%%"
)
_JS_SOURCE_MARKERS = (
    "<script", "</script", "document.", "navigator.", "window.",
    "addeventlistener", "queryselector", "getelementby", ".innerhtml",
    "console.log", "clipboard.writetext", "=>", "typeof ", "prototype.",
    "json.parse", "json.stringify", "xmlhttprequest",
)
_FUNCTION_DECL_RE = re.compile(
    r"\b(?:function\s*\w*\s*\(|=>\s*\{|\bconst\s+\w+\s*=\s*\()", re.IGNORECASE
)
_HTML_TAG_RE = re.compile(r"<\s*/?\s*(?:div|span|p|body|html|head|iframe|textarea|input|"
                          r"button|form|a|img|pre|code|br|h[1-6])\b", re.IGNORECASE)
# Narrow signature of an UNRESOLVED string-concatenation template: a bare
# identifier sandwiched between two '&' operators with adjacent quotes, e.g.
#   """ & nqklncw & """ -File """ & sjopqxtu & """
# This is VBScript/VBA/MSI string-building of variables we could not resolve.
# Deliberately NOT a broad "contains &" rule: it does NOT match cmd '&&', a
# WebDAV '... & net use ...', or PowerShell's call operator '& "prog"'.
_UNRESOLVED_CONCAT_RE = re.compile(r"""["']\s*&\s*[A-Za-z_]\w*\s*&\s*["']""")
_INCOMPLETE_DECODER_RE = re.compile(
    r"\b(?:atob|btoa|decodeURIComponent|unescape|fromCharCode)\s*\(\s*$|"
    r"\b(?:atob|btoa|decodeURIComponent)\s*\([^)]*$",
    re.IGNORECASE,
)
# Prose that mentions a shell without being one.
_PROSE_RE = re.compile(
    r"\b(?:will\s+(?:now\s+)?(?:run|open|verify|start|launch)|"
    r"please\s+(?:open|run|paste|press)|"
    r"click\s+(?:here|the)|"
    r"copy\s+(?:this|the)\s+command|"
    r"instructions?\b|verification\s+(?:code|step))",
    re.IGNORECASE,
)
# Genuine command/script syntax, any one of which vouches for the payload.
_SYNTAX_SIGNALS = (
    re.compile(r"[\s\"'](?:-{1,2}|/)[A-Za-z]"),        # -nop, --flag, /c
    re.compile(r"https?://"),
    re.compile(r"\b(?:iex|irm|iwr)\s*[\(\'\"]?\w", re.IGNORECASE),
    re.compile(r"\b(?:invoke|new|start|expand|write|get|set|add|remove|test)-\w+",
               re.IGNORECASE),
    re.compile(r"\.(?:exe|ps1|bat|cmd|hta|dll|vbs|scr|msi)\b", re.IGNORECASE),
    re.compile(r"\$\w+\s*="),                            # $w = ...
    re.compile(r"\$env:", re.IGNORECASE),
    re.compile(r"%\w+%"),                                # %TEMP%
    re.compile(r"[;|&]{1,2}\s*\S"),
    re.compile(r"\bnet\s+use\b", re.IGNORECASE),
    re.compile(r"\\\\[\w.-]+\\"),                        # UNC path
)


@dataclass
class ValidationResult:
    valid: bool
    reason: str = ""
    signals: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "valid" if self.valid else "invalid"


def _is_truncated(text: str) -> bool:
    """Structural signs the payload was cut off mid-expression."""
    if text.count('"') % 2 or text.count("'") % 2:
        return True
    if text.count("(") != text.count(")"):
        return True
    if text.count("{") != text.count("}"):
        return True
    if text.count("[") != text.count("]"):
        return True
    if text.rstrip().endswith(("+", "&&", "||", "|", ",", "\\", "=")):
        return True
    return False


# A genuine command keyed by one of these can be large when obfuscated (AMOS /
# ClickFix PowerShell loaders are routinely 20-50 KB of base64 / env-var junk),
# and CAPE runs a big .ps1 fine -- so we allow such payloads up to CMD_MAX_LENGTH.
# Anything WITHOUT one of these markers keeps the tight max_length, so a grabbed
# HTML page or JS library (long, but not a command) is still rejected on length.
CMD_MAX_LENGTH = 200000
_CMD_LENGTH_MARKERS = re.compile(
    r"\b(?:iex|invoke-expression|irm|invoke-restmethod|iwr|invoke-webrequest|"
    r"powershell(?:\.exe)?|pwsh|msiexec|mshta|rundll32|regsvr32|certutil|bitsadmin|"
    r"cscript|wscript|cmd(?:\.exe)?\s*/c)\b", re.I)


def validate_payload(text: str, min_length: int = 8, max_length: int = 20000,
                     cmd_max_length: int = CMD_MAX_LENGTH) -> ValidationResult:
    """Final gate before a payload may be turned into a CAPE task."""
    if not text or not text.strip():
        return ValidationResult(False, R_EMPTY)

    raw = text.strip()
    if len(raw) < min_length:
        return ValidationResult(False, R_TOO_SHORT)
    # Content-aware length cap: real command -> generous limit; otherwise tight.
    effective_max = cmd_max_length if _CMD_LENGTH_MARKERS.search(raw) else max_length
    if len(raw) > effective_max:
        return ValidationResult(False, R_TOO_LONG)

    detect = normalize_for_detection(raw)
    lowered = detect.lower()

    # Unresolved template placeholders mean our decoder gave up halfway.
    # Submitting this would detonate a literally broken command.
    if _TEMPLATE_RE.search(detect):
        return ValidationResult(False, R_UNRESOLVED_TEMPLATE)

    if _PLACEHOLDER_RE.search(detect):
        return ValidationResult(False, R_PLACEHOLDER)

    if _INCOMPLETE_DECODER_RE.search(detect):
        return ValidationResult(False, R_INCOMPLETE_DECODER)

    if _UNRESOLVED_CONCAT_RE.search(detect):
        return ValidationResult(False, R_UNRESOLVED_CONCAT)

    if any(marker in lowered for marker in _JS_SOURCE_MARKERS):
        return ValidationResult(False, R_JS_SOURCE)

    if _FUNCTION_DECL_RE.search(detect):
        return ValidationResult(False, R_FUNCTION_DECL)

    if _HTML_TAG_RE.search(detect):
        return ValidationResult(False, R_HTML_MARKUP)

    if _is_truncated(detect):
        return ValidationResult(False, R_TRUNCATED)

    signals = [rx.pattern[:24] for rx in _SYNTAX_SIGNALS if rx.search(detect)]
    if not signals:
        # Nothing that looks like a command. If it also reads like UI copy,
        # say so specifically -- that distinction drives the statistics.
        if _PROSE_RE.search(detect):
            return ValidationResult(False, R_UI_PROSE)
        return ValidationResult(False, R_NO_SYNTAX)

    # Prose that merely *contains* a flag-like token is still prose.
    if _PROSE_RE.search(detect) and len(signals) < 2:
        return ValidationResult(False, R_UI_PROSE)

    return ValidationResult(True, "", signals)
