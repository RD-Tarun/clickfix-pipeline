"""Recover the PowerShell command a ClickFix lure would put on the clipboard.

Layered strategy, cheapest/highest-confidence evidence first:

  1. urlscan rendered DOM   -- the lure's JS already ran in urlscan's browser
  2. live fetch of final URL (after redirects)
  3. live fetch of the original task URL, if it differs
  4. linked scripts, from both the live HTML and urlscan's request log
  5. iframes (srcdoc inline, and src fetched)
  6. raw-line fallback: a bare command sitting in the markup

Within each layer we look for clipboard payload construction and statically
evaluate it (see jsdecode). We never execute JavaScript, and we never execute
the recovered PowerShell -- that only ever happens inside the CAPE guest.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

from config import ExtractConfig, UrlscanConfig
from jsdecode import decode_js_string, eval_expr, iter_call_args, resolve_variables
from lurepatterns import (
    clickfix_instruction_score,
    contains_homoglyphs,
    looks_obfuscated,
    normalize_for_detection,
)
from urlnorm import normalize_url
from urlscan_result import ScanDetail, fetch_response_body

log = logging.getLogger("clickfix.extractor")

# --- layers, in priority order --------------------------------------------
LAYER_DOM = "urlscan_dom"                      # 1. rendered DOM (post-JS)
LAYER_RESULT = "urlscan_result"                # 2. Result API: frames/links
LAYER_RESPONSE_BODY = "urlscan_response_body"  # 3. captured bodies by hash
LAYER_URLSCAN_JS = "urlscan_linked_js"         # 4. JS urlscan saw load
LAYER_LIVE_FINAL = "live_final_url"            # 5. direct HTTP, final URL
LAYER_LIVE_ORIGINAL = "live_original_url"      # 5. direct HTTP, original URL
LAYER_SCRIPT = "linked_script"                 # 5. JS linked from live HTML
LAYER_IFRAME = "iframe"                        # 5. iframe documents

LAYER_ORDER = (
    LAYER_DOM,
    LAYER_RESULT,
    LAYER_RESPONSE_BODY,
    LAYER_URLSCAN_JS,
    LAYER_LIVE_FINAL,
    LAYER_LIVE_ORIGINAL,
    LAYER_SCRIPT,
    LAYER_IFRAME,
)

# --- failure reasons ------------------------------------------------------
FAIL_NO_COMMAND = "no_command"
FAIL_PAGE_UNREACHABLE = "page_unreachable"
FAIL_UNSUPPORTED = "unsupported_obfuscation"
FAIL_DOM_UNAVAILABLE = "dom_unavailable"
FAIL_RESOURCE_FETCH = "resource_fetch_failure"
FAIL_BINARY = "binary_resource"
FAIL_REDIRECT = "redirect_failure"
# Layer 7: the page is a ClickFix lure, but the command only materialises on
# user interaction (a click handler firing an XHR, a key fetched on demand).
# Distinct from no_command: this is "we know it's there and cannot reach it".
FAIL_INTERACTION = "interaction_dependent"
# The scan captured an HTTP error page, not the lure: the infrastructure was
# already down when urlscan visited. Distinct from page_unreachable (we could
# not connect at all) and from no_command (a live page with no payload).
FAIL_DEAD_INFRA = "dead_infrastructure"

# --- payload construction sites -------------------------------------------
_CLIPBOARD_CALL = r"clipboard\.writeText"
_SETDATA_CALL = r"setData"
_EXECCOMMAND_COPY_RE = re.compile(r"execCommand\(\s*['\"]copy['\"]\s*\)", re.IGNORECASE)

_TEXTAREA_RE = re.compile(r"<textarea[^>]*>(.*?)</textarea>", re.DOTALL | re.IGNORECASE)
_HIDDEN_VALUE_RE = re.compile(
    r'<input[^>]+(?:type=["\']hidden["\'])[^>]*value=(["\'])(.*?)\1', re.IGNORECASE
)
_ANY_INPUT_VALUE_RE = re.compile(r'<input[^>]+value=(["\'])(.*?)\1', re.IGNORECASE)
_DATA_ATTR_RE = re.compile(
    r'data-(?:clipboard-text|command|cmd|copy|payload)=(["\'])(.*?)\1', re.IGNORECASE
)
_VALUE_ASSIGN_RE = re.compile(r"\.value\s*=\s*(.+?)(?:;|\n)", re.DOTALL)
_INNERTEXT_ASSIGN_RE = re.compile(
    r"\.(?:innerText|textContent|innerHTML)\s*=\s*(.+?)(?:;|\n)", re.DOTALL
)

_ATOB_LITERAL_RE = re.compile(r"atob\(\s*([`'\"])([A-Za-z0-9+/=\s]{16,})\1\s*\)")
_FROMCHARCODE_RE = re.compile(r"String\.fromCharCode\(([0-9a-fA-Fx,\s]+)\)")
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=(["\'])(.*?)\1', re.IGNORECASE)
_IFRAME_SRC_RE = re.compile(r'<iframe[^>]+src=(["\'])(.*?)\1', re.IGNORECASE)
_IFRAME_SRCDOC_RE = re.compile(r'<iframe[^>]+srcdoc=(["\'])(.*?)\1', re.DOTALL | re.IGNORECASE)
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\';]+)',
    re.IGNORECASE,
)
_DOC_WRITE_CALL = r"document\.write(?:ln)?"

# JSON / JSONP payload delivery. Observed in the wild: an XHR to /first_allow
# returns  callback({"allow":true,"payload":"<powershell>"})  -- the command
# never touches a clipboard API in the captured resource, so the call-site
# patterns above cannot see it.
_JSONP_WRAPPER_RE = re.compile(r"^[^({]*\(\s*(\{.*\})\s*\)\s*;?\s*$", re.DOTALL)
_JSON_FIELD_RE = re.compile(
    r'"(?:payload|cmd|command|commandline|script|ps|ps1|powershell|clip|clipboard|'
    r'copy|text|code|data|value|exec|run)"\s*:\s*"((?:[^"\\]|\\.)*)"',
    re.IGNORECASE,
)

# Error/parking pages served in place of a taken-down lure.
_ERROR_PAGE_RE = re.compile(
    r"<title>[^<]*?\b(?:4\d\d|5\d\d)\b[^<]*</title>|"
    r"web server is returning an unknown error|"
    r"<title>[^<]*(?:not found|forbidden|bad gateway|service unavailable|"
    r"gateway time-?out|origin (?:error|unreachable)|site can.t be reached)[^<]*</title>|"
    r"error\s*(?:52[0-7]|10\d\d)\b|"
    r"<center>\s*<h1>\s*4\d\d [^<]*</h1>\s*</center>|"
    r"this domain (?:has expired|is (?:for sale|parked))|"
    r"default (?:web)?\s*(?:site|page)\s*$",
    re.IGNORECASE | re.DOTALL,
)


def looks_like_error_page(text: Optional[str]) -> bool:
    """True when the captured content is an HTTP error/parking page."""
    if not text:
        return False
    head = text[:4000]
    return bool(_ERROR_PAGE_RE.search(head))


_COMMAND_MARKERS = (
    "powershell",
    "pwsh",
    "iex ",
    "iex(",
    "invoke-expression",
    "mshta",
    "cmd.exe",
    "cmd /c",
    "curl ",
    "irm ",
    "iwr ",
    "-w hidden",
    "-windowstyle hidden",
    "downloadstring",
    "downloadfile",
    "certutil",
    "bitsadmin",
    "-enc",
    "-nop",
    "invoke-webrequest",
    "start-process",
    "rundll32",
    "regsvr32",
    "conhost",
    "msiexec",
    # Raw PowerShell script bodies: a JSON-delivered payload is often the
    # script itself, never prefixed with "powershell".
    "new-object",
    "net.webclient",
    "expand-archive",
    "-executionpolicy",
    "invoke-restmethod",
    "$env:",
    "net use ",
    "webdav",
    "add-mppreference",
    "frombase64string",
)

# Higher wins when several candidates are recovered from the same page.
_METHOD_PRIORITY = {
    "clipboard_writetext": 100,
    "setdata_clipboard": 95,
    "data_clipboard_attr": 85,
    "value_assign": 70,
    "hidden_input": 65,
    "textarea": 60,
    "innertext_assign": 55,
    "document_write": 50,
    "json_field": 80,
    "atob_literal": 40,
    "fromcharcode_literal": 40,
    "input_value": 35,
    "raw_line": 10,
}


@dataclass
class RawCandidate:
    text: str
    method: str
    layer: str
    source_url: Optional[str] = None


@dataclass
class ExtractResult:
    command_text: Optional[str] = None
    method: Optional[str] = None
    layer: Optional[str] = None
    candidates_found: int = 0
    failure_reason: Optional[str] = None
    source_note: str = ""
    final_url: Optional[str] = None
    original_url: Optional[str] = None
    normalized_url: Optional[str] = None
    # When the command came from a fetched resource rather than the page
    # itself, this is that resource's URL.
    source_resource_url: Optional[str] = None
    urlscan_uuid: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    layers_tried: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    # Confirmation that the page is a ClickFix lure at all, independent of
    # whether the recovered command itself looks malicious.
    lure_score: int = 0
    lure_hits: List[str] = field(default_factory=list)
    homoglyphs_detected: bool = False
    obfuscated_bundle: bool = False


# Markers that prove a string is still JavaScript/markup rather than a
# pasteable command. Any hit disqualifies the candidate outright.
_NOT_A_COMMAND = (
    "${",
    "<script",
    "</script",
    "function(",
    "function ",
    "=>",
    "document.",
    "navigator.",
    "window.",
    "addeventlistener",
    "queryselector",
    "getelementby",
    "innerhtml",
    "clipboard.",
    "console.log",
    "var ",
    "let ",
    "const ",
    "atob(",
    "=atob",
    "[object ",
    "undefined",
)


# A real command carries command-line syntax. Prose that merely mentions
# PowerShell ("PowerShell will run to verify you") does not, and must never be
# mistaken for a payload.
_COMMAND_SYNTAX = (
    re.compile(r"[\s\"\'](?:-{1,2}|/)[A-Za-z]"),   # -nop, --flag, /c
    re.compile(r"https?://"),
    re.compile(r"\b(?:iex|irm|iwr)\s*[\(\'\"]?\w", re.IGNORECASE),
    re.compile(r"\binvoke-\w+", re.IGNORECASE),
    re.compile(r"\bdownload(?:string|file)\b", re.IGNORECASE),
    re.compile(r"\.(?:exe|ps1|bat|cmd|hta|dll|vbs|js)\b", re.IGNORECASE),
    re.compile(r"[;|&]{1,2}\s*\w"),
    re.compile(r"\$\w+\s*="),                       # PowerShell variable
)


def _has_command_syntax(text: str) -> bool:
    return any(rx.search(text) for rx in _COMMAND_SYNTAX)


def is_plausible_command(text: Optional[str]) -> bool:
    """Fail-closed gate: would this string make sense pasted into Win+R?

    Rejects anything still carrying unresolved template expressions or raw
    JS/markup syntax. Guessing here is how a broken command reaches the
    sandbox and produces a misleading report, so the bar is deliberately high.
    """
    if not text:
        return False
    stripped = text.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if any(marker in lowered for marker in _NOT_A_COMMAND):
        return False
    # Unbalanced braces are a strong sign of a truncated JS fragment.
    if stripped.count("{") != stripped.count("}"):
        return False
    if not looks_like_command(stripped):
        return False
    # Mentioning "powershell" is not enough -- it has to look like a command
    # line, or lure UI copy gets submitted to the sandbox as a payload.
    return _has_command_syntax(stripped)


def looks_like_command(text: str) -> bool:
    # Fold homoglyphs first: "роwershell" with Cyrillic characters is
    # visually identical to a victim but matches no marker as raw bytes.
    lowered = normalize_for_detection(text).lower()
    return any(marker in lowered for marker in _COMMAND_MARKERS)


# --------------------------------------------------------------------------
# Candidate gathering (pure -- operates on text, no network)
# --------------------------------------------------------------------------
def gather_candidates(
    text: str, layer: str, depth: int = 0, source_url: Optional[str] = None
) -> Tuple[List[RawCandidate], List[str]]:
    """Return (candidates, notes). Pure function -- unit-testable directly."""
    found: List[RawCandidate] = []
    notes: List[str] = []
    variables = resolve_variables(text)

    def _add(value: Optional[str], method: str):
        if value and value.strip():
            found.append(RawCandidate(value.strip(), method, layer, source_url))

    unresolved = 0

    # clipboard.writeText(<any expression>)
    for arg in iter_call_args(text, _CLIPBOARD_CALL):
        val = eval_expr(arg, variables)
        if val is None:
            unresolved += 1
        _add(val, "clipboard_writetext")

    # dataTransfer.setData('text/plain', <expr>) -- second argument.
    for arg in iter_call_args(text, _SETDATA_CALL):
        parts = _split_args(arg)
        if len(parts) >= 2:
            val = eval_expr(parts[1], variables)
            if val is None:
                unresolved += 1
            _add(val, "setdata_clipboard")

    # document.write(<expr>) can inject the whole lure block.
    for arg in iter_call_args(text, _DOC_WRITE_CALL):
        val = eval_expr(arg, variables)
        if val:
            _add(val, "document_write")
            nested, nested_notes = gather_candidates(val, layer, depth + 1, source_url)
            found.extend(nested)
            notes.extend(nested_notes)

    # element.value = <expr>  (the classic hidden-textarea + execCommand copy)
    for m in _VALUE_ASSIGN_RE.finditer(text):
        val = eval_expr(m.group(1), variables)
        _add(val, "value_assign")

    for m in _INNERTEXT_ASSIGN_RE.finditer(text):
        val = eval_expr(m.group(1), variables)
        _add(val, "innertext_assign")

    # Static markup carriers.
    for m in _DATA_ATTR_RE.finditer(text):
        _add(decode_js_string(m.group(2)), "data_clipboard_attr")
    for m in _TEXTAREA_RE.finditer(text):
        _add(decode_js_string(m.group(1)), "textarea")
    for m in _HIDDEN_VALUE_RE.finditer(text):
        _add(decode_js_string(m.group(2)), "hidden_input")
    for m in _ANY_INPUT_VALUE_RE.finditer(text):
        _add(decode_js_string(m.group(2)), "input_value")

    # Bare decode primitives anywhere in the text.
    for m in _ATOB_LITERAL_RE.finditer(text):
        val = eval_expr(f'atob("{m.group(2)}")', variables)
        _add(val, "atob_literal")
        # A decoded blob is frequently a nested lure block, not a bare
        # command -- re-run the gatherer over it.
        if val and depth < 3 and ("clipboard" in val.lower() or "<textarea" in val.lower()):
            nested, nested_notes = gather_candidates(val, layer, depth + 1, source_url)
            found.extend(nested)
            notes.extend(nested_notes)
    for m in _FROMCHARCODE_RE.finditer(text):
        val = eval_expr(f"String.fromCharCode({m.group(1)})", variables)
        _add(val, "fromcharcode_literal")

    # JSON / JSONP response payloads.
    for value in _json_string_values(text):
        _add(value, "json_field")

    # Inline iframe documents carry their own lure markup.
    for m in _IFRAME_SRCDOC_RE.finditer(text):
        inner = decode_js_string(m.group(2))
        sub, sub_notes = gather_candidates(inner, layer, depth + 1, source_url)
        found.extend(sub)
        notes.extend(sub_notes)

    # Any resolved variable that itself looks like a command.
    for name, value in variables.items():
        if looks_like_command(value):
            _add(value, "clipboard_writetext" if _references_clipboard(text, name) else "value_assign")

    if unresolved:
        notes.append(f"{FAIL_UNSUPPORTED}:{unresolved}_unresolved_clipboard_expr")
    if _EXECCOMMAND_COPY_RE.search(text) and not found:
        notes.append("execcommand_copy_without_recoverable_source")

    return found, notes


def _json_string_values(text: str) -> List[str]:
    """Pull command-looking strings out of a JSON or JSONP response body.

    Tries a real parse first (handles nesting and escaping correctly), then
    falls back to a targeted regex for truncated or malformed bodies.
    """
    out: List[str] = []
    stripped = text.strip()
    if not stripped or ("{" not in stripped and "[" not in stripped):
        return out

    payload = stripped
    wrapper = _JSONP_WRAPPER_RE.match(stripped)
    if wrapper:
        payload = wrapper.group(1)

    parsed = None
    for candidate in (payload, stripped):
        try:
            parsed = json.loads(candidate)
            break
        except (ValueError, TypeError):
            continue

    if parsed is not None:
        def _walk(node, depth=0):
            if depth > 8:
                return
            if isinstance(node, str):
                if looks_like_command(node):
                    out.append(node)
            elif isinstance(node, dict):
                for v in node.values():
                    _walk(v, depth + 1)
            elif isinstance(node, list):
                for v in node:
                    _walk(v, depth + 1)

        _walk(parsed)

    if not out:
        for m in _JSON_FIELD_RE.finditer(text):
            try:
                value = json.loads(f'"{m.group(1)}"')
            except ValueError:
                value = decode_js_string(m.group(1))
            if looks_like_command(value):
                out.append(value)
    return out


def _references_clipboard(text: str, name: str) -> bool:
    return bool(re.search(r"clipboard\.writeText\(\s*%s\s*\)" % re.escape(name), text))


def _split_args(arg_text: str) -> List[str]:
    from jsdecode import split_top_level

    return split_top_level(arg_text, ",")


# A raw line containing any of these is page source, not a pasted command.
# Without this guard the fallback happily returns a line of JavaScript.
_SOURCE_ARTEFACTS = (
    "<script",
    "</script",
    "clipboard.writetext",
    "setdata(",
    "document.getelementbyid",
    "document.queryselector",
    "function(",
    "=>",
    "addeventlistener",
    "innerhtml",
    "onclick=",
)
_TAG_RE = re.compile(r"<[^>]+>")


def _raw_line_candidates(text: str, layer: str) -> List[RawCandidate]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not (8 <= len(line) <= 20000) or not looks_like_command(line):
            continue
        lowered = line.lower()
        if any(marker in lowered for marker in _SOURCE_ARTEFACTS):
            continue
        # A command shown to the victim is usually wrapped in markup
        # (<div>, <code>, <p>). Keep the text, drop the tags.
        text_content = decode_js_string(_TAG_RE.sub("", line)).strip()
        if not text_content or not looks_like_command(text_content):
            continue
        out.append(RawCandidate(text_content, "raw_line", layer))
    return out


def _structured_extraction_failed(notes: List[str]) -> bool:
    """True when we found a payload construction site but could not decode it.

    That is a *known* failure, not an absence of structure, so the raw-line
    fallback must not fire -- guessing at page source after an explicit
    decode failure is how broken commands reach the sandbox.
    """
    return any(FAIL_UNSUPPORTED in n for n in notes)


def _rank(cand: RawCandidate) -> Tuple[int, int, int]:
    return (
        _METHOD_PRIORITY.get(cand.method, 0),
        1 if looks_like_command(cand.text) else 0,
        len(cand.text),
    )


def select_best(candidates: List[RawCandidate]) -> Optional[RawCandidate]:
    """Pick the best candidate that survives the fail-closed gate.

    Never falls back to "the least bad option": if nothing is a plausible
    command, we return None and the caller classifies the failure.
    """
    if not candidates:
        return None
    usable = [c for c in candidates if is_plausible_command(c.text)]
    if not usable:
        return None
    return max(usable, key=_rank)


def _apply_lure_signals(result: ExtractResult, *texts: Optional[str]) -> None:
    """Record how strongly the page reads as a ClickFix lure."""
    best_score, best_hits = 0, []
    for text in texts:
        if not text:
            continue
        score, hits = clickfix_instruction_score(text)
        if score > best_score:
            best_score, best_hits = score, hits
        if looks_obfuscated(text):
            result.obfuscated_bundle = True
    result.lure_score = best_score
    result.lure_hits = best_hits
    if result.command_text and contains_homoglyphs(result.command_text):
        result.homoglyphs_detected = True


def extract_from_text(text: str, layer: str = "text") -> ExtractResult:
    """Extract from a single blob of HTML/JS. No network. Used by tests."""
    cands, notes = gather_candidates(text, layer)
    if not cands and not _structured_extraction_failed(notes):
        cands = _raw_line_candidates(text, layer)
    best = select_best(cands)
    result = ExtractResult(candidates_found=len(cands), notes=list(notes), layers_tried=[layer])
    _apply_lure_signals(result, text)
    if best is None:
        result.failure_reason = (
            FAIL_UNSUPPORTED if any(FAIL_UNSUPPORTED in n for n in notes) else FAIL_NO_COMMAND
        )
        result.source_note = result.failure_reason
        return result
    result.command_text = best.text
    result.method = best.method
    result.layer = best.layer
    result.source_note = f"{best.layer}:{best.method}"
    _apply_lure_signals(result, text)
    return result


# --------------------------------------------------------------------------
# Network layers
# --------------------------------------------------------------------------

# --- binary-resource guard (Fix 1) --------------------------------------
# A command extractor must only parse TEXT (HTML/JS/JSON). Binary bodies
# (MSI/PE/ZIP/PDF/images...) must be rejected BEFORE text extraction so their
# bytes are never mined for spurious "commands" (the 23.94.252.153/68993 MSI
# case). Order: Content-Type (binary->reject w/o download, text->accept) ->
# magic bytes on a small prefix -> printable ratio ONLY for ambiguous types.
_BINARY_CTYPES = (
    "application/x-msi", "application/x-msdownload", "application/x-ms-installer",
    "application/zip", "application/x-zip-compressed", "application/x-7z-compressed",
    "application/x-rar-compressed", "application/vnd.ms-cab-compressed",
    "application/pdf", "application/x-dosexec", "application/x-executable",
    "application/gzip", "application/x-msdos-program",
)
_TEXT_CTYPES = (
    "text/html", "application/xhtml+xml", "text/javascript", "application/javascript",
    "application/ecmascript", "text/ecmascript", "application/json", "text/json",
    "text/plain", "text/xml", "application/xml", "text/css",
)
_AMBIGUOUS_CTYPES = ("", "application/octet-stream", "binary/octet-stream")
_BINARY_MAGICS = (
    b"\xd0\xcf\x11\xe0",       # OLE / MSI
    b"MZ",                       # PE (.exe/.dll)
    b"PK\x03\x04",             # ZIP (.docx/.jar...)
    b"%PDF",                     # PDF
    b"\x7fELF",                # ELF
    b"\x1f\x8b",               # gzip
    b"7z\xbc\xaf\x27\x1c",   # 7z
    b"Rar!",                     # RAR
)


def _printable_ratio(prefix):
    if not prefix:
        return 1.0
    ok = sum(1 for b in prefix if b in (9, 10, 13) or 32 <= b <= 126)
    return ok / len(prefix)


def _is_binary_body(ctype, prefix):
    """True if this response should NOT be text-extracted."""
    ct = (ctype or "").split(";")[0].strip().lower()
    if ct.startswith(("image/", "font/", "video/", "audio/")):
        return True
    if ct in _BINARY_CTYPES:
        return True
    if any(prefix.startswith(m) for m in _BINARY_MAGICS):
        return True
    if ct in _TEXT_CTYPES:
        return False                      # declared text: never reject on ratio
    if ct in _AMBIGUOUS_CTYPES:
        return _printable_ratio(prefix) < 0.80   # secondary heuristic only
    return False


def _fetch(url: str, cfg: ExtractConfig) -> Tuple[Optional[str], Optional[str], List[str], Optional[str]]:
    """Return (text, final_url, redirect_chain, skip).
    text is None on failure OR binary-skip; skip="binary" distinguishes an
    intentional binary skip from a retrieval failure (skip=None)."""
    headers = {"User-Agent": cfg.user_agent}
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=cfg.fetch_timeout,
            stream=True,
            allow_redirects=True,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.warning("fetch failed for %s: %s", url, exc)
        return None, None, [], None
    except Exception as exc:
        # urllib3 can surface ReadTimeoutError/ProtocolError that are not
        # wrapped as requests.RequestException when reading a streamed body.
        log.warning("fetch errored for %s: %s", url, exc.__class__.__name__)
        return None, None, [], None

    chain = [r.url for r in resp.history] + [resp.url]
    ctype = resp.headers.get("Content-Type", "")
    ct = ctype.split(";")[0].strip().lower()
    if ct.startswith(("image/", "font/", "video/", "audio/")) or ct in _BINARY_CTYPES:
        log.info("skipping binary resource %s (content-type=%s)", url, ct)
        resp.close()
        return None, resp.url, chain, "binary"
    try:
        prefix = resp.raw.read(2048, decode_content=True)
    except Exception as exc:
        log.warning("body read failed for %s: %s", url, exc.__class__.__name__)
        return None, None, chain, None
    if _is_binary_body(ctype, prefix):
        log.info("skipping binary-looking resource %s (magic/ratio)", url)
        resp.close()
        return None, resp.url, chain, "binary"
    try:
        rest = resp.raw.read(cfg.max_page_bytes + 1 - len(prefix), decode_content=True)
    except Exception as exc:
        log.warning("body read failed for %s: %s", url, exc.__class__.__name__)
        return None, None, chain, None
    content = prefix + rest
    if len(content) > cfg.max_page_bytes:
        log.warning("page %s exceeded size cap, truncating", url)
        content = content[: cfg.max_page_bytes]
    try:
        text = content.decode(resp.encoding or "utf-8", errors="replace")
    except (LookupError, TypeError):
        text = content.decode("utf-8", errors="replace")
    return text, resp.url, chain, None


def _follow_meta_refresh(text: str, base_url: str, cfg: ExtractConfig, depth: int = 0):
    """ClickFix lures sometimes hop via <meta refresh> rather than a 3xx."""
    if depth >= cfg.max_meta_refresh_hops:
        return None, None
    m = _META_REFRESH_RE.search(text)
    if not m:
        return None, None
    target = urljoin(base_url, m.group(1).strip().strip("'\""))
    body, final_url, _, _ = _fetch(target, cfg)
    if body is None:
        return None, target
    return body, final_url or target


def _harvest_layer(
    text: str, layer: str, base_url: Optional[str], cfg: ExtractConfig, result: ExtractResult
) -> List[RawCandidate]:
    """Gather from one text blob plus its inline iframes."""
    cands, notes = gather_candidates(text, layer)
    result.notes.extend(notes)

    if base_url and cfg.follow_iframes:
        for _q, src in _IFRAME_SRC_RE.findall(text)[: cfg.max_iframes]:
            iframe_url = urljoin(base_url, src)
            body, _, _, skip = _fetch(iframe_url, cfg)
            if body is None:
                reason = FAIL_BINARY if skip == "binary" else FAIL_RESOURCE_FETCH
                result.notes.append(f"{reason}:iframe:{iframe_url[:120]}")
                continue
            sub, sub_notes = gather_candidates(body, LAYER_IFRAME)
            cands.extend(sub)
            result.notes.extend(sub_notes)
    return cands


def extract_command(
    page_url: str,
    cfg: ExtractConfig,
    scan: Optional[ScanDetail] = None,
    urlscan_cfg: Optional["UrlscanConfig"] = None,
) -> ExtractResult:
    """Layered extraction, cheapest and highest-confidence evidence first.

      1. urlscan rendered DOM (post-JS, captured by a real browser)
      2. urlscan Result API: frames/iframes, links, redirect chain
      3. urlscan captured response bodies, fetched by content hash
      4. JavaScript urlscan recorded the page loading, fetched live
      5. direct HTTP retrieval of final/original page and its linked JS
      6. the static deobfuscation engine (applied within every layer above)
      7. otherwise: unresolved / interaction-dependent

    No JavaScript is executed and no recovered command is executed. Both only
    ever happen inside the CAPE Windows guest.
    """
    result = ExtractResult(original_url=page_url)
    candidates: List[RawCandidate] = []
    reachable = False
    binary_seen = [False]
    fetched_bodies = 0
    handled_urls = set()

    final_url = page_url
    if scan is not None:
        result.urlscan_uuid = scan.uuid
        result.original_url = scan.task_url or page_url
        if scan.final_url:
            final_url = scan.final_url
        result.redirect_chain = list(scan.redirect_chain)
        result.notes.extend(scan.notes)
    result.final_url = final_url
    result.normalized_url = normalize_url(final_url)

    def _harvest(text, layer, source_url):
        nonlocal candidates
        cands, notes = gather_candidates(text, layer, source_url=source_url)
        candidates.extend(cands)
        result.notes.extend(notes)

    def _satisfied() -> bool:
        return cfg.stop_on_first_hit and any(is_plausible_command(c.text) for c in candidates)

    # --- Layer 1: urlscan rendered DOM ------------------------------------
    if scan is not None and scan.dom:
        result.layers_tried.append(LAYER_DOM)
        reachable = True
        _harvest(scan.dom, LAYER_DOM, final_url)

    # --- Layer 2: Result API frames / iframes / links ----------------------
    can_read_bodies = urlscan_cfg is not None and bool(urlscan_cfg.api_key)
    if scan is not None and not _satisfied() and scan.frames:
        result.layers_tried.append(LAYER_RESULT)
        by_url = {r.url: r for r in scan.resources}
        for frame_url in scan.frames[: cfg.max_iframes]:
            if frame_url in handled_urls:
                continue
            handled_urls.add(frame_url)
            res = by_url.get(frame_url)
            body = None
            if (
                res is not None
                and res.readable
                and can_read_bodies
                and fetched_bodies < cfg.max_response_bodies
            ):
                body, note = fetch_response_body(res.body_hash, urlscan_cfg)
                fetched_bodies += 1
                if note:
                    result.notes.append(f"{note}:frame:{frame_url[:100]}")
            if body is None:
                body, _, _, skip = _fetch(frame_url, cfg)
            if body is None:
                reason = FAIL_BINARY if 'skip' in dir() and skip == "binary" else FAIL_RESOURCE_FETCH
                result.notes.append(f"{reason}:frame:{frame_url[:100]}")
                continue
            reachable = True
            _harvest(body, LAYER_RESULT, frame_url)

    # --- Layer 3: urlscan captured response bodies -------------------------
    if scan is not None and not _satisfied() and can_read_bodies:
        selected = [
            r
            for r in scan.prioritized_resources(cfg.max_response_bodies)
            if r.url not in handled_urls
        ]
        if selected:
            result.layers_tried.append(LAYER_RESPONSE_BODY)
        for res in selected:
            if _satisfied() or fetched_bodies >= cfg.max_response_bodies:
                break
            handled_urls.add(res.url)
            body, note = fetch_response_body(res.body_hash, urlscan_cfg)
            fetched_bodies += 1
            if body is None:
                result.notes.append(f"{note}:{res.url[:100]}")
                continue
            reachable = True
            _harvest(body, LAYER_RESPONSE_BODY, res.url)

    # --- Layer 4: JS urlscan saw load, fetched live ------------------------
    if scan is not None and not _satisfied() and scan.script_urls:
        pending = [u for u in scan.script_urls if u not in handled_urls]
        if pending:
            result.layers_tried.append(LAYER_URLSCAN_JS)
        for script_url in pending[: cfg.max_linked_scripts]:
            if _satisfied():
                break
            handled_urls.add(script_url)
            body, _, _, skip = _fetch(script_url, cfg)
            if body is None:
                reason = FAIL_BINARY if skip == "binary" else FAIL_RESOURCE_FETCH
                result.notes.append(f"{reason}:urlscan_js:{script_url[:100]}")
                continue
            reachable = True
            _harvest(body, LAYER_URLSCAN_JS, script_url)

    # --- Layer 5: direct HTTP retrieval ------------------------------------
    live_text = None
    for url, layer in ((final_url, LAYER_LIVE_FINAL), (result.original_url, LAYER_LIVE_ORIGINAL)):
        if not url or _satisfied():
            break
        if layer == LAYER_LIVE_ORIGINAL and url == final_url:
            continue
        result.layers_tried.append(layer)
        body, resolved_url, chain, skip = _fetch(url, cfg)
        if body is None:
            if skip == "binary":
                binary_seen[0] = True
                result.notes.append(f"{FAIL_BINARY}:{layer}:{url[:100]}")
            else:
                result.notes.append(f"{FAIL_PAGE_UNREACHABLE}:{layer}:{url[:100]}")
            continue
        reachable = True
        if chain and not result.redirect_chain:
            result.redirect_chain = chain
        if resolved_url and layer == LAYER_LIVE_FINAL:
            result.final_url = resolved_url
            result.normalized_url = normalize_url(resolved_url)
        live_text = live_text or body
        candidates.extend(_harvest_layer(body, layer, resolved_url or url, cfg, result))

        refreshed, refreshed_url = _follow_meta_refresh(body, resolved_url or url, cfg)
        if refreshed:
            result.notes.append(f"meta_refresh_followed:{(refreshed_url or '')[:100]}")
            result.final_url = refreshed_url or result.final_url
            candidates.extend(_harvest_layer(refreshed, layer, refreshed_url, cfg, result))
        elif refreshed_url:
            result.notes.append(f"{FAIL_REDIRECT}:meta_refresh:{refreshed_url[:100]}")

    # --- Layer 5b: scripts linked from the live HTML -----------------------
    if live_text and not _satisfied():
        script_urls = [
            urljoin(result.final_url or page_url, sc)
            for _q, sc in _SCRIPT_SRC_RE.findall(live_text)
        ]
        pending = [u for u in script_urls if u not in handled_urls]
        if pending:
            result.layers_tried.append(LAYER_SCRIPT)
        for script_url in pending[: cfg.max_linked_scripts]:
            if _satisfied():
                break
            handled_urls.add(script_url)
            body, _, _, skip = _fetch(script_url, cfg)
            if body is None:
                reason = FAIL_BINARY if skip == "binary" else FAIL_RESOURCE_FETCH
                result.notes.append(f"{reason}:script:{script_url[:100]}")
                continue
            reachable = True
            _harvest(body, LAYER_SCRIPT, script_url)

    result.candidates_found = len(candidates)
    _apply_lure_signals(result, scan.dom if scan else None, live_text)
    best = select_best(candidates)

    # --- Layer 7: classify the failure -------------------------------------
    if best is None:
        result.failure_reason = _classify_failure(
            result, reachable, candidates, (scan.dom if scan else None, live_text),
            binary_seen=binary_seen[0]
        )
        result.source_note = result.failure_reason
        return result

    result.command_text = best.text
    result.method = best.method
    result.layer = best.layer
    result.source_resource_url = best.source_url
    result.source_note = f"{best.layer}:{best.method}"
    if contains_homoglyphs(best.text):
        result.homoglyphs_detected = True
    return result


def _classify_failure(result: ExtractResult, reachable: bool, candidates,
                      texts=(), binary_seen=False) -> str:
    """Turn an empty result into a precise, actionable reason."""
    if not reachable:
        # The server responded, but only with a binary body we intentionally
        # skipped -- distinct from an actual retrieval failure.
        return FAIL_BINARY if binary_seen else FAIL_PAGE_UNREACHABLE
    if any(FAIL_UNSUPPORTED in n for n in result.notes):
        return FAIL_UNSUPPORTED
    # An error page means the lure was gone before urlscan arrived -- counting
    # that as an extraction miss would slander the extractor.
    if any(looks_like_error_page(t) for t in texts if t):
        return FAIL_DEAD_INFRA
    # We saw payload-construction sites but nothing survived the fail-closed
    # gate, or the page is clearly a lure yet holds no recoverable command:
    # the command almost certainly materialises only on user interaction.
    if candidates or result.lure_score >= 4:
        return FAIL_INTERACTION
    return FAIL_NO_COMMAND


def _has_command(candidates: List[RawCandidate]) -> bool:
    return any(looks_like_command(c.text) for c in candidates)
