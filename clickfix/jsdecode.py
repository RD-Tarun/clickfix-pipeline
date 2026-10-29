"""Static evaluation of the small subset of JavaScript that ClickFix lures
use to build a clipboard payload.

This is deliberately NOT a JS engine. It understands string literals,
concatenation, variable references, and a handful of decode primitives
(atob, String.fromCharCode, decodeURIComponent, unescape, reverse). Anything
outside that subset returns None so the caller can record
`unsupported_obfuscation` rather than silently guessing.

Nothing here executes attacker-controlled code -- it is pure string parsing.
"""

import base64
import binascii
import html
import re
from typing import Dict, List, Optional
from urllib.parse import unquote

_QUOTES = "'\"`"

# `var x = ...` / `let x = ...` / `const x = ...` / bare `x = ...` reassignment.
# Terminated by a semicolon or a newline, whichever comes first, so lures that
# omit semicolons still resolve.
_VAR_ASSIGN_RE = re.compile(
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+?)(?:;|\n|$)", re.DOTALL
)
_BARE_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?)(?:;|$)", re.MULTILINE)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
_FROMCHARCODE_RE = re.compile(r"^String\.fromCharCode\((.*)\)$", re.DOTALL)
# Template placeholders may hold any expression, not just a bare name:
# `${proto} ${atob(h)} ${a + "b"}`.
_TEMPLATE_SUB_RE = re.compile(r"\$\{([^{}]+)\}")
_REVERSE_SUFFIX_RE = re.compile(
    r"^(.*?)\.split\(\s*(['\"`])\2\s*\)\.reverse\(\)\.join\(\s*(['\"`])\3\s*\)$", re.DOTALL
)
_SPLIT_JOIN_RE = re.compile(
    r"^(.*?)\.split\(\s*(['\"`])(.*?)\2\s*\)\.join\(\s*(['\"`])(.*?)\4\s*\)$", re.DOTALL
)
_REPLACE_RE = re.compile(
    r"^(.*?)\.replace\(\s*(?:/(.*?)/[gimsuy]*|(['\"`])(.*?)\3)\s*,\s*(['\"`])(.*?)\5\s*\)$",
    re.DOTALL,
)
_CALL_RE = re.compile(r"^([A-Za-z_$][\w$.]*)\(\s*(.*)\s*\)$", re.DOTALL)


def decode_js_string(s: str) -> str:
    """Unescape the literal escape sequences that survive in page source."""
    s = html.unescape(s)
    out: List[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt == "t":
                out.append("\t")
            elif nxt == "u" and i + 5 < len(s) + 1:
                try:
                    out.append(chr(int(s[i + 2 : i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    out.append(nxt)
            elif nxt == "x" and i + 3 < len(s) + 1:
                try:
                    out.append(chr(int(s[i + 2 : i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    out.append(nxt)
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_B64_ALPHABET_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return ok / len(text)


def _b64(blob: str) -> Optional[str]:
    blob = re.sub(r"\s+", "", blob)
    if not blob:
        return None
    # Reject anything that is not actually base64 before decoding. Python's
    # decoder silently discards non-alphabet bytes, which would otherwise turn
    # arbitrary page text into binary garbage that then looks like a
    # "recovered command" and gets submitted to the sandbox.
    if not _B64_ALPHABET_RE.match(blob):
        return None
    blob = blob.replace("-", "+").replace("_", "/")
    try:
        padded = blob + "=" * (-len(blob) % 4)
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    # UTF-16LE is common for PowerShell -enc payloads embedded in lures.
    if len(raw) > 2 and raw[1::2].count(0) > len(raw) // 4:
        try:
            text = raw.decode("utf-16-le")
            if _printable_ratio(text) >= 0.85:
                return text
        except UnicodeDecodeError:
            pass
    text = raw.decode("utf-8", errors="replace")
    # Decoded bytes that are mostly unprintable were not really base64 text.
    return text if _printable_ratio(text) >= 0.85 else None


def split_top_level(expr: str, sep: str) -> List[str]:
    """Split on `sep` only where it is not inside quotes/brackets."""
    parts: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None
    depth = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(expr):
                cur.append(expr[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in _QUOTES:
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _strip_quotes(term: str) -> Optional[str]:
    if len(term) >= 2 and term[0] in _QUOTES and term[-1] == term[0]:
        return term[1:-1]
    return None


def eval_expr(expr: str, variables: Optional[Dict[str, str]] = None, depth: int = 0) -> Optional[str]:
    """Evaluate a JS string expression to text, or None if unsupported."""
    if depth > 8:
        return None
    variables = variables or {}
    expr = expr.strip().rstrip(";").strip()
    if not expr:
        return None

    parts = split_top_level(expr, "+")
    if len(parts) > 1:
        out: List[str] = []
        for part in parts:
            val = _eval_term(part, variables, depth + 1)
            if val is None:
                return None
            out.append(val)
        return "".join(out)
    return _eval_term(expr, variables, depth + 1)


def _eval_term(term: str, variables: Dict[str, str], depth: int) -> Optional[str]:
    if depth > 8:
        return None
    term = term.strip()
    if not term:
        return None

    # Parenthesised sub-expression.
    if term.startswith("(") and term.endswith(")") and len(split_top_level(term[1:-1], ")")) >= 1:
        inner = eval_expr(term[1:-1], variables, depth + 1)
        if inner is not None:
            return inner

    # `<expr>.split('').reverse().join('')`
    m = _REVERSE_SUFFIX_RE.match(term)
    if m:
        base = _eval_term(m.group(1), variables, depth + 1)
        return base[::-1] if base is not None else None

    m = _SPLIT_JOIN_RE.match(term)
    if m:
        base = _eval_term(m.group(1), variables, depth + 1)
        if base is None:
            return None
        return base.replace(decode_js_string(m.group(3)), decode_js_string(m.group(5)))

    m = _REPLACE_RE.match(term)
    if m:
        base = _eval_term(m.group(1), variables, depth + 1)
        if base is None:
            return None
        needle = m.group(2) if m.group(2) is not None else m.group(4)
        repl = decode_js_string(m.group(6))
        if m.group(2) is not None:
            try:
                return re.sub(m.group(2), repl, base)
            except re.error:
                return None
        return base.replace(decode_js_string(needle), repl)

    # Plain string literal (including template literals with ${var}).
    lit = _strip_quotes(term)
    if lit is not None:
        text = decode_js_string(lit)
        if term[0] == "`" and "${" in text:
            failed = []

            def _sub(mo):
                inner = eval_expr(mo.group(1), variables, depth + 1)
                if inner is None:
                    failed.append(mo.group(1))
                    return mo.group(0)
                return inner

            text = _TEMPLATE_SUB_RE.sub(_sub, text)
            # A placeholder we could not resolve would leave a literal
            # "${...}" in the command. Submitting that to the sandbox would
            # detonate a broken command and produce a misleading report, so
            # report the whole expression as unresolved instead.
            if failed:
                return None
        return text

    # Bare identifier -> resolved variable.
    if _IDENTIFIER_RE.match(term):
        return variables.get(term)

    m = _FROMCHARCODE_RE.match(term)
    if m:
        codes = []
        for c in split_top_level(m.group(1), ","):
            c = c.strip()
            if re.fullmatch(r"0x[0-9a-fA-F]+", c):
                codes.append(int(c, 16))
            elif c.isdigit():
                codes.append(int(c))
            else:
                return None
        return "".join(chr(c) for c in codes) if codes else None

    m = _CALL_RE.match(term)
    if m:
        fn, arg = m.group(1), m.group(2)
        inner = eval_expr(arg, variables, depth + 1)
        if inner is None:
            return None
        fn_short = fn.split(".")[-1]
        if fn_short == "atob":
            return _b64(inner)
        if fn_short in ("decodeURIComponent", "unescape", "decodeURI"):
            return unquote(inner)
        if fn_short in ("String", "toString"):
            return inner
    return None


def resolve_variables(text: str, max_passes: int = 4) -> Dict[str, str]:
    """Build a name -> value map for assignments we can statically evaluate.

    Runs several passes so `var a = "x"; var b = a + "y";` resolves `b` once
    `a` is known.
    """
    raw: Dict[str, str] = {}
    for m in _VAR_ASSIGN_RE.finditer(text):
        raw[m.group(1)] = m.group(2)
    for m in _BARE_ASSIGN_RE.finditer(text):
        raw.setdefault(m.group(1), m.group(2))

    resolved: Dict[str, str] = {}
    for _ in range(max_passes):
        progress = False
        for name, rhs in raw.items():
            if name in resolved:
                continue
            val = eval_expr(rhs, resolved)
            if val is not None:
                resolved[name] = val
                progress = True
        if not progress:
            break
    return resolved


def iter_call_args(text: str, name_pattern: str):
    """Yield the raw argument text of every `<name_pattern>(...)` call.

    Uses balanced-paren scanning rather than a regex so nested calls like
    `writeText(atob(x + "="))` are captured whole.
    """
    for m in re.finditer(name_pattern, text):
        start = m.end()
        while start < len(text) and text[start] != "(":
            if not text[start].isspace():
                break
            start += 1
        if start >= len(text) or text[start] != "(":
            continue
        depth = 0
        quote = None
        i = start
        while i < len(text):
            ch = text[i]
            if quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in _QUOTES:
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    yield text[start + 1 : i]
                    break
            i += 1
