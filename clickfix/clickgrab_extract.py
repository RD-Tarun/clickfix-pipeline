"""Static ClickFix command recovery, ported from MHaggis/ClickGrab.

Recovers the pasteable command from a page's HTML/JS *without a browser* by
parsing the clipboard-assembly JavaScript and command patterns. Nothing is
executed; recovered text is treated strictly as DATA.

Patterns reused (with thanks) from https://github.com/MHaggis/ClickGrab
(extractors.py / models.CommonPatterns).
"""
import base64
import re
from typing import List, Tuple

try:
    from extractor import is_plausible_command as _is_plausible_command
except Exception:  # pragma: no cover - extractor always importable in-tree
    def _is_plausible_command(text):
        return bool(text)

# --- command recovery pattern libraries (from ClickGrab CommonPatterns) ------
POWERSHELL_COMMAND_PATTERNS = [
    r'powershell(?:\.exe)?\s+(?:-\w+\s+)*.*',
    r'iex\s*\(.*\)', r'invoke-expression.*?', r'invoke-webrequest.*?',
    r'iwr\s+.*?', r'irm\s+.*?',
    r'cmd\s*/c\s+start\s+/min\s+powershell.*', r'cmd\s+/c\s+.*powershell.*',
    r'powershell\.exe\s+-w\s+hidden\s+(?:-\w+\s+)*.*',
    r'powershell\.exe\s+-ExecutionPolicy\s+[Bb]ypass\s+(?:-\w+\s+)*.*',
    r'powershell\s+-w\s+hidden\s+-c',
    r'\(New-Object\s+(?:System\.)?Net\.WebClient\)\.DownloadString',
    r'IEX\s+\(New-Object\s+(?:System\.)?Net\.WebClient\)\.DownloadString',
    r'mshta\s+https?://\S+', r'msiexec\s+/i\s+https?://\S+',
    r'const\s+command\s*=\s*["\'`]powershell.*?["`]',
    r'const\s+cmd\s*=\s*["\'`]powershell.*?["`]',
    r'const\s+text\s*=\s*["\'`]powershell.*?["`]',
    r'var\s+command\s*=\s*["\'`]powershell.*?["`]',
    r'let\s+command\s*=\s*["\'`]powershell.*?["`]',
]
POWERSHELL_DOWNLOAD_PATTERNS = [
    r'(?:iwr|Invoke-WebRequest|curl|wget|irm|Invoke-RestMethod)\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*(?:iex|Invoke-Expression)',
    r'\.DownloadString\(["\']?(https?://[^"\'\)\s]+)["\']?\)',
    r'["\']?(https?://[^"\'\)\s]+\.(?:ps1|hta))["\']?',
]
ENCODED_PS_PATTERNS = [
    r'powershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{8,})',
    r'-EncodedCommand\s+([A-Za-z0-9+/=]{8,})',
    r'-enc\s+([A-Za-z0-9+/=]{8,})',
]
CLICKFIX_INSTRUCTION_PATTERNS = [
    r'Win(?:dows)?\s*(?:key)?\s*\+\s*R', r'(?:CTRL|Ctrl)\s*\+\s*V',
    r'Win\s*\+\s*X', r'(?:Open|Launch)\s+(?:Windows\s+)?(?:PowerShell|Terminal|Command\s+Prompt)',
    r'(?:copy|paste|run|execute)\s+(?:this|the)\s+(?:command|code|script)',
]

_NOT_A_COMMAND = ("<script", "</script", "function(", "=>", "document.", "window.",
                  "navigator.", "addeventlistener", "queryselector", "getelementby",
                  "innerhtml", "console.log")
_CMD_MARKERS = ("powershell", "pwsh", "mshta", "msiexec", "cmd.exe", "cmd /c", "cmd/c",
                "iex", "irm", "iwr", "-enc", "-nop", "-w hidden", "-windowstyle",
                "curl ", "certutil", "bitsadmin", "rundll32", "regsvr32", "nslookup",
                "net use", "finger ")


def _looks_cmd(t: str) -> bool:
    tl = (t or "").lower()
    return any(m in tl for m in _CMD_MARKERS)


def _too_js(t: str) -> bool:
    tl = (t or "").lower()
    return any(m in tl for m in _NOT_A_COMMAND)


def extract_encoded_powershell(text: str) -> List[Tuple[str, str]]:
    out = []
    for pat in ENCODED_PS_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            enc = m.group(1)
            for codec in ("utf-16le", "utf-8"):
                try:
                    dec = base64.b64decode(enc + "=" * (-len(enc) % 4)).decode(codec, "ignore")
                    if len(dec) > 5 and _looks_cmd(dec):
                        out.append(("encoded_powershell", dec))
                        break
                except Exception:
                    continue
    return out


# A JS string literal of ANY delimiter, capturing its FULL content -- a backtick
# string may legitimately contain " and ', so we must not stop at the first quote.
_JS_STR = r'(`[^`]*`|"[^"]*"|\'[^\']*\')'


def _unquote(s: str) -> str:
    return s[1:-1] if s and s[0] in "`'\"" else s


def _clean_json_embedded(t: str) -> str:
    """Repair a command over-captured out of a JSON per-OS array/object, e.g.
        iex(irm 'h//x')","macos":"curl ... | zsh",""
    A greedy capture runs past the command's closing quote into the next array
    element. Cut right after the command's own closing char ( ) ' } ) when it is
    immediately followed by a JSON separator ( ", / "] / "} ), then undo any
    JSON slash-escaping. The 'closing char + separator' anchor means a legit
    in-command double-quoted array like @("a","b") is left untouched."""
    m = re.search(r"([)\]}'])\s*(?<!\\)\"\s*(?=[,\]}])", t)
    if m:
        t = t[:m.start() + 1]
    if "\\/" in t:
        for a, b in (("\\/", "/"), ('\\"', '"'), ("\\\\", "\\")):
            t = t.replace(a, b)
    return t.strip()


def extract_clipboard_commands(html: str) -> List[Tuple[str, str]]:
    """The core ClickFix recovery: the JS string that gets copied.

    Builds a map of `const/let/var NAME = <string literal>` (delimiter-aware, so
    the full command is captured even when a backtick string embeds quotes),
    then reports (a) any assigned string that itself looks like a command, and
    (b) the value behind a clipboard sink (writeText/setData) that references
    such a variable or passes a literal directly."""
    out = []
    varmap = {}
    for m in re.finditer(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*' + _JS_STR, html, re.DOTALL):
        varmap[m.group(1)] = _unquote(m.group(2))
    # (a) any variable whose value is itself a command
    for name, val in varmap.items():
        if _looks_cmd(val):
            out.append(("clipboard_literal", val))
    # (b) clipboard sink referencing a known variable: writeText(cmd) / setData('text', cmd)
    for m in re.finditer(r'(?:writeText|setData)\s*\(\s*(?:["\'][^"\']*["\']\s*,\s*)?'
                         r'([A-Za-z_$][\w$]*)\s*\)', html):
        v = varmap.get(m.group(1))
        if v and _looks_cmd(v):
            out.append(("clipboard_var", v))
    # (c) clipboard sink with a direct string literal
    for m in re.finditer(r'(?:writeText|setData)\s*\(\s*(?:["\'][^"\']*["\']\s*,\s*)?' + _JS_STR + r'\s*\)',
                         html):
        v = _unquote(m.group(1))
        if _looks_cmd(v):
            out.append(("clipboard_write", v))
    return out


def extract_powershell_commands(text: str) -> List[Tuple[str, str]]:
    out = []
    for pat in POWERSHELL_COMMAND_PATTERNS:
        try:
            for m in re.finditer(pat, text, re.IGNORECASE):
                mt = m.group(0)
                sm = re.search(r'[`\'"]((?:powershell|cmd|mshta|msiexec)[^`\'"]+)[`\'"]', mt, re.IGNORECASE)
                if sm:
                    mt = sm.group(1)
                out.append(("powershell", mt.strip()))
        except re.error:
            continue
    for pat in POWERSHELL_DOWNLOAD_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            out.append(("ps_download", m.group(0).strip()))
    return out


def clickfix_lure_score(text: str) -> int:
    s = 0
    for pat in CLICKFIX_INSTRUCTION_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            s += 1
    return s


def recover_commands(html: str) -> List[dict]:
    """Return de-duplicated recovered command candidates, best-looking first.
    Each: {method, text}. Clipboard-assembly hits rank above generic matches."""
    raw = (extract_clipboard_commands(html)
           + extract_encoded_powershell(html)
           + extract_powershell_commands(html))
    seen, cleaned = set(), []
    for method, text in raw:
        t = _clean_json_embedded((text or "").strip())
        if len(t) < 6 or _too_js(t) or not _looks_cmd(t):
            continue
        # Authoritative gate: must read as a real pasteable command, not lure
        # prose ("PowerShell or Terminal...") or markup. Kills false positives.
        if not _is_plausible_command(t):
            continue
        if t in seen:
            continue
        seen.add(t)
        cleaned.append({"method": method, "text": t})
    rank = {"clipboard_var": 0, "clipboard_literal": 0, "clipboard_write": 1,
            "encoded_powershell": 2, "ps_download": 3, "powershell": 4}
    cleaned.sort(key=lambda c: (rank.get(c["method"], 9), -len(c["text"])))
    return cleaned
