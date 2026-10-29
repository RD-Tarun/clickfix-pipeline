"""Payload classification: decide what a recovered payload actually IS, and
which CAPE analysis package will execute it faithfully.

This is deliberately not a "does it contain the word powershell" check. A
ClickFix payload can be a raw PowerShell script body with no interpreter
prefix, a one-liner starting with powershell.exe, a cmd.exe command line that
happens to invoke PowerShell, a pure batch command, or a base64-wrapped PE.
Each needs a different CAPE package, and running one under the wrong package
produces a failed detonation and a misleading report.

Ambiguity is resolved by classifying as `unknown`, never by guessing: unknown
payloads are recorded and held back from automatic submission.
"""

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import List, Optional

from lurepatterns import normalize_for_detection

# --- payload types ---------------------------------------------------------
TYPE_POWERSHELL = "powershell"
TYPE_BATCH = "batch_cmd"
TYPE_PE = "pe_executable"
TYPE_UNKNOWN = "unknown"

# --- subtypes --------------------------------------------------------------
SUB_PS_SCRIPT = "ps_script_body"      # raw script, no interpreter prefix
SUB_PS_ONELINER = "ps_oneliner"       # starts with powershell/pwsh
SUB_PS_VIA_CMD = "ps_via_cmd"         # cmd.exe /c ... powershell ...
SUB_CMD_ONELINER = "cmd_oneliner"     # cmd.exe /c <not powershell>
SUB_MSIEXEC = "msiexec_remote_install"  # msiexec /i <remote url> -- run via cmd
SUB_BAT_SCRIPT = "bat_script"         # @echo off / labels / goto
SUB_PE_BASE64 = "pe_base64"
SUB_PE_RAW = "pe_raw"
SUB_NONE = ""

# --- CAPE packages ---------------------------------------------------------
PKG_PS1 = "ps1"
PKG_BATCH = "batch"
PKG_EXE = "exe"
PKG_NONE = ""

_PS_INTERPRETER_RE = re.compile(
    r"^\s*[\"']?(?:[a-z]:\\\\?[^\s\"']*\\)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)[\"']?\s",
    re.IGNORECASE,
)
_CMD_INTERPRETER_RE = re.compile(
    r"^\s*[\"']?(?:[a-z]:\\\\?[^\s\"']*\\)?cmd(?:\.exe)?[\"']?\s*/(?:c|k)\b", re.IGNORECASE
)
# Bare LOLBIN command lines that fetch + execute a remote stage. These ARE the
# whole payload (the classic "msiexec /i http://..." and "mshta http://..."
# ClickFix lures), and run faithfully as a cmd command line under `batch`.
_MSIEXEC_RE = re.compile(r"^\s*msiexec(?:\.exe)?\s+/[iI]\b.*https?://", re.IGNORECASE | re.DOTALL)
_MSHTA_RE = re.compile(r"^\s*mshta(?:\.exe)?\s+https?://", re.IGNORECASE)
_RUNDLL_RE = re.compile(r"^\s*rundll32(?:\.exe)?\s+", re.IGNORECASE)
_REGSVR_RE = re.compile(r"^\s*regsvr32(?:\.exe)?\s+", re.IGNORECASE)
_PS_TOKENS = (
    "new-object", "invoke-expression", "invoke-webrequest", "invoke-restmethod",
    "start-process", "expand-archive", "write-host", "out-null", "test-path",
    "new-item", "get-item", "set-item", "add-mppreference", "add-type",
    "downloadstring", "downloadfile", "net.webclient", "frombase64string",
    "iex", "irm", "iwr", "$env:", "-executionpolicy", "join-path",
    "convertto-securestring", "start-sleep", "remove-item", "copy-item",
)
_BATCH_TOKENS = (
    "@echo off", "@echo on", "setlocal", "endlocal", "goto ", ":eof",
    "%~dp0", "%comspec%", "%temp%", "%appdata%", "if exist ", "for /f",
    "start /wait", "net use ", "reg add ", "schtasks ", "del /", "copy /",
)
_PE_B64_PREFIXES = ("TVqQ", "TVpQ", "TVoA", "TVro", "TVpB")
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")

# Wrappers that hide the real interpreter one level down.
_WRAPPER_RE = re.compile(
    r"^\s*(?:start\s+(?:/\w+\s+)*|\"\"\s*)?", re.IGNORECASE
)


@dataclass
class Classification:
    payload_type: str = TYPE_UNKNOWN
    subtype: str = SUB_NONE
    cape_package: str = PKG_NONE
    reason: str = ""
    confidence: int = 0
    signals: List[str] = field(default_factory=list)

    @property
    def submittable(self) -> bool:
        """Only a confidently-typed payload with a package may be submitted."""
        return self.payload_type != TYPE_UNKNOWN and bool(self.cape_package)


def _looks_like_pe(text: str) -> Optional[str]:
    stripped = text.strip()
    if stripped.startswith("MZ") and "This program cannot be run" in stripped[:512]:
        return SUB_PE_RAW
    for m in _BASE64_BLOB_RE.finditer(stripped):
        blob = m.group(0)
        if blob[:4] in _PE_B64_PREFIXES:
            return SUB_PE_BASE64
        try:
            head = base64.b64decode(blob[:64] + "=" * (-len(blob[:64]) % 4), validate=False)
            if head[:2] == b"MZ":
                return SUB_PE_BASE64
        except (binascii.Error, ValueError):
            continue
    return None


def _count_tokens(lowered: str, tokens) -> List[str]:
    return [t.strip() for t in tokens if t in lowered]


def classify_payload(text: str) -> Classification:
    """Classify a recovered payload. Never raises; never guesses."""
    if not text or not text.strip():
        return Classification(reason="empty_payload", confidence=0)

    raw = text.strip()
    # Detection only -- homoglyph folding must not reach the stored payload.
    detect = normalize_for_detection(raw)
    lowered = detect.lower()

    # --- PE executable ----------------------------------------------------
    pe_sub = _looks_like_pe(detect)
    if pe_sub:
        return Classification(
            payload_type=TYPE_PE,
            subtype=pe_sub,
            cape_package=PKG_EXE,
            reason="pe_header_detected",
            confidence=90,
            signals=["MZ_header"],
        )

    ps_tokens = _count_tokens(lowered, _PS_TOKENS)
    bat_tokens = _count_tokens(lowered, _BATCH_TOKENS)

    # --- bare LOLBIN remote-install command lines ------------------------
    # msiexec /i <url>, mshta <url>, rundll32, regsvr32 : the command line IS
    # the payload, and CAPE's file-based msi package expects a local .msi, so
    # these detonate faithfully as a cmd command line under `batch`.
    if _MSIEXEC_RE.match(detect):
        return Classification(
            payload_type=TYPE_BATCH, subtype=SUB_MSIEXEC, cape_package=PKG_BATCH,
            reason="msiexec_remote_install", confidence=85,
            signals=["msiexec", "/i", "remote_url"],
        )
    for rx, name in ((_MSHTA_RE, "mshta_remote"), (_RUNDLL_RE, "rundll32"),
                     (_REGSVR_RE, "regsvr32")):
        if rx.match(detect):
            return Classification(
                payload_type=TYPE_BATCH, subtype=SUB_CMD_ONELINER, cape_package=PKG_BATCH,
                reason=name, confidence=80, signals=[name.split("_")[0]],
            )

    # --- cmd.exe /c wrapper ----------------------------------------------
    if _CMD_INTERPRETER_RE.match(detect):
        if "powershell" in lowered or "pwsh" in lowered:
            # PowerShell, but launched by cmd -- the artifact is a cmd command
            # line, so it must run under the batch package to stay faithful.
            return Classification(
                payload_type=TYPE_POWERSHELL,
                subtype=SUB_PS_VIA_CMD,
                cape_package=PKG_BATCH,
                reason="cmd_interpreter_launching_powershell",
                confidence=85,
                signals=["cmd_/c", "powershell"] + ps_tokens[:4],
            )
        return Classification(
            payload_type=TYPE_BATCH,
            subtype=SUB_CMD_ONELINER,
            cape_package=PKG_BATCH,
            reason="cmd_interpreter_prefix",
            confidence=80,
            signals=["cmd_/c"] + bat_tokens[:4],
        )

    # --- explicit PowerShell interpreter ---------------------------------
    if _PS_INTERPRETER_RE.match(detect):
        return Classification(
            payload_type=TYPE_POWERSHELL,
            subtype=SUB_PS_ONELINER,
            cape_package=PKG_PS1,
            reason="powershell_interpreter_prefix",
            confidence=90,
            signals=["powershell_prefix"] + ps_tokens[:4],
        )

    # --- batch script body ------------------------------------------------
    if len(bat_tokens) >= 2 and len(bat_tokens) > len(ps_tokens):
        return Classification(
            payload_type=TYPE_BATCH,
            subtype=SUB_BAT_SCRIPT,
            cape_package=PKG_BATCH,
            reason=f"batch_tokens={len(bat_tokens)}",
            confidence=70,
            signals=bat_tokens[:6],
        )

    # --- raw PowerShell script body --------------------------------------
    # No interpreter prefix, but unmistakably PowerShell: cmdlet verbs,
    # $variables, .NET type calls. This is how JSON-delivered payloads arrive.
    if len(ps_tokens) >= 2:
        return Classification(
            payload_type=TYPE_POWERSHELL,
            subtype=SUB_PS_SCRIPT,
            cape_package=PKG_PS1,
            reason=f"powershell_tokens={len(ps_tokens)}",
            confidence=75 if len(ps_tokens) >= 3 else 60,
            signals=ps_tokens[:6],
        )

    if len(ps_tokens) == 1 and re.search(r"\$\w+\s*=", detect):
        return Classification(
            payload_type=TYPE_POWERSHELL,
            subtype=SUB_PS_SCRIPT,
            cape_package=PKG_PS1,
            reason="powershell_token_plus_variable_assignment",
            confidence=55,
            signals=ps_tokens + ["$var="],
        )

    # --- give up ----------------------------------------------------------
    return Classification(
        payload_type=TYPE_UNKNOWN,
        subtype=SUB_NONE,
        cape_package=PKG_NONE,
        reason="no_confident_interpreter_match",
        confidence=0,
        signals=(ps_tokens + bat_tokens)[:6],
    )
