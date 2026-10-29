"""Staged dry-run harness around the static + browser extractors.

Safety-first evaluation tool (NOT production, NOT the poll loop):
  * Local fixtures by default. ANY network navigation requires the host to be
    in an explicit allowlist -- live sites are refused (no richmondparkhomes.ca,
    no arbitrary hosts) unless the caller opts them in by host.
  * Static extraction runs first; browser extraction runs ONLY when explicitly
    enabled (use_browser=True).
  * Every captured candidate goes through the existing validator + classifier.
  * Structured JSON evidence is persisted per case (source, mechanism,
    interaction step, timestamp, response provenance, validation, failure),
    with secret redaction and artifact-size caps.
  * It NEVER executes recovered commands, fetches URLs embedded in recovered
    commands, or submits anything to CAPE. There is no CAPE code path here.
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlsplit

from config import Config
from extractor import extract_command
from validate import validate_payload
from classify import classify_payload
from sanitize import evaluate as sanitize_eval

try:
    from browser_extractor import browser_extract, HAVE_PLAYWRIGHT
except Exception:
    HAVE_PLAYWRIGHT = False
    def browser_extract(*a, **k):  # noqa: D401 - fallback
        raise RuntimeError("playwright unavailable")

# Hard safety constants.
SUBMIT_TO_CAPE = False                 # this harness NEVER submits; do not flip
DEFAULT_ALLOWLIST = frozenset({"127.0.0.1", "localhost", "::1"})
MAX_ARTIFACT_CHARS = 8192              # per stored text field
MAX_NET_PROVENANCE = 5


# --- secret redaction ------------------------------------------------------
_REDACT_PATTERNS = (
    (re.compile(r"(?i)\b(api[-_]?key|token|password|passwd|secret|auth|bearer)\b"
                r"(\s*[=:]\s*|\s+)([^\s'\"&]{4,})"), r"\1\2<redacted>"),
    (re.compile(r"://[^/@\s:]+:[^/@\s]+@"), "://<redacted-userinfo>@"),   # URL creds
    (re.compile(r"\b[A-Fa-f0-9]{40,}\b"), "<redacted-hex>"),              # long hex tokens
    (re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b"), "<redacted-b64>"),      # long base64 blobs
)


def redact(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    out = text
    for rx, repl in _REDACT_PATTERNS:
        out = rx.sub(repl, out)
    return out


def _cap(text: Optional[str]):
    """Return (capped_text, truncated_bool)."""
    if text is None:
        return None, False
    if len(text) > MAX_ARTIFACT_CHARS:
        return text[:MAX_ARTIFACT_CHARS], True
    return text, False


def _defang(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    return text.replace("http://", "hxxp://").replace("https://", "hxxps://")


def host_allowed(url: str, allowlist) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host in {h.lower() for h in allowlist}


def _assess(command_text):
    """Validate + classify a captured candidate (DATA only)."""
    if not command_text:
        return {}
    sres = sanitize_eval(command_text, Config().sanitize)
    v = validate_payload(command_text)
    c = classify_payload(command_text)
    capped, trunc = _cap(redact(command_text))
    return {
        "command_sha256": sres.sha256,
        "command_redacted_preview": _defang(capped),
        "command_truncated": trunc,
        "validation_status": v.status,
        "validation_reason": v.reason,
        "payload_type": c.payload_type,
        "cape_package": c.cape_package,
        # a candidate only "counts" as a recovered command if it VALIDATES
        "is_valid_command": bool(v.valid and c.payload_type != "unknown"),
    }


@dataclass
class CaseResult:
    source_url: str
    timestamp: str
    host_allowed: bool
    cape_submitted: bool = False          # ALWAYS False (invariant)
    static: dict = field(default_factory=dict)
    browser: Optional[dict] = None
    notes: List[str] = field(default_factory=list)

    def to_evidence(self) -> dict:
        return {
            "source_url": self.source_url,
            "timestamp": self.timestamp,
            "host_allowed": self.host_allowed,
            "cape_submitted": self.cape_submitted,
            "static": self.static,
            "browser": self.browser,
            "notes": self.notes,
        }


def run_case(url, *, allowlist=DEFAULT_ALLOWLIST, use_browser=False,
             out_dir=None, cfg=None, browser_kw=None) -> CaseResult:
    """Run static (always) then optional browser extraction on one URL.

    A URL whose host is not in `allowlist` is REFUSED: no static fetch, no
    browser navigation. Returns a CaseResult; also persists JSON if out_dir.
    """
    cfg = cfg or Config()
    ts = datetime.now(timezone.utc).isoformat()
    allowed = host_allowed(url, allowlist)
    res = CaseResult(source_url=url, timestamp=ts, host_allowed=allowed)

    if not allowed:
        res.notes.append("refused: host not in allowlist -- no navigation performed")
        res.static = {"recovered": False, "failure_reason": "host_not_allowlisted"}
        _persist(res, out_dir)
        return res

    # --- static first ---
    try:
        sres = extract_command(url, cfg.extract, scan=None, urlscan_cfg=cfg.urlscan)
        st = {
            "recovered": bool(sres.command_text),
            "method": sres.method,
            "layer": sres.layer,
            "failure_reason": sres.failure_reason,
        }
        st.update(_assess(sres.command_text))
        res.static = st
    except Exception as exc:
        res.static = {"recovered": False, "failure_reason": "static_error:%s" % exc.__class__.__name__}

    # --- browser only when explicitly enabled ---
    if use_browser:
        if not HAVE_PLAYWRIGHT:
            res.browser = {"recovered": False, "failure_reason": "playwright_unavailable"}
        else:
            try:
                br = browser_extract(url, **(browser_kw or {}))
                b = {
                    "recovered": bool(br.command_text),
                    "capture_mechanism": br.method,
                    "via_interaction": br.via_interaction,
                    "interaction_steps": br.clicked_selectors,
                    "failure_reason": br.failure_reason,
                    "elapsed_ms": br.elapsed_ms,
                    "response_provenance": [
                        _defang(_cap(redact(x))[0]) for x in (br.network_hits or [])[:MAX_NET_PROVENANCE]
                    ],
                }
                b.update(_assess(br.command_text))
                res.browser = b
            except Exception as exc:
                res.browser = {"recovered": False, "failure_reason": "browser_error:%s" % exc.__class__.__name__}

    _persist(res, out_dir)
    return res


def _persist(res: CaseResult, out_dir):
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", res.source_url)[:120]
    path = os.path.join(out_dir, "evidence_%s.json" % safe)
    with open(path, "w") as fh:
        json.dump(res.to_evidence(), fh, indent=2, default=str)
    res.notes.append("evidence:%s" % path)


def run_suite(cases, *, allowlist=DEFAULT_ALLOWLIST, use_browser=False,
              out_dir=None, cfg=None, browser_kw=None) -> dict:
    """cases: list of {"url":..., "expected": "command"|"none"}.
    Returns a static-vs-browser comparison incl. FP/FN."""
    rows, summary = [], {
        "total": 0,
        "static": {"recovered_valid": 0, "fp": 0, "fn": 0},
        "browser": {"recovered_valid": 0, "fp": 0, "fn": 0, "ran": use_browser},
    }
    for case in cases:
        url = case["url"]
        expected = case.get("expected", "none")
        r = run_case(url, allowlist=allowlist, use_browser=use_browser,
                     out_dir=out_dir, cfg=cfg, browser_kw=browser_kw)
        summary["total"] += 1
        s_valid = bool(r.static.get("is_valid_command"))
        if s_valid:
            summary["static"]["recovered_valid"] += 1
        if s_valid and expected == "none":
            summary["static"]["fp"] += 1
        if (not s_valid) and expected == "command":
            summary["static"]["fn"] += 1
        if use_browser and r.browser:
            b_valid = bool(r.browser.get("is_valid_command"))
            if b_valid:
                summary["browser"]["recovered_valid"] += 1
            if b_valid and expected == "none":
                summary["browser"]["fp"] += 1
            if (not b_valid) and expected == "command":
                summary["browser"]["fn"] += 1
        rows.append({"url": url, "expected": expected,
                     "static_valid": s_valid,
                     "browser_valid": bool(r.browser and r.browser.get("is_valid_command"))})
    return {"summary": summary, "rows": rows}
