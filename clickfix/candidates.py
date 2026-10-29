"""Candidate triage.

`task.tags:clickfix` is a community tag applied to a whole scan, and urlscan
scans resources as readily as pages. A single campaign therefore produces
scans of the lure page, of its minified JS bundle, of a .zip it drops, and of
the JSON endpoint that serves the payload -- all carrying the same tag.

Treating all of those as "lure pages" makes the recovery rate meaningless: a
scan of `jquery.min.js` was never going to yield a command, and counting it as
a miss hides real extractor gaps. So we type each candidate up front and keep
that type in the database.

Resource-level candidates are NOT discarded -- some real payloads are only
ever delivered through an XHR/JS resource -- they are just labelled honestly.
"""

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

# --- candidate types -------------------------------------------------------
CAND_LURE_PAGE = "lure_page"        # an HTML page a victim would land on
CAND_API_ENDPOINT = "api_endpoint"  # JSON/text endpoint serving the payload
CAND_RESOURCE_JS = "resource_js"    # a script file scanned on its own
CAND_ARCHIVE = "archive"            # .zip/.rar/.7z etc -- a dropped stage
CAND_BINARY = "binary"              # PE/installer
CAND_NON_PAGE = "non_page"          # image/css/font/media
CAND_UNKNOWN = "unknown"

_ARCHIVE_EXT = (".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".iso", ".img")
_BINARY_EXT = (".exe", ".msi", ".dll", ".scr", ".msix", ".appx")
_NONPAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
                ".css", ".woff", ".woff2", ".ttf", ".mp4", ".webm", ".mp3")
_JS_EXT = (".js", ".mjs", ".jsx")

# Endpoint paths seen serving ClickFix payloads as JSON.
_API_HINTS = ("first_allow", "get_verify", "verify", "allow", "check", "gate",
              "api/", "/cmd", "payload", "callback", "token", "auth")

_HTML_MIME = ("text/html", "application/xhtml")
_JS_MIME = ("javascript", "ecmascript")
_TEXTY_MIME = ("application/json", "text/plain", "text/json")


@dataclass
class CandidateType:
    kind: str
    rank: int          # higher = more likely to yield a payload
    reason: str

    @property
    def is_page_like(self) -> bool:
        return self.kind in (CAND_LURE_PAGE, CAND_API_ENDPOINT)


def _ext(url: str) -> str:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return ""
    for sep in ("?", "#"):
        path = path.split(sep)[0]
    idx = path.rfind(".")
    return path[idx:] if idx >= 0 else ""


def classify_candidate(page_url: str, mime: str = "", title: str = "",
                       status: Optional[int] = None) -> CandidateType:
    """Type a search hit from whatever metadata urlscan gave us."""
    url = (page_url or "").lower()
    mime_l = (mime or "").lower()
    ext = _ext(url)

    if ext in _NONPAGE_EXT or any(mime_l.startswith(m) for m in
                                  ("image/", "font/", "video/", "audio/", "text/css")):
        return CandidateType(CAND_NON_PAGE, 0, f"non_page_asset:{ext or mime_l}")

    if ext in _ARCHIVE_EXT:
        return CandidateType(CAND_ARCHIVE, 20, f"archive_extension:{ext}")

    if ext in _BINARY_EXT:
        return CandidateType(CAND_BINARY, 25, f"binary_extension:{ext}")

    if ext in _JS_EXT or any(m in mime_l for m in _JS_MIME):
        # A JS bundle scanned standalone can still carry the payload.
        return CandidateType(CAND_RESOURCE_JS, 55, f"javascript_resource:{ext or mime_l}")

    if any(hint in url for hint in _API_HINTS) or any(m in mime_l for m in _TEXTY_MIME):
        return CandidateType(CAND_API_ENDPOINT, 85, "payload_endpoint_shape")

    if any(m in mime_l for m in _HTML_MIME) or not ext or ext in (".html", ".htm", ".php", ".aspx"):
        return CandidateType(CAND_LURE_PAGE, 100, "html_page")

    return CandidateType(CAND_UNKNOWN, 40, f"unrecognised:{ext or mime_l or 'no_metadata'}")


def is_probably_not_a_lure(cand: CandidateType) -> bool:
    """True when a miss should NOT be counted against the extractor.

    A scan of an image or a stylesheet was never going to contain a ClickFix
    command, so failing to recover one from it says nothing about extraction
    quality.
    """
    return cand.kind in (CAND_NON_PAGE, CAND_ARCHIVE, CAND_BINARY)
