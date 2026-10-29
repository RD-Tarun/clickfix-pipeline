"""urlscan.io Result API access.

The search API only tells us a scan exists. The Result API is where the
useful extraction evidence lives: the original task URL, the final URL after
redirects, the full request/response chain (so we can enumerate the scripts
the page actually loaded), and -- most importantly -- the rendered DOM.

The DOM matters because urlscan already ran the page in a real browser. Any
payload the lure builds at runtime in JavaScript is already materialised
there, which lets us recover commands we could never get from a plain HTTP
GET, without ever executing JavaScript ourselves.

NOTE: unlike /api/v1/search/, both /api/v1/result/<uuid>/ and /dom/<uuid>/
require an API key. Without URLSCAN_API_KEY set they return HTTP 403 and this
whole tier degrades to unavailable (the live-fetch tiers still work).
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from config import UrlscanConfig

log = logging.getLogger("clickfix.urlscan.result")

RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
DOM_URL = "https://urlscan.io/dom/{uuid}/"
# urlscan stores every captured response body keyed by its SHA256; this is how
# we read a resource as urlscan saw it, even after the origin is offline.
RESPONSE_URL = "https://urlscan.io/responses/{body_hash}/"

# Resource kinds worth reading. Images/fonts/media never carry the payload and
# downloading them would waste the rate limit.
_USEFUL_TYPES = {"script", "document", "xhr", "fetch", "subdocument", "iframe", "other"}
_USELESS_MIME = ("image/", "font/", "video/", "audio/", "text/css")
_USEFUL_MIME = ("javascript", "ecmascript", "text/html", "text/plain", "json", "text/")

# Substrings that make a resource far more likely to hold the lure payload.
_INDICATOR_HINTS = (
    "clip", "copy", "verify", "captcha", "human", "robot", "check",
    "fix", "cmd", "command", "payload", "ps1", "powershell", "run",
    "step", "invoke", "shell",
)


@dataclass
class Resource:
    """One resource urlscan captured while rendering the page."""

    url: str
    mime: str = ""
    rtype: str = ""
    body_hash: str = ""
    size: int = 0
    priority: int = 0

    @property
    def readable(self) -> bool:
        """Whether urlscan retained a body we can fetch by hash."""
        return bool(self.body_hash)


def _score_resource(url: str, mime: str, rtype: str) -> int:
    """Rank how likely a resource is to contain the clipboard payload.

    Higher wins. Returns 0 for resources we should not download at all.
    """
    mime_l = (mime or "").lower()
    rtype_l = (rtype or "").lower()
    url_l = (url or "").lower()

    if any(mime_l.startswith(bad) for bad in _USELESS_MIME):
        return 0
    if url_l.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
                       ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".css")):
        return 0

    score = 0
    if "javascript" in mime_l or "ecmascript" in mime_l or url_l.endswith(".js"):
        score += 5
    if rtype_l in ("xhr", "fetch"):
        score += 6          # runtime-fetched payloads are the whole point
    if rtype_l in ("subdocument", "iframe"):
        score += 4
    if rtype_l == "script":
        score += 4
    if rtype_l == "document":
        score += 3
    if "json" in mime_l or "text/plain" in mime_l:
        score += 3
    if "text/html" in mime_l:
        score += 2
    if any(hint in url_l for hint in _INDICATOR_HINTS):
        score += 6

    if score and rtype_l and rtype_l not in _USEFUL_TYPES and not any(
        m in mime_l for m in _USEFUL_MIME
    ):
        return 0
    return score


@dataclass
class ScanDetail:
    """Everything we managed to pull from one urlscan scan."""

    uuid: str
    task_url: Optional[str] = None          # originally submitted URL
    final_url: Optional[str] = None         # URL after redirects
    redirect_chain: List[str] = field(default_factory=list)
    dom: Optional[str] = None
    script_urls: List[str] = field(default_factory=list)
    resource_urls: List[str] = field(default_factory=list)
    result_api_url: Optional[str] = None
    screenshot_url: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    resources: List[Resource] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    frames: List[str] = field(default_factory=list)

    def prioritized_resources(self, limit: int) -> List[Resource]:
        """Readable resources, most promising first."""
        usable = [r for r in self.resources if r.priority > 0 and r.readable]
        usable.sort(key=lambda r: (-r.priority, r.size))
        return usable[:limit]

    @property
    def available(self) -> bool:
        return self.task_url is not None or self.dom is not None


def _headers(cfg: UrlscanConfig) -> Dict[str, str]:
    return {"API-Key": cfg.api_key} if cfg.api_key else {}


def fetch_dom(uuid: str, cfg: UrlscanConfig) -> (Optional[str], Optional[str]):
    """Return (dom_text, failure_note)."""
    if not cfg.api_key:
        return None, "dom_unavailable:no_api_key"
    try:
        resp = requests.get(
            DOM_URL.format(uuid=uuid), headers=_headers(cfg), timeout=cfg.result_timeout
        )
    except requests.RequestException as exc:
        return None, f"dom_unavailable:request_failed:{exc.__class__.__name__}"
    if resp.status_code == 404:
        return None, "dom_unavailable:not_found"
    if resp.status_code == 403:
        return None, "dom_unavailable:forbidden"
    if resp.status_code != 200:
        return None, f"dom_unavailable:http_{resp.status_code}"
    text = resp.text
    if len(text) > cfg.max_dom_bytes:
        text = text[: cfg.max_dom_bytes]
    return text, None


def fetch_response_body(body_hash: str, cfg: UrlscanConfig):
    """Fetch one captured response body by its SHA256. Returns (text, note)."""
    if not cfg.api_key:
        return None, "resource_fetch_failure:no_api_key"
    try:
        resp = requests.get(
            RESPONSE_URL.format(body_hash=body_hash),
            headers=_headers(cfg),
            timeout=cfg.result_timeout,
        )
    except requests.RequestException as exc:
        return None, f"resource_fetch_failure:{exc.__class__.__name__}"
    if resp.status_code == 404:
        return None, "resource_fetch_failure:body_not_retained"
    if resp.status_code != 200:
        return None, f"resource_fetch_failure:http_{resp.status_code}"
    text = resp.text
    if len(text) > cfg.max_dom_bytes:
        text = text[: cfg.max_dom_bytes]
    return text, None


@dataclass
class ResultFetch:
    """Outcome of one Result API call, with the status spelled out so callers
    can back off (rate_limited/timeout) or stop (not_found/forbidden) without
    guessing from an exception type. `payload` is the raw JSON on success."""

    uuid: str
    status: str                       # ok|no_api_key|not_found|forbidden|rate_limited|
                                      # timeout|request_failed|bad_json|http_error
    http_code: Optional[int] = None
    payload: Optional[dict] = None
    retry_after: Optional[int] = None
    note: Optional[str] = None


def fetch_result_json(uuid: str, cfg: UrlscanConfig) -> ResultFetch:
    """Fetch the raw Result API JSON for one existing scan.

    Reuses the shared key/header handling. Never raises: every failure maps to
    a status so the feeder can decide whether to retry, skip, or record the
    scan as unavailable. This does NOT submit a scan or browse the URL.
    """
    if not cfg.api_key:
        return ResultFetch(uuid, "no_api_key", note="result_unavailable:no_api_key")
    try:
        resp = requests.get(
            RESULT_URL.format(uuid=uuid), headers=_headers(cfg), timeout=cfg.result_timeout
        )
    except requests.Timeout:
        return ResultFetch(uuid, "timeout", note="request_timeout")
    except requests.RequestException as exc:
        return ResultFetch(uuid, "request_failed", note=exc.__class__.__name__)

    if resp.status_code == 200:
        try:
            return ResultFetch(uuid, "ok", 200, payload=resp.json())
        except ValueError:
            return ResultFetch(uuid, "bad_json", 200, note="bad_json")
    if resp.status_code == 404:
        return ResultFetch(uuid, "not_found", 404, note="scan_unavailable_or_deleted")
    if resp.status_code == 403:
        return ResultFetch(uuid, "forbidden", 403, note="forbidden_or_private")
    if resp.status_code == 429:
        ra = resp.headers.get("Retry-After")
        return ResultFetch(uuid, "rate_limited", 429,
                           retry_after=int(ra) if ra and ra.isdigit() else None)
    return ResultFetch(uuid, "http_error", resp.status_code, note=f"http_{resp.status_code}")


def fetch_scan_detail(uuid: str, cfg: UrlscanConfig) -> ScanDetail:
    """Pull the Result API record + rendered DOM for one scan.

    Never raises: any failure is recorded in `notes` so the caller can fall
    back to live fetching and still report a precise reason.
    """
    detail = ScanDetail(uuid=uuid, result_api_url=RESULT_URL.format(uuid=uuid))

    if not cfg.api_key:
        detail.notes.append("result_unavailable:no_api_key")
    else:
        try:
            resp = requests.get(
                RESULT_URL.format(uuid=uuid), headers=_headers(cfg), timeout=cfg.result_timeout
            )
            if resp.status_code == 200:
                _parse_result(resp.json(), detail)
            elif resp.status_code == 404:
                detail.notes.append("result_unavailable:not_found")
            elif resp.status_code == 403:
                detail.notes.append("result_unavailable:forbidden")
            else:
                detail.notes.append(f"result_unavailable:http_{resp.status_code}")
        except requests.RequestException as exc:
            detail.notes.append(f"result_unavailable:request_failed:{exc.__class__.__name__}")
        except ValueError:
            detail.notes.append("result_unavailable:bad_json")

    dom, dom_note = fetch_dom(uuid, cfg)
    detail.dom = dom
    if dom_note:
        detail.notes.append(dom_note)
    return detail


def _parse_result(payload: dict, detail: ScanDetail) -> None:
    task = payload.get("task") or {}
    page = payload.get("page") or {}

    detail.task_url = task.get("url")
    detail.final_url = page.get("url") or task.get("url")
    detail.screenshot_url = task.get("screenshotURL")

    data = payload.get("data") or {}
    requests_list = data.get("requests") or []

    seen_scripts, seen_resources, chain = [], [], []
    resources: List[Resource] = []
    seen_hashes = set()
    for entry in requests_list:
        req_wrap = entry.get("request") or {}
        req = req_wrap.get("request") or {}
        url = req.get("url")
        rtype = (req_wrap.get("type") or "").lower()

        resp_wrap = entry.get("response") or {}
        resp_meta = resp_wrap.get("response") or {}
        mime = (resp_meta.get("mimeType") or "").lower()
        body_hash = resp_wrap.get("hash") or ""
        size = int(resp_wrap.get("size") or resp_meta.get("encodedDataLength") or 0)

        if url:
            if rtype == "script" and url not in seen_scripts:
                seen_scripts.append(url)
            if url not in seen_resources:
                seen_resources.append(url)

            priority = _score_resource(url, mime, rtype)
            key = body_hash or url
            if priority > 0 and key not in seen_hashes:
                seen_hashes.add(key)
                resources.append(
                    Resource(url=url, mime=mime, rtype=rtype, body_hash=body_hash,
                             size=size, priority=priority)
                )
            if rtype in ("subdocument", "iframe") and url not in detail.frames:
                detail.frames.append(url)

        # Redirect hops are recorded as redirectResponse entries.
        redirect = (entry.get("request") or {}).get("redirectResponse") or {}
        if redirect.get("url") and redirect["url"] not in chain:
            chain.append(redirect["url"])

        resp_meta = (entry.get("response") or {}).get("response") or {}
        if resp_meta.get("status") in (301, 302, 303, 307, 308):
            loc = (resp_meta.get("headers") or {}).get("Location") or (
                resp_meta.get("headers") or {}
            ).get("location")
            if loc and loc not in chain:
                chain.append(loc)

    # data.redirects is the authoritative hop list when present.
    for hop in (data.get("redirects") or []):
        for key in ("from", "to"):
            u = hop.get(key) if isinstance(hop, dict) else None
            if u and u not in chain:
                chain.append(u)

    if detail.task_url and detail.task_url not in chain:
        chain.insert(0, detail.task_url)
    if detail.final_url and detail.final_url not in chain:
        chain.append(detail.final_url)

    detail.redirect_chain = chain
    detail.script_urls = seen_scripts
    detail.resource_urls = seen_resources
    detail.resources = resources

    # data.links: anchors urlscan found on the rendered page.
    for link in (data.get("links") or [])[:200]:
        href = link.get("href") if isinstance(link, dict) else link
        if href and href not in detail.links:
            detail.links.append(href)

    # `lists.urls` catches resources the request log missed.
    lists = payload.get("lists") or {}
    for url in (lists.get("urls") or [])[:200]:
        if url not in detail.resource_urls:
            detail.resource_urls.append(url)
