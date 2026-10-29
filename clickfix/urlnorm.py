"""URL normalisation for deduplication.

urlscan issues a fresh scan UUID every time anyone rescans a URL, so UUID
dedup alone lets the same lure through repeatedly -- measured at ~46% waste
in a single 100-result poll, with one URL appearing 14 times.

Normalising collapses the cosmetic variations (scheme case, default ports,
tracking parameters, trailing slashes) that make identical pages look like
distinct URLs, without collapsing meaningful ones: query parameters that
actually select content are preserved.
"""

import re
from typing import Optional, Tuple
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

# Analytics/referral parameters that never change what the page serves.
_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "utm_creative_format",
    "fbclid", "gclid", "gbraid", "wbraid", "dclid", "msclkid", "yclid",
    "mc_cid", "mc_eid", "igshid", "ttclid", "twclid", "li_fat_id",
    "_ga", "_gl", "ref", "referrer", "source", "campaign_id",
}

_DEFAULT_PORTS = {"http": "80", "https": "443"}
_MULTISLASH_RE = re.compile(r"/{2,}")


def normalize_url(url: str) -> str:
    """Return a canonical form of `url` for dedup comparisons.

    Best-effort: an unparseable URL is returned lowercased and stripped rather
    than raising, so a malformed candidate still dedups against itself.
    """
    if not url:
        return ""
    url = url.strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.lower()

    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return url.lower()

    port = parts.port
    if port is not None and _DEFAULT_PORTS.get(scheme) == str(port):
        port = None
    netloc = f"{host}:{port}" if port else host

    path = _MULTISLASH_RE.sub("/", parts.path or "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    if not path:
        path = "/"

    # Keep meaningful query parameters, drop tracking noise, sort for
    # order-independence.
    kept = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_PARAMS
    ]
    query = urlencode(sorted(kept), doseq=True)

    # Fragments are never sent to the server.
    return urlunsplit((scheme, netloc, path, query, ""))


def url_parts(url: str) -> Tuple[str, str]:
    """Return (domain, apex_domain) for cooldown bookkeeping."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return "", ""
    if not host:
        return "", ""
    labels = host.split(".")
    if len(labels) >= 2:
        # Naive apex: good enough for cooldowns, and never used for security
        # decisions. Multi-part TLDs (co.uk) simply yield a slightly narrower
        # apex, which only makes the cooldown more conservative.
        apex = ".".join(labels[-2:])
    else:
        apex = host
    return host, apex
