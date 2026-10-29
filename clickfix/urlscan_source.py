"""Periodic candidate discovery via the urlscan.io search API.

Only reads urlscan's *search* results (scans other people/tools already
submitted) -- this module never submits URLs to urlscan itself, so it works
fine without an API key, just at a lower rate limit.
"""

import datetime
import logging
import time
from typing import Dict, List, Optional

import requests

from config import UrlscanConfig

log = logging.getLogger("clickfix.urlscan")


class Candidate:
    def __init__(self, source_uuid: str, page_url: str, scan_time: str,
                 mime: str = "", title: str = "", status: str = "",
                 task_url: str = "", domain: str = ""):
        self.source_uuid = source_uuid
        self.page_url = page_url
        self.scan_time = scan_time
        # Metadata used to triage the candidate before any fetch happens.
        self.mime = mime
        self.title = title
        self.status = status
        self.task_url = task_url
        self.domain = domain


def _build_query(cfg: UrlscanConfig) -> str:
    since = f"now-{cfg.lookback_minutes}m"
    return f"{cfg.query} AND date:>{since}"


def search_candidates(cfg: UrlscanConfig, max_results: Optional[int] = None) -> List[Candidate]:
    """Search, following urlscan's search_after cursor until `max_results`
    (or one page, when max_results is None -- the cron-poll default).

    Read-only: only retrieves existing scan results, never submits URLs.
    Honours x-rate-limit-remaining and backs off on 429.
    """
    headers = {}
    if cfg.api_key:
        headers["API-Key"] = cfg.api_key

    target = max_results or cfg.page_size
    collected: List[Candidate] = []
    seen_ids = set()
    search_after: Optional[str] = None
    pages = 0

    while len(collected) < target and pages < 50:
        pages += 1
        page_size = min(cfg.page_size, target - len(collected))
        page, cursor, has_more = _search_page(cfg, headers, page_size, search_after)
        for cand in page:
            if cand.source_uuid in seen_ids:
                continue
            seen_ids.add(cand.source_uuid)
            collected.append(cand)
        if not has_more or not cursor or not page:
            break
        search_after = cursor
        time.sleep(0.6)   # ~100 search calls/min ceiling, under the 120 limit

    log.info("urlscan search returned %d candidate(s) over %d page(s)", len(collected), pages)
    return collected


def _search_page(cfg: UrlscanConfig, headers: dict, size: int, search_after: Optional[str]):
    """One page. Returns (candidates, next_cursor, has_more)."""
    params = {"q": _build_query(cfg), "size": size}
    if search_after:
        params["search_after"] = search_after
    # Only send `sort` when explicitly configured: urlscan returns HTTP 403
    # ("not allowed to use a custom sort value") for accounts without the
    # entitlement, which would silently zero out discovery.
    if cfg.sort:
        params["sort"] = cfg.sort

    try:
        resp = requests.get(cfg.base_url, params=params, headers=headers, timeout=30)
    except requests.RequestException as exc:
        log.warning("urlscan search request failed: %s", exc)
        return [], None, False

    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "5"))
        log.warning("urlscan rate-limited us, backing off %ss", retry_after)
        time.sleep(retry_after)
        return [], search_after, True   # caller may retry from the same cursor

    if resp.status_code == 403:
        log.error(
            "urlscan search rejected the request (HTTP 403): %s -- check URLSCAN_API_KEY "
            "and the [urlscan] sort setting",
            resp.text[:200],
        )
        return [], None, False

    if resp.status_code != 200:
        log.warning("urlscan search returned HTTP %s: %s", resp.status_code, resp.text[:300])
        return [], None, False

    remaining = resp.headers.get("x-rate-limit-remaining")
    if remaining is not None and remaining.isdigit() and int(remaining) < 10:
        wait = int(resp.headers.get("x-rate-limit-reset-after", "20"))
        log.warning("urlscan search quota nearly exhausted (%s left); sleeping %ss", remaining, wait)
        time.sleep(wait)

    data = resp.json()
    results = data.get("results", [])
    has_more = bool(data.get("has_more"))
    cursor = None
    if results:
        last_sort = results[-1].get("sort")
        if isinstance(last_sort, list) and last_sort:
            cursor = ",".join(str(x) for x in last_sort)
    candidates = []
    for item in results:
        page = item.get("page", {}) or {}
        task = item.get("task", {}) or {}
        page_url = page.get("url") or task.get("url")
        source_uuid = item.get("_id") or task.get("uuid")
        scan_time = task.get("time", "")
        if not page_url or not source_uuid:
            continue
        candidates.append(
            Candidate(
                source_uuid,
                page_url,
                scan_time,
                mime=page.get("mimeType") or "",
                title=page.get("title") or "",
                status=str(page.get("status") or ""),
                task_url=task.get("url") or "",
                domain=page.get("domain") or "",
            )
        )

    return candidates, cursor, has_more
