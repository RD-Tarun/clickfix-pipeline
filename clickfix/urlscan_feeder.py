"""Ingest an existing urlscan.io scan result into the passive collection DB.

Passive and read-only: it fetches the Result API record for a scan UUID that
*already exists* (reusing the shared client in `urlscan_result`), and records
what that scan observed -- the original/final URL, page hostname and IP,
contacted domains and IPs, the domain->IP resolutions urlscan saw, and any
delivered-payload artifacts with the SHA256 urlscan already computed. It never
submits a new scan, never browses the suspicious URL, performs no WHOIS/RDAP,
and downloads no payload body.

Safety and correctness properties:
  * Dry-run is the default. A dry run computes and reports the ingest plan but
    writes nothing to the DB or disk. `--commit` performs the writes.
  * Idempotent: a per-scan marker in `enrichment_runs` means a committed scan
    is skipped on re-run (no duplicate rows, no counter inflation); `--force`
    re-ingests.
  * Failures never invent data. no_api_key / not_found (deleted or private) /
    forbidden / bad_json / exhausted rate-limit / timeout each record the
    outcome in `enrichment_runs` and insert no observations.
  * Rate limits and timeouts are retried with capped exponential backoff,
    honouring any Retry-After urlscan sends.
  * Only globally-routable IPs are collected. Raw JSON is size-capped and
    written atomically under a UUID-validated filename.
  * The API key comes from config/env via the existing client; it is never
    logged or printed.

The HTTP fetch is injectable (`fetcher`) and so is the sleep (`sleeper`), so
tests exercise every path -- valid, missing fields, 429, timeout, deleted --
with no network and no real delay.
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse

from collection import CollectionStore, artifact_key
from urlscan_result import ResultFetch, fetch_result_json

log = logging.getLogger("clickfix.urlscan.feeder")

_INGEST_LOOKUP = "urlscan_ingest"
_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")

# Extensions that mark a delivered payload worth recording as an artifact.
# Deliberately excludes .js/.css/images: those are page assets, not payloads,
# and recording them would flood the corpus.
_PAYLOAD_EXT = {
    ".msi", ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".jar",
    ".scr", ".zip", ".7z", ".rar", ".lnk", ".iso", ".img", ".cab",
}
_PAYLOAD_MIME = (
    "application/octet-stream", "application/x-msdownload", "application/x-msi",
    "application/x-ms-installer", "application/vnd.microsoft.portable-executable",
    "application/x-dosexec", "application/zip", "application/x-zip-compressed",
    "application/java-archive", "application/x-msdos-program",
)
_EXT_TYPE = {
    ".msi": "msi", ".exe": "exe", ".dll": "dll", ".ps1": "ps1", ".bat": "command",
    ".cmd": "command", ".vbs": "vbs", ".hta": "hta", ".jar": "jar", ".scr": "exe",
    ".zip": "zip", ".7z": "archive", ".rar": "archive", ".lnk": "lnk", ".iso": "iso",
    ".img": "iso", ".cab": "archive",
}
# Web assets are never payloads, even when a CDN mislabels them as
# application/octet-stream (e.g. Cloudflare serving .woff2 fonts). An explicit
# benign-extension guard keeps these out of the artifact corpus.
_BENIGN_EXT = (
    ".woff2", ".woff", ".ttf", ".eot", ".otf", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".avif", ".bmp",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".m4a",
)


def _is_routable(addr) -> bool:
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except (ValueError, TypeError):
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local
                or ip.is_unspecified or ip.is_reserved)


def _host(url) -> Optional[str]:
    try:
        return urlparse(url).hostname
    except (ValueError, AttributeError):
        return None


def _payload_type(url: str, mime: str = "") -> Optional[str]:
    path = (urlparse(url).path or "").lower()
    for ext, t in _EXT_TYPE.items():
        if path.endswith(ext):
            return t
    # A benign web-asset extension is never a payload, whatever the MIME says.
    if path.endswith(_BENIGN_EXT):
        return None
    if any(mime.lower().startswith(m) for m in _PAYLOAD_MIME):
        return "download"
    return None


def _asn_int(asn) -> Optional[int]:
    if asn is None:
        return None
    m = re.search(r"(\d+)", str(asn))
    return int(m.group(1)) if m else None


@dataclass
class ScanObservations:
    """Everything a single scan's JSON yielded (pure parse, no DB/network)."""

    uuid: str
    scan_time: Optional[str] = None
    task_url: Optional[str] = None
    final_url: Optional[str] = None
    page_domain: Optional[str] = None
    page_ip: Optional[str] = None
    page_asn: Optional[int] = None
    page_as_org: Optional[str] = None
    page_country: Optional[str] = None
    domains: set = field(default_factory=set)
    ips: dict = field(default_factory=dict)          # ip -> {asn, as_org, country}
    dns: list = field(default_factory=list)          # (domain, rrtype, ip)
    artifacts: list = field(default_factory=list)    # dict(sha256,url,type,domain,status)
    cert_count: int = 0
    hash_count: int = 0
    resource_url_count: int = 0

    def plan_counts(self) -> dict:
        return {"domains": len(self.domains), "ips": len(self.ips),
                "dns_records": len(self.dns), "artifacts": len(self.artifacts)}


def extract_observations(payload: dict, uuid: str) -> ScanObservations:
    """Parse a urlscan Result JSON into observations. Pure: no I/O.

    Missing sections simply yield empty collections -- never fabricated rows.
    """
    payload = payload or {}
    task = payload.get("task") or {}
    page = payload.get("page") or {}
    lists = payload.get("lists") or {}
    data = payload.get("data") or {}

    obs = ScanObservations(
        uuid=task.get("uuid") or uuid,
        scan_time=task.get("time"),
        task_url=task.get("url"),
        final_url=page.get("url") or task.get("url"),
        page_domain=(page.get("domain") or "").lower() or None,
        page_ip=page.get("ip"),
        page_asn=_asn_int(page.get("asn")),
        page_as_org=page.get("asnname") or page.get("asname"),
        page_country=page.get("country"),
    )

    # Domains: urlscan's contacted-domain list, the page domain, and the
    # hostnames of the task/final URLs.
    for d in (lists.get("domains") or []):
        if d:
            obs.domains.add(str(d).lower())
    for d in (obs.page_domain, _host(obs.task_url), _host(obs.final_url)):
        if d:
            obs.domains.add(d.lower())

    # IPs: contacted-IP list + page IP (carrying its ASN/country). Only global.
    def _note_ip(addr, asn=None, as_org=None, country=None):
        if addr and _is_routable(addr):
            rec = obs.ips.setdefault(str(addr), {"asn": None, "as_org": None, "country": None})
            rec["asn"] = rec["asn"] or asn
            rec["as_org"] = rec["as_org"] or as_org
            rec["country"] = rec["country"] or country

    for ip in (lists.get("ips") or []):
        _note_ip(ip)
    _note_ip(obs.page_ip, obs.page_asn, obs.page_as_org, obs.page_country)

    # DNS resolutions urlscan observed: page domain -> page IP, plus each
    # request's hostname -> remoteIPAddress.
    seen_dns = set()
    def _note_dns(domain, addr):
        if not domain or not addr or not _is_routable(addr):
            return
        rrtype = "AAAA" if ":" in str(addr) else "A"
        key = (domain.lower(), rrtype, str(addr))
        if key not in seen_dns:
            seen_dns.add(key)
            obs.dns.append(key)

    _note_dns(obs.page_domain, obs.page_ip)

    seen_art = set()
    def _note_artifact(sha256, url, atype, domain, status):
        key = artifact_key(sha256, url) if (sha256 or url) else None
        if key is None or key in seen_art:
            return
        seen_art.add(key)
        obs.artifacts.append({"sha256": sha256, "url": url, "type": atype,
                              "domain": domain, "status": status})

    for entry in (data.get("requests") or []):
        if not isinstance(entry, dict):
            continue
        req = ((entry.get("request") or {}).get("request") or {})
        url = req.get("url")
        resp = entry.get("response") or {}
        meta = resp.get("response") or {}
        remote_ip = meta.get("remoteIPAddress")
        mime = (meta.get("mimeType") or "")
        body_hash = resp.get("hash") or ""
        host = _host(url)
        if host:
            obs.domains.add(host.lower())
        _note_ip(remote_ip)
        _note_dns(host, remote_ip)
        if url:
            atype = _payload_type(url, mime)
            if atype:
                # urlscan retained the body (hash present) -> available in TI
                # but not acquired by us; otherwise just a referenced URL.
                if body_hash:
                    _note_artifact(body_hash, url, atype, host, "available_in_ti")
                else:
                    _note_artifact(None, url, atype, host, "not_acquired")

    # A task URL that is itself a direct download is a payload, too.
    if obs.task_url:
        atype = _payload_type(obs.task_url)
        if atype:
            _note_artifact(None, obs.task_url, atype, _host(obs.task_url), "not_acquired")

    obs.cert_count = len(lists.get("certificates") or [])
    obs.hash_count = len(lists.get("hashes") or [])
    obs.resource_url_count = len(lists.get("urls") or [])
    return obs


def _store_raw(payload: dict, uuid: str, raw_dir: str, max_bytes: int) -> dict:
    """Write raw scan JSON atomically under a validated filename. Returns a
    dict describing the outcome (never raises for size/path issues)."""
    if not _UUID_RE.match(uuid):
        return {"stored": False, "reason": "invalid_uuid"}
    blob = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    if len(blob) > max_bytes:
        return {"stored": False, "reason": "oversize", "size": len(blob), "cap": max_bytes}
    os.makedirs(raw_dir, exist_ok=True)
    dest = os.path.join(raw_dir, f"{uuid}.json")
    tmp = dest + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(blob)
    os.replace(tmp, dest)
    return {"stored": True, "path": dest, "size": len(blob)}


def _fetch_with_backoff(uuid, cfg, fetcher, sleeper, max_retries, base_backoff,
                        max_backoff) -> ResultFetch:
    attempt = 0
    while True:
        rf = fetcher(uuid, cfg)
        transient = rf.status in ("rate_limited", "timeout")
        if transient and attempt < max_retries:
            delay = rf.retry_after if (rf.status == "rate_limited" and rf.retry_after) \
                else base_backoff * (2 ** attempt)
            sleeper(min(delay, max_backoff))
            attempt += 1
            continue
        return rf


def ingest_scan(store: CollectionStore, cfg, uuid: str, *, raw_dir: str,
                max_raw_bytes: int = 8_000_000, dry_run: bool = True, force: bool = False,
                source: Optional[str] = None,
                fetcher: Callable[..., ResultFetch] = fetch_result_json,
                sleeper: Callable[[float], None] = time.sleep,
                max_retries: int = 3, base_backoff: float = 2.0,
                max_backoff: float = 60.0) -> dict:
    """Ingest one existing scan UUID. Returns a summary dict.

    dry_run=True (default) writes nothing. The HTTP fetch is still performed so
    the plan reflects real data, unless `fetcher` is overridden (tests).
    """
    uuid = uuid.strip()
    src = source or f"urlscan:{uuid}"
    prior = store.last_enrichment("scan", uuid, _INGEST_LOOKUP)
    already = prior is not None and prior["status"] == "ok"
    if already and not force and not dry_run:
        return {"uuid": uuid, "skipped": True, "reason": "already ingested",
                "ingested_at": prior["ran_at"]}

    rf = _fetch_with_backoff(uuid, cfg, fetcher, sleeper, max_retries, base_backoff, max_backoff)
    if rf.status != "ok" or not rf.payload:
        status = "quota" if rf.status == "rate_limited" else rf.status
        note = rf.note or rf.status
        if not dry_run:
            store.record_enrichment("scan", uuid, "urlscan_fetch", status, detail=note)
        return {"uuid": uuid, "skipped": False, "fetched": False, "dry_run": dry_run,
                "status": status, "http_code": rf.http_code, "note": note}

    obs = extract_observations(rf.payload, uuid)
    plan = obs.plan_counts()
    manifest = {"uuid": obs.uuid, "scan_time": obs.scan_time, "task_url": obs.task_url,
                "final_url": obs.final_url, "page_domain": obs.page_domain,
                "page_ip": obs.page_ip, "counts": plan,
                "certificates": obs.cert_count, "response_hashes": obs.hash_count,
                "resource_urls": obs.resource_url_count}

    if dry_run:
        return {"uuid": uuid, "skipped": False, "fetched": True, "dry_run": True,
                "status": "ok", "already_ingested": already, "would_insert": plan,
                "manifest": manifest}

    # --- Commit -----------------------------------------------------------
    inserted = {"domains": 0, "ips": 0, "dns_records": 0, "artifacts": 0,
                "artifact_sources": 0}
    for dom in sorted(obs.domains):
        _, new = store.upsert_domain(dom, source=src)
        inserted["domains"] += int(new)
    for ip, meta in sorted(obs.ips.items()):
        _, new = store.upsert_ip(ip, asn=meta.get("asn"), as_org=meta.get("as_org"),
                                 country=meta.get("country"), source=src)
        inserted["ips"] += int(new)
    for domain, rrtype, addr in obs.dns:
        _, new = store.record_dns(domain, rrtype, addr, source=src)
        inserted["dns_records"] += int(new)
    for art in obs.artifacts:
        _, new = store.upsert_payload_artifact(
            sha256=art["sha256"], url=art["url"], artifact_type=art["type"],
            served_by_domain=art["domain"], acquisition_status=art["status"],
            source=src, notes=f"observed by urlscan {uuid}",
        )
        inserted["artifacts"] += int(new)
        _, e = store.link_artifact_source(
            artifact_key(art["sha256"], art["url"]), domain=art["domain"],
            url=art["url"], source=src,
        )
        inserted["artifact_sources"] += int(e)

    raw = _store_raw(rf.payload, uuid, raw_dir, max_raw_bytes)
    manifest["raw"] = raw
    manifest["inserted"] = inserted
    store.record_enrichment("scan", uuid, "urlscan_fetch", "ok", detail=rf.note or "ok")
    store.record_enrichment("scan", uuid, _INGEST_LOOKUP, "ok", detail=json.dumps(manifest))
    return {"uuid": uuid, "skipped": False, "fetched": True, "dry_run": False,
            "status": "ok", "forced": force and already, "inserted": inserted,
            "raw": raw, "manifest": manifest}


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="urlscan_feeder",
        description="Ingest an existing urlscan.io scan result into the passive collection DB. "
                    "Dry-run by default; pass --commit to write.",
    )
    p.add_argument("uuid", help="an EXISTING urlscan scan UUID (never submits a new scan)")
    p.add_argument("--commit", action="store_true",
                   help="perform the writes (default is a no-write dry run)")
    p.add_argument("--db", default=None, help="collection DB path (default: config)")
    p.add_argument("--raw-dir", default=None, help="raw-JSON evidence dir (default: config)")
    p.add_argument("--source", default=None, help="override provenance source tag")
    p.add_argument("--force", action="store_true", help="re-ingest even if already recorded")
    p.add_argument("--max-retries", type=int, default=3)
    return p


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _build_arg_parser().parse_args(argv)
    if not _UUID_RE.match(args.uuid.strip()):
        print(f"error: {args.uuid!r} is not a valid scan UUID", file=sys.stderr)
        return 2
    from config import load_config
    cfg = load_config()
    db_path = args.db or cfg.pipeline.collection_db_path
    raw_dir = args.raw_dir or cfg.pipeline.urlscan_raw_dir
    with CollectionStore(db_path) as store:
        summary = ingest_scan(
            store, cfg.urlscan, args.uuid, raw_dir=raw_dir,
            max_raw_bytes=cfg.pipeline.urlscan_max_raw_bytes,
            dry_run=not args.commit, force=args.force, source=args.source,
            max_retries=args.max_retries,
        )
        totals = store.stats()
    print(json.dumps({"ingest": summary, "collection_totals": totals}, indent=2, default=str))
    # A failed fetch is not a crash, but signal it for scripting.
    return 0 if summary.get("fetched", True) or summary.get("skipped") else 1


if __name__ == "__main__":
    raise SystemExit(main())
