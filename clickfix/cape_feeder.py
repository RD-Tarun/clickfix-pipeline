"""Ingest an existing CAPE task's evidence into the passive collection DB.

Passive by construction: it reads a finished analysis on disk (its
`reports/report.json`, `dump.pcap` metadata and task info) and records what was
*observed* -- domains, IP addresses, DNS records, and payload/URL artifacts --
into `collection.CollectionStore`. It never executes a sample, never fetches a
URL, and never contacts external infrastructure.

Design notes:
  * Nothing about any specific task is hardcoded; `ingest_cape_task` takes a
    task directory and discovers the task id from the report.
  * The submitted sample is the one artifact whose body we actually have, so it
    is stored `acquired` with its real sha256. A URL the sample tried to fetch
    (e.g. an MSI delivery link) is stored `not_acquired` with no hash -- the
    absence of the body is itself the finding, and no hash is invented.
  * Idempotent: a per-task marker in `enrichment_runs` records that a task was
    ingested. A second run detects the marker and makes no changes, so counters
    are not inflated and no duplicate rows or provenance edges appear. `force`
    re-ingests deliberately.
  * Only globally-routable IPs are collected; loopback/private/multicast/
    link-local addresses (gateway DNS, mDNS, SSDP, the guest itself) are guest
    plumbing, not infrastructure, and are skipped.
  * Missing data is treated as unknown: absent sections simply yield no rows,
    never a fabricated or negative observation.
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from typing import Optional
from urllib.parse import urlparse

from collection import CollectionStore, artifact_key

_INGEST_LOOKUP = "cape_ingest"
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]}]+", re.IGNORECASE)

_EXT_TYPE = {
    ".msi": "msi", ".exe": "exe", ".dll": "dll", ".ps1": "ps1", ".bat": "command",
    ".cmd": "command", ".js": "js", ".vbs": "vbs", ".hta": "hta", ".zip": "zip",
    ".7z": "archive", ".rar": "archive", ".scr": "exe", ".jar": "jar", ".lnk": "lnk",
}


class FeederError(Exception):
    """Raised when a task directory cannot be ingested (missing/invalid report)."""


def _is_routable(addr: str) -> bool:
    """True only for a globally-routable unicast address worth collecting."""
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local
        or ip.is_unspecified or ip.is_reserved
    )


def _artifact_type_for(url: str) -> str:
    path = urlparse(url).path.lower()
    for ext, t in _EXT_TYPE.items():
        if path.endswith(ext):
            return t
    return "download"


def _type_for_name(name: str, fallback: str = "file") -> str:
    low = (name or "").lower()
    for ext, t in _EXT_TYPE.items():
        if low.endswith(ext):
            return t
    return fallback


def load_report(task_dir: str) -> dict:
    path = os.path.join(task_dir, "reports", "report.json")
    if not os.path.isfile(path):
        raise FeederError(f"no report.json under {task_dir!r} (expected {path})")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise FeederError(f"could not parse {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FeederError(f"{path}: top-level JSON is not an object")
    return data


def _pcap_meta(task_dir: str) -> dict:
    """Read dump.pcap *metadata* only -- size, and packet count/duration via
    capinfos when it is installed. Never parses packet contents here."""
    path = os.path.join(task_dir, "dump.pcap")
    if not os.path.isfile(path):
        return {"present": False}
    meta = {"present": True, "path": path, "size": os.path.getsize(path)}
    try:
        out = subprocess.run(
            ["capinfos", "-M", "-c", "-u", path],
            capture_output=True, text=True, timeout=20,
        )
        for line in out.stdout.splitlines():
            if "Number of packets" in line:
                meta["packets"] = line.split("=")[-1].strip() if "=" in line else line.split()[-1]
            elif "Capture duration" in line:
                meta["duration"] = line.split("=")[-1].strip() if "=" in line else line.split()[-1]
    except (OSError, subprocess.SubprocessError):
        pass  # capinfos absent -> size-only metadata is fine
    return meta


def _extract_urls(report: dict) -> set:
    """Collect every URL the analysis saw referenced: HTTP entries, signature
    marks carrying a url/uri, and http links embedded in command lines."""
    urls = set()
    net = report.get("network") or {}
    for h in (net.get("http") or []):
        if isinstance(h, dict):
            u = h.get("uri") or h.get("url")
            if u:
                urls.add(u)
    for sig in (report.get("signatures") or []):
        for mark in (sig.get("data") or sig.get("marks") or []):
            if not isinstance(mark, dict):
                continue
            for key in ("url", "uri"):
                if mark.get(key):
                    urls.add(mark[key])
            for key in ("command", "commandline", "cmdline"):
                if mark.get(key):
                    urls.update(m.group(0) for m in _URL_RE.finditer(str(mark[key])))
    # Process command lines (e.g. msiexec /i https://...).
    beh = report.get("behavior") or {}
    def _walk(p):
        cl = (p.get("environ", {}) or {}).get("CommandLine") or p.get("command_line") or ""
        urls.update(m.group(0) for m in _URL_RE.finditer(str(cl)))
        for c in p.get("children", []) or []:
            _walk(c)
    for p in (beh.get("processtree") or []):
        _walk(p)
    # Trim trailing punctuation a greedy match may have caught.
    return {u.rstrip(".,;'\")") for u in urls if u}


def ingest_cape_task(store: CollectionStore, task_dir: str,
                     task_id: Optional[int] = None, source: Optional[str] = None,
                     force: bool = False) -> dict:
    """Ingest one CAPE task directory into the collection store.

    Returns a summary dict with the task id, per-category counts, and any
    notes. Raises FeederError if the report is missing or unparseable.
    """
    report = load_report(task_dir)
    info = report.get("info") or {}
    tid = task_id if task_id is not None else info.get("id")
    task_key = str(tid) if tid is not None else os.path.basename(os.path.normpath(task_dir))
    src = source or f"cape:{task_key}"

    # Idempotency guard: skip a task already ingested unless forced.
    prior = store.last_enrichment("task", task_key, _INGEST_LOOKUP)
    if prior is not None and prior["status"] == "ok" and not force:
        return {"task_id": tid, "task_key": task_key, "skipped": True,
                "reason": "already ingested", "ingested_at": prior["ran_at"]}

    net = report.get("network") or {}
    started = info.get("started")
    ended = info.get("ended")

    # --- Gather unique observations first, so one ingest = one sighting ----
    domains = set()
    dns_tuples = []          # (domain, rrtype, value)
    ips = set()
    dead = {d[0] for d in (net.get("dead_hosts") or []) if isinstance(d, (list, tuple)) and d}

    for d in (net.get("dns") or []):
        if not isinstance(d, dict):
            continue
        req = d.get("request")
        if req:
            domains.add(req)
        for ans in (d.get("answers") or []):
            if isinstance(ans, dict) and ans.get("data"):
                dns_tuples.append((req, d.get("type") or "A", ans["data"]))
                if _is_routable(str(ans["data"])):
                    ips.add(str(ans["data"]))

    for h in (net.get("hosts") or []):
        addr = h.get("ip") if isinstance(h, dict) else h
        if addr and _is_routable(str(addr)):
            ips.add(str(addr))
    for conns in ("tcp", "udp"):
        for c in (net.get(conns) or []):
            dst = c.get("dst") if isinstance(c, dict) else None
            if dst and _is_routable(str(dst)):
                ips.add(str(dst))
    ips.update(a for a in dead if _is_routable(str(a)))

    urls = _extract_urls(report)
    for u in urls:
        host = urlparse(u).hostname
        if host:
            domains.add(host)

    # --- Write observations (each unique value once) ----------------------
    counts = {"domains": 0, "ips": 0, "dns_records": 0, "artifacts": 0,
              "artifact_sources": 0}

    for dom in sorted(domains):
        _, new = store.upsert_domain(dom, source=src)
        counts["domains"] += int(new)
    for addr in sorted(ips):
        note = "dead_host (no response)" if addr in dead else None
        _, new = store.upsert_ip(addr, source=src)
        counts["ips"] += int(new)
        if note:
            store.record_enrichment("ip", addr, "cape_observation", "ok", detail=note)
    seen_dns = set()
    for dom, rrtype, value in dns_tuples:
        if (dom, rrtype, value) in seen_dns:
            continue
        seen_dns.add((dom, rrtype, value))
        _, new = store.record_dns(dom, rrtype, value, source=src)
        counts["dns_records"] += int(new)

    # Submitted sample: the one artifact whose body we actually have.
    tgt = report.get("target") or {}
    tf = tgt.get("file") or {}
    if tf.get("sha256"):
        notes = f"submitted sample; type={tf.get('type')}"
        if started:
            notes += f"; task_started={started}"
        _, new = store.upsert_payload_artifact(
            sha256=tf["sha256"], artifact_type=_type_for_name(tf.get("name", "")),
            size=tf.get("size"), acquisition_status="acquired", cape_task_id=tid,
            source=src, notes=notes,
        )
        counts["artifacts"] += int(new)
        _, e = store.link_artifact_source(artifact_key(tf["sha256"]), source=src)
        counts["artifact_sources"] += int(e)

    # Referenced URLs: recorded, never acquired, never hashed here.
    for u in sorted(urls):
        host = urlparse(u).hostname
        _, new = store.upsert_payload_artifact(
            url=u, artifact_type=_artifact_type_for(u), served_by_domain=host,
            acquisition_status="not_acquired", cape_task_id=tid, source=src,
            notes="referenced by analysis; body not downloaded",
        )
        counts["artifacts"] += int(new)
        _, e = store.link_artifact_source(artifact_key(url=u), domain=host, url=u, source=src)
        counts["artifact_sources"] += int(e)

    # pcap metadata + task window, preserved as task-level enrichment detail.
    pcap = _pcap_meta(task_dir)
    store.record_enrichment("task", task_key, "pcap",
                            "ok" if pcap.get("present") else "empty",
                            detail=json.dumps(pcap))

    manifest = {"task_id": tid, "task_dir": os.path.abspath(task_dir),
                "started": started, "ended": ended,
                "machine": (info.get("machine") or {}).get("name")
                if isinstance(info.get("machine"), dict) else info.get("machine"),
                "counts": counts}
    store.record_enrichment("task", task_key, _INGEST_LOOKUP, "ok",
                            detail=json.dumps(manifest))

    summary = dict(manifest)
    summary["skipped"] = False
    summary["pcap"] = pcap
    return summary


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cape_feeder",
        description="Ingest a CAPE task directory's evidence into the passive collection DB.",
    )
    p.add_argument("task_dir", help="path to a CAPE analysis dir (contains reports/report.json)")
    p.add_argument("--task-id", type=int, default=None,
                   help="override the task id (default: read from report info.id)")
    p.add_argument("--db", default=None,
                   help="collection DB path (default: config pipeline.collection_db_path)")
    p.add_argument("--source", default=None, help="override provenance source tag")
    p.add_argument("--force", action="store_true", help="re-ingest even if already recorded")
    return p


def main(argv=None) -> int:
    args = _build_arg_parser().parse_args(argv)
    db_path = args.db
    if db_path is None:
        from config import load_config
        db_path = load_config().pipeline.collection_db_path
    try:
        with CollectionStore(db_path) as store:
            summary = ingest_cape_task(store, args.task_dir, task_id=args.task_id,
                                       source=args.source, force=args.force)
            totals = store.stats()
    except FeederError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"ingest": summary, "collection_totals": totals}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
