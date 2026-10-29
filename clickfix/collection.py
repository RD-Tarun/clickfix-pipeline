"""Passive intelligence-collection store for the ClickFix -> CAPE pipeline.

This is deliberately *separate* from `state.py`. `ClickfixStore` tracks the
operational lifecycle of candidate pages (discovered -> submitted -> reported)
and is pruned/retried as work moves through it. This store is the opposite: a
write-mostly, never-pruned intel corpus that accumulates everything we ever
*observe* about the infrastructure behind the lures -- domains, IP addresses,
DNS resolutions, WHOIS/RDAP registration, TLS certificates, and the payload
artifacts each host served -- so campaigns can be correlated and pivoted long
after a single task is done.

It is "passive" in two senses:

  1. It only records what was already observed (urlscan results, a CAPE
     report, a PCAP, an out-of-band TI lookup). Writing a row never fetches
     anything or contacts a host -- the caller supplies the facts.
  2. A payload the pipeline could never download is still first-class here. The
     Task-76 MSI, for example, is recorded as an artifact with a URL, a
     `served_by_domain`, and `acquisition_status='not_acquired'` -- the absence
     of the body is itself intelligence worth keeping.

Identity rules (so poll volume never inflates the tables):
  * one row per FQDN, per IP, per (domain, rrtype, value) DNS tuple;
  * WHOIS/TLS keep *history* -- a new row only when the content hash changes;
  * a payload artifact is keyed by its sha256 when known, otherwise by its
    URL, so an artifact first seen as a bare URL and later acquired collapses
    to one identity;
  * every (artifact, where-it-was-served, source) edge is kept for provenance,
    repeat sightings bumping a counter rather than adding rows.

Cross-references to `clickfix.db` are by sha256/string value, not foreign key,
because the two databases are independent files with independent lifecycles.
"""

import datetime
import hashlib
import json
import sqlite3
from typing import List, Optional

SCHEMA = """
-- One row per fully-qualified domain ever observed serving or linked to a lure.
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn TEXT UNIQUE NOT NULL,
    apex_domain TEXT,
    registrable TEXT,              -- eTLD+1 when known (may equal apex_domain)
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    status TEXT,                   -- active | dead | sinkholed | remediated | unknown
    source TEXT,                   -- where first observed (urlscan, cape, pcap, ...)
    tags TEXT,                     -- JSON list, campaign/cluster labels
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_dom_apex ON domains(apex_domain);
CREATE INDEX IF NOT EXISTS idx_dom_registrable ON domains(registrable);
CREATE INDEX IF NOT EXISTS idx_dom_status ON domains(status);

-- One row per IP address ever observed.
CREATE TABLE IF NOT EXISTS ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    version INTEGER,               -- 4 or 6
    asn INTEGER,
    as_org TEXT,
    country TEXT,
    ptr TEXT,                      -- reverse-DNS name, if observed
    is_sinkhole INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_ips_asn ON ips(asn);

-- Observed DNS resolutions / records. One row per distinct
-- (domain, record_type, value). This is the domain<->ip linkage (A/AAAA) as
-- well as NS/CNAME/MX/TXT pivots. Historical: a value that stops resolving is
-- kept, its last_seen simply stops advancing.
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,     -- A | AAAA | CNAME | NS | MX | TXT | ...
    value TEXT NOT NULL,           -- the RHS (IP for A/AAAA, name for CNAME/NS)
    ip TEXT,                       -- convenience copy when value is an address
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    source TEXT,
    UNIQUE (domain, record_type, value)
);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_records(domain);
CREATE INDEX IF NOT EXISTS idx_dns_value ON dns_records(value);
CREATE INDEX IF NOT EXISTS idx_dns_ip ON dns_records(ip);

-- WHOIS / RDAP snapshots. Registration data changes over time (registrar
-- hops, re-registration), so we keep a new snapshot whenever the raw content
-- hash differs; identical re-fetches only bump last_seen/times_seen.
CREATE TABLE IF NOT EXISTS whois_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,          -- registrable domain or IP/CIDR
    kind TEXT NOT NULL,            -- domain | ip
    registrar TEXT,
    created TEXT,
    updated TEXT,
    expires TEXT,
    registrant_org TEXT,
    name_servers TEXT,             -- JSON list
    asn INTEGER,
    cidr TEXT,
    raw_sha256 TEXT NOT NULL,      -- hash of raw_text or of the field tuple
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    source TEXT,
    UNIQUE (target, raw_sha256)
);
CREATE INDEX IF NOT EXISTS idx_whois_target ON whois_records(target);
CREATE INDEX IF NOT EXISTS idx_whois_registrar ON whois_records(registrar);

-- Certificate-transparency log entries for a host (e.g. from crt.sh). These
-- are NOT a substitute for an observed leaf certificate: CT entries carry no
-- SHA256 fingerprint, so they live here keyed by the log entry id rather than
-- being forced into tls_certs with a fabricated fingerprint. A real observed
-- cert (with a true fingerprint) still goes into tls_certs.
CREATE TABLE IF NOT EXISTS ct_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,          -- the queried host/apex
    ct_id TEXT NOT NULL,           -- CT log entry id (crt.sh "id"), as string
    common_name TEXT,
    name_value TEXT,               -- JSON list of SANs / names on the cert
    issuer TEXT,
    serial TEXT,
    not_before TEXT,
    not_after TEXT,
    entry_timestamp TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    source TEXT,
    UNIQUE (domain, ct_id)
);
CREATE INDEX IF NOT EXISTS idx_ct_domain ON ct_logs(domain);
CREATE INDEX IF NOT EXISTS idx_ct_issuer ON ct_logs(issuer);

-- Raw RDAP/WHOIS response evidence. Stores the exact response body (on disk,
-- content-addressed by the SHA256 of its raw bytes) plus the metadata needed
-- to audit a normalized whois row: which entity/provider/endpoint produced it,
-- when, and the field-tuple hash of the whois snapshot it maps to
-- (whois_raw_sha256 == whois_records.raw_sha256). Only SUCCESSFUL lookups are
-- recorded; failures/invalid bodies are never stored as evidence.
CREATE TABLE IF NOT EXISTS rdap_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity TEXT NOT NULL,
    kind TEXT,                     -- domain | ip
    provider TEXT,                 -- e.g. rdap:rdap.identitydigital.services
    endpoint TEXT,                 -- full URL queried
    raw_sha256 TEXT NOT NULL,      -- SHA256 of the exact raw response bytes
    byte_len INTEGER,
    raw_path TEXT,                 -- file holding the raw bytes (NULL if oversize/not stored)
    whois_raw_sha256 TEXT,         -- -> whois_records.raw_sha256 (same lookup's normalized row)
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    UNIQUE (entity, provider, raw_sha256)
);
CREATE INDEX IF NOT EXISTS idx_rdapev_entity ON rdap_evidence(entity);
CREATE INDEX IF NOT EXISTS idx_rdapev_sha ON rdap_evidence(raw_sha256);
CREATE INDEX IF NOT EXISTS idx_rdapev_whois ON rdap_evidence(whois_raw_sha256);

-- Observed TLS certificates. Pivot by fingerprint or issuer across domains.
CREATE TABLE IF NOT EXISTS tls_certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_sha256 TEXT UNIQUE NOT NULL,
    subject_cn TEXT,
    issuer TEXT,
    sans TEXT,                     -- JSON list of subjectAltNames
    not_before TEXT,
    not_after TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_tls_issuer ON tls_certs(issuer);

-- Payload artifacts observed being served or referenced by the infrastructure.
-- Keyed by sha256 when the body is known, otherwise by URL, so a payload first
-- seen as an undownloaded URL and later acquired is one identity. Links back
-- to clickfix.db payloads by sha256 (string, not FK).
CREATE TABLE IF NOT EXISTS payload_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_key TEXT UNIQUE NOT NULL,   -- 'sha256:<h>' or 'url:<normalised>'
    sha256 TEXT,                         -- NULL until/unless the body is known
    url TEXT,                            -- where it was/would be fetched
    artifact_type TEXT,                  -- command | msi | exe | dll | js | ps1 | zip | ...
    size INTEGER,
    served_by_domain TEXT,
    served_by_ip TEXT,
    acquisition_status TEXT,             -- not_acquired | acquired | available_in_ti | blocked
    cape_task_id INTEGER,                -- task that detonated / attempted it
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    source TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_art_sha ON payload_artifacts(sha256);
CREATE INDEX IF NOT EXISTS idx_art_domain ON payload_artifacts(served_by_domain);
CREATE INDEX IF NOT EXISTS idx_art_status ON payload_artifacts(acquisition_status);
CREATE INDEX IF NOT EXISTS idx_art_task ON payload_artifacts(cape_task_id);

-- Provenance edges: where an artifact was seen, and from which source. One row
-- per distinct (artifact, domain, ip, url, source); repeats bump a counter.
CREATE TABLE IF NOT EXISTS artifact_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_key TEXT NOT NULL,
    domain TEXT,
    ip TEXT,
    url TEXT,
    source TEXT,                   -- urlscan:<uuid> | cape:<task> | pcap:<path> | ti:<name>
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    UNIQUE (artifact_key, domain, ip, url, source)
);
CREATE INDEX IF NOT EXISTS idx_artsrc_key ON artifact_sources(artifact_key);
CREATE INDEX IF NOT EXISTS idx_artsrc_domain ON artifact_sources(domain);

-- Append-only log of passive enrichment lookups and their outcome. Lets the
-- collector skip a recent lookup and keeps an audit trail of *why* a field is
-- blank -- e.g. a VirusTotal query that returned quota_exceeded.
CREATE TABLE IF NOT EXISTS enrichment_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,     -- domain | ip | url | artifact
    entity_value TEXT NOT NULL,
    lookup TEXT NOT NULL,          -- whois | rdap | asn | passive_dns | tls | vt | mb
    status TEXT NOT NULL,          -- ok | empty | error | quota | skipped
    detail TEXT,
    ran_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enrich_entity ON enrichment_runs(entity_type, entity_value, lookup);
CREATE INDEX IF NOT EXISTS idx_enrich_ran ON enrichment_runs(ran_at);

-- Every candidate URL the pipeline CONSUMED (fetched/triaged), tagged with the
-- feed it came from (urlscan | gist | urlhaus | ...). Deduped by url; a repeat
-- sighting bumps times_seen. This is the raw intake ledger, separate from what
-- actually detonated (payload_artifacts/domains).
CREATE TABLE IF NOT EXISTS consumed_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    source TEXT,                   -- urlscan | gist | urlhaus
    domain TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_consumed_source ON consumed_urls(source);
CREATE INDEX IF NOT EXISTS idx_consumed_seen ON consumed_urls(first_seen);

-- Full activity ledger: EVERY recovered command and what happened to it --
-- submitted, dup_command, skipped_unclassified (macOS/bash), skipped_invalid:*,
-- submit_error:* -- with the command text + reason. Separate from the 'domains'
-- table (which only holds detonatable sites); this captures the ones we logged
-- but would otherwise drop (e.g. the bash lures, the too-long ones). Deduped on
-- (sha256, domain) so repeats bump times_seen.
CREATE TABLE IF NOT EXISTS recoveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT,
    domain TEXT,
    url TEXT,
    source TEXT,                   -- browser | urlscan_dom | live:gist | live:urlhaus | manual
    package TEXT,                  -- ps1 | batch | exe | NULL
    decision TEXT NOT NULL,        -- submitted | dup_command | skipped_* | submit_error:*
    reason TEXT,
    cape_task_id INTEGER,
    command TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    UNIQUE (sha256, domain)
);
CREATE INDEX IF NOT EXISTS idx_recoveries_decision ON recoveries(decision);
CREATE INDEX IF NOT EXISTS idx_recoveries_seen ON recoveries(first_seen);
"""

# Columns added after v1. Applied with ALTER TABLE on open so an existing
# collection.db upgrades in place, mirroring ClickfixStore._migrate().
_MIGRATIONS: tuple = (
    # (table, column, coltype) -- applied on open so an existing collection.db
    # upgrades in place. These back RDAP/WHOIS enrichment fields added after v1.
    ("whois_records", "statuses", "TEXT"),        # JSON list of EPP/registry statuses
    ("whois_records", "abuse_contact", "TEXT"),   # abuse email/handle when public
)


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _norm_domain(fqdn: Optional[str]) -> Optional[str]:
    if not fqdn:
        return fqdn
    return fqdn.strip().strip(".").lower() or None


def artifact_key(sha256: Optional[str] = None, url: Optional[str] = None) -> str:
    """Stable identity for an artifact: its hash when known, else its URL.

    An artifact seen first as a bare URL (never downloaded) and later acquired
    keeps whichever key it was created with; callers merge by passing the known
    sha256 to `upsert_payload_artifact`, which backfills the column.
    """
    if sha256:
        return "sha256:" + sha256.strip().lower()
    if url:
        return "url:" + url.strip()
    raise ValueError("artifact_key needs a sha256 or a url")


class CollectionStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        # Same concurrency posture as ClickfixStore: a passive collector and an
        # ad-hoc query can touch this file at once, so WAL + busy_timeout let a
        # reader and a writer coexist instead of raising "database is locked".
        self._conn = sqlite3.connect(db_path, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self):
        for table, column, coltype in _MIGRATIONS:
            existing = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- Domains ----------------------------------------------------------
    def upsert_domain(self, fqdn: str, apex_domain: Optional[str] = None,
                      registrable: Optional[str] = None, status: Optional[str] = None,
                      source: Optional[str] = None, tags: Optional[list] = None,
                      notes: Optional[str] = None):
        """Record a domain sighting. Returns (row, is_new).

        A repeat sighting bumps last_seen/times_seen and fills any field that
        was previously blank (COALESCE) without clobbering what is already set.
        """
        fqdn = _norm_domain(fqdn)
        ts = now_iso()
        tags_json = json.dumps(tags) if tags is not None else None
        row = self._conn.execute("SELECT * FROM domains WHERE fqdn = ?", (fqdn,)).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO domains (fqdn, apex_domain, registrable, first_seen, last_seen, "
                "times_seen, status, source, tags, notes) VALUES (?,?,?,?,?,1,?,?,?,?)",
                (fqdn, _norm_domain(apex_domain), _norm_domain(registrable), ts, ts,
                 status, source, tags_json, notes),
            )
            self._conn.commit()
            return self._conn.execute("SELECT * FROM domains WHERE fqdn = ?", (fqdn,)).fetchone(), True
        self._conn.execute(
            "UPDATE domains SET last_seen = ?, times_seen = times_seen + 1, "
            "apex_domain = COALESCE(apex_domain, ?), registrable = COALESCE(registrable, ?), "
            "status = COALESCE(?, status), source = COALESCE(source, ?), "
            "tags = COALESCE(?, tags), notes = COALESCE(?, notes) WHERE id = ?",
            (ts, _norm_domain(apex_domain), _norm_domain(registrable), status, source,
             tags_json, notes, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM domains WHERE id = ?", (row["id"],)).fetchone(), False

    def set_domain_status(self, fqdn: str, status: str):
        self._conn.execute(
            "UPDATE domains SET status = ?, last_seen = ? WHERE fqdn = ?",
            (status, now_iso(), _norm_domain(fqdn)),
        )
        self._conn.commit()

    def domain(self, fqdn: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM domains WHERE fqdn = ?", (_norm_domain(fqdn),)
        ).fetchone()

    def domain_detonated(self, fqdn: str) -> bool:
        """True if we have ALREADY detonated a payload served by this domain/IP.
        Used to dedup on the source: a polymorphic host that serves a fresh
        payload on every fetch is only run once, not once per variant."""
        fqdn = _norm_domain(fqdn)
        if not fqdn:
            return False
        return self._conn.execute(
            "SELECT 1 FROM payload_artifacts WHERE served_by_domain = ? "
            "AND cape_task_id IS NOT NULL LIMIT 1", (fqdn,)).fetchone() is not None

    # --- Consumed-URL intake ledger --------------------------------------
    def record_consumed(self, url: str, source: Optional[str] = None,
                        domain: Optional[str] = None):
        """Log a candidate URL the pipeline consumed, tagged with its feed.
        Deduped by url (a repeat sighting just bumps times_seen/last_seen)."""
        url = (url or "").strip()
        if not url:
            return
        ts = now_iso()
        row = self._conn.execute("SELECT id FROM consumed_urls WHERE url = ?", (url,)).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO consumed_urls (url, source, domain, first_seen, last_seen, times_seen) "
                "VALUES (?,?,?,?,?,1)", (url, source, _norm_domain(domain), ts, ts))
        else:
            self._conn.execute(
                "UPDATE consumed_urls SET last_seen = ?, times_seen = times_seen + 1, "
                "source = COALESCE(source, ?), domain = COALESCE(domain, ?) WHERE id = ?",
                (ts, source, _norm_domain(domain), row["id"]))
        self._conn.commit()

    def consumed_counts(self) -> List[sqlite3.Row]:
        """(source, n_urls, total_sightings) per feed, busiest first."""
        return self._conn.execute(
            "SELECT COALESCE(source,'?') AS source, COUNT(*) AS urls, "
            "SUM(times_seen) AS sightings FROM consumed_urls GROUP BY source "
            "ORDER BY urls DESC").fetchall()

    def consumed_recent(self, limit: int = 50) -> List[sqlite3.Row]:
        return self._conn.execute(
            "SELECT url, source, domain, times_seen, last_seen FROM consumed_urls "
            "ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()

    # --- Recovery activity ledger ----------------------------------------
    def record_recovery(self, sha256: Optional[str] = None, domain: Optional[str] = None,
                        url: Optional[str] = None, source: Optional[str] = None,
                        package: Optional[str] = None, decision: Optional[str] = None,
                        reason: Optional[str] = None, cape_task_id: Optional[int] = None,
                        command: Optional[str] = None):
        """Append/update one recovery outcome. Deduped on (sha256, domain): a
        repeat bumps times_seen and refreshes the decision (so a later detonation
        of a once-skipped command is reflected)."""
        ts = now_iso()
        domain = _norm_domain(domain)
        sha = sha256.strip().lower() if sha256 else None
        row = self._conn.execute(
            "SELECT id FROM recoveries WHERE IFNULL(sha256,'')=IFNULL(?,'') "
            "AND IFNULL(domain,'')=IFNULL(?,'')", (sha, domain)).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO recoveries (sha256, domain, url, source, package, decision, reason, "
                "cape_task_id, command, first_seen, last_seen, times_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,1)",
                (sha, domain, url, source, package, decision, reason, cape_task_id, command, ts, ts))
        else:
            self._conn.execute(
                "UPDATE recoveries SET last_seen = ?, times_seen = times_seen + 1, decision = ?, "
                "reason = ?, cape_task_id = COALESCE(?, cape_task_id), package = COALESCE(package, ?), "
                "url = COALESCE(url, ?), source = COALESCE(source, ?), command = COALESCE(command, ?) "
                "WHERE id = ?",
                (ts, decision, reason, cape_task_id, package, url, source, command, row["id"]))
        self._conn.commit()

    def recovery_decisions(self) -> List[sqlite3.Row]:
        """(decision, distinct, total_sightings) grouped by outcome."""
        return self._conn.execute(
            "SELECT decision, COUNT(*) AS n, SUM(times_seen) AS sightings FROM recoveries "
            "GROUP BY decision ORDER BY n DESC").fetchall()

    def recoveries_recent(self, limit: int = 40) -> List[sqlite3.Row]:
        return self._conn.execute(
            "SELECT decision, domain, source, package, cape_task_id, command, last_seen "
            "FROM recoveries ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()

    @staticmethod
    def _source_filter(source: str):
        """Build a ``WHERE`` fragment matching a discovery source on SEGMENT
        boundaries, so 'cape:76' matches exactly 'cape:76' (and 'cape:76:...')
        but never the unrelated 'cape:760'. 'cape' matches every 'cape:*'.
        The LIKE pattern is literal-escaped (ESCAPE '\\') against %/_ injection.
        """
        esc = source.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return "(source = ? OR source LIKE ? ESCAPE '\\')", [source, esc + ":%"]

    def list_domains(self, source_prefix: Optional[str] = None,
                     limit: Optional[int] = None) -> List[sqlite3.Row]:
        """Domains for enrichment, optionally scoped to a discovery source
        (e.g. 'cape:76' to target only payload infra, keeping urlscan page
        dependencies out)."""
        sql = "SELECT * FROM domains"
        params: list = []
        if source_prefix:
            frag, fp = self._source_filter(source_prefix)
            sql += " WHERE " + frag
            params += fp
        sql += " ORDER BY first_seen"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return self._conn.execute(sql, params).fetchall()

    def list_ips(self, source_prefix: Optional[str] = None,
                 limit: Optional[int] = None) -> List[sqlite3.Row]:
        sql = "SELECT * FROM ips"
        params: list = []
        if source_prefix:
            frag, fp = self._source_filter(source_prefix)
            sql += " WHERE " + frag
            params += fp
        sql += " ORDER BY first_seen"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return self._conn.execute(sql, params).fetchall()

    # --- IPs --------------------------------------------------------------
    def upsert_ip(self, ip: str, version: Optional[int] = None, asn: Optional[int] = None,
                  as_org: Optional[str] = None, country: Optional[str] = None,
                  ptr: Optional[str] = None, is_sinkhole: Optional[bool] = None,
                  source: Optional[str] = None):
        """Record an IP sighting. Returns (row, is_new)."""
        ip = (ip or "").strip()
        if version is None and ip:
            version = 6 if ":" in ip else 4
        ts = now_iso()
        row = self._conn.execute("SELECT * FROM ips WHERE ip = ?", (ip,)).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO ips (ip, version, asn, as_org, country, ptr, is_sinkhole, "
                "first_seen, last_seen, times_seen, source) VALUES (?,?,?,?,?,?,?,?,?,1,?)",
                (ip, version, asn, as_org, country, ptr, int(bool(is_sinkhole)), ts, ts, source),
            )
            self._conn.commit()
            return self._conn.execute("SELECT * FROM ips WHERE ip = ?", (ip,)).fetchone(), True
        self._conn.execute(
            "UPDATE ips SET last_seen = ?, times_seen = times_seen + 1, "
            "asn = COALESCE(?, asn), as_org = COALESCE(?, as_org), "
            "country = COALESCE(?, country), ptr = COALESCE(?, ptr), "
            "is_sinkhole = CASE WHEN ? IS NULL THEN is_sinkhole ELSE ? END, "
            "source = COALESCE(source, ?) WHERE id = ?",
            (ts, asn, as_org, country, ptr,
             None if is_sinkhole is None else 1,
             int(bool(is_sinkhole)), source, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM ips WHERE id = ?", (row["id"],)).fetchone(), False

    def ip(self, ip: str) -> Optional[sqlite3.Row]:
        return self._conn.execute("SELECT * FROM ips WHERE ip = ?", ((ip or "").strip(),)).fetchone()

    # --- DNS --------------------------------------------------------------
    def record_dns(self, domain: str, record_type: str, value: str,
                   ip: Optional[str] = None, source: Optional[str] = None):
        """Record a DNS resolution/record. Returns (row, is_new).

        Deduplicated on (domain, record_type, value); a repeat only bumps the
        counter. For A/AAAA the resolved address is also mirrored into `ip` for
        a cheap domain<->ip pivot.
        """
        domain = _norm_domain(domain)
        record_type = (record_type or "").strip().upper()
        if ip is None and record_type in ("A", "AAAA"):
            ip = value
        ts = now_iso()
        row = self._conn.execute(
            "SELECT * FROM dns_records WHERE domain = ? AND record_type = ? AND value = ?",
            (domain, record_type, value),
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO dns_records (domain, record_type, value, ip, first_seen, "
                "last_seen, times_seen, source) VALUES (?,?,?,?,?,?,1,?)",
                (domain, record_type, value, ip, ts, ts, source),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM dns_records WHERE domain = ? AND record_type = ? AND value = ?",
                (domain, record_type, value),
            ).fetchone(), True
        self._conn.execute(
            "UPDATE dns_records SET last_seen = ?, times_seen = times_seen + 1 WHERE id = ?",
            (ts, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM dns_records WHERE id = ?", (row["id"],)).fetchone(), False

    def ips_for_domain(self, domain: str) -> List[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM dns_records WHERE domain = ? AND record_type IN ('A','AAAA') "
            "ORDER BY last_seen DESC",
            (_norm_domain(domain),),
        ).fetchall()

    def domains_for_ip(self, ip: str) -> List[sqlite3.Row]:
        return self._conn.execute(
            "SELECT DISTINCT domain FROM dns_records WHERE value = ? OR ip = ? ORDER BY domain",
            ((ip or "").strip(), (ip or "").strip()),
        ).fetchall()

    # --- WHOIS / RDAP -----------------------------------------------------
    @staticmethod
    def whois_basis_sha256(raw_text: Optional[str] = None, registrar: Optional[str] = None,
                           created: Optional[str] = None, updated: Optional[str] = None,
                           expires: Optional[str] = None, registrant_org: Optional[str] = None,
                           name_servers_json: Optional[str] = None, asn: Optional[int] = None,
                           cidr: Optional[str] = None, statuses_json: Optional[str] = None,
                           abuse_contact: Optional[str] = None) -> str:
        """The canonical content hash of a whois snapshot.

        This is the SINGLE source of truth for the snapshot identity used by
        `record_whois` (its dedup/history key) and by any read-only check that
        needs the would-be hash without writing (e.g. evidence-only backfill).
        `name_servers_json`/`statuses_json` are the JSON-encoded list columns,
        exactly as stored, so the hash matches a row read back from the DB.
        """
        basis = raw_text if raw_text is not None else json.dumps(
            [registrar, created, updated, expires, registrant_org, name_servers_json,
             asn, cidr, statuses_json, abuse_contact],
            sort_keys=True,
        )
        return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()

    def record_whois(self, target: str, kind: str = "domain", raw_text: Optional[str] = None,
                     registrar: Optional[str] = None, created: Optional[str] = None,
                     updated: Optional[str] = None, expires: Optional[str] = None,
                     registrant_org: Optional[str] = None, name_servers: Optional[list] = None,
                     asn: Optional[int] = None, cidr: Optional[str] = None,
                     statuses: Optional[list] = None, abuse_contact: Optional[str] = None,
                     source: Optional[str] = None):
        """Record a WHOIS/RDAP snapshot. Returns (row, is_new).

        A new row is kept only when the content hash differs from a prior
        snapshot for the same target, so re-fetches that return identical data
        just bump last_seen -- but a registrar/nameserver/status change is
        preserved as its own historical row.
        """
        target = _norm_domain(target) if kind == "domain" else (target or "").strip()
        ns_json = json.dumps(name_servers) if name_servers is not None else None
        st_json = json.dumps(statuses) if statuses is not None else None
        raw_sha256 = self.whois_basis_sha256(
            raw_text=raw_text, registrar=registrar, created=created, updated=updated,
            expires=expires, registrant_org=registrant_org, name_servers_json=ns_json,
            asn=asn, cidr=cidr, statuses_json=st_json, abuse_contact=abuse_contact,
        )
        ts = now_iso()
        row = self._conn.execute(
            "SELECT * FROM whois_records WHERE target = ? AND raw_sha256 = ?",
            (target, raw_sha256),
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO whois_records (target, kind, registrar, created, updated, expires, "
                "registrant_org, name_servers, asn, cidr, statuses, abuse_contact, raw_sha256, "
                "first_seen, last_seen, times_seen, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)",
                (target, kind, registrar, created, updated, expires, registrant_org, ns_json,
                 asn, cidr, st_json, abuse_contact, raw_sha256, ts, ts, source),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM whois_records WHERE target = ? AND raw_sha256 = ?",
                (target, raw_sha256),
            ).fetchone(), True
        self._conn.execute(
            "UPDATE whois_records SET last_seen = ?, times_seen = times_seen + 1 WHERE id = ?",
            (ts, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM whois_records WHERE id = ?", (row["id"],)).fetchone(), False

    def record_rdap_evidence(self, entity: str, kind: str, provider: str, endpoint: str,
                             raw_sha256: str, byte_len: int, raw_path: Optional[str] = None,
                             whois_raw_sha256: Optional[str] = None):
        """Record raw RDAP response evidence for a SUCCESSFUL lookup.

        Returns (row, is_new). Deduplicated on (entity, provider, raw_sha256):
        a repeat lookup returning the identical body just bumps last_seen/
        times_seen, while a changed body is kept as a new evidence row (history).
        """
        entity = _norm_domain(entity) if kind == "domain" else (entity or "").strip()
        ts = now_iso()
        row = self._conn.execute(
            "SELECT * FROM rdap_evidence WHERE entity = ? AND provider = ? AND raw_sha256 = ?",
            (entity, provider, raw_sha256),
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO rdap_evidence (entity, kind, provider, endpoint, raw_sha256, "
                "byte_len, raw_path, whois_raw_sha256, first_seen, last_seen, times_seen) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,1)",
                (entity, kind, provider, endpoint, raw_sha256, byte_len, raw_path,
                 whois_raw_sha256, ts, ts),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM rdap_evidence WHERE entity = ? AND provider = ? AND raw_sha256 = ?",
                (entity, provider, raw_sha256),
            ).fetchone(), True
        self._conn.execute(
            "UPDATE rdap_evidence SET last_seen = ?, times_seen = times_seen + 1 WHERE id = ?",
            (ts, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM rdap_evidence WHERE id = ?", (row["id"],)).fetchone(), False

    def rdap_evidence_for(self, entity: str) -> List[sqlite3.Row]:
        e = _norm_domain(entity) or (entity or "").strip()
        return self._conn.execute(
            "SELECT * FROM rdap_evidence WHERE entity = ? ORDER BY first_seen", (e,)
        ).fetchall()

    def whois_history(self, target: str) -> List[sqlite3.Row]:
        t = _norm_domain(target) or (target or "").strip()
        return self._conn.execute(
            "SELECT * FROM whois_records WHERE target = ? ORDER BY first_seen", (t,)
        ).fetchall()

    def latest_whois(self, target: str) -> Optional[sqlite3.Row]:
        t = _norm_domain(target) or (target or "").strip()
        return self._conn.execute(
            "SELECT * FROM whois_records WHERE target = ? ORDER BY last_seen DESC LIMIT 1", (t,)
        ).fetchone()

    # --- TLS certificates -------------------------------------------------
    def record_tls(self, fingerprint_sha256: str, subject_cn: Optional[str] = None,
                   issuer: Optional[str] = None, sans: Optional[list] = None,
                   not_before: Optional[str] = None, not_after: Optional[str] = None,
                   source: Optional[str] = None):
        """Record an observed TLS certificate. Returns (row, is_new)."""
        fp = (fingerprint_sha256 or "").strip().lower()
        sans_json = json.dumps(sans) if sans is not None else None
        ts = now_iso()
        row = self._conn.execute(
            "SELECT * FROM tls_certs WHERE fingerprint_sha256 = ?", (fp,)
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO tls_certs (fingerprint_sha256, subject_cn, issuer, sans, "
                "not_before, not_after, first_seen, last_seen, times_seen, source) "
                "VALUES (?,?,?,?,?,?,?,?,1,?)",
                (fp, subject_cn, issuer, sans_json, not_before, not_after, ts, ts, source),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM tls_certs WHERE fingerprint_sha256 = ?", (fp,)
            ).fetchone(), True
        self._conn.execute(
            "UPDATE tls_certs SET last_seen = ?, times_seen = times_seen + 1 WHERE id = ?",
            (ts, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM tls_certs WHERE id = ?", (row["id"],)).fetchone(), False

    def record_ct_log(self, domain: str, ct_id, common_name: Optional[str] = None,
                      name_value: Optional[list] = None, issuer: Optional[str] = None,
                      serial: Optional[str] = None, not_before: Optional[str] = None,
                      not_after: Optional[str] = None, entry_timestamp: Optional[str] = None,
                      source: Optional[str] = None):
        """Record a certificate-transparency log entry. Returns (row, is_new).

        Deduplicated on (domain, ct_id); a repeat only bumps last_seen. Keeps
        historical CT entries -- an expired/old cert is evidence, not noise.
        """
        domain = _norm_domain(domain)
        ct_id = str(ct_id)
        nv_json = json.dumps(name_value) if name_value is not None else None
        ts = now_iso()
        row = self._conn.execute(
            "SELECT * FROM ct_logs WHERE domain = ? AND ct_id = ?", (domain, ct_id)
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO ct_logs (domain, ct_id, common_name, name_value, issuer, serial, "
                "not_before, not_after, entry_timestamp, first_seen, last_seen, times_seen, source) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)",
                (domain, ct_id, common_name, nv_json, issuer, serial, not_before, not_after,
                 entry_timestamp, ts, ts, source),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM ct_logs WHERE domain = ? AND ct_id = ?", (domain, ct_id)
            ).fetchone(), True
        self._conn.execute(
            "UPDATE ct_logs SET last_seen = ?, times_seen = times_seen + 1 WHERE id = ?",
            (ts, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM ct_logs WHERE id = ?", (row["id"],)).fetchone(), False

    def ct_logs_for(self, domain: str) -> List[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM ct_logs WHERE domain = ? ORDER BY not_before", (_norm_domain(domain),)
        ).fetchall()

    # --- Payload artifacts ------------------------------------------------
    def upsert_payload_artifact(self, sha256: Optional[str] = None, url: Optional[str] = None,
                                artifact_type: Optional[str] = None, size: Optional[int] = None,
                                served_by_domain: Optional[str] = None,
                                served_by_ip: Optional[str] = None,
                                acquisition_status: Optional[str] = None,
                                cape_task_id: Optional[int] = None,
                                source: Optional[str] = None, notes: Optional[str] = None):
        """Record a payload artifact (acquired or merely referenced).

        Returns (row, is_new). Identity is the sha256 when known, else the URL
        (see `artifact_key`). Calling again with a sha256 for a URL-keyed row
        backfills the hash column so the two sightings stay linked, and blank
        enrichment fields fill without clobbering set ones.
        """
        if not sha256 and not url:
            raise ValueError("a payload artifact needs at least a sha256 or a url")
        key = artifact_key(sha256, url)
        sha_norm = sha256.strip().lower() if sha256 else None
        served_by_domain = _norm_domain(served_by_domain)
        ts = now_iso()
        row = self._conn.execute(
            "SELECT * FROM payload_artifacts WHERE artifact_key = ?", (key,)
        ).fetchone()
        # A URL-keyed artifact whose body we have now acquired: find it by URL
        # and backfill the hash rather than creating a second row.
        if row is None and sha_norm and url:
            row = self._conn.execute(
                "SELECT * FROM payload_artifacts WHERE artifact_key = ?",
                (artifact_key(url=url),),
            ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO payload_artifacts (artifact_key, sha256, url, artifact_type, size, "
                "served_by_domain, served_by_ip, acquisition_status, cape_task_id, first_seen, "
                "last_seen, times_seen, source, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
                (key, sha_norm, url, artifact_type, size, served_by_domain, served_by_ip,
                 acquisition_status or ("acquired" if sha_norm else "not_acquired"),
                 cape_task_id, ts, ts, source, notes),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM payload_artifacts WHERE artifact_key = ?", (key,)
            ).fetchone(), True
        self._conn.execute(
            "UPDATE payload_artifacts SET last_seen = ?, times_seen = times_seen + 1, "
            "sha256 = COALESCE(sha256, ?), url = COALESCE(url, ?), "
            "artifact_type = COALESCE(?, artifact_type), size = COALESCE(size, ?), "
            "served_by_domain = COALESCE(served_by_domain, ?), "
            "served_by_ip = COALESCE(served_by_ip, ?), "
            "acquisition_status = COALESCE(?, acquisition_status), "
            "cape_task_id = COALESCE(?, cape_task_id), source = COALESCE(source, ?), "
            "notes = COALESCE(?, notes) WHERE id = ?",
            (ts, sha_norm, url, artifact_type, size, served_by_domain, served_by_ip,
             acquisition_status, cape_task_id, source, notes, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute(
            "SELECT * FROM payload_artifacts WHERE id = ?", (row["id"],)
        ).fetchone(), False

    def link_artifact_source(self, key: str, domain: Optional[str] = None,
                             ip: Optional[str] = None, url: Optional[str] = None,
                             source: Optional[str] = None):
        """Record a provenance edge: where/when an artifact was seen. Returns
        (row, is_new). Deduplicated on the full tuple so polling cannot inflate
        it; a repeat edge just bumps its counter."""
        domain = _norm_domain(domain)
        ts = now_iso()
        row = self._conn.execute(
            "SELECT * FROM artifact_sources WHERE artifact_key = ? AND IFNULL(domain,'')=IFNULL(?,'') "
            "AND IFNULL(ip,'')=IFNULL(?,'') AND IFNULL(url,'')=IFNULL(?,'') "
            "AND IFNULL(source,'')=IFNULL(?,'')",
            (key, domain, ip, url, source),
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO artifact_sources (artifact_key, domain, ip, url, source, "
                "first_seen, last_seen, times_seen) VALUES (?,?,?,?,?,?,?,1)",
                (key, domain, ip, url, source, ts, ts),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM artifact_sources WHERE artifact_key = ? ORDER BY id DESC LIMIT 1", (key,)
            ).fetchone(), True
        self._conn.execute(
            "UPDATE artifact_sources SET last_seen = ?, times_seen = times_seen + 1 WHERE id = ?",
            (ts, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM artifact_sources WHERE id = ?", (row["id"],)).fetchone(), False

    def payloads_for_domain(self, domain: str) -> List[sqlite3.Row]:
        """Every artifact ever seen served by / linked to a domain, via both the
        artifact's own served_by_domain and recorded provenance edges."""
        domain = _norm_domain(domain)
        return self._conn.execute(
            "SELECT DISTINCT a.* FROM payload_artifacts a "
            "LEFT JOIN artifact_sources s ON s.artifact_key = a.artifact_key "
            "WHERE a.served_by_domain = ? OR s.domain = ? ORDER BY a.first_seen",
            (domain, domain),
        ).fetchall()

    def infra_for_payload(self, key: str) -> List[sqlite3.Row]:
        """Every (domain, ip, url, source) an artifact was observed at."""
        return self._conn.execute(
            "SELECT * FROM artifact_sources WHERE artifact_key = ? ORDER BY first_seen", (key,)
        ).fetchall()

    def artifact(self, key: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM payload_artifacts WHERE artifact_key = ?", (key,)
        ).fetchone()

    # --- Enrichment bookkeeping ------------------------------------------
    def record_enrichment(self, entity_type: str, entity_value: str, lookup: str,
                          status: str, detail: Optional[str] = None):
        """Append a passive-lookup outcome (ok|empty|error|quota|skipped)."""
        self._conn.execute(
            "INSERT INTO enrichment_runs (entity_type, entity_value, lookup, status, detail, ran_at) "
            "VALUES (?,?,?,?,?,?)",
            (entity_type, entity_value, lookup, status, detail, now_iso()),
        )
        self._conn.commit()

    def last_enrichment(self, entity_type: str, entity_value: str,
                        lookup: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM enrichment_runs WHERE entity_type = ? AND entity_value = ? "
            "AND lookup = ? ORDER BY ran_at DESC LIMIT 1",
            (entity_type, entity_value, lookup),
        ).fetchone()

    def needs_enrichment(self, entity_type: str, entity_value: str, lookup: str,
                         min_age_hours: float = 24.0) -> bool:
        """True if this lookup has never succeeded recently enough to skip.

        A prior `ok`/`empty`/`quota` within the window suppresses a re-query;
        an `error` or nothing at all means try again.
        """
        last = self.last_enrichment(entity_type, entity_value, lookup)
        if last is None or last["status"] == "error":
            return True
        try:
            then = datetime.datetime.fromisoformat(last["ran_at"])
        except (ValueError, TypeError):
            return True
        age = datetime.datetime.now(datetime.timezone.utc) - then
        return age.total_seconds() >= min_age_hours * 3600

    # --- Stats ------------------------------------------------------------
    def stats(self) -> dict:
        q = self._conn.execute
        def n(sql):
            return q(sql).fetchone()["n"]
        return {
            "domains": n("SELECT COUNT(*) n FROM domains"),
            "apex_domains": n("SELECT COUNT(DISTINCT apex_domain) n FROM domains WHERE apex_domain IS NOT NULL"),
            "ips": n("SELECT COUNT(*) n FROM ips"),
            "dns_records": n("SELECT COUNT(*) n FROM dns_records"),
            "whois_snapshots": n("SELECT COUNT(*) n FROM whois_records"),
            "rdap_evidence": n("SELECT COUNT(*) n FROM rdap_evidence"),
            "ct_logs": n("SELECT COUNT(*) n FROM ct_logs"),
            "tls_certs": n("SELECT COUNT(*) n FROM tls_certs"),
            "artifacts": n("SELECT COUNT(*) n FROM payload_artifacts"),
            "artifacts_acquired": n("SELECT COUNT(*) n FROM payload_artifacts WHERE acquisition_status='acquired'"),
            "artifacts_not_acquired": n("SELECT COUNT(*) n FROM payload_artifacts WHERE acquisition_status='not_acquired'"),
            "artifact_source_edges": n("SELECT COUNT(*) n FROM artifact_sources"),
            "enrichment_runs": n("SELECT COUNT(*) n FROM enrichment_runs"),
        }
