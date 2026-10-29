"""SQLite-backed state for the ClickFix -> CAPE pipeline.

Tracks every candidate page from discovery through extraction, review,
submission, and report retrieval so a re-run never reprocesses the same
urlscan result or resubmits the same command twice.
"""

import contextlib
import datetime
import sqlite3
from typing import Iterable, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    source_uuid TEXT UNIQUE NOT NULL,
    page_url TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    command_text TEXT,
    command_sha256 TEXT,
    sanitize_score INTEGER,
    sanitize_reasons TEXT,
    status TEXT NOT NULL DEFAULT 'discovered',
    cape_task_id INTEGER,
    cape_status TEXT,
    report_path TEXT,
    ioc_path TEXT,
    error TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pages_status ON pages(status);
CREATE INDEX IF NOT EXISTS idx_pages_sha ON pages(command_sha256);

-- One row per unique NORMALISED url, regardless of how many times urlscan
-- rescans it. Repeat sightings bump a counter instead of inserting a row, so
-- the table grows with distinct lures rather than with poll volume.
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_norm TEXT UNIQUE NOT NULL,
    url_original TEXT NOT NULL,
    domain TEXT,
    apex_domain TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    last_scan_uuid TEXT,
    last_analyzed_at TEXT,
    last_analysis_status TEXT,
    analysis_count INTEGER NOT NULL DEFAULT 0,
    content_sha256 TEXT
);
CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(domain);
CREATE INDEX IF NOT EXISTS idx_urls_apex ON urls(apex_domain);
CREATE INDEX IF NOT EXISTS idx_urls_last_analyzed ON urls(last_analyzed_at);
CREATE INDEX IF NOT EXISTS idx_urls_content ON urls(content_sha256);

-- One row per DISTINCT recovered payload. Many sightings across many
-- domains collapse to one payload, and therefore to one CAPE task.
CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT UNIQUE NOT NULL,
    original_text TEXT NOT NULL,          -- faithful, never rewritten
    normalized_text TEXT NOT NULL,        -- hashing/comparison form
    defanged_preview TEXT,
    payload_type TEXT,
    payload_subtype TEXT,
    cape_package TEXT,
    classifier_reason TEXT,
    classifier_confidence INTEGER,
    classifier_signals TEXT,
    validation_status TEXT,
    validation_reason TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    sighting_count INTEGER NOT NULL DEFAULT 0,
    cape_task_id INTEGER,
    cape_machine TEXT,
    cape_status TEXT,
    submitted_at TEXT,
    reported_at TEXT,
    report_path TEXT,
    ioc_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_payloads_type ON payloads(payload_type);
CREATE INDEX IF NOT EXISTS idx_payloads_task ON payloads(cape_task_id);
CREATE INDEX IF NOT EXISTS idx_payloads_valid ON payloads(validation_status);

-- Every place a payload was ever seen. Never deleted: duplicates are
-- research provenance, not noise.
CREATE TABLE IF NOT EXISTS payload_sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id INTEGER NOT NULL,
    page_id INTEGER,
    url_id INTEGER,
    source_uuid TEXT,
    url_norm TEXT,
    domain TEXT,
    apex_domain TEXT,
    extraction_layer TEXT,
    extraction_method TEXT,
    source_resource_url TEXT,
    seen_at TEXT NOT NULL,
    FOREIGN KEY (payload_id) REFERENCES payloads(id)
);
CREATE INDEX IF NOT EXISTS idx_sightings_payload ON payload_sightings(payload_id);
CREATE INDEX IF NOT EXISTS idx_sightings_uuid ON payload_sightings(source_uuid);
CREATE INDEX IF NOT EXISTS idx_sightings_apex ON payload_sightings(apex_domain);
"""

# Provenance/diagnostic columns added after the first schema version. Applied
# with ALTER TABLE on open so an existing clickfix.db upgrades in place.
_MIGRATIONS = (
    ("task_url", "TEXT"),            # originally submitted URL (urlscan task.url)
    ("final_url", "TEXT"),           # URL after redirects (urlscan page.url / resp.url)
    ("redirect_chain", "TEXT"),      # JSON list of hops
    ("extraction_method", "TEXT"),   # clipboard_writetext, atob_literal, ...
    ("extraction_layer", "TEXT"),    # urlscan_dom, live_final_url, linked_script, ...
    ("extraction_notes", "TEXT"),    # JSON list: decode/failure diagnostics
    ("layers_tried", "TEXT"),        # JSON list
    ("candidates_found", "INTEGER"),
    ("failure_reason", "TEXT"),      # no_command, page_unreachable, ...
    ("urlscan_result_url", "TEXT"),
    ("screenshot_url", "TEXT"),
    ("cape_machine", "TEXT"),
    ("submitted_at", "TEXT"),
    ("reported_at", "TEXT"),
    ("url_id", "INTEGER"),           # -> urls.id
    ("url_norm", "TEXT"),            # denormalised for direct querying
    ("content_sha256", "TEXT"),      # hash of the fetched page body
    ("source_resource_url", "TEXT"), # resource the command came from, if any
    ("lure_score", "INTEGER"),
    ("payload_id", "INTEGER"),       # -> payloads.id
    ("candidate_type", "TEXT"),      # lure_page | resource_js | archive | ...
    ("candidate_rank", "INTEGER"),
    ("validation_status", "TEXT"),
    ("validation_reason", "TEXT"),
)

_PAGE_INDEXES = (
    ("idx_pages_url_norm", "pages(url_norm)"),
    ("idx_pages_url_id", "pages(url_id)"),
    ("idx_pages_content", "pages(content_sha256)"),
    ("idx_pages_task", "pages(cape_task_id)"),
    ("idx_pages_payload", "pages(payload_id)"),
    ("idx_pages_candtype", "pages(candidate_type)"),
)

# Status lifecycle:
#   discovered -> extracted -> (auto_approved | pending_review) -> approved/rejected
#   approved -> submitted -> reported | failed
#   extracted with no command found -> no_command / page_unreachable /
#       unsupported_obfuscation / resource_fetch_failure / redirect_failure
#   extracted but below the submit bar (review_mode=off) -> low_confidence
#   any stage exception -> error


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class ClickfixStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        # `poll` and `collect` are separate cron jobs writing this same file,
        # so a default connection would hit "database is locked". WAL lets a
        # reader and a writer coexist; busy_timeout makes a blocked writer
        # wait instead of failing immediately.
        self._conn = sqlite3.connect(db_path, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self):
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(pages)")}
        for column, coltype in _MIGRATIONS:
            if column not in existing:
                self._conn.execute(f"ALTER TABLE pages ADD COLUMN {column} {coltype}")
        # Indexes are created after the columns they cover exist.
        for name, target in _PAGE_INDEXES:
            self._conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {target}")

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def has_seen(self, source_uuid: str) -> bool:
        cur = self._conn.execute("SELECT 1 FROM pages WHERE source_uuid = ?", (source_uuid,))
        return cur.fetchone() is not None

    def recent_submission_for_hash(self, command_sha256: str, since_iso: str) -> Optional[sqlite3.Row]:
        cur = self._conn.execute(
            """SELECT * FROM pages WHERE command_sha256 = ? AND discovered_at >= ?
               AND status IN ('submitted', 'reported', 'approved', 'auto_approved')
               ORDER BY discovered_at DESC LIMIT 1""",
            (command_sha256, since_iso),
        )
        return cur.fetchone()

    # --- Payload identity & sightings -------------------------------------
    def upsert_payload(self, sha256: str, original_text: str, normalized_text: str,
                       defanged: str, classification, validation):
        """Create or update the single row representing this payload.

        Returns (row, is_new). The stored `original_text` is written once, on
        first sight, and never rewritten -- the artifact sent to CAPE must stay
        faithful to what was actually recovered.
        """
        ts = now_iso()
        existing = self._conn.execute(
            "SELECT * FROM payloads WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO payloads (sha256, original_text, normalized_text, "
                "defanged_preview, payload_type, payload_subtype, cape_package, "
                "classifier_reason, classifier_confidence, classifier_signals, "
                "validation_status, validation_reason, first_seen, last_seen, "
                "sighting_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (
                    sha256, original_text, normalized_text, defanged,
                    classification.payload_type, classification.subtype,
                    classification.cape_package, classification.reason,
                    classification.confidence, ",".join(classification.signals),
                    validation.status, validation.reason, ts, ts,
                ),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM payloads WHERE sha256 = ?", (sha256,)
            ).fetchone(), True

        self._conn.execute("UPDATE payloads SET last_seen = ? WHERE id = ?", (ts, existing["id"]))
        self._conn.commit()
        return self._conn.execute(
            "SELECT * FROM payloads WHERE id = ?", (existing["id"],)
        ).fetchone(), False

    def add_payload_sighting(self, payload_id: int, **fields):
        """Record another place this payload was seen. Never overwrites."""
        fields.setdefault("seen_at", now_iso())
        cols = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        self._conn.execute(
            f"INSERT INTO payload_sightings (payload_id, {cols}) VALUES (?, {marks})",
            (payload_id, *fields.values()),
        )
        self._conn.execute(
            "UPDATE payloads SET sighting_count = sighting_count + 1 WHERE id = ?", (payload_id,)
        )
        self._conn.commit()

    def payload_by_sha(self, sha256: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM payloads WHERE sha256 = ?", (sha256,)
        ).fetchone()

    def sightings_for_payload(self, payload_id: int) -> List[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM payload_sightings WHERE payload_id = ? ORDER BY seen_at",
            (payload_id,),
        ).fetchall()

    def update_payload(self, payload_id: int, **fields):
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._conn.execute(
            f"UPDATE payloads SET {cols} WHERE id = ?", (*fields.values(), payload_id)
        )
        self._conn.commit()

    def payloads_awaiting_submission(self) -> List[sqlite3.Row]:
        """Validated, confidently-classified payloads with no CAPE task yet."""
        return self._conn.execute(
            "SELECT * FROM payloads WHERE cape_task_id IS NULL "
            "AND validation_status = 'valid' AND payload_type != 'unknown' "
            "AND cape_package != '' ORDER BY first_seen"
        ).fetchall()

    def payload_stats(self) -> dict:
        q = self._conn.execute
        rows = q("SELECT payload_type, COUNT(*) n FROM payloads GROUP BY payload_type").fetchall()
        pkgs = q("SELECT cape_package, COUNT(*) n FROM payloads GROUP BY cape_package").fetchall()
        return {
            "unique_payloads": q("SELECT COUNT(*) n FROM payloads").fetchone()["n"],
            "total_sightings": q("SELECT COUNT(*) n FROM payload_sightings").fetchone()["n"],
            "by_type": {r["payload_type"]: r["n"] for r in rows},
            "by_package": {(r["cape_package"] or "-"): r["n"] for r in pkgs},
            "valid": q(
                "SELECT COUNT(*) n FROM payloads WHERE validation_status='valid'"
            ).fetchone()["n"],
            "submitted": q(
                "SELECT COUNT(*) n FROM payloads WHERE cape_task_id IS NOT NULL"
            ).fetchone()["n"],
        }

    # --- URL-level deduplication -----------------------------------------
    def record_url_sighting(self, url_norm: str, url_original: str, domain: str,
                            apex_domain: str, scan_uuid: str):
        """Register that urlscan showed us this URL again.

        Returns the urls row. A repeat sighting only bumps counters -- it does
        not add a row -- so poll volume never inflates the table.
        """
        ts = now_iso()
        cur = self._conn.execute("SELECT * FROM urls WHERE url_norm = ?", (url_norm,))
        row = cur.fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO urls (url_norm, url_original, domain, apex_domain, first_seen, "
                "last_seen, times_seen, last_scan_uuid) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                (url_norm, url_original, domain, apex_domain, ts, ts, scan_uuid),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM urls WHERE url_norm = ?", (url_norm,)
            ).fetchone()

        self._conn.execute(
            "UPDATE urls SET last_seen = ?, times_seen = times_seen + 1, last_scan_uuid = ? "
            "WHERE id = ?",
            (ts, scan_uuid, row["id"]),
        )
        self._conn.commit()
        return self._conn.execute("SELECT * FROM urls WHERE id = ?", (row["id"],)).fetchone()

    def mark_url_analyzed(self, url_id: int, status: str, content_sha256: Optional[str] = None):
        self._conn.execute(
            "UPDATE urls SET last_analyzed_at = ?, last_analysis_status = ?, "
            "analysis_count = analysis_count + 1, content_sha256 = COALESCE(?, content_sha256) "
            "WHERE id = ?",
            (now_iso(), status, content_sha256, url_id),
        )
        self._conn.commit()

    def apex_analyzed_since(self, apex_domain: str, since_iso: str) -> Optional[sqlite3.Row]:
        """Any URL on this apex domain analysed since `since_iso`."""
        if not apex_domain:
            return None
        cur = self._conn.execute(
            "SELECT * FROM urls WHERE apex_domain = ? AND last_analyzed_at IS NOT NULL "
            "AND last_analyzed_at >= ? ORDER BY last_analyzed_at DESC LIMIT 1",
            (apex_domain, since_iso),
        )
        return cur.fetchone()

    def content_seen(self, content_sha256: str, since_iso: str) -> Optional[sqlite3.Row]:
        """Same page body already analysed elsewhere (campaign sprayed across
        many domains)."""
        if not content_sha256:
            return None
        cur = self._conn.execute(
            "SELECT * FROM urls WHERE content_sha256 = ? AND last_analyzed_at >= ? "
            "ORDER BY last_analyzed_at DESC LIMIT 1",
            (content_sha256, since_iso),
        )
        return cur.fetchone()

    def dedup_stats(self) -> dict:
        q = self._conn.execute
        total_sightings = q("SELECT COALESCE(SUM(times_seen), 0) AS n FROM urls").fetchone()["n"]
        unique_urls = q("SELECT COUNT(*) AS n FROM urls").fetchone()["n"]
        analyzed = q(
            "SELECT COUNT(*) AS n FROM urls WHERE last_analyzed_at IS NOT NULL"
        ).fetchone()["n"]
        domains = q("SELECT COUNT(DISTINCT apex_domain) AS n FROM urls").fetchone()["n"]
        attempts = q("SELECT COUNT(*) AS n FROM pages").fetchone()["n"]
        return {
            "url_sightings": total_sightings,
            "unique_urls": unique_urls,
            "analyzed_urls": analyzed,
            "unique_apex_domains": domains,
            "analysis_rows": attempts,
            "fetches_avoided": max(total_sightings - analyzed, 0),
        }

    def insert_discovered(self, source: str, source_uuid: str, page_url: str) -> int:
        ts = now_iso()
        cur = self._conn.execute(
            "INSERT INTO pages (source, source_uuid, page_url, discovered_at, status, updated_at) "
            "VALUES (?, ?, ?, ?, 'discovered', ?)",
            (source, source_uuid, page_url, ts, ts),
        )
        self._conn.commit()
        return cur.lastrowid

    def update(self, row_id: int, **fields):
        fields["updated_at"] = now_iso()
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._conn.execute(f"UPDATE pages SET {cols} WHERE id = ?", (*fields.values(), row_id))
        self._conn.commit()

    def get(self, row_id: int) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM pages WHERE id = ?", (row_id,))
        return cur.fetchone()

    def list_by_status(self, status: str) -> List[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM pages WHERE status = ? ORDER BY discovered_at", (status,))
        return cur.fetchall()

    def list_all(self, limit: int = 50) -> List[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM pages ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()
