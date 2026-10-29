"""Configuration loading for the ClickFix -> CAPE collection pipeline.

Reads clickfix.conf (INI) next to this file, with secrets overridable via
environment variables so the conf file itself never needs to hold API keys.
"""

import configparser
import os
from dataclasses import dataclass, field
from typing import List

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONF_PATH = os.path.join(_HERE, "clickfix.conf")


@dataclass
class UrlscanConfig:
    api_key: str = ""
    # Lucene-style urlscan.io search query. Tune this to your ClickFix lure
    # phrasing of the day -- lure text/wording drifts frequently.
    query: str = (
        '(page.title:"verify you are human" OR page.title:"I am not a robot" OR '
        'page.title:"human verification" OR page.title:"Cloudflare" ) AND '
        'page.url:*'
    )
    lookback_minutes: int = 20
    page_size: int = 100
    base_url: str = "https://urlscan.io/api/v1/search/"
    # Result API / DOM tier. Both REQUIRE an API key (they 403 without one);
    # search itself works unauthenticated.
    # urlscan rejects a custom sort value for anonymous (and some keyed)
    # accounts with HTTP 403, which silently zeroes out discovery. Leave empty
    # unless your plan permits it.
    sort: str = ""
    use_result_api: bool = True
    result_timeout: int = 20
    max_dom_bytes: int = 5_000_000


@dataclass
class ExtractConfig:
    fetch_timeout: int = 15
    max_page_bytes: int = 3_000_000
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
    max_linked_scripts: int = 5
    follow_iframes: bool = True
    max_iframes: int = 3
    max_meta_refresh_hops: int = 2
    # Stop descending into extra layers once a marker-matching command is in
    # hand -- saves fetches on the common case.
    stop_on_first_hit: bool = True
    # Cap on urlscan captured-response bodies fetched per candidate. Each is an
    # API call against the account's rate limit, so we read the highest-value
    # resources only (see urlscan_result._score_resource).
    max_response_bodies: int = 6


@dataclass
class SanitizeConfig:
    auto_approve_threshold: int = 2
    min_length: int = 8
    max_length: int = 20000
    # review_mode = off  -> fully automatic: anything scoring >= min_submit_score
    #                       is submitted, the rest is recorded as low_confidence.
    # review_mode = on   -> scores below auto_approve_threshold wait for a human.
    review_mode: str = "off"
    min_submit_score: int = 1
    # A page that clearly carries the Win+R / Ctrl+V instruction sequence is a
    # ClickFix lure even when the recovered command scores weakly, so the lure
    # score can rescue a borderline candidate from being dropped.
    lure_score_rescue_threshold: int = 4


@dataclass
class CapeConfig:
    base_url: str = "http://127.0.0.1:8000"
    api_token: str = ""
    package: str = "ps1"
    route: str = "internet"
    # Analysis VM label. Must match a machine in CAPE's machinery conf.
    machine: str = "cuckoo1"
    # CAPE matches task tags against MACHINE tags -- a tag no machine carries
    # makes the task permanently unschedulable. Leave empty and use `machine`
    # for targeting; label the campaign via `custom` instead.
    tags: str = ""
    timeout: int = 200
    priority: int = 1
    poll_interval: int = 30
    max_wait: int = 1800


@dataclass
class PipelineConfig:
    db_path: str = os.path.join(_HERE, "storage", "clickfix.db")
    # Passive intel-collection DB (collection.CollectionStore). A separate file
    # from the operational db_path: it accumulates infrastructure observations
    # and is never pruned, so it keeps a different lifecycle.
    collection_db_path: str = os.path.join(_HERE, "storage", "collection.db")
    # Raw urlscan Result JSON kept alongside the collection DB for evidence and
    # reproducibility (urlscan_feeder). One file per scan UUID, size-capped.
    urlscan_raw_dir: str = os.path.join(_HERE, "storage", "urlscan_raw")
    urlscan_max_raw_bytes: int = 8_000_000
    commands_dir: str = os.path.join(_HERE, "storage", "commands")
    reports_dir: str = os.path.join(_HERE, "storage", "reports")
    audit_log: str = os.path.join(_HERE, "storage", "audit.log")
    skip_duplicate_commands_days: int = 7
    # --- URL-level deduplication -----------------------------------------
    # urlscan issues a new scan UUID on every rescan, so the same lure URL
    # arrives repeatedly (measured ~46% of a 100-result poll). These gates run
    # BEFORE any page fetch.
    # Re-analyse a URL we already analysed only after this many days -- lure
    # domains do swap payloads, so 0 would be wrong, but so is every poll.
    revisit_url_days: int = 7
    # Skip a URL if any other URL on the same apex domain was analysed within
    # this many hours. 0 disables the domain-level gate.
    domain_cooldown_hours: int = 0
    # Skip when the fetched page body hashes identical to one already analysed
    # (same campaign kit sprayed across many domains).
    skip_duplicate_content_days: int = 7


@dataclass
class EnrichmentConfig:
    """Passive infrastructure enrichment (enrichment.py).

    All providers are read-only lookups against public registries / aggregators
    -- never the suspicious host itself. Credentials come from env vars so the
    conf file holds no secrets. A lookup is skipped when a fresh-enough result
    already exists (cache_ttl_hours), and transient failures retry with backoff.
    """

    # Master + per-provider enable switches. RDAP and crt.sh need no key and are
    # on by default; passive DNS needs a configured provider so it is off.
    enabled: bool = True
    rdap_enabled: bool = True
    ct_enabled: bool = True
    pdns_enabled: bool = False

    # RDAP discovery. By default we resolve the AUTHORITATIVE registry server
    # from IANA's official bootstrap registries (data.iana.org/rdap/*.json) and
    # query it directly; rdap_base (the rdap.org redirector) is only the
    # fallback when bootstrap is unavailable or has no entry for the TLD/range.
    use_bootstrap: bool = True
    rdap_bootstrap_dns: str = "https://data.iana.org/rdap/dns.json"
    rdap_bootstrap_ipv4: str = "https://data.iana.org/rdap/ipv4.json"
    rdap_bootstrap_ipv6: str = "https://data.iana.org/rdap/ipv6.json"
    rdap_base: str = "https://rdap.org"
    crtsh_base: str = "https://crt.sh"
    # Hard cap on any single response body we will read into memory.
    max_response_bytes: int = 10_000_000
    # Raw RDAP response evidence kept on disk for audit/reproducibility, one
    # content-addressed file per response (SHA256 of the raw bytes), size-capped.
    rdap_raw_dir: str = os.path.join(_HERE, "storage", "rdap_raw")
    rdap_max_raw_bytes: int = 2_000_000
    # Bound on HTTP redirects followed per request (RDAP can hop registry->server).
    max_redirects: int = 5
    pdns_base: str = ""                     # e.g. a CIRCL/Mnemonic PDNS base URL
    pdns_provider: str = ""                 # label stored in provenance (circl, ...)

    # Secrets: filled from env only (never written here). pdns_user/pass for
    # HTTP-basic PDNS providers like CIRCL.
    pdns_api_key: str = ""
    pdns_user: str = ""
    pdns_password: str = ""

    timeout: int = 20
    cache_ttl_hours: float = 168.0          # re-enrich a SUCCEEDED lookup at most weekly
    transient_ttl_hours: float = 1.0        # retry a failed/quota/timeout lookup this soon
    max_retries: int = 3
    base_backoff: float = 2.0
    max_backoff: float = 60.0
    max_ct_records: int = 200               # cap crt.sh rows ingested per host
    user_agent: str = "clickfix-collector/passive-enrichment"


@dataclass
class Config:
    urlscan: UrlscanConfig = field(default_factory=UrlscanConfig)
    extract: ExtractConfig = field(default_factory=ExtractConfig)
    sanitize: SanitizeConfig = field(default_factory=SanitizeConfig)
    cape: CapeConfig = field(default_factory=CapeConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)


def load_config(path: str = DEFAULT_CONF_PATH) -> Config:
    cfg = Config()
    parser = configparser.ConfigParser()
    if os.path.exists(path):
        parser.read(path)

    if parser.has_section("urlscan"):
        s = parser["urlscan"]
        cfg.urlscan.query = s.get("query", cfg.urlscan.query)
        cfg.urlscan.lookback_minutes = s.getint("lookback_minutes", cfg.urlscan.lookback_minutes)
        cfg.urlscan.page_size = s.getint("page_size", cfg.urlscan.page_size)
        cfg.urlscan.base_url = s.get("base_url", cfg.urlscan.base_url)
        cfg.urlscan.sort = s.get("sort", cfg.urlscan.sort).strip()
        cfg.urlscan.use_result_api = s.getboolean("use_result_api", cfg.urlscan.use_result_api)
        cfg.urlscan.result_timeout = s.getint("result_timeout", cfg.urlscan.result_timeout)
        cfg.urlscan.max_dom_bytes = s.getint("max_dom_bytes", cfg.urlscan.max_dom_bytes)

    if parser.has_section("extract"):
        s = parser["extract"]
        cfg.extract.fetch_timeout = s.getint("fetch_timeout", cfg.extract.fetch_timeout)
        cfg.extract.max_page_bytes = s.getint("max_page_bytes", cfg.extract.max_page_bytes)
        cfg.extract.user_agent = s.get("user_agent", cfg.extract.user_agent)
        cfg.extract.max_linked_scripts = s.getint("max_linked_scripts", cfg.extract.max_linked_scripts)
        cfg.extract.follow_iframes = s.getboolean("follow_iframes", cfg.extract.follow_iframes)
        cfg.extract.max_iframes = s.getint("max_iframes", cfg.extract.max_iframes)
        cfg.extract.max_meta_refresh_hops = s.getint(
            "max_meta_refresh_hops", cfg.extract.max_meta_refresh_hops
        )
        cfg.extract.stop_on_first_hit = s.getboolean("stop_on_first_hit", cfg.extract.stop_on_first_hit)
        cfg.extract.max_response_bodies = s.getint(
            "max_response_bodies", cfg.extract.max_response_bodies
        )

    if parser.has_section("sanitize"):
        s = parser["sanitize"]
        cfg.sanitize.auto_approve_threshold = s.getint("auto_approve_threshold", cfg.sanitize.auto_approve_threshold)
        cfg.sanitize.min_length = s.getint("min_length", cfg.sanitize.min_length)
        cfg.sanitize.max_length = s.getint("max_length", cfg.sanitize.max_length)
        cfg.sanitize.review_mode = s.get("review_mode", cfg.sanitize.review_mode).strip().lower()
        cfg.sanitize.min_submit_score = s.getint("min_submit_score", cfg.sanitize.min_submit_score)
        cfg.sanitize.lure_score_rescue_threshold = s.getint(
            "lure_score_rescue_threshold", cfg.sanitize.lure_score_rescue_threshold
        )

    if parser.has_section("cape"):
        s = parser["cape"]
        cfg.cape.base_url = s.get("base_url", cfg.cape.base_url)
        cfg.cape.package = s.get("package", cfg.cape.package)
        cfg.cape.route = s.get("route", cfg.cape.route)
        cfg.cape.machine = s.get("machine", cfg.cape.machine)
        cfg.cape.tags = s.get("tags", cfg.cape.tags)
        cfg.cape.timeout = s.getint("timeout", cfg.cape.timeout)
        cfg.cape.priority = s.getint("priority", cfg.cape.priority)
        cfg.cape.poll_interval = s.getint("poll_interval", cfg.cape.poll_interval)
        cfg.cape.max_wait = s.getint("max_wait", cfg.cape.max_wait)

    if parser.has_section("pipeline"):
        s = parser["pipeline"]
        cfg.pipeline.db_path = s.get("db_path", cfg.pipeline.db_path)
        cfg.pipeline.collection_db_path = s.get("collection_db_path", cfg.pipeline.collection_db_path)
        cfg.pipeline.urlscan_raw_dir = s.get("urlscan_raw_dir", cfg.pipeline.urlscan_raw_dir)
        cfg.pipeline.urlscan_max_raw_bytes = s.getint(
            "urlscan_max_raw_bytes", cfg.pipeline.urlscan_max_raw_bytes
        )
        cfg.pipeline.commands_dir = s.get("commands_dir", cfg.pipeline.commands_dir)
        cfg.pipeline.reports_dir = s.get("reports_dir", cfg.pipeline.reports_dir)
        cfg.pipeline.audit_log = s.get("audit_log", cfg.pipeline.audit_log)
        cfg.pipeline.skip_duplicate_commands_days = s.getint(
            "skip_duplicate_commands_days", cfg.pipeline.skip_duplicate_commands_days
        )
        cfg.pipeline.revisit_url_days = s.getint("revisit_url_days", cfg.pipeline.revisit_url_days)
        cfg.pipeline.domain_cooldown_hours = s.getint(
            "domain_cooldown_hours", cfg.pipeline.domain_cooldown_hours
        )
        cfg.pipeline.skip_duplicate_content_days = s.getint(
            "skip_duplicate_content_days", cfg.pipeline.skip_duplicate_content_days
        )

    if parser.has_section("enrichment"):
        s = parser["enrichment"]
        e = cfg.enrichment
        e.enabled = s.getboolean("enabled", e.enabled)
        e.rdap_enabled = s.getboolean("rdap_enabled", e.rdap_enabled)
        e.ct_enabled = s.getboolean("ct_enabled", e.ct_enabled)
        e.pdns_enabled = s.getboolean("pdns_enabled", e.pdns_enabled)
        e.use_bootstrap = s.getboolean("use_bootstrap", e.use_bootstrap)
        e.rdap_bootstrap_dns = s.get("rdap_bootstrap_dns", e.rdap_bootstrap_dns)
        e.rdap_bootstrap_ipv4 = s.get("rdap_bootstrap_ipv4", e.rdap_bootstrap_ipv4)
        e.rdap_bootstrap_ipv6 = s.get("rdap_bootstrap_ipv6", e.rdap_bootstrap_ipv6)
        e.rdap_base = s.get("rdap_base", e.rdap_base)
        e.crtsh_base = s.get("crtsh_base", e.crtsh_base)
        e.pdns_base = s.get("pdns_base", e.pdns_base)
        e.pdns_provider = s.get("pdns_provider", e.pdns_provider)
        e.timeout = s.getint("timeout", e.timeout)
        e.cache_ttl_hours = s.getfloat("cache_ttl_hours", e.cache_ttl_hours)
        e.transient_ttl_hours = s.getfloat("transient_ttl_hours", e.transient_ttl_hours)
        e.max_response_bytes = s.getint("max_response_bytes", e.max_response_bytes)
        e.max_redirects = s.getint("max_redirects", e.max_redirects)
        e.rdap_raw_dir = s.get("rdap_raw_dir", e.rdap_raw_dir)
        e.rdap_max_raw_bytes = s.getint("rdap_max_raw_bytes", e.rdap_max_raw_bytes)
        e.max_retries = s.getint("max_retries", e.max_retries)
        e.base_backoff = s.getfloat("base_backoff", e.base_backoff)
        e.max_backoff = s.getfloat("max_backoff", e.max_backoff)
        e.max_ct_records = s.getint("max_ct_records", e.max_ct_records)
        e.user_agent = s.get("user_agent", e.user_agent)

    # Secrets: env vars always win over the conf file.
    cfg.urlscan.api_key = os.environ.get("URLSCAN_API_KEY", cfg.urlscan.api_key)
    cfg.cape.api_token = os.environ.get("CAPE_API_TOKEN", cfg.cape.api_token)
    cfg.enrichment.pdns_api_key = os.environ.get("PDNS_API_KEY", cfg.enrichment.pdns_api_key)
    cfg.enrichment.pdns_user = os.environ.get("PDNS_USER", cfg.enrichment.pdns_user)
    cfg.enrichment.pdns_password = os.environ.get("PDNS_PASSWORD", cfg.enrichment.pdns_password)

    os.makedirs(cfg.pipeline.commands_dir, exist_ok=True)
    os.makedirs(cfg.pipeline.reports_dir, exist_ok=True)
    os.makedirs(os.path.dirname(cfg.pipeline.db_path), exist_ok=True)
    os.makedirs(os.path.dirname(cfg.pipeline.collection_db_path), exist_ok=True)
    return cfg
