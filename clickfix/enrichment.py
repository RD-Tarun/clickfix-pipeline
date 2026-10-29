"""Passive infrastructure enrichment for the collection DB.

Adds registration / network / certificate / passive-DNS context to domains and
IPs that are ALREADY in the collection, using only read-only public sources:

  * RDAP (domain)  -> registrar, created/updated/expires, nameservers, statuses,
                      abuse contact                              [rdap.org]
  * RDAP (ip)      -> network range (CIDR), org, country, abuse contact, status
                      [rdap.org]
  * crt.sh (CT)    -> certificate-transparency log entries for a host
  * passive DNS    -> historical resolutions, when a provider is configured

None of these connect to the suspicious host itself: RDAP talks to registries,
crt.sh is a CT aggregator, passive DNS is a third-party sensor network. There
is no port scanning, no payload retrieval, and no CAPE submission here.

Design:
  * Every provider is a pure function (entity, cfg, getter, sleeper) ->
    EnrichmentOutcome. The HTTP `getter` and the `sleeper` are injected, so
    tests drive every branch offline with no network and no real delay.
  * Results are cached: a lookup is skipped when `needs_enrichment` says a
    fresh-enough run already exists (per EnrichmentConfig.cache_ttl_hours),
    unless --force.
  * Failures are explicit: unavailable / not_found / forbidden / rate-limit
    (-> quota) / timeout are recorded in enrichment_runs and write no rows.
    Missing data is never fabricated and never read as "benign".
  * History is preserved: record_whois keeps a new snapshot only on change,
    record_ct_log/record_dns dedup, so prior evidence is never overwritten.
  * Provenance: enrichment rows are tagged with the provider (rdap:rdap.org,
    ct:crt.sh, pdns:<provider>). The discovery source on the domain/ip row
    (cape:76, urlscan:<uuid>) is preserved -- upsert_ip only fills blank fields.
  * Enrichment makes NO maliciousness judgement; it enriches benign CDN hosts
    and payload hosts alike. Use --only-source to scope to payload infra.

API keys (passive-DNS only) come from env via config and are never logged.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from collection import CollectionStore

log = logging.getLogger("clickfix.enrichment")


# --------------------------------------------------------------------------
# HTTP abstraction (injectable)
# --------------------------------------------------------------------------
@dataclass
class HttpResult:
    status: str                       # ok|not_found|forbidden|rate_limited|timeout|
                                      # request_failed|bad_json|http_error
    code: Optional[int] = None
    data: object = None               # parsed JSON (dict/list) when available
    text: Optional[str] = None
    raw_bytes: Optional[bytes] = None  # exact response body bytes (for evidence)
    retry_after: Optional[int] = None
    note: Optional[str] = None


MAX_RESPONSE_BYTES = 10_000_000          # default body cap; overridable per call
MAX_REDIRECTS = 5


def _read_capped(chunks, max_bytes: int):
    """Accumulate byte chunks up to max_bytes. Returns (bytes, truncated).

    Pure and unit-testable: stops as soon as the cap is exceeded so an
    unbounded body is never fully materialised in memory.
    """
    buf = bytearray()
    truncated = False
    for chunk in chunks:
        if not chunk:
            continue
        buf.extend(chunk)
        if len(buf) > max_bytes:
            truncated = True
            break
    return bytes(buf[:max_bytes]), truncated


_REDIRECT_CODES = (301, 302, 303, 307, 308)
_SENSITIVE_HEADERS = ("authorization", "cookie", "proxy-authorization")
_DEFAULT_PORTS = {"https": 443, "http": 80}


def _effective_origin(parsed):
    """Normalised (scheme, host, port) so credentials are retained only for an
    EXACT origin match -- a different scheme, host, or port (even on the same
    hostname) is a distinct trust boundary and must not receive the creds."""
    port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme)
    return (parsed.scheme, parsed.hostname, port)


def requests_getter(url, headers=None, params=None, auth=None, timeout=20,
                    max_bytes: int = MAX_RESPONSE_BYTES,
                    max_redirects: int = MAX_REDIRECTS, expect_json: bool = True) -> HttpResult:
    """Default getter backed by `requests`. Never raises.

    Redirects are followed MANUALLY (allow_redirects=False) so each hop can be
    validated BEFORE the next request is issued:
      * an HTTPS->non-HTTPS downgrade is refused before the insecure host is
        ever contacted (checking the post-redirect URL would be too late);
      * a non-http(s) scheme is refused;
      * the redirect count is bounded and loops are detected;
      * credentials (basic auth + Authorization/Cookie headers) are dropped the
        moment a redirect leaves the original host, so they never reach an
        untrusted destination.
    The body is streamed under a hard size cap (works for chunked responses
    with no Content-Length), and the response/session are always closed.
    """
    import requests
    from urllib.parse import urlparse, urljoin

    origin = urlparse(url)
    origin_https = origin.scheme == "https"
    origin_tuple = _effective_origin(origin)
    req_headers = dict(headers or {})
    req_auth = auth
    current = url
    first_params = params
    visited = {current}
    try:
        with requests.Session() as sess:                      # always closed
            for hop in range(max_redirects + 1):
                resp = sess.get(current, headers=req_headers,
                                params=(first_params if hop == 0 else None),
                                auth=req_auth, timeout=timeout, stream=True,
                                allow_redirects=False)         # we follow by hand
                try:
                    code = resp.status_code
                    if code in _REDIRECT_CODES:
                        loc = resp.headers.get("Location")
                        if not loc:
                            return HttpResult("http_error", code, note="redirect_no_location")
                        nxt = urljoin(current, loc)
                        ps = urlparse(nxt)
                        # --- validate the target BEFORE contacting it ---
                        if ps.scheme not in ("http", "https"):
                            return HttpResult("request_failed", code, note="bad_redirect_scheme")
                        if origin_https and ps.scheme != "https":
                            return HttpResult("request_failed", code, note="insecure_redirect")
                        if nxt in visited:
                            return HttpResult("request_failed", code, note="redirect_loop")
                        if hop == max_redirects:
                            return HttpResult("request_failed", code, note="too_many_redirects")
                        # leaving the exact origin (scheme/host/port): never
                        # carry credentials along to a different trust boundary
                        if _effective_origin(ps) != origin_tuple:
                            req_auth = None
                            req_headers = {k: v for k, v in req_headers.items()
                                           if k.lower() not in _SENSITIVE_HEADERS}
                        visited.add(nxt)
                        current = nxt
                        continue
                    if code == 429:
                        ra = resp.headers.get("Retry-After")
                        return HttpResult("rate_limited", 429,
                                          retry_after=int(ra) if ra and ra.isdigit() else None)
                    if code == 404:
                        return HttpResult("not_found", 404)
                    if code == 403:
                        return HttpResult("forbidden", 403)
                    raw, truncated = _read_capped(resp.iter_content(65536), max_bytes)
                    if truncated:
                        return HttpResult("http_error", code, note="oversize_response")
                    text = raw.decode(resp.encoding or "utf-8", "replace")
                    if code == 200:
                        data = None
                        if text.strip():
                            try:
                                data = json.loads(text)
                            except ValueError:
                                if expect_json:
                                    return HttpResult("bad_json", 200, text=text, note="non_json_body")
                        return HttpResult("ok", 200, data=data, text=text, raw_bytes=raw)
                    return HttpResult("http_error", code, text=text, note=f"http_{code}")
                finally:
                    resp.close()
            return HttpResult("request_failed", note="too_many_redirects")
    except requests.Timeout:
        return HttpResult("timeout", note="request_timeout")
    except requests.RequestException as exc:
        # Covers connect/read/chunked-decode errors raised mid-stream too.
        return HttpResult("request_failed", note=exc.__class__.__name__)


def _http_opts(cfg, expect_json: bool = True) -> dict:
    """The per-request limits from config, passed to every getter call so the
    configured timeout / size cap / redirect bound are actually honoured."""
    return {"timeout": cfg.timeout, "max_bytes": cfg.max_response_bytes,
            "max_redirects": cfg.max_redirects, "expect_json": expect_json}


def _with_backoff(call: Callable[[], HttpResult], max_retries, base, cap, sleeper) -> HttpResult:
    attempt = 0
    while True:
        r = call()
        if r.status in ("rate_limited", "timeout") and attempt < max_retries:
            delay = r.retry_after if (r.status == "rate_limited" and r.retry_after) \
                else base * (2 ** attempt)
            sleeper(min(delay, cap))
            attempt += 1
            continue
        return r


# --------------------------------------------------------------------------
# Provider outcomes
# --------------------------------------------------------------------------
@dataclass
class EnrichmentOutcome:
    lookup: str
    status: str                       # ok|empty|not_configured|not_found|forbidden|
                                      # quota|timeout|error
    source: str = ""
    whois: Optional[dict] = None      # for rdap / rdap_ip
    ip_fields: Optional[dict] = None  # for rdap_ip -> ips table
    ct: List[dict] = field(default_factory=list)
    dns: List[dict] = field(default_factory=list)
    note: Optional[str] = None
    raw: Optional[bytes] = None        # exact raw response bytes (RDAP evidence)
    endpoint: Optional[str] = None     # the URL actually queried

    def counts(self) -> dict:
        return {"whois": 1 if self.whois else 0, "ct": len(self.ct), "dns": len(self.dns),
                "ip_fields": 1 if self.ip_fields else 0}


def _map_fail(status: str) -> str:
    return {"rate_limited": "quota", "bad_json": "error", "request_failed": "error",
            "http_error": "error"}.get(status, status)


# --------------------------------------------------------------------------
# RDAP parsing helpers
# --------------------------------------------------------------------------
def _vcard_prop(entity: dict, name: str) -> Optional[str]:
    """Pull a property (fn/email/...) from an RDAP entity's jCard."""
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == name:
            return prop[3] if isinstance(prop[3], str) else None
    return None


def _find_entity(entities, role):
    """Depth-first search for an entity carrying `role`, returning it."""
    for ent in entities or []:
        if not isinstance(ent, dict):
            continue
        if role in (ent.get("roles") or []):
            return ent
        nested = _find_entity(ent.get("entities"), role)
        if nested is not None:
            return nested
    return None


def _abuse_email(entities) -> Optional[str]:
    abuse = _find_entity(entities, "abuse")
    return _vcard_prop(abuse, "email") if abuse else None


def _events(payload: dict) -> dict:
    out = {}
    for ev in (payload.get("events") or []):
        if isinstance(ev, dict) and ev.get("eventAction") and ev.get("eventDate"):
            out[ev["eventAction"].lower()] = ev["eventDate"]
    return out


# --------------------------------------------------------------------------
# RDAP bootstrap (RFC 7484): resolve the authoritative registry server from
# IANA's official bootstrap registries rather than hardcoding one endpoint.
# --------------------------------------------------------------------------
def _hostname(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


def _pick_https(urls) -> Optional[str]:
    if not isinstance(urls, list):
        return None
    for u in urls:
        if isinstance(u, str) and u.startswith("https://"):
            return u
    return urls[0] if urls and isinstance(urls[0], str) else None


class RdapBootstrap:
    """Lazily loads and caches IANA RDAP bootstrap registries, then maps a
    domain's TLD / an IP to its authoritative RDAP base URL (RFC 7484).

    Network access goes through the injected `getter`, so this is fully offline
    testable. A failed or missing bootstrap yields None, and the caller falls
    back to the configured redirector."""

    def __init__(self, cfg):
        self.cfg = cfg
        self._dns = None     # {tld: base_url}
        self._v4 = None      # [(ip_network, base_url)]
        self._v6 = None
        self._tried = set()

    def _fetch(self, url, getter, sleeper):
        r = _with_backoff(
            lambda: getter(url, headers={"User-Agent": self.cfg.user_agent}, **_http_opts(self.cfg)),
            self.cfg.max_retries, self.cfg.base_backoff, self.cfg.max_backoff, sleeper)
        return r.data if (r.status == "ok" and isinstance(r.data, dict)) else None

    def _dns_map(self, getter, sleeper):
        if self._dns is None and "dns" not in self._tried:
            self._tried.add("dns")
            data = self._fetch(self.cfg.rdap_bootstrap_dns, getter, sleeper)
            m = {}
            for svc in (data or {}).get("services") or []:
                if len(svc) >= 2:
                    base = _pick_https(svc[1])
                    for tld in svc[0] or []:
                        if base:
                            m[str(tld).lower().strip(".")] = base
            self._dns = m
        return self._dns or {}

    def _ip_nets(self, which, url, getter, sleeper):
        attr = "_" + which
        if getattr(self, attr) is None and which not in self._tried:
            self._tried.add(which)
            data = self._fetch(url, getter, sleeper)
            nets = []
            for svc in (data or {}).get("services") or []:
                if len(svc) >= 2:
                    base = _pick_https(svc[1])
                    for cidr in svc[0] or []:
                        try:
                            nets.append((ipaddress.ip_network(cidr, strict=False), base))
                        except ValueError:
                            continue
            setattr(self, attr, nets)
        return getattr(self, attr) or []

    def domain_base(self, domain, getter, sleeper) -> Optional[str]:
        m = self._dns_map(getter, sleeper)
        if not m:
            return None
        labels = domain.lower().strip(".").split(".")
        # Longest-suffix match (handles both 'com' and any multi-label keys).
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in m:
                return m[suffix]
        return None

    def ip_base(self, ip, getter, sleeper) -> Optional[str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        which, url = ("v6", self.cfg.rdap_bootstrap_ipv6) if addr.version == 6 \
            else ("v4", self.cfg.rdap_bootstrap_ipv4)
        best = None
        for net, base in self._ip_nets(which, url, getter, sleeper):
            if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, base)
        return best[1] if best else None


# --------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------
def _rdap_base_for(kind, entity, cfg, getter, sleeper, bootstrap):
    """Return (base_url, note). Uses IANA bootstrap first, rdap.org as fallback."""
    base = None
    if cfg.use_bootstrap and bootstrap is not None:
        base = (bootstrap.domain_base(entity, getter, sleeper) if kind == "domain"
                else bootstrap.ip_base(entity, getter, sleeper))
    if base:
        return base, None
    return cfg.rdap_base, ("bootstrap_fallback" if cfg.use_bootstrap else None)


def rdap_domain(domain: str, cfg, getter, sleeper, bootstrap=None) -> EnrichmentOutcome:
    base, note = _rdap_base_for("domain", domain, cfg, getter, sleeper, bootstrap)
    src = f"rdap:{_hostname(base)}"
    url = f"{base.rstrip('/')}/domain/{domain}"
    r = _with_backoff(lambda: getter(url, headers={"User-Agent": cfg.user_agent,
                                                   "Accept": "application/rdap+json"},
                                     **_http_opts(cfg)),
                      cfg.max_retries, cfg.base_backoff, cfg.max_backoff, sleeper)
    if r.status != "ok":
        return EnrichmentOutcome("rdap", _map_fail(r.status), src, note=r.note or r.status)
    if not isinstance(r.data, dict):
        # A 200 whose body did not parse as a JSON object is a provider glitch,
        # not an authoritative "no data" -- treat as transient error.
        return EnrichmentOutcome("rdap", "error", src, note="bad_json")
    p = r.data
    ev = _events(p)
    registrar = None
    reg_ent = _find_entity(p.get("entities"), "registrar")
    if reg_ent:
        registrar = _vcard_prop(reg_ent, "fn")
    nameservers = [ns.get("ldhName") for ns in (p.get("nameservers") or [])
                   if isinstance(ns, dict) and ns.get("ldhName")]
    whois = {
        "registrar": registrar,
        "created": ev.get("registration"),
        "updated": ev.get("last changed") or ev.get("last update of rdap database"),
        "expires": ev.get("expiration"),
        "registrant_org": _vcard_prop(_find_entity(p.get("entities"), "registrant") or {}, "org"),
        "name_servers": nameservers or None,
        "statuses": p.get("status") or None,
        "abuse_contact": _abuse_email(p.get("entities")),
    }
    raw = r.raw_bytes if r.raw_bytes is not None else (r.text or "").encode("utf-8")
    return EnrichmentOutcome("rdap", "ok", src, whois=whois, note=note, raw=raw, endpoint=url)


def rdap_ip(ip: str, cfg, getter, sleeper, bootstrap=None) -> EnrichmentOutcome:
    base, note = _rdap_base_for("ip", ip, cfg, getter, sleeper, bootstrap)
    src = f"rdap:{_hostname(base)}"
    url = f"{base.rstrip('/')}/ip/{ip}"
    r = _with_backoff(lambda: getter(url, headers={"User-Agent": cfg.user_agent,
                                                   "Accept": "application/rdap+json"},
                                     **_http_opts(cfg)),
                      cfg.max_retries, cfg.base_backoff, cfg.max_backoff, sleeper)
    if r.status != "ok":
        return EnrichmentOutcome("rdap_ip", _map_fail(r.status), src, note=r.note or r.status)
    if not isinstance(r.data, dict):
        return EnrichmentOutcome("rdap_ip", "error", src, note="bad_json")
    p = r.data
    cidr = None
    cidrs = p.get("cidr0_cidrs")
    if isinstance(cidrs, list) and cidrs:
        c = cidrs[0]
        pref = c.get("v4prefix") or c.get("v6prefix")
        if pref and c.get("length") is not None:
            cidr = f"{pref}/{c['length']}"
    if not cidr and p.get("startAddress") and p.get("endAddress"):
        cidr = f"{p['startAddress']}-{p['endAddress']}"
    org = p.get("name")
    country = p.get("country")
    whois = {"cidr": cidr, "registrant_org": org, "statuses": p.get("status") or None,
             "abuse_contact": _abuse_email(p.get("entities"))}
    ip_fields = {"as_org": org, "country": country}  # ASN not in RDAP-ip; leave unknown
    raw = r.raw_bytes if r.raw_bytes is not None else (r.text or "").encode("utf-8")
    return EnrichmentOutcome("rdap_ip", "ok", src, whois=whois, ip_fields=ip_fields, note=note,
                             raw=raw, endpoint=url)


def ct_crtsh(domain: str, cfg, getter, sleeper, bootstrap=None) -> EnrichmentOutcome:
    src = "ct:crt.sh"
    url = f"{cfg.crtsh_base.rstrip('/')}/"
    r = _with_backoff(lambda: getter(url, params={"q": domain, "output": "json"},
                                     headers={"User-Agent": cfg.user_agent}, **_http_opts(cfg)),
                      cfg.max_retries, cfg.base_backoff, cfg.max_backoff, sleeper)
    if r.status != "ok":
        return EnrichmentOutcome("ct", _map_fail(r.status), src, note=r.note or r.status)
    rows = r.data
    if rows is None and r.text:
        try:
            rows = json.loads(r.text)
        except ValueError:
            return EnrichmentOutcome("ct", "error", src, note="bad_json")
    if not isinstance(rows, list):
        return EnrichmentOutcome("ct", "empty", src)
    out = []
    for row in rows[: cfg.max_ct_records]:
        if not isinstance(row, dict) or row.get("id") is None:
            continue
        names = row.get("name_value") or ""
        out.append({
            "ct_id": row.get("id"),
            "common_name": row.get("common_name"),
            "name_value": [n for n in str(names).splitlines() if n] or None,
            "issuer": row.get("issuer_name"),
            "serial": row.get("serial_number"),
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "entry_timestamp": row.get("entry_timestamp"),
        })
    return EnrichmentOutcome("ct", "ok" if out else "empty", src, ct=out)


def pdns_lookup(entity: str, cfg, getter, sleeper, bootstrap=None) -> EnrichmentOutcome:
    src = f"pdns:{cfg.pdns_provider or 'generic'}"
    if not (cfg.pdns_enabled and cfg.pdns_base):
        return EnrichmentOutcome("pdns", "not_configured", src,
                                 note="no passive-DNS provider configured")
    url = f"{cfg.pdns_base.rstrip('/')}/{entity}"
    auth = (cfg.pdns_user, cfg.pdns_password) if cfg.pdns_user else None
    headers = {"User-Agent": cfg.user_agent}
    if cfg.pdns_api_key:
        headers["Authorization"] = cfg.pdns_api_key  # never logged
    r = _with_backoff(lambda: getter(url, headers=headers, auth=auth,
                                     **_http_opts(cfg, expect_json=False)),
                      cfg.max_retries, cfg.base_backoff, cfg.max_backoff, sleeper)
    if r.status != "ok":
        return EnrichmentOutcome("pdns", _map_fail(r.status), src, note=r.note or r.status)
    # Accept either a JSON array or JSONL (one record per line), as providers vary.
    records = []
    if isinstance(r.data, list):
        records = r.data
    elif r.text:
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    dns = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        name = rec.get("rrname") or rec.get("name")
        rtype = (rec.get("rrtype") or rec.get("type") or "").upper()
        value = rec.get("rdata") or rec.get("value")
        if name and value and rtype:
            dns.append({"domain": str(name).rstrip("."), "rrtype": rtype, "value": str(value)})
    return EnrichmentOutcome("pdns", "ok" if dns else "empty", src, dns=dns)


# --------------------------------------------------------------------------
# Apply outcomes to the store (only on commit)
# --------------------------------------------------------------------------
def _store_rdap_raw(raw: bytes, raw_dir: str, max_bytes: int) -> dict:
    """Persist raw RDAP bytes to a content-addressed file (SHA256 name), atomic
    write, size-capped. Returns {sha256, byte_len, stored, path?}. A body over
    the cap is hashed/sized but not written (path stays None)."""
    sha = hashlib.sha256(raw).hexdigest()
    out = {"sha256": sha, "byte_len": len(raw), "stored": False, "path": None}
    if len(raw) > max_bytes:
        out["reason"] = "oversize"
        return out
    os.makedirs(raw_dir, exist_ok=True)
    dest = os.path.join(raw_dir, f"{sha}.json")
    if not os.path.exists(dest):                 # content-addressed => identical body reused
        tmp = dest + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(raw)
        os.replace(tmp, dest)
    out["stored"] = True
    out["path"] = dest
    return out


def _apply(store: CollectionStore, cfg, etype: str, entity: str, oc: EnrichmentOutcome) -> dict:
    wrote = {"whois": 0, "ct": 0, "dns": 0, "ip_fields": 0, "evidence": 0}
    whois_row = None
    if oc.whois:
        kind = "ip" if etype == "ip" else "domain"
        whois_row, new = store.record_whois(entity, kind=kind, source=oc.source, **oc.whois)
        wrote["whois"] += int(new)
    # Raw RDAP evidence: only for a SUCCEEDED rdap lookup that produced a whois
    # row (failures/invalid bodies never get here -- they have no oc.whois/raw).
    if oc.raw and oc.lookup in ("rdap", "rdap_ip") and whois_row is not None:
        ev = _store_rdap_raw(oc.raw, cfg.rdap_raw_dir, cfg.rdap_max_raw_bytes)
        _, enew = store.record_rdap_evidence(
            entity, kind=("ip" if etype == "ip" else "domain"), provider=oc.source,
            endpoint=oc.endpoint, raw_sha256=ev["sha256"], byte_len=ev["byte_len"],
            raw_path=ev["path"], whois_raw_sha256=whois_row["raw_sha256"],
        )
        wrote["evidence"] += int(enew)
    if oc.ip_fields and etype == "ip":
        store.upsert_ip(entity, as_org=oc.ip_fields.get("as_org"),
                        country=oc.ip_fields.get("country"), source=oc.source)
        wrote["ip_fields"] = 1
    for c in oc.ct:
        _, new = store.record_ct_log(entity, source=oc.source, **c)
        wrote["ct"] += int(new)
    for d in oc.dns:
        _, new = store.record_dns(d["domain"], d["rrtype"], d["value"], source=oc.source)
        wrote["dns"] += int(new)
    return wrote


# Which lookups apply to each entity type.
_DOMAIN_PROVIDERS = {"rdap": rdap_domain, "ct": ct_crtsh, "pdns": pdns_lookup}
_IP_PROVIDERS = {"rdap": rdap_ip, "pdns": pdns_lookup}


def _entity_type(entity: str) -> str:
    try:
        ipaddress.ip_address(entity.strip())
        return "ip"
    except ValueError:
        return "domain"


def _enabled_lookups(cfg, requested: Optional[List[str]]) -> List[str]:
    base = []
    if cfg.rdap_enabled:
        base.append("rdap")
    if cfg.ct_enabled:
        base.append("ct")
    if cfg.pdns_enabled:
        base.append("pdns")
    if requested:
        base = [l for l in base if l in requested]
        # 'pdns' can be explicitly requested even if only base-configured off
        for l in requested:
            if l == "pdns" and "pdns" not in base and cfg.pdns_enabled:
                base.append("pdns")
    return base


# Outcomes that are authoritative enough to cache for the full TTL. Anything
# else (error/timeout/quota) is transient and retried after transient_ttl_hours,
# so a single 429 or timeout never locks an entity out for a week.
_TERMINAL_STATUSES = {"ok", "empty", "not_found", "forbidden", "not_configured"}


def _is_fresh(store: CollectionStore, etype: str, entity: str, lookup: str, cfg) -> bool:
    """True if a recent-enough prior run means we can skip this lookup."""
    last = store.last_enrichment(etype, entity, lookup)
    if last is None:
        return False
    ttl = cfg.cache_ttl_hours if last["status"] in _TERMINAL_STATUSES else cfg.transient_ttl_hours
    try:
        then = datetime.datetime.fromisoformat(last["ran_at"])
    except (ValueError, TypeError):
        return False
    age = (datetime.datetime.now(datetime.timezone.utc) - then).total_seconds()
    return age < ttl * 3600


def _whois_hash_for_outcome(store: CollectionStore, oc: EnrichmentOutcome) -> str:
    """Compute the whois content hash the normalized row WOULD get from this
    RDAP outcome, using the store's single hashing basis -- no writes."""
    w = oc.whois or {}
    ns_json = json.dumps(w["name_servers"]) if w.get("name_servers") is not None else None
    st_json = json.dumps(w["statuses"]) if w.get("statuses") is not None else None
    return store.whois_basis_sha256(
        registrar=w.get("registrar"), created=w.get("created"), updated=w.get("updated"),
        expires=w.get("expires"), registrant_org=w.get("registrant_org"),
        name_servers_json=ns_json, asn=w.get("asn"), cidr=w.get("cidr"),
        statuses_json=st_json, abuse_contact=w.get("abuse_contact"),
    )


def backfill_rdap_evidence(store: CollectionStore, cfg, entity: str, etype: str, *,
                           getter: Callable, sleeper: Callable[[float], None],
                           bootstrap: RdapBootstrap, dry_run: bool = False) -> dict:
    """Evidence-only RDAP backfill for one entity.

    Fetches RDAP, computes the normalized-field hash, and compares it to the
    EXISTING whois row. On a match it persists only the raw evidence (linked to
    that row) and never calls record_whois -- so times_seen/last_seen are
    untouched and no snapshot is inserted. On a mismatch (or no stored row) it
    writes nothing and reports a stale/mismatch status.
    """
    provider = rdap_domain if etype == "domain" else rdap_ip
    oc = provider(entity, cfg, getter, sleeper, bootstrap=bootstrap)
    base = {"lookup": oc.lookup, "mode": "evidence_only", "source": oc.source,
            "endpoint": oc.endpoint}
    if oc.status != "ok" or not oc.whois or not oc.raw:
        return {**base, "status": oc.status, "note": oc.note, "evidence_written": False}

    want = _whois_hash_for_outcome(store, oc)
    match = next((r for r in store.whois_history(entity) if r["raw_sha256"] == want), None)
    if match is None:
        return {**base, "status": "evidence_skipped_stale_whois", "computed_hash": want,
                "evidence_written": False,
                "note": "fetched RDAP hash matches no stored whois snapshot; whois left unchanged"}
    if dry_run:
        return {**base, "status": "match", "computed_hash": want, "evidence_written": False,
                "dry_run": True}

    ev = _store_rdap_raw(oc.raw, cfg.rdap_raw_dir, cfg.rdap_max_raw_bytes)
    _, enew = store.record_rdap_evidence(
        entity, kind=("ip" if etype == "ip" else "domain"), provider=oc.source,
        endpoint=oc.endpoint, raw_sha256=ev["sha256"], byte_len=ev["byte_len"],
        raw_path=ev["path"], whois_raw_sha256=match["raw_sha256"])
    # audited under a distinct lookup name so the normal 'rdap' cache is untouched
    store.record_enrichment(etype, entity, "rdap_evidence", "ok",
                            detail=json.dumps({"raw_sha256": ev["sha256"],
                                               "byte_len": ev["byte_len"], "stored": ev["stored"]}))
    return {**base, "status": "evidence_written", "computed_hash": want,
            "evidence_sha256": ev["sha256"], "raw_path": ev["path"], "stored": ev["stored"],
            "evidence_written": bool(enew), "whois_untouched": True}


def enrich_entity(store: CollectionStore, cfg, entity: str, *, dry_run: bool = True,
                  force: bool = False, lookups: Optional[List[str]] = None,
                  getter: Callable = requests_getter,
                  sleeper: Callable[[float], None] = time.sleep,
                  bootstrap: Optional[RdapBootstrap] = None,
                  evidence_only: bool = False) -> dict:
    """Enrich a single domain or IP. Returns a per-lookup summary. Writes only
    when dry_run is False. In evidence_only mode, RDAP raw evidence is backfilled
    without ever mutating the normalized whois row (see backfill_rdap_evidence)."""
    entity = entity.strip()
    etype = _entity_type(entity)
    if bootstrap is None:
        bootstrap = RdapBootstrap(cfg)
    if evidence_only:
        res = backfill_rdap_evidence(store, cfg, entity, etype, getter=getter,
                                     sleeper=sleeper, bootstrap=bootstrap, dry_run=dry_run)
        return {"entity": entity, "entity_type": etype, "dry_run": dry_run,
                "evidence_only": True, "lookups": [res]}
    providers = _DOMAIN_PROVIDERS if etype == "domain" else _IP_PROVIDERS
    chosen = [l for l in _enabled_lookups(cfg, lookups) if l in providers]
    results = []
    for lookup in chosen:
        if not force and _is_fresh(store, etype, entity, lookup, cfg):
            results.append({"lookup": lookup, "status": "cached"})
            continue
        oc = providers[lookup](entity, cfg, getter, sleeper, bootstrap=bootstrap)
        entry = {"lookup": lookup, "status": oc.status, "source": oc.source,
                 "counts": oc.counts(), "note": oc.note}
        if not dry_run:
            entry["wrote"] = _apply(store, cfg, etype, entity, oc)
            store.record_enrichment(etype, entity, lookup, oc.status,
                                    detail=oc.note or json.dumps(oc.counts()))
        results.append(entry)
    return {"entity": entity, "entity_type": etype, "dry_run": dry_run, "lookups": results}


def enrich_many(store: CollectionStore, cfg, *, which: str, only_source: Optional[str] = None,
                limit: Optional[int] = None, **kw) -> dict:
    """Enrich selected collection entities. `which` in {domains, ips, all}."""
    entities = []
    if which in ("domains", "all"):
        entities += [("domain", r["fqdn"]) for r in store.list_domains(only_source, limit)]
    if which in ("ips", "all"):
        entities += [("ip", r["ip"]) for r in store.list_ips(only_source, limit)]
    kw.setdefault("bootstrap", RdapBootstrap(cfg))   # one bootstrap, cached across entities
    summaries = [enrich_entity(store, cfg, ent, **kw) for _etype, ent in entities]
    return {"selected": len(entities), "which": which, "only_source": only_source,
            "results": summaries}


# --------------------------------------------------------------------------
def inspect_evidence(store: CollectionStore, entity: str) -> dict:
    """Read-only inspection of stored RDAP raw evidence for one entity.

    Never writes, never fetches. For each rdap_evidence row it independently
    re-verifies the on-disk raw file (size == byte_len, sha256 == raw_sha256),
    checks the linked whois_records snapshot exists, and recomputes that
    snapshot's canonical hash via the project's single hash helper
    (CollectionStore.whois_basis_sha256) to confirm the linkage.
    """
    rows = store.rdap_evidence_for(entity)
    whois_by_hash = {w["raw_sha256"]: w for w in store.whois_history(entity)}
    out = {"entity": entity, "count": len(rows), "evidence": []}
    for r in rows:
        item = {
            "entity": r["entity"], "kind": r["kind"], "provider": r["provider"],
            "endpoint": r["endpoint"], "raw_path": r["raw_path"],
            "stored_sha256": r["raw_sha256"], "stored_byte_len": r["byte_len"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "times_seen": r["times_seen"], "whois_raw_sha256": r["whois_raw_sha256"],
        }
        # --- independent raw-file verification (binary read) ---
        if not r["raw_path"]:
            item["file_status"] = "metadata_only"      # oversize: body was not persisted
        elif not os.path.isfile(r["raw_path"]):
            item["file_status"] = "missing"
        else:
            try:
                with open(r["raw_path"], "rb") as fh:
                    data = fh.read()
            except OSError as exc:
                item["file_status"] = "unreadable"
                item["error"] = exc.__class__.__name__
            else:
                item["actual_byte_len"] = len(data)
                item["actual_sha256"] = hashlib.sha256(data).hexdigest()
                item["size_ok"] = (len(data) == r["byte_len"])
                item["sha_ok"] = (item["actual_sha256"] == r["raw_sha256"])
                item["file_status"] = "ok" if (item["size_ok"] and item["sha_ok"]) else "mismatch"
        # --- linked whois snapshot ---
        w = whois_by_hash.get(r["whois_raw_sha256"])
        item["whois_linked"] = w is not None
        if w is not None:
            recomputed = store.whois_basis_sha256(
                registrar=w["registrar"], created=w["created"], updated=w["updated"],
                expires=w["expires"], registrant_org=w["registrant_org"],
                name_servers_json=w["name_servers"], asn=w["asn"], cidr=w["cidr"],
                statuses_json=w["statuses"], abuse_contact=w["abuse_contact"])
            item["whois_snapshot_hash"] = recomputed
            item["whois_hash_matches_evidence"] = (recomputed == r["whois_raw_sha256"])
            item["whois_stored_hash_ok"] = (recomputed == w["raw_sha256"])
        else:
            item["whois_snapshot_hash"] = None
            item["whois_hash_matches_evidence"] = False
        out["evidence"].append(item)
    return out


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="enrichment",
        description="Passive RDAP/CT/passive-DNS enrichment of the collection DB. "
                    "Dry-run by default; pass --commit to write. Read-only public "
                    "sources only -- never connects to the target host.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("entity", nargs="?", help="a single domain or IP already in the collection")
    g.add_argument("--entity", dest="which", choices=["domains", "ips", "all"],
                   help="enrich a selected set of collection entities")
    p.add_argument("--show-evidence", action="store_true",
                   help="read-only: show and re-verify stored RDAP raw evidence for the entity "
                        "(no network, no writes, no enrichment)")
    p.add_argument("--commit", action="store_true", help="write results (default: dry run)")
    p.add_argument("--evidence-only", action="store_true",
                   help="backfill raw RDAP evidence only; never mutate the normalized whois row "
                        "(writes evidence just when the fetched hash matches the stored snapshot)")
    p.add_argument("--force", action="store_true", help="ignore the enrichment cache TTL")
    p.add_argument("--lookups", help="comma list to restrict: rdap,ct,pdns")
    p.add_argument("--only-source", help="limit --entity sets to rows whose source starts with this "
                                         "(e.g. 'cape:76' for payload infra only)")
    p.add_argument("--limit", type=int, default=None, help="max entities for --entity sets")
    p.add_argument("--db", default=None, help="collection DB path (default: config)")
    return p


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _build_arg_parser().parse_args(argv)
    from config import load_config
    cfg = load_config()
    db_path = args.db or cfg.pipeline.collection_db_path
    # Read-only evidence inspection: works regardless of the enrichment enable
    # flag, performs no network/writes, and returns before the enrich paths.
    if args.show_evidence:
        if not args.entity:
            print("error: --show-evidence requires a single entity (not --entity sets)",
                  file=sys.stderr)
            return 2
        with CollectionStore(db_path) as store:
            out = inspect_evidence(store, args.entity)
        print(json.dumps({"show_evidence": out}, indent=2, default=str))
        return 0
    if not cfg.enrichment.enabled:
        print("error: enrichment is disabled in config ([enrichment] enabled=no)", file=sys.stderr)
        return 2
    lookups = [x.strip() for x in args.lookups.split(",")] if args.lookups else None
    with CollectionStore(db_path) as store:
        if args.which:
            out = enrich_many(store, cfg.enrichment, which=args.which, only_source=args.only_source,
                              limit=args.limit, dry_run=not args.commit, force=args.force,
                              lookups=lookups)
        else:
            out = enrich_entity(store, cfg.enrichment, args.entity, dry_run=not args.commit,
                                force=args.force, lookups=lookups,
                                evidence_only=args.evidence_only)
        totals = store.stats()
    print(json.dumps({"enrichment": out, "collection_totals": totals}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
