"""Scheduled ClickFix lure catcher.

The problem this solves: ClickFix lures are ephemeral and gated, so a slow poll
almost always arrives after they are dead. This runs a fast, repeatable *sweep*
so we can catch one while it is still live:

  urlscan search (fresh)  ->  triage each by urlscan's OWN captured DOM signal
  (clipboard-write JS / Win+R instructions / a statically recoverable command)
  ->  for signalled lures only, render in a Windows-UA headless browser, click
      the verify/robot elements, and capture the clipboard-written command
  ->  record any recovered command to a JSONL evidence log.

Nothing is executed and no recovered command is run; captured text is DATA.
Designed to be run every few minutes (cron) or with --loop. Browser extraction
needs the Playwright env (PLAYWRIGHT_BROWSERS_PATH + the pwenv interpreter);
without it the sweep still reports static/urlscan-DOM hits.
"""

import argparse
import configparser
import datetime
import json
import logging
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from config import load_config                       # noqa: E402
from urlscan_source import search_candidates         # noqa: E402
from urlscan_result import fetch_scan_detail         # noqa: E402
import clickgrab_extract as cg                        # noqa: E402
from classify import classify_payload                # noqa: E402
from validate import validate_payload                # noqa: E402
from sanitize import evaluate as sanitize_eval       # noqa: E402
from cape_client import CapeClient                   # noqa: E402
from collection import CollectionStore, artifact_key  # noqa: E402  (domain + payload dedup)
import livefeeds                                     # noqa: E402

# Routes that detonate WITHOUT spilling onto the physical/host network: a VPN
# "dirty line", Tor, or a fully-isolated fake internet (inetsim). `internet`
# NATs out the host's real uplink and is NEVER used for auto-detonation; `drop`
# blocks egress (no real detonation). The submitter refuses anything not here.
ISOLATED_ROUTES = ("vpn", "tor", "inetsim")
_ENABLED_TRUE = ("yes", "true", "on", "1")
_ROUTING_CONF = "/opt/CAPEv2/conf/routing.conf"
_EXT = {"ps1": ".ps1", "batch": ".bat", "exe": ".exe"}

try:
    from browser_extractor import browser_extract
    HAVE_BROWSER = True
except Exception:
    HAVE_BROWSER = False

log = logging.getLogger("clickfix.catcher")

# urlscan-DOM signals that a live lure was actually captured.
_CLIP_RE = re.compile(r'writeText\s*\(|execCommand\s*\(\s*[\'"]copy|commandToRun|'
                      r'navigator\.clipboard', re.IGNORECASE)
_PAYLOAD_EXT = ('.ps1', '.dat', '.msi', '.bat', '.exe', '.zip', '.hta', '.vbs',
                '.cmd', '.jar', '.scr')

# Interaction selectors for the fake-captcha UIs (bounded clicks).
_INTERACTIONS = (
    'input[type=checkbox]', '[class*="robot"]', '[class*="verify"]', '[class*="captcha"]',
    "text=/i.?m not a robot/i", "text=/verify/i", "text=/human/i", "text=/continue/i",
    "text=/copy/i", "text=/fix/i", 'button', 'a[role="button"]',
)

# Optional residential/clean-IP proxy for the browser path. Unset -> direct
# (current behaviour). Set CLICKFIX_PROXY in ~/.clickfix-env to e.g.
# 'http://user:pass@host:port' and restart to make IP-gated lures inject for us.
_PROXY = os.getenv("CLICKFIX_PROXY") or None


def _is_payload_url(url: str) -> bool:
    return (url or "").split("?")[0].lower().endswith(_PAYLOAD_EXT)


def isolated_route_ready(routing_conf: str = _ROUTING_CONF):
    """Return (route, reason): an ISOLATED, enabled CAPE route usable to detonate
    without spilling onto the physical network, or (None, reason) if none is.

    This is the no-spill guard. It deliberately never returns 'internet'. For
    'vpn' it checks the section is enabled (the rooter still fails the task if
    the tunnel is actually down -- a second backstop)."""
    cp = configparser.ConfigParser()
    try:
        read = cp.read(routing_conf)
    except configparser.Error as exc:
        return None, "routing_conf_parse_error:%s" % exc.__class__.__name__
    if not read:
        return None, "routing_conf_not_found"
    for route in ISOLATED_ROUTES:
        if cp.has_section(route) and \
           cp.get(route, "enabled", fallback="no").strip().lower() in _ENABLED_TRUE:
            return route, "%s_enabled" % route
    return None, "no_isolated_route_enabled"


def _domain_slug(domain, cap: int = 60) -> str:
    """Filesystem-safe form of a domain, for naming the .ps1 after its source
    site (e.g. 'evil.example' -> 'evil.example', 'a/b?.com' -> 'a_b_.com').

    The full domain -- INCLUDING the TLD -- is kept. Only a pathologically long
    domain (> `cap` chars) is trimmed, and then from the FRONT so the TLD / most
    specific labels survive (the sha in the filename disambiguates anyway)."""
    slug = re.sub(r"[^A-Za-z0-9.-]", "_", (domain or "nodomain").strip().lower()).strip(".")
    if not slug:
        return "nodomain"
    if len(slug) > cap:
        slug = slug[-cap:].lstrip(".-_")   # keep the TLD-bearing tail, trim the front
    return slug or "nodomain"


def _maybe_detonate(cfg, recovered: dict, *, submit: bool, routing_conf: str,
                    client=None, route=None, store=None) -> dict:
    """Classify/validate a recovered command and, when `submit`, detonate it in
    CAPE. Route selection:
      * route=None (default): isolated route (vpn/tor/inetsim) if set up, else
        'drop'.
      * route given (e.g. 'internet' for full second-stage): used as-is -- the
        CAPE VM is the network-isolated sandbox, so this is the operator's call."""
    text = recovered.get("text") or ""
    val = validate_payload(text)
    cls = classify_payload(text)
    san = sanitize_eval(text, cfg.sanitize)
    rec = {**recovered, "sha256": san.sha256, "payload_type": cls.payload_type,
           "cape_package": cls.cape_package, "validation": val.status,
           "sanitize_score": san.score, "detonation": None, "cape_task_id": None,
           "route": None}

    def _fin(r):
        """Append EVERY processed recovery to the DB ledger (submitted, dup, or
        skipped-with-reason) so nothing we logged is lost. Dry-runs aren't logged.
        This is a separate activity ledger -- it does NOT add skipped sites to the
        'domains' table."""
        if store is not None and r.get("detonation") and r["detonation"] != "dry_run":
            try:
                store.record_recovery(
                    sha256=r.get("sha256"), domain=recovered.get("domain"),
                    url=recovered.get("url"), source=recovered.get("source"),
                    package=r.get("cape_package"), decision=r.get("detonation"),
                    reason=r.get("validation"), cape_task_id=r.get("cape_task_id"),
                    command=(text or "")[:4000])
            except Exception as exc:
                log.debug("record_recovery failed: %s", exc)
        return r

    if not submit:
        rec["detonation"] = "dry_run"
        return rec
    if not val.valid:
        rec["detonation"] = "skipped_invalid:%s" % val.reason
        return _fin(rec)
    if not cls.cape_package:
        rec["detonation"] = "skipped_unclassified"
        return _fin(rec)
    # At this point we have a usable payload (extracted + validated + classified).
    #   * The DOMAIN is recorded now -- even if the command turns out to be a
    #     duplicate -- so every site we successfully extract a lure from is kept
    #     in the DB. A site we could NOT extract from never reaches here, so it
    #     is never recorded.
    #   * The command HASH gates DETONATION only: the same command is never run
    #     in CAPE twice, but a second domain serving that same command is still
    #     recorded and linked to the payload.
    domain = recovered.get("domain")
    key = artifact_key(sha256=san.sha256)
    # Name the sample after the full source domain only (no sha): source-dedup
    # means one detonation per domain, so the domain alone is unique. Keeping it
    # short also dodges CAPE's filename truncation (sanitize_to_len).
    fname = "clickfix_%s%s" % (_domain_slug(domain), _EXT.get(cls.cape_package, ".bin"))
    rec["filename"] = fname
    if store is not None and domain:
        store.upsert_domain(domain, source="catcher", status="malicious")

    existing = store.artifact(key) if store is not None else None
    if existing is not None and existing["cape_task_id"]:
        # Command already detonated -> don't re-run it in CAPE, but still record
        # THIS domain's link to the known payload (two domains, one payload).
        rec["detonation"] = "dup_command"
        store.upsert_payload_artifact(sha256=san.sha256, url=recovered.get("url"),
                                      served_by_domain=domain, source="catcher")
        store.link_artifact_source(key, domain=domain, url=recovered.get("url"),
                                   source="catcher")
        return _fin(rec)

    # SOURCE dedup: if we already detonated a payload from this domain/IP, don't
    # run another one from it -- even if THIS payload is new. This stops a
    # polymorphic host (fresh/repacked payload every fetch, so the hash always
    # differs) from generating one CAPE run per sweep forever.
    if store is not None and domain and store.domain_detonated(domain):
        rec["detonation"] = "dup_domain"
        return _fin(rec)

    if not route:
        iso, _reason = isolated_route_ready(routing_conf)
        route = iso or "drop"
    content = san.normalized_text.encode("utf-8", "replace")
    # Persist a local, domain-named copy so every detonated payload is browsable
    # on disk (storage/commands/), not just inside CAPE. Written before submit so
    # it survives even a submit failure.
    try:
        cmd_dir = cfg.pipeline.commands_dir
        os.makedirs(cmd_dir, exist_ok=True)
        local_path = os.path.join(cmd_dir, fname)
        with open(local_path, "wb") as fh:
            fh.write(content)
        rec["local_path"] = local_path
    except OSError as exc:
        log.warning("could not write local .ps1 %s: %s", fname, exc)
    cfg.cape.route = route
    try:
        client = client or CapeClient(cfg.cape)
        out = client.submit_payload(fname, content, cls.cape_package,
                                    custom="clickfix;urlscan:%s;route:%s" %
                                    (recovered.get("uuid", ""), route))
        rec.update(detonation="submitted", cape_task_id=out.task_id, route=route)
        if store is not None:
            store.upsert_payload_artifact(
                sha256=san.sha256, url=recovered.get("url"),
                artifact_type=cls.cape_package, served_by_domain=domain,
                cape_task_id=out.task_id, acquisition_status="detonated",
                source="catcher", notes=(text[:500] or None))
            store.link_artifact_source(key, domain=domain, url=recovered.get("url"),
                                       source="catcher")
    except Exception as exc:
        rec["detonation"] = "submit_error:%s" % exc.__class__.__name__
    return _fin(rec)


def triage_candidate(cand, cfg) -> dict:
    """Fetch urlscan's captured DOM and score it for live-lure signal. No host
    contact (urlscan.io only)."""
    dom = ""
    try:
        dom = fetch_scan_detail(cand.source_uuid, cfg.urlscan).dom or ""
    except Exception as exc:
        log.debug("scan detail failed for %s: %s", cand.source_uuid, exc)
    static = cg.recover_commands(dom) if dom else []
    return {
        "domain": cand.domain, "url": cand.page_url, "uuid": cand.source_uuid,
        "scan_time": cand.scan_time, "dom_bytes": len(dom),
        "static_cmd": static[0] if static else None,
        "clip_js": bool(_CLIP_RE.search(dom)),
        "instructions": cg.clickfix_lure_score(dom) > 0,
        "payload_url": _is_payload_url(cand.page_url),
    }


def _signalled(t: dict) -> bool:
    return bool(t["static_cmd"]) or t["clip_js"] or t["instructions"]


def _sweep_live(cfg, max_results: int, store=None) -> tuple:
    """Primary source: live, liveness-verified feeds (ClickFix gist + URLhaus),
    static fetch + extract (no browser). Returns (recovered, n_candidates)."""
    cands = livefeeds.collect_live(max_results)
    recovered = []
    for url, src in cands:
        res = livefeeds.recover_from_url(url)
        if store is not None:
            store.record_consumed(url, source=src, domain=res.get("domain"))
        if res["command"]:
            recovered.append({"text": res["command"], "method": res["method"],
                              "domain": res["domain"], "url": url,
                              "source": "live:%s" % src, "uuid": ""})
    return recovered, len(cands)


def _sweep_urlscan(cfg, max_results: int, use_browser: bool, max_browser: int, store=None) -> tuple:
    """Secondary source: urlscan discovery + DOM triage + browser fallback."""
    cands = search_candidates(cfg.urlscan, max_results=max_results)
    if store is not None:
        for c in cands:
            store.record_consumed(c.page_url, source="urlscan", domain=c.domain)
    triaged = [triage_candidate(c, cfg) for c in cands]
    hits = [t for t in triaged if _signalled(t)]
    recovered, browsed = [], 0
    for t in triaged:
        if t["static_cmd"] and not t["payload_url"]:
            recovered.append({**t["static_cmd"], "domain": t["domain"], "url": t["url"],
                              "source": "urlscan_dom", "uuid": t["uuid"]})
    if use_browser and HAVE_BROWSER:
        for t in hits:
            if browsed >= max_browser:
                break
            if t["static_cmd"] or t["payload_url"]:
                continue
            browsed += 1
            r = browser_extract(t["url"], interactions=_INTERACTIONS, max_clicks=6,
                                nav_timeout_ms=35000, settle_ms=1500, post_click_ms=1200,
                                final_settle_ms=4000, overall_timeout_ms=95000, proxy=_PROXY)
            if r.command_text:
                recovered.append({"text": r.command_text, "method": r.method,
                                  "domain": t["domain"], "url": t["url"],
                                  "source": "browser", "uuid": t["uuid"],
                                  "via_interaction": r.via_interaction})
    return recovered, len(cands)


def sweep(cfg, *, source: str = "urlscan", use_browser: bool = True, max_results: int = 30,
          max_browser: int = 3, submit: bool = False, routing_conf: str = _ROUTING_CONF,
          client=None, log_path: str = None, route=None) -> dict:
    """One sweep: discover -> recover -> (optionally) detonate.

    `source`:
      * 'urlscan' -- urlscan archive + browser fallback.
      * 'live'    -- ClickFix gist + URLhaus (abuse.ch), static extract.
      * 'both'    -- run urlscan AND the live feeds in the same sweep and union
                     the results (dedup across sources handled downstream).
    With submit=True, usable commands are detonated in CAPE. Cross-source
    duplicates are collapsed by the dedup store (command hash + domain)."""
    # Open the dedup/intel store once per sweep (domain + payload-hash uniqueness).
    store = None
    if submit:
        try:
            store = CollectionStore(cfg.pipeline.collection_db_path)
        except Exception as exc:
            log.warning("dedup store unavailable (%s); running without dedup",
                        exc.__class__.__name__)
    recovered, n_cands = [], 0
    if source in ("urlscan", "both"):
        r, n = _sweep_urlscan(cfg, max_results, use_browser, max_browser, store)
        recovered += r; n_cands += n
    if source in ("live", "both"):
        r, n = _sweep_live(cfg, max_results, store)
        recovered += r; n_cands += n
    browsed = 0

    # classify + (optionally) detonate each recovered command
    if submit and client is None and recovered:
        client = CapeClient(cfg.cape)
    detonated = [_maybe_detonate(cfg, rec, submit=submit, routing_conf=routing_conf,
                                 client=client, route=route, store=store) for rec in recovered]

    summary = {
        "swept_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source, "candidates": n_cands, "browsed": browsed,
        "recovered": detonated, "browser_available": HAVE_BROWSER, "submit": submit,
        "isolated_route": isolated_route_ready(routing_conf)[0] if submit else None,
    }
    if log_path and detonated:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            for rec in detonated:
                fh.write(json.dumps({"swept_at": summary["swept_at"], **rec}) + "\n")
    if store is not None:
        store.close()
    return summary


def _emit(summary: dict) -> None:
    rec = summary["recovered"]
    log.info("sweep[%s]: %d candidates, %d browsed -> %d command(s) recovered"
             " (submit=%s, isolated_route=%s)", summary["source"], summary["candidates"],
             summary["browsed"], len(rec), summary["submit"], summary["isolated_route"])
    for r in rec:
        log.info("  RECOVERED [%s via %s] det=%s task=%s -> %s", r["domain"], r.get("source"),
                 r.get("detonation"), r.get("cape_task_id"), (r.get("text") or "")[:140])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="clickfix_catcher",
                                description="Fast, repeatable ClickFix lure catcher.")
    p.add_argument("--loop", type=int, default=0,
                   help="seconds between sweeps (0 = one sweep and exit; use cron for scheduling)")
    p.add_argument("--max", type=int, default=25, help="max urlscan candidates per sweep")
    p.add_argument("--max-browser", type=int, default=3, help="max browser renders per sweep")
    p.add_argument("--source", choices=["urlscan", "live", "both"], default="urlscan",
                   help="'urlscan' (default) | 'live' = ClickFix gist + URLhaus (abuse.ch) | "
                        "'both' = urlscan + live feeds in one sweep")
    p.add_argument("--no-browser", action="store_true", help="urlscan source: triage + static only")
    p.add_argument("--submit", action="store_true",
                   help="detonate recovered commands in CAPE (writes .ps1 and submits). "
                        "Route from --route (default: isolated-if-up-else-drop).")
    p.add_argument("--routing-conf", default=_ROUTING_CONF, help="CAPE routing.conf path (no-spill check)")
    p.add_argument("--route", default=None,
                   choices=["drop", "vpn", "tor", "inetsim", "internet"],
                   help="CAPE route (default: isolated-if-up-else-drop). "
                        "'internet' = full second-stage detonation.")
    p.add_argument("--lookback-min", type=int, default=None, help="override urlscan lookback minutes")
    p.add_argument("--log", default=os.path.join(_HERE, "storage", "detonations.jsonl"),
                   help="JSONL log of recovered/detonated ClickFix payloads")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    if args.lookback_min is not None:
        cfg.urlscan.lookback_minutes = args.lookback_min
    if args.no_browser or not HAVE_BROWSER:
        if not HAVE_BROWSER and not args.no_browser:
            log.warning("Playwright not importable here; running triage/static only "
                        "(launch via the pwenv interpreter to enable the browser)")

    if args.submit:
        if args.route:
            eff = args.route
        else:
            iso, _r = isolated_route_ready(args.routing_conf)
            eff = iso or "drop"
        log.info("auto-detonate ON, route=%s", eff)

    def once():
        s = sweep(cfg, source=args.source, use_browser=not args.no_browser, max_results=args.max,
                  max_browser=args.max_browser, submit=args.submit,
                  routing_conf=args.routing_conf, log_path=args.log, route=args.route)
        _emit(s)
        return s

    if args.loop <= 0:
        once()
        return 0
    log.info("looping every %ds (Ctrl-C to stop)", args.loop)
    while True:
        try:
            once()
        except KeyboardInterrupt:
            log.info("stopped")
            return 0
        except Exception as exc:
            log.exception("sweep error: %s", exc)
        time.sleep(args.loop)


if __name__ == "__main__":
    raise SystemExit(main())
