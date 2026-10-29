#!/usr/bin/env python3
"""ClickFix -> CAPE collection pipeline.

    urlscan.io search --> fetch page --> extract clipboard command
        --> sanitize/score (auto-approve or queue for human review)
        --> submit to local CAPE via REST API --> poll --> save report + IOCs

Usage:
    python pipeline.py poll                 # one discovery pass (cron-friendly)
    python pipeline.py collect              # fetch reports for submitted tasks
    python pipeline.py loop --interval 300  # run poll+collect forever
    python pipeline.py review list
    python pipeline.py review show <id>
    python pipeline.py review approve <id>
    python pipeline.py review reject <id>
    python pipeline.py submit-approved      # submit anything a human approved
"""

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cape_client import CapeClient, CapeError
from config import load_config
from extractor import extract_command
from sanitize import defang_preview, evaluate
from state import ClickfixStore, now_iso
from candidates import classify_candidate, is_probably_not_a_lure
from classify import classify_payload
from urlnorm import normalize_url, url_parts
from validate import validate_payload
from urlscan_result import ScanDetail, fetch_scan_detail
from urlscan_source import search_candidates

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("clickfix.pipeline")


def _audit(cfg, message: str):
    line = f"{now_iso()} {message}\n"
    with open(cfg.pipeline.audit_log, "a") as fh:
        fh.write(line)


def _dedup_decision(cfg, store: ClickfixStore, url_row):
    """Decide whether a sighted URL is worth fetching. Runs BEFORE any network
    request, so a duplicate costs one indexed SELECT rather than a page fetch
    plus a full extraction pass.

    Returns (should_analyze, reason).
    """
    now = datetime.now(timezone.utc)

    if url_row["last_analyzed_at"]:
        revisit_after = now - timedelta(days=cfg.pipeline.revisit_url_days)
        if url_row["last_analyzed_at"] >= revisit_after.isoformat():
            return False, f"duplicate_url:seen {url_row['times_seen']}x"

    if cfg.pipeline.domain_cooldown_hours > 0:
        since = (now - timedelta(hours=cfg.pipeline.domain_cooldown_hours)).isoformat()
        hit = store.apex_analyzed_since(url_row["apex_domain"], since)
        if hit is not None and hit["id"] != url_row["id"]:
            return False, f"domain_cooldown:{url_row['apex_domain']}"

    return True, "new"


def discover_and_extract(cfg, store: ClickfixStore):
    candidates = search_candidates(cfg.urlscan)
    stats = {"new": 0, "dup_uuid": 0, "dup_url": 0, "dup_domain": 0}

    for cand in candidates:
        # Layer 1: the same scan, already processed.
        if store.has_seen(cand.source_uuid):
            stats["dup_uuid"] += 1
            continue

        # Layer 2: the same URL under a different scan UUID. This is the one
        # that matters -- urlscan rescans popular lures constantly.
        url_norm = normalize_url(cand.page_url)
        domain, apex = url_parts(cand.page_url)
        url_row = store.record_url_sighting(
            url_norm, cand.page_url, domain, apex, cand.source_uuid
        )

        ok, reason = _dedup_decision(cfg, store, url_row)
        if not ok:
            stats["dup_domain" if reason.startswith("domain_cooldown") else "dup_url"] += 1
            log.debug("skipping %s: %s", cand.page_url[:80], reason)
            continue

        stats["new"] += 1
        ctype = classify_candidate(cand.page_url, cand.mime, cand.title, cand.status)
        row_id = store.insert_discovered("urlscan", cand.source_uuid, cand.page_url)
        store.update(row_id, url_id=url_row["id"], url_norm=url_norm,
                     candidate_type=ctype.kind, candidate_rank=ctype.rank)
        _audit(cfg, f"discovered id={row_id} url={cand.page_url}")
        _process_extraction(cfg, store, row_id, cand.page_url, cand.source_uuid, url_row,
                            candidate_type=ctype.kind)

    log.info(
        "discovery pass: %d returned -> %d analysed (skipped: %d repeat scans, "
        "%d duplicate URLs, %d domain cooldown)",
        len(candidates), stats["new"], stats["dup_uuid"], stats["dup_url"], stats["dup_domain"],
    )


def _process_extraction(cfg, store: ClickfixStore, row_id: int, page_url: str,
                        source_uuid: str, url_row=None, candidate_type=None):
    # Fix 3: do not mine commands out of binary/archive/non-page resources --
    # the goal is recovering commands from website HTML/JS. Uses the EXISTING
    # candidate metadata (candidates.classify_candidate), not a new classifier.
    if candidate_type in ("archive", "binary", "non_page"):
        store.update(row_id, status="skipped_non_lure",
                     failure_reason="non_lure_resource:%s" % candidate_type)
        _audit(cfg, "skipped_non_lure id=%s type=%s url=%s" % (row_id, candidate_type, page_url))
        return

    # Layer 1 evidence: urlscan's own record of the scan (final URL, redirect
    # chain, loaded scripts, and the post-JS rendered DOM).
    scan = None
    if cfg.urlscan.use_result_api:
        try:
            scan = fetch_scan_detail(source_uuid, cfg.urlscan)
        except Exception as exc:
            log.warning("urlscan result fetch failed for %s: %s", source_uuid, exc)
            scan = ScanDetail(uuid=source_uuid, notes=[f"result_unavailable:{exc.__class__.__name__}"])

    try:
        result = extract_command(page_url, cfg.extract, scan=scan, urlscan_cfg=cfg.urlscan)
    except Exception as exc:
        log.exception("extraction crashed for id=%s", row_id)
        store.update(row_id, status="error", error=f"extract_exception: {exc}")
        return

    # Provenance is recorded whether or not extraction succeeded.
    store.update(
        row_id,
        task_url=result.original_url,
        final_url=result.final_url,
        redirect_chain=json.dumps(result.redirect_chain),
        extraction_method=result.method,
        extraction_layer=result.layer,
        url_norm=result.normalized_url or None,
        source_resource_url=result.source_resource_url,
        extraction_notes=json.dumps(
            result.notes
            + [f"lure_score={result.lure_score}", f"lure_hits={','.join(result.lure_hits)}"]
            + (["homoglyphs_detected"] if result.homoglyphs_detected else [])
            + (["obfuscated_bundle"] if result.obfuscated_bundle else [])
        ),
        layers_tried=json.dumps(result.layers_tried),
        candidates_found=result.candidates_found,
        urlscan_result_url=(scan.result_api_url if scan else None),
        screenshot_url=(scan.screenshot_url if scan else None),
    )

    if url_row is not None:
        store.mark_url_analyzed(
            url_row["id"],
            result.failure_reason or "extracted",
            _content_hash(result),
        )

    if not result.command_text:
        reason = result.failure_reason or "no_command"
        store.update(row_id, status=reason, failure_reason=reason, error=result.source_note)
        _audit(cfg, f"extract_failed id={row_id} reason={reason} layers={result.layers_tried}")
        return

    sresult = evaluate(result.command_text, cfg.sanitize)

    dup_since = (datetime.now(timezone.utc) - timedelta(days=cfg.pipeline.skip_duplicate_commands_days)).isoformat()
    dup = store.recent_submission_for_hash(sresult.sha256, dup_since)

    cmd_path = os.path.join(cfg.pipeline.commands_dir, f"{sresult.sha256}.ps1")
    if not os.path.exists(cmd_path):
        with open(cmd_path, "w") as fh:
            fh.write(sresult.normalized_text)

    status = "extracted"
    store.update(
        row_id,
        command_text=sresult.normalized_text,
        command_sha256=sresult.sha256,
        sanitize_score=sresult.score,
        sanitize_reasons=json.dumps(sresult.reasons),
        status=status,
    )
    _audit(
        cfg,
        f"extracted id={row_id} sha256={sresult.sha256} score={sresult.score} "
        f"preview={defang_preview(sresult.normalized_text, 120)!r}",
    )

    if dup is not None:
        store.update(row_id, status="duplicate_skipped", error=f"same command as row {dup['id']}")
        _audit(cfg, f"duplicate id={row_id} matches row {dup['id']}, skipping submission")
        return

    _apply_submission_policy(cfg, store, row_id, sresult, result)


def _apply_submission_policy(cfg, store: ClickfixStore, row_id: int, sresult, eresult=None):
    """Decide whether a recovered command is submitted automatically.

    The project goal is a pipeline with no manual step, so review_mode=off
    (the default) never parks anything on a human. A floor of
    min_submit_score still keeps obvious extraction noise out of the VM
    queue -- those rows land in `low_confidence`, recorded but not submitted.
    """
    if cfg.sanitize.review_mode == "on":
        if sresult.auto_approve:
            store.update(row_id, status="auto_approved")
            _audit(cfg, f"auto_approved id={row_id} score={sresult.score} reasons={sresult.reasons}")
        else:
            store.update(row_id, status="pending_review")
            _audit(cfg, f"pending_review id={row_id} score={sresult.score} reasons={sresult.reasons}")
        return

    lure_score = getattr(eresult, "lure_score", 0) or 0
    rescued = (
        sresult.score < cfg.sanitize.min_submit_score
        and lure_score >= cfg.sanitize.lure_score_rescue_threshold
    )

    if sresult.score >= cfg.sanitize.min_submit_score or rescued:
        store.update(row_id, status="auto_approved")
        note = f" lure_rescue={lure_score}" if rescued else ""
        _audit(
            cfg,
            f"auto_approved id={row_id} score={sresult.score} reasons={sresult.reasons}{note}",
        )
    else:
        store.update(
            row_id,
            status="low_confidence",
            failure_reason="below_min_submit_score",
            error=f"score={sresult.score} < min_submit_score={cfg.sanitize.min_submit_score}",
        )
        _audit(cfg, f"low_confidence id={row_id} score={sresult.score} reasons={sresult.reasons}")


def submit_ready(cfg, store: ClickfixStore):
    client = CapeClient(cfg.cape)
    for status in ("auto_approved", "approved"):
        for row in store.list_by_status(status):
            _submit_one(cfg, store, client, row)


def _submit_one(cfg, store: ClickfixStore, client: CapeClient, row):
    row_id = row["id"]
    try:
        content = row["command_text"].encode("utf-8")
        filename = f"clickfix_{row['command_sha256'][:12]}.ps1"
        outcome = client.submit_ps1(filename, content, custom=f"urlscan:{row['source_uuid']}")
        store.update(
            row_id,
            status="submitted",
            cape_task_id=outcome.task_id,
            cape_status="pending",
            cape_machine=cfg.cape.machine,
            submitted_at=now_iso(),
        )
        _audit(
            cfg,
            f"submitted id={row_id} task_id={outcome.task_id} machine={cfg.cape.machine} "
            f"uuid={row['source_uuid']} sha256={row['command_sha256']}",
        )
    except Exception as exc:
        log.exception("submission failed for id=%s", row_id)
        store.update(row_id, status="error", error=f"submit_exception: {exc}")
        _audit(cfg, f"submit_error id={row_id} error={exc}")


def collect_reports(cfg, store: ClickfixStore):
    client = CapeClient(cfg.cape)
    for row in store.list_by_status("submitted"):
        row_id = row["id"]
        task_id = row["cape_task_id"]
        try:
            status = client.get_status(task_id)
            store.update(row_id, cape_status=status)
            if status not in ("reported", "failed_analysis", "failed_processing", "failed_reporting"):
                continue

            if status != "reported":
                store.update(row_id, status="failed", error=f"cape_status={status}")
                _audit(cfg, f"failed id={row_id} task_id={task_id} status={status}")
                continue

            report = client.get_report(task_id)
            iocs = client.get_iocs(task_id)

            task_dir = os.path.join(cfg.pipeline.reports_dir, str(task_id))
            os.makedirs(task_dir, exist_ok=True)
            report_path = os.path.join(task_dir, "report.json")
            ioc_path = os.path.join(task_dir, "iocs.json")
            with open(report_path, "w") as fh:
                json.dump(report, fh, indent=2, default=str)
            with open(ioc_path, "w") as fh:
                json.dump(iocs, fh, indent=2, default=str)

            store.update(
                row_id,
                status="reported",
                report_path=report_path,
                ioc_path=ioc_path,
                reported_at=now_iso(),
            )
            _write_linkage(cfg, store, row_id, task_dir)
            _audit(cfg, f"reported id={row_id} task_id={task_id} report={report_path}")
        except Exception as exc:
            log.exception("report collection failed for id=%s task_id=%s", row_id, task_id)
            store.update(row_id, error=f"collect_exception: {exc}")


def process_recovered_payload(cfg, store: ClickfixStore, row_id, result, cand,
                              url_row=None, submit: bool = False):
    """Strict pre-submission pipeline for one recovered payload.

        validation -> classification -> normalization/hash -> dedup
        -> package selection -> (submission, only when explicitly enabled)

    Returns the payloads row, or None when the payload was rejected.
    Submission is opt-in via `submit`; every caller in the dry-run path
    leaves it False.
    """
    original = result.command_text

    # 1. Validate BEFORE anything else -- a malformed payload must never
    #    reach classification, hashing, or the submission queue.
    validation = validate_payload(
        original, cfg.sanitize.min_length, cfg.sanitize.max_length
    )

    # 2. Normalise + hash. The normalised form is the dedup identity; the
    #    original text is what would actually be sent to CAPE.
    sres = evaluate(original, cfg.sanitize)

    # 3. Classify -- what is this, and which package runs it faithfully?
    classification = classify_payload(original)

    store.update(
        row_id,
        command_text=original,
        command_sha256=sres.sha256,
        sanitize_score=sres.score,
        sanitize_reasons=json.dumps(sres.reasons),
        lure_score=result.lure_score,
        validation_status=validation.status,
        validation_reason=validation.reason,
    )

    # Keep the faithful artifact on disk, content-addressed -- valid or not,
    # a recovered payload is evidence.
    cmd_path = os.path.join(cfg.pipeline.commands_dir, f"{sres.sha256}.ps1")
    if not os.path.exists(cmd_path):
        with open(cmd_path, "w") as fh:
            fh.write(original)

    # 4. Payload-level identity: one payload -> many sightings. Invalid
    #    payloads (templates, truncations) are stored too, flagged invalid,
    #    so the same template seen on ten domains is one row with ten
    #    sightings rather than ten unexplained failures. They can never
    #    reach submission: payloads_awaiting_submission() requires 'valid'.
    payload_row, is_new = store.upsert_payload(
        sres.sha256, original, sres.normalized_text,
        defang_preview(original, 300), classification, validation,
    )
    domain, apex = url_parts(result.final_url or cand.page_url)
    store.add_payload_sighting(
        payload_row["id"],
        page_id=row_id,
        url_id=(url_row["id"] if url_row is not None else None),
        source_uuid=cand.source_uuid,
        url_norm=result.normalized_url,
        domain=domain,
        apex_domain=apex,
        extraction_layer=result.layer,
        extraction_method=result.method,
        source_resource_url=result.source_resource_url,
    )
    store.update(row_id, payload_id=payload_row["id"])

    if not validation.valid:
        store.update(row_id, status="invalid_payload", failure_reason=validation.reason)
        _audit(cfg, f"invalid_payload id={row_id} sha256={sres.sha256} reason={validation.reason}")
        return payload_row

    if not is_new:
        # Already known. Record the sighting, link to the existing task,
        # and do not detonate the same payload twice.
        store.update(
            row_id,
            status="duplicate_payload",
            cape_task_id=payload_row["cape_task_id"],
            error=f"payload already seen (sha256 {sres.sha256[:16]}...)",
        )
        _audit(cfg, f"duplicate_payload id={row_id} sha256={sres.sha256} "
                    f"task={payload_row['cape_task_id']}")
        return payload_row

    # 5. Package selection. An ambiguous payload is held, never guessed at.
    if not classification.submittable:
        store.update(row_id, status="unclassified_payload",
                     failure_reason=f"unknown_payload_type:{classification.reason}")
        _audit(cfg, f"unclassified id={row_id} reason={classification.reason}")
        return payload_row

    store.update(row_id, status="ready_to_submit")
    _audit(
        cfg,
        f"ready_to_submit id={row_id} sha256={sres.sha256} "
        f"type={classification.payload_type}/{classification.subtype} "
        f"pkg={classification.cape_package} conf={classification.confidence}",
    )
    return payload_row


def _content_hash(result) -> str:
    """Stable hash of what we actually recovered, for cross-domain campaign
    dedup. Uses the command when we have one, since page bodies differ
    cosmetically across domains far more often than payloads do."""
    basis = result.command_text or ""
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest() if basis else ""


def _write_linkage(cfg, store: ClickfixStore, row_id: int, task_dir: str):
    """Persist the urlscan -> ClickFix URL -> command -> CAPE task chain next
    to the report, so a stored result is self-describing without the DB."""
    row = store.get(row_id)
    if row is None:
        return
    linkage = {
        "urlscan_uuid": row["source_uuid"],
        "urlscan_result_url": row["urlscan_result_url"],
        "screenshot_url": row["screenshot_url"],
        "original_url": row["task_url"] or row["page_url"],
        "final_url": row["final_url"],
        "redirect_chain": json.loads(row["redirect_chain"] or "[]"),
        "extraction_method": row["extraction_method"],
        "extraction_layer": row["extraction_layer"],
        "extraction_notes": json.loads(row["extraction_notes"] or "[]"),
        "layers_tried": json.loads(row["layers_tried"] or "[]"),
        "candidates_found": row["candidates_found"],
        "command_sha256": row["command_sha256"],
        "command_path": os.path.join(cfg.pipeline.commands_dir, f"{row['command_sha256']}.ps1"),
        "sanitize_score": row["sanitize_score"],
        "sanitize_reasons": json.loads(row["sanitize_reasons"] or "[]"),
        "cape_task_id": row["cape_task_id"],
        "cape_machine": row["cape_machine"],
        "cape_status": row["cape_status"],
        "discovered_at": row["discovered_at"],
        "submitted_at": row["submitted_at"],
        "reported_at": row["reported_at"],
    }
    with open(os.path.join(task_dir, "linkage.json"), "w") as fh:
        json.dump(linkage, fh, indent=2, default=str)


def cmd_preflight(cfg, store, args):
    """Check the things that silently break a run before it starts."""
    ok = True
    print(f"urlscan API key      : {'set' if cfg.urlscan.api_key else 'MISSING'}")
    if not cfg.urlscan.api_key:
        print("  -> Result API and DOM tiers will be skipped (both 403 without a key).")
        print("     Search-only discovery still works; extraction loses its best layer.")
        ok = False

    client = CapeClient(cfg.cape)
    try:
        machines = client.list_machines()
        print(f"CAPE machines        : {machines}")
        if cfg.cape.machine and cfg.cape.machine not in machines:
            print(f"  -> configured machine '{cfg.cape.machine}' NOT in CAPE's machine list")
            ok = False
    except CapeError as exc:
        # [machinelist] is disabled by default in api.conf. Not a blocker --
        # the pipeline never calls it at runtime -- so warn without failing.
        print(f"CAPE machines        : cannot verify ({exc})")
        print(f"     machine '{cfg.cape.machine}' will be validated by CAPE at submit time;")
        print("     an unknown label is rejected with an explicit error, not silently queued.")
        print("     To enable this check: set [machinelist] enabled = yes in conf/api.conf.")
    except Exception as exc:
        print(f"CAPE api             : UNREACHABLE ({exc})")
        ok = False

    if cfg.cape.tags:
        print(f"CAPE task tags       : '{cfg.cape.tags}'")
        print("  -> WARNING: CAPE requires every non-arch task tag to also be a MACHINE")
        print("     tag. If cuckoo1 lacks it, tasks stay pending forever. Prefer machine=.")
        ok = False
    else:
        print("CAPE task tags       : (none) - correct, targeting by machine label")

    print(f"CAPE route           : {cfg.cape.route}")
    print(f"review_mode          : {cfg.sanitize.review_mode} "
          f"({'fully automatic' if cfg.sanitize.review_mode != 'on' else 'manual gate active'})")
    print(f"\npreflight: {'PASS' if ok else 'ISSUES FOUND'}")
    return ok


def cmd_poll(cfg, store, args):
    discover_and_extract(cfg, store)
    submit_ready(cfg, store)


def cmd_collect(cfg, store, args):
    collect_reports(cfg, store)


def cmd_loop(cfg, store, args):
    log.info("starting loop, interval=%ss (ctrl-c to stop)", args.interval)
    while True:
        try:
            discover_and_extract(cfg, store)
            submit_ready(cfg, store)
            collect_reports(cfg, store)
        except Exception:
            log.error("loop iteration failed:\n%s", traceback.format_exc())
        time.sleep(args.interval)


def cmd_submit_approved(cfg, store, args):
    submit_ready(cfg, store)


def cmd_review_list(cfg, store, args):
    rows = store.list_by_status("pending_review")
    if not rows:
        print("no pending reviews")
        return
    for row in rows:
        print(
            f"[{row['id']}] score={row['sanitize_score']} url={row['page_url']}\n"
            f"    {defang_preview(row['command_text'] or '', 160)}"
        )


def cmd_review_show(cfg, store, args):
    row = store.get(args.id)
    if not row:
        print(f"no such id: {args.id}")
        return
    print(f"id: {row['id']}")
    print(f"page_url: {row['page_url']}")
    print(f"status: {row['status']}")
    print(f"original_url: {row['task_url']}")
    print(f"final_url: {row['final_url']}")
    print(f"redirect_chain: {row['redirect_chain']}")
    print(f"extraction: layer={row['extraction_layer']} method={row['extraction_method']}")
    print(f"layers_tried: {row['layers_tried']}  candidates_found: {row['candidates_found']}")
    print(f"notes: {row['extraction_notes']}")
    print(f"failure_reason: {row['failure_reason']}")
    print(f"command_sha256: {row['command_sha256']}")
    print(f"cape: task={row['cape_task_id']} machine={row['cape_machine']} status={row['cape_status']}")
    print(f"score: {row['sanitize_score']}  reasons: {row['sanitize_reasons']}")
    print("--- raw command (undefanged) ---")
    print(row["command_text"])


def cmd_review_approve(cfg, store, args):
    store.update(args.id, status="approved")
    _audit(cfg, f"manual_approve id={args.id}")
    print(f"approved id={args.id}")


def cmd_review_reject(cfg, store, args):
    store.update(args.id, status="rejected")
    _audit(cfg, f"manual_reject id={args.id}")
    print(f"rejected id={args.id}")


def cmd_dryrun(cfg, store, args):
    """Discovery -> extraction -> validation -> classification -> dedup.

    Stops immediately before submission. There is deliberately no call to
    submit_ready() anywhere in this function, so "no submission" is a
    structural property rather than a flag that could be flipped by accident.
    """
    candidates = search_candidates(cfg.urlscan, max_results=args.limit)
    log.info("dry-run over %d candidate(s), limit=%d", len(candidates), args.limit)

    rows = []
    seen_uuids = set()
    dup_url_skipped = 0

    for idx, cand in enumerate(candidates[: args.limit]):
        if cand.source_uuid in seen_uuids:
            continue
        seen_uuids.add(cand.source_uuid)
        if idx and args.pace > 0:
            time.sleep(args.pace)
        if idx and idx % 25 == 0:
            log.info("progress: %d/%d candidates", idx, len(candidates))

        ctype = classify_candidate(cand.page_url, cand.mime, cand.title, cand.status)
        url_norm = normalize_url(cand.page_url)
        domain, apex = url_parts(cand.page_url)

        url_row = store.record_url_sighting(url_norm, cand.page_url, domain, apex,
                                            cand.source_uuid)
        ok, dreason = _dedup_decision(cfg, store, url_row)
        if not ok:
            dup_url_skipped += 1
            rows.append(_row(cand, ctype, None, None, dreason, skipped=True))
            continue

        row_id = store.insert_discovered("urlscan", cand.source_uuid, cand.page_url)
        store.update(row_id, url_id=url_row["id"], url_norm=url_norm,
                     candidate_type=ctype.kind, candidate_rank=ctype.rank)

        scan = None
        if cfg.urlscan.use_result_api:
            try:
                scan = fetch_scan_detail(cand.source_uuid, cfg.urlscan)
            except Exception as exc:
                log.warning("result fetch failed for %s: %s", cand.source_uuid, exc)

        try:
            res = extract_command(cand.page_url, cfg.extract, scan=scan,
                                  urlscan_cfg=cfg.urlscan)
        except Exception as exc:
            log.exception("extraction crashed for %s", cand.page_url)
            store.update(row_id, status="error", error=str(exc))
            store.mark_url_analyzed(url_row["id"], "error")
            rows.append(_row(cand, ctype, None, None, f"crash:{exc.__class__.__name__}"))
            continue

        store.update(
            row_id,
            task_url=res.original_url, final_url=res.final_url,
            url_norm=res.normalized_url or url_norm,
            redirect_chain=json.dumps(res.redirect_chain),
            extraction_method=res.method, extraction_layer=res.layer,
            extraction_notes=json.dumps(res.notes), layers_tried=json.dumps(res.layers_tried),
            candidates_found=res.candidates_found, lure_score=res.lure_score,
            source_resource_url=res.source_resource_url,
            urlscan_result_url=(scan.result_api_url if scan else None),
        )
        store.mark_url_analyzed(url_row["id"], res.failure_reason or "extracted")

        if not res.command_text:
            reason = res.failure_reason or "no_command"
            store.update(row_id, status=reason, failure_reason=reason)
            rows.append(_row(cand, ctype, res, None, reason))
            continue

        payload = process_recovered_payload(cfg, store, row_id, res, cand, url_row,
                                            submit=False)
        page = store.get(row_id)
        rows.append(_row(cand, ctype, res, payload, page["failure_reason"] or "",
                         status=page["status"]))

    _print_dryrun_table(rows)
    _print_aggregates(rows, store, dup_url_skipped)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rows, fh, indent=2, default=str)
        print(f"\nfull provenance written to {args.json}")

    print("\nCAPE submission: DISABLED (dryrun never calls submit_ready)")


def _row(cand, ctype, res, payload, failure, skipped=False, status=""):
    return {
        "uuid": cand.source_uuid,
        "url": (res.final_url if res else None) or cand.page_url,
        "original_url": (res.original_url if res else cand.task_url) or cand.page_url,
        "url_norm": (res.normalized_url if res else None) or normalize_url(cand.page_url),
        "candidate_type": ctype.kind,
        "candidate_rank": ctype.rank,
        "not_a_lure": is_probably_not_a_lure(ctype),
        "layer": (res.layer if res else None) or "-",
        "method": (res.method if res else None) or "-",
        "recovered": bool(res and res.command_text),
        "payload_type": (payload["payload_type"] if payload else "-"),
        "payload_subtype": (payload["payload_subtype"] if payload else "-"),
        "cape_package": (payload["cape_package"] if payload else "-"),
        "classifier_reason": (payload["classifier_reason"] if payload else ""),
        "classifier_confidence": (payload["classifier_confidence"] if payload else 0),
        "validation_status": (payload["validation_status"] if payload else "-"),
        "validation_reason": (payload["validation_reason"] if payload else ""),
        "resolved": bool(payload and payload["validation_status"] == "valid"),
        "templated": bool(payload and payload["validation_reason"] ==
                          "unsubstituted_server_side_placeholder"),
        "sha256": (payload["sha256"] if payload else ""),
        "cmd_score": 0,
        "lure_score": (res.lure_score if res else 0),
        "failure": failure or "",
        "status": status,
        "skipped": skipped,
        "resource": (res.source_resource_url if res else "") or "",
        "layers_tried": ",".join(res.layers_tried) if res else "",
    }


def _print_dryrun_table(rows):
    hdr = (f"{'UUID':<14}{'URL':<30}{'CAND TYPE':<14}{'LAYER':<22}{'METHOD':<21}"
           f"{'REC':<5}{'PAYLOAD TYPE':<15}{'PKG':<8}{'CONF':<6}{'SHA256':<11}FAILURE")
    print("\n" + hdr)
    print("-" * len(hdr))
    for r in rows:
        print(
            f"{r['uuid'][:12]:<14}{r['url'][:28]:<30}{r['candidate_type'][:12]:<14}"
            f"{r['layer'][:20]:<22}{r['method'][:19]:<21}"
            f"{('YES' if r['recovered'] else 'no'):<5}{r['payload_type'][:13]:<15}"
            f"{(r['cape_package'] or '-')[:6]:<8}{str(r['classifier_confidence']):<6}"
            f"{(r['sha256'][:8] + '..' if r['sha256'] else '-'):<11}{r['failure'][:26]}"
        )


def _print_aggregates(rows, store, dup_url_skipped):
    total = len(rows)
    analysed = [r for r in rows if not r["skipped"]]
    recovered = [r for r in rows if r["recovered"]]
    hashes = {r["sha256"] for r in recovered if r["sha256"]}

    def _tally(key, src=None):
        out = {}
        for r in (src if src is not None else analysed):
            v = r.get(key) or "-"
            out[v] = out.get(v, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    print("\n" + "=" * 78)
    print("AGGREGATE STATISTICS")
    print("=" * 78)
    print(f"  total candidates            : {total}")
    print(f"  unique normalised URLs      : {len({r['url_norm'] for r in rows})}")
    print(f"  duplicate URLs avoided      : {dup_url_skipped}")
    print(f"  analysed (fetched)          : {len(analysed)}")
    resolved = [r for r in recovered if r["resolved"]]
    templated = [r for r in recovered if r["templated"]]
    other_invalid = [r for r in recovered if not r["resolved"] and not r["templated"]]
    print(f"  payloads recovered          : {len(recovered)}")
    print(f"      resolved (detonatable)  : {len(resolved)}")
    print(f"      unresolved / template   : {len(templated)}")
    print(f"      other invalid           : {len(other_invalid)}")
    print(f"  unique payload hashes       : {len(hashes)}")
    print(f"      unique resolved hashes  : {len({r['sha256'] for r in resolved})}")
    print(f"      unique template hashes  : {len({r['sha256'] for r in templated})}")
    if recovered:
        print(f"  sightings per payload       : {len(recovered) / max(len(hashes), 1):.2f}")

    print("\n  candidate types:")
    for k, v in _tally("candidate_type").items():
        print(f"      {k:<20} {v}")
    if recovered:
        print("\n  payload types:")
        for k, v in _tally("payload_type", recovered).items():
            print(f"      {k:<20} {v}")
        print("\n  CAPE packages:")
        for k, v in _tally("cape_package", recovered).items():
            print(f"      {k:<20} {v}")
        print("\n  extraction layers:")
        for k, v in _tally("layer", recovered).items():
            print(f"      {k:<20} {v}")
        print("\n  extraction methods:")
        for k, v in _tally("method", recovered).items():
            print(f"      {k:<20} {v}")

    print("\n  outcomes:")
    for k, v in _tally("failure").items():
        print(f"      {(k or '(recovered)'):<28} {v}")

    # The distinction that actually matters.
    misses = [r for r in analysed if not r["recovered"]]
    not_lure_shape = [r for r in misses if r["not_a_lure"]]
    unreachable = [r for r in misses
                   if r["failure"] in ("page_unreachable", "dead_infrastructure")]
    no_cmd_low_lure = [
        r for r in misses
        if r["failure"] == "no_command" and r["lure_score"] < 4 and not r["not_a_lure"]
    ]
    extractor_gap = [
        r for r in misses
        if r["failure"] in ("interaction_dependent", "unsupported_obfuscation")
        or (r["failure"] == "no_command" and r["lure_score"] >= 4)
    ]
    invalid = [r for r in analysed if r["failure"] and "payload" in r["failure"]]
    dup_payload = [r for r in analysed if r["status"] == "duplicate_payload"]

    print("\n" + "-" * 78)
    print("  WHY WE DID NOT RECOVER  (the distinction that matters)")
    print("-" * 78)
    print("  A. Not actually a ClickFix payload target:")
    print(f"       non-lure resource (archive/binary/asset) : {len(not_lure_shape)}")
    print(f"       reachable, no lure signal, no command    : {len(no_cmd_low_lure)}")
    print(f"       infrastructure dead (unreachable/error)  : {len(unreachable)}")
    print(f"     subtotal (NOT an extractor problem)        : "
          f"{len(not_lure_shape) + len(no_cmd_low_lure) + len(unreachable)}")
    print("\n  B. Real lure our extractor could not handle:")
    print(f"       interaction_dependent                    : "
          f"{sum(1 for r in extractor_gap if r['failure'] == 'interaction_dependent')}")
    print(f"       unsupported_obfuscation                  : "
          f"{sum(1 for r in extractor_gap if r['failure'] == 'unsupported_obfuscation')}")
    print(f"       lure signal present but nothing found    : "
          f"{sum(1 for r in extractor_gap if r['failure'] == 'no_command')}")
    print(f"     subtotal (EXTRACTOR GAP)                   : {len(extractor_gap)}")
    print(f"\n  C. Recovered but rejected pre-submission     : {len(invalid)}")
    print(f"       templated / unresolved placeholders      : {len(templated)}")
    print(f"       other validation failures                : {len(other_invalid)}")
    print(f"  D. Duplicate payload (already known hash)   : {len(dup_payload)}")

    # Denominator = targets that plausibly HAD a payload to recover:
    # what we got, plus what we missed for extractor reasons, plus what we
    # recovered then rejected. Computed additively -- subtracting the bucket-A
    # sets from the total double-counts their overlaps and flatters the rate.
    denom = len(recovered) + len(extractor_gap) + len(invalid)
    if denom > 0:
        print(f"\n  recovery rate on plausible lure targets     : "
              f"{len(recovered)}/{denom} ({100.0 * len(recovered) / denom:.1f}%)")
        print("     (denominator = recovered + extractor gaps + rejected payloads;"
              "\n      dead infrastructure and non-lure resources excluded)")

    ps = store.payload_stats()
    print(f"\n  payload store: {ps['unique_payloads']} unique / "
          f"{ps['total_sightings']} sightings / {ps['valid']} valid / "
          f"{ps['submitted']} submitted")


def _preflight_payload(cfg, store, payload, sightings):
    """Print exactly what would be detonated, before anything is sent."""
    print("=" * 78)
    print("PRE-SUBMISSION PREFLIGHT")
    print("=" * 78)
    print(f"  payload SHA256    : {payload['sha256']}")
    print(f"  payload type      : {payload['payload_type']} / {payload['payload_subtype']}")
    print(f"  CAPE package      : {payload['cape_package']}")
    print(f"  classifier        : {payload['classifier_reason']} "
          f"(confidence {payload['classifier_confidence']})")
    print(f"  validation        : {payload['validation_status']} "
          f"{payload['validation_reason'] or ''}")
    print(f"  target machine    : {cfg.cape.machine}")
    print(f"  route             : {cfg.cape.route}")
    print(f"  artifact bytes    : {len(payload['original_text'].encode('utf-8'))}")
    print(f"  sightings         : {len(sightings)}")
    for sg in sightings:
        print(f"      urlscan {sg['source_uuid']}")
        print(f"        normalized url : {sg['url_norm']}")
        print(f"        extraction     : {sg['extraction_layer']} / {sg['extraction_method']}")
        if sg["source_resource_url"]:
            print(f"        source resource: {sg['source_resource_url']}")
    print("\n  ARTIFACT TO BE SUBMITTED (defanged preview):")
    for line in defang_preview(payload["original_text"], 600).splitlines():
        print(f"      {line}")
    print()


def _verify_artifact_is_payload(payload, sightings):
    """Guard: the file sent to CAPE must be the recovered script, never a URL.

    Submitting the ClickFix URL instead of the payload would detonate a web
    page fetch and produce a report about nothing.
    """
    artifact = payload["original_text"]
    problems = []
    stripped = artifact.strip()
    if stripped.lower().startswith(("http://", "https://")) and "\n" not in stripped:
        problems.append("artifact is a bare URL, not a script")
    for sg in sightings:
        if sg["url_norm"] and stripped == sg["url_norm"].strip():
            problems.append(f"artifact equals the sighting URL {sg['url_norm']}")
    if len(stripped) < 8:
        problems.append("artifact too short to be a payload")
    return problems


def cmd_submit_one(cfg, store, args):
    """Controlled, single-payload submission. Requires --submit to send.

    Deliberately submits at most ONE task, never retries, and never touches
    duplicate sightings -- they already resolve to this same payload row.
    """
    matches = [
        r for r in store._conn.execute("SELECT * FROM payloads ORDER BY id")
        if r["sha256"].startswith(args.sha)
    ]
    if not matches:
        print(f"no payload matching sha256 prefix {args.sha!r}")
        return
    if len(matches) > 1:
        print(f"ambiguous prefix {args.sha!r} matches {len(matches)} payloads:")
        for m in matches:
            print(f"   {m['sha256']}")
        return

    payload = matches[0]
    sightings = store.sightings_for_payload(payload["id"])
    _preflight_payload(cfg, store, payload, sightings)

    # --- refuse to proceed on anything unsafe ----------------------------
    # Re-validate the artifact NOW rather than trusting the status stored at
    # extraction time: validator rules get tightened, and a payload that was
    # recorded as valid under older rules must not slip through on that
    # stale verdict.
    revalidation = validate_payload(
        payload["original_text"], cfg.sanitize.min_length, cfg.sanitize.max_length
    )
    if revalidation.status != payload["validation_status"]:
        print(f"  NOTE: re-validation changed the verdict "
              f"{payload['validation_status']} -> {revalidation.status} "
              f"({revalidation.reason or 'ok'}); the current rules win.")
        store.update_payload(payload["id"], validation_status=revalidation.status,
                             validation_reason=revalidation.reason)
    if not revalidation.valid:
        print(f"STOP: payload fails current validation ({revalidation.reason}). "
              f"Not submitting.")
        return
    if not payload["cape_package"] or payload["payload_type"] == "unknown":
        print("STOP: payload is unclassified; no package selected. Not submitting.")
        return
    if payload["cape_task_id"] is not None:
        print(f"STOP: payload already has CAPE task {payload['cape_task_id']}. "
              f"Refusing to resubmit ({len(sightings)} sightings share it).")
        return

    problems = _verify_artifact_is_payload(payload, sightings)
    if problems:
        print("STOP: artifact verification failed:")
        for p_ in problems:
            print(f"   - {p_}")
        return
    print("  artifact verification: OK (recovered script, not a URL)\n")

    if not args.submit:
        print("DRY PREFLIGHT ONLY -- pass --submit to actually send this one task.")
        return

    # --- submit exactly one task -----------------------------------------
    client = CapeClient(cfg.cape)
    ext = {"ps1": ".ps1", "batch": ".bat", "exe": ".exe"}.get(payload["cape_package"], ".bin")
    filename = f"clickfix_{payload['sha256'][:12]}{ext}"
    content = payload["original_text"].encode("utf-8")
    custom = f"urlscan:{sightings[0]['source_uuid']}" if sightings else "clickfix"

    print(f"submitting {filename} ({len(content)} bytes) "
          f"package={payload['cape_package']} machine={cfg.cape.machine} "
          f"route={cfg.cape.route} ...")
    try:
        outcome = client.submit_payload(
            filename, content, payload["cape_package"], custom=custom,
            machine=cfg.cape.machine,
        )
    except Exception as exc:
        print(f"\nSTOP: submission failed at the SUBMIT stage.\n  {exc.__class__.__name__}: {exc}")
        return

    task_id = outcome.task_id
    store.update_payload(
        payload["id"], cape_task_id=task_id, cape_machine=cfg.cape.machine,
        cape_status="pending", submitted_at=now_iso(),
    )
    for sg in sightings:
        if sg["page_id"]:
            store.update(sg["page_id"], cape_task_id=task_id, cape_machine=cfg.cape.machine)
    _audit(cfg, f"controlled_submit sha256={payload['sha256']} task_id={task_id} "
                f"package={payload['cape_package']}")
    print(f"  -> CAPE task id {task_id}\n")

    _await_and_collect(cfg, store, payload["id"], task_id, args)


def _await_and_collect(cfg, store, payload_id, task_id, args):
    """Poll to a terminal state, then pull report/IOCs/PCAP. Never retries."""
    client = CapeClient(cfg.cape)
    terminal = {"reported", "failed_analysis", "failed_processing", "failed_reporting"}
    waited = 0
    status = "unknown"
    print(f"polling task {task_id} (max {args.max_wait}s, every {cfg.cape.poll_interval}s)")
    while waited < args.max_wait:
        try:
            status = client.get_status(task_id)
        except Exception as exc:
            print(f"STOP: status poll failed: {exc.__class__.__name__}: {exc}")
            return
        print(f"    t+{waited:>4}s  status={status}")
        store.update_payload(payload_id, cape_status=status)
        if status in terminal:
            break
        time.sleep(cfg.cape.poll_interval)
        waited += cfg.cape.poll_interval

    if status not in terminal:
        print(f"\nSTOP: task {task_id} did not reach a terminal state within "
              f"{args.max_wait}s (last status={status}). Not retrying.")
        return

    if status != "reported":
        print(f"\nSTOP: task {task_id} finished as {status}. Not retrying, not "
              f"modifying CAPE. Inspect with: "
              f"curl -s {cfg.cape.base_url}/apiv2/tasks/status/{task_id}/")
        store.update_payload(payload_id, cape_status=status)
        return

    task_dir = os.path.join(cfg.pipeline.reports_dir, str(task_id))
    os.makedirs(task_dir, exist_ok=True)
    summary = {"task_id": task_id, "status": status}

    try:
        report = client.get_report(task_id)
        with open(os.path.join(task_dir, "report.json"), "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        summary["report"] = True
    except Exception as exc:
        print(f"  report retrieval FAILED: {exc.__class__.__name__}: {exc}")
        summary["report"] = False
        report = {}

    try:
        iocs = client.get_iocs(task_id)
        with open(os.path.join(task_dir, "iocs.json"), "w") as fh:
            json.dump(iocs, fh, indent=2, default=str)
        summary["iocs"] = True
    except Exception as exc:
        print(f"  IOC retrieval FAILED: {exc.__class__.__name__}: {exc}")
        summary["iocs"] = False

    pcap = client.pcap_info(task_id)
    summary["pcap"] = pcap
    with open(os.path.join(task_dir, "pcap_info.json"), "w") as fh:
        json.dump(pcap, fh, indent=2, default=str)

    store.update_payload(
        payload_id, cape_status=status, reported_at=now_iso(),
        report_path=os.path.join(task_dir, "report.json"),
        ioc_path=os.path.join(task_dir, "iocs.json"),
    )
    _print_final_summary(store, payload_id, summary, report)


def _print_final_summary(store, payload_id, summary, report):
    payload = store._conn.execute(
        "SELECT * FROM payloads WHERE id = ?", (payload_id,)
    ).fetchone()
    sightings = store.sightings_for_payload(payload_id)
    net = (report.get("network") or {}) if isinstance(report, dict) else {}

    print("\n" + "=" * 78)
    print("CONTROLLED SUBMISSION RESULT")
    print("=" * 78)
    print(f"  payload SHA256    : {payload['sha256']}")
    print(f"  urlscan sightings : {len(sightings)}")
    for sg in sightings:
        print(f"      {sg['source_uuid']}  {sg['apex_domain']}  "
              f"({sg['extraction_layer']}/{sg['extraction_method']})")
    print(f"  extracted artifact: {payload['payload_type']}/{payload['payload_subtype']}, "
          f"{len(payload['original_text'])} chars")
    print(f"  CAPE package      : {payload['cape_package']}")
    print(f"  CAPE task ID      : {payload['cape_task_id']}")
    print(f"  task status       : {payload['cape_status']}")
    print(f"  report generated  : {'YES' if summary.get('report') else 'NO'}")
    p = summary.get("pcap") or {}
    print(f"  PCAP available    : {'YES (' + str(p.get('bytes', 0)) + ' bytes)' if p.get('available') else 'NO'}")
    print(f"  IOCs available    : {'YES' if summary.get('iocs') else 'NO'}")
    if net:
        for k in ("hosts", "domains", "http", "http_ex", "dns"):
            v = net.get(k)
            if isinstance(v, list) and v:
                print(f"      network.{k:<10}: {len(v)} entries")
    print(f"  report path       : {payload['report_path']}")


def cmd_dedupe(cfg, store, args):
    """Show how much work deduplication is saving."""
    s = store.dedup_stats()
    print(f"URL sightings from urlscan : {s['url_sightings']}")
    print(f"Unique URLs (normalised)   : {s['unique_urls']}")
    print(f"Unique apex domains        : {s['unique_apex_domains']}")
    print(f"URLs actually analysed     : {s['analyzed_urls']}")
    print(f"Analysis attempts logged   : {s['analysis_rows']}")
    print(f"Page fetches avoided       : {s['fetches_avoided']}")
    if s["url_sightings"]:
        pct = 100.0 * s["fetches_avoided"] / s["url_sightings"]
        print(f"Duplicate rate             : {pct:.1f}%")
    print()
    print("Most-rescanned URLs:")
    rows = store._conn.execute(
        "SELECT url_norm, times_seen, analysis_count, last_analysis_status FROM urls "
        "ORDER BY times_seen DESC LIMIT ?", (args.limit,)
    ).fetchall()
    for r in rows:
        print(f"  {r['times_seen']:>4}x  analysed={r['analysis_count']}  "
              f"{(r['last_analysis_status'] or '-'):<22} {r['url_norm'][:60]}")


def cmd_status(cfg, store, args):
    rows = store.list_all(args.limit)
    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
        print(
            f"[{row['id']}] {row['status']:<22} task={str(row['cape_task_id'] or '-'):<6} "
            f"{(row['extraction_layer'] or '-'):<18} {(row['extraction_method'] or '-'):<20} "
            f"{row['page_url'][:60]}"
        )
    if counts:
        print("\n" + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--conf", default=None, help="path to clickfix.conf (default: alongside this script)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("poll", help="one discovery+submit pass").set_defaults(func=cmd_poll)
    sub.add_parser("preflight", help="check API keys, CAPE machines, and tag config").set_defaults(
        func=cmd_preflight
    )
    sub.add_parser("collect", help="poll CAPE for submitted tasks and save finished reports").set_defaults(
        func=cmd_collect
    )
    sub.add_parser("submit-approved", help="submit rows a human approved").set_defaults(func=cmd_submit_approved)

    loop_p = sub.add_parser("loop", help="run poll+collect forever")
    loop_p.add_argument("--interval", type=int, default=300, help="seconds between passes")
    loop_p.set_defaults(func=cmd_loop)

    dry_p = sub.add_parser("dryrun", help="discovery+extraction only, NEVER submits to CAPE")
    dry_p.add_argument("--limit", type=int, default=10)
    dry_p.add_argument("--json", default=None, help="write full provenance to this file")
    dry_p.add_argument("--pace", type=float, default=1.5,
                       help="seconds between candidates (urlscan retrieve limit is 120/min)")
    dry_p.set_defaults(func=cmd_dryrun)

    sub1 = sub.add_parser("submit-one",
                          help="controlled single-payload submission (requires --submit)")
    sub1.add_argument("--sha", required=True, help="payload sha256 prefix")
    sub1.add_argument("--submit", action="store_true",
                      help="actually send it; without this only the preflight prints")
    sub1.add_argument("--max-wait", dest="max_wait", type=int, default=1800)
    sub1.set_defaults(func=cmd_submit_one)

    dedupe_p = sub.add_parser("dedupe", help="show deduplication effectiveness")
    dedupe_p.add_argument("--limit", type=int, default=15)
    dedupe_p.set_defaults(func=cmd_dedupe)

    status_p = sub.add_parser("status", help="show recent pipeline rows")
    status_p.add_argument("--limit", type=int, default=50)
    status_p.set_defaults(func=cmd_status)

    review = sub.add_parser("review", help="manage the human-review queue")
    review_sub = review.add_subparsers(dest="review_command", required=True)

    review_sub.add_parser("list", help="list pending-review candidates").set_defaults(func=cmd_review_list)

    show_p = review_sub.add_parser("show", help="print full details for one candidate")
    show_p.add_argument("id", type=int)
    show_p.set_defaults(func=cmd_review_show)

    approve_p = review_sub.add_parser("approve", help="approve a candidate for submission")
    approve_p.add_argument("id", type=int)
    approve_p.set_defaults(func=cmd_review_approve)

    reject_p = review_sub.add_parser("reject", help="reject a candidate")
    reject_p.add_argument("id", type=int)
    reject_p.set_defaults(func=cmd_review_reject)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    cfg = load_config(args.conf) if args.conf else load_config()
    with ClickfixStore(cfg.pipeline.db_path) as store:
        args.func(cfg, store, args)


if __name__ == "__main__":
    main()
