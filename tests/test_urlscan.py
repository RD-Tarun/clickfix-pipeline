"""urlscan discovery-layer tests (offline, against a stub urlscan API)."""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

from config import UrlscanConfig  # noqa: E402
from urlscan_result import ScanDetail, _parse_result  # noqa: E402
from urlscan_source import _build_query, search_candidates  # noqa: E402

LAST_QUERY = {}
RESPONSE = {"status": 200, "body": {"results": []}}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        LAST_QUERY.clear()
        LAST_QUERY.update(parse_qs(urlparse(self.path).query))
        body = json.dumps(RESPONSE["body"]).encode()
        self.send_response(RESPONSE["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class UrlscanTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        RESPONSE["status"] = 200
        RESPONSE["body"] = {"results": []}
        self.cfg = UrlscanConfig(base_url=self.base)


class TestSearchParams(UrlscanTestCase):
    def test_sort_is_omitted_by_default(self):
        # Regression: hardcoding sort=date made urlscan reject the request with
        # HTTP 403 for accounts without the entitlement, silently returning
        # zero candidates on every poll.
        search_candidates(self.cfg)
        self.assertNotIn("sort", LAST_QUERY)

    def test_sort_is_sent_when_configured(self):
        self.cfg.sort = "date"
        search_candidates(self.cfg)
        self.assertEqual(LAST_QUERY["sort"], ["date"])

    def test_lookback_window_is_appended(self):
        self.cfg.lookback_minutes = 45
        self.assertIn("date:>now-45m", _build_query(self.cfg))

    def test_api_key_header_is_optional(self):
        self.assertEqual(search_candidates(self.cfg), [])

    def test_403_returns_empty_without_raising(self):
        RESPONSE["status"] = 403
        RESPONSE["body"] = {"message": "not allowed"}
        self.assertEqual(search_candidates(self.cfg), [])

    def test_malformed_results_are_skipped(self):
        RESPONSE["body"] = {"results": [{"page": {}, "task": {}}, {"_id": "x"}]}
        self.assertEqual(search_candidates(self.cfg), [])

    def test_candidate_parsing(self):
        RESPONSE["body"] = {
            "results": [
                {
                    "_id": "abc",
                    "page": {"url": "http://final.invalid/"},
                    "task": {"url": "http://orig.invalid/", "time": "2026-01-01T00:00:00Z"},
                }
            ]
        }
        cands = search_candidates(self.cfg)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0].source_uuid, "abc")
        self.assertEqual(cands[0].page_url, "http://final.invalid/")


class TestResultParsing(unittest.TestCase):
    def test_original_and_final_urls(self):
        detail = ScanDetail(uuid="u")
        _parse_result(
            {
                "task": {"url": "http://orig.invalid/a"},
                "page": {"url": "http://final.invalid/b"},
                "data": {"requests": []},
            },
            detail,
        )
        self.assertEqual(detail.task_url, "http://orig.invalid/a")
        self.assertEqual(detail.final_url, "http://final.invalid/b")
        self.assertIn("http://orig.invalid/a", detail.redirect_chain)
        self.assertIn("http://final.invalid/b", detail.redirect_chain)

    def test_script_urls_collected(self):
        detail = ScanDetail(uuid="u")
        _parse_result(
            {
                "task": {"url": "http://x.invalid/"},
                "page": {"url": "http://x.invalid/"},
                "data": {
                    "requests": [
                        {"request": {"type": "script", "request": {"url": "http://x.invalid/a.js"}}},
                        {"request": {"type": "image", "request": {"url": "http://x.invalid/p.png"}}},
                    ]
                },
            },
            detail,
        )
        self.assertEqual(detail.script_urls, ["http://x.invalid/a.js"])
        self.assertIn("http://x.invalid/p.png", detail.resource_urls)

    def test_redirect_hop_recorded(self):
        detail = ScanDetail(uuid="u")
        _parse_result(
            {
                "task": {"url": "http://a.invalid/"},
                "page": {"url": "http://c.invalid/"},
                "data": {
                    "requests": [
                        {
                            "request": {
                                "request": {"url": "http://b.invalid/"},
                                "redirectResponse": {"url": "http://a.invalid/hop"},
                            }
                        }
                    ]
                },
            },
            detail,
        )
        self.assertIn("http://a.invalid/hop", detail.redirect_chain)

    def test_empty_payload_does_not_crash(self):
        detail = ScanDetail(uuid="u")
        _parse_result({}, detail)
        self.assertIsNone(detail.task_url)

    def test_scan_detail_availability_flag(self):
        self.assertFalse(ScanDetail(uuid="u").available)
        self.assertTrue(ScanDetail(uuid="u", dom="<html>").available)


if __name__ == "__main__":
    unittest.main(verbosity=2)
