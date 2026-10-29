"""Live, liveness-verified ClickFix URL sources + static command extraction.

Why this exists: urlscan's `task.tags:clickfix` is a scan *archive* -- stale and
noisy, so lures are usually dead by the time we poll it. These feeds instead
point at URLs that are live *now*:

  * ClickFix gist  -- a curated, daily-updated list of current ClickFix domains
                      (the source MHaggis/ClickGrab uses).
  * URLhaus        -- abuse.ch's `csv_online` feed = currently-ONLINE malware
                      URLs; we keep only ClickFix/fake-captcha-tagged rows.

Recovery is ClickGrab-style and needs no browser: fetch the page HTML (+ linked
JS) with a Windows UA and run the ported static extractor. Nothing is executed;
recovered commands are DATA. Network note: fetching a FEED hits github/abuse.ch
(safe); fetching a candidate hits the malicious host (static GET, Windows UA,
no JS run).
"""

import random
import re
import sys
import os
import warnings
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import requests  # noqa: E402
import clickgrab_extract as cg  # noqa: E402

warnings.filterwarnings("ignore")
try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

WINDOWS_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
_HDR = {"User-Agent": WINDOWS_UA, "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua-platform": '"Windows"',
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}

CLICKFIX_GIST_ID = "9f563dfb78a06fad5db794f33ba93a3f"
CLICKFIX_GIST_FILE = "clickfix_domains.txt"
URLHAUS_ONLINE_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
URLHAUS_TAG_API = "https://urlhaus-api.abuse.ch/v1/tag/"
_URLHAUS_TAGS = ("clickfix", "fakecaptcha", "fake-captcha", "fakeupdate")
# Tag names as the abuse.ch API expects them (case-sensitive-ish; the API is
# tolerant but these match how ClickFix URLs are tagged on URLhaus).
_URLHAUS_API_TAGS = ("ClickFix", "FakeCaptcha", "fake-captcha", "fakeupdate")


def fetch_clickfix_gist(gist_id: str = CLICKFIX_GIST_ID, filename: str = CLICKFIX_GIST_FILE,
                        timeout: int = 30) -> list:
    """Return the curated ClickFix domain list from the gist (via GitHub API,
    which resolves the current revision). Returns [] on any failure."""
    try:
        r = requests.get("https://api.github.com/gists/%s" % gist_id,
                         headers={"User-Agent": "clickfix-collector"}, timeout=timeout)
        if r.status_code != 200:
            return []
        fd = (r.json().get("files") or {}).get(filename) or {}
        content = fd.get("content") or ""
        if fd.get("truncated") and fd.get("raw_url"):
            content = requests.get(fd["raw_url"], headers={"User-Agent": "clickfix-collector"},
                                   timeout=timeout).text
    except (requests.RequestException, ValueError):
        return []
    doms = []
    for line in content.splitlines():
        line = line.strip().lstrip("|").strip()
        if not line or line.startswith("#") or " " in line or "." not in line:
            continue
        if line.lower() in ("domain", "domains"):
            continue
        doms.append(line)
    # de-dup, preserve order
    seen = []
    [seen.append(d) for d in doms if d not in seen]
    return seen


def fetch_urlhaus_online(timeout: int = 30, max_bytes: int = 8_000_000) -> list:
    """Currently-online URLhaus URLs tagged ClickFix/fake-captcha.

    If a URLhaus Auth-Key is set (URLHAUS_AUTH_KEY / URLHAUS_API_KEY) we use the
    authenticated tag API -- far richer than the public CSV, which rarely has
    ClickFix rows online. Falls back to the CSV when no key is configured.
    Returns [] on failure."""
    key = os.getenv("URLHAUS_AUTH_KEY") or os.getenv("URLHAUS_API_KEY")
    if key:
        api = _fetch_urlhaus_api(key, timeout)
        if api:
            return api
        # key present but API gave nothing -> fall through to CSV as a backstop
    return _fetch_urlhaus_csv(timeout, max_bytes)


def _fetch_urlhaus_api(key: str, timeout: int = 30) -> list:
    """Query the abuse.ch URLhaus tag API for each ClickFix-ish tag and return
    the currently-ONLINE URLs (deduped). Mirrors ClickGrab's auth path."""
    urls, seen = [], set()
    for tag in _URLHAUS_API_TAGS:
        try:
            r = requests.post(URLHAUS_TAG_API, headers={"Auth-Key": key},
                              data={"tag": tag}, timeout=timeout)
            data = r.json()
        except (requests.RequestException, ValueError):
            continue
        if data.get("query_status") != "ok":
            continue
        for u in data.get("urls", []):
            url = u.get("url")
            if url and u.get("url_status") == "online" and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def _fetch_urlhaus_csv(timeout: int = 30, max_bytes: int = 8_000_000) -> list:
    """Public csv_online feed, filtered to ClickFix-tagged rows. No key needed."""
    try:
        r = requests.get(URLHAUS_ONLINE_CSV, headers={"User-Agent": "clickfix-collector"},
                         timeout=timeout, stream=True)
        raw = r.raw.read(max_bytes, decode_content=True).decode("utf-8", "ignore")
        r.close()
    except requests.RequestException:
        return []
    urls = []
    for line in raw.splitlines():
        if line.startswith("#") or not line:
            continue
        # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        parts = [p.strip('"') for p in re.split(r'","|^"|"$', line) if p]
        if len(parts) < 7:
            parts = line.split(",")
        url = next((p for p in parts if p.startswith("http")), None)
        tags = line.lower()
        if url and any(t in tags for t in _URLHAUS_TAGS):
            urls.append(url)
    seen = []
    [seen.append(u) for u in urls if u not in seen]
    return seen


def collect_live(max_urls: int = 30, use_gist: bool = True, use_urlhaus: bool = True) -> list:
    """Unified live candidate list: [(url, source)].

    URLhaus online URLs and ClickFix-gist domains are INTERLEAVED (round-robin)
    so both sources get represented under `max_urls` -- otherwise URLhaus (which
    now returns hundreds via the auth API) would fill every slot and the gist
    would never be sampled. The gist is shuffled first so continuous runs explore
    the whole list over time rather than re-checking the same first N."""
    uh = [(u, "urlhaus") for u in fetch_urlhaus_online()] if use_urlhaus else []
    gist = []
    if use_gist:
        gist = [("https://%s/" % d if not d.startswith("http") else d, "gist")
                for d in fetch_clickfix_gist()]
        random.shuffle(gist)
    # round-robin interleave urlhaus + gist, then de-dup by url and cap
    seen, capped, i, j = set(), [], 0, 0
    while (i < len(uh) or j < len(gist)) and len(capped) < max_urls:
        for lst, idx in ((uh, "uh"), (gist, "gist")):
            k = i if idx == "uh" else j
            if k < len(lst) and len(capped) < max_urls:
                url, src = lst[k]
                if url not in seen:
                    seen.add(url)
                    capped.append((url, src))
            if idx == "uh":
                i += 1
            else:
                j += 1
    return capped


def _fetch(url: str, timeout: int = 12, max_bytes: int = 1_500_000) -> str:
    try:
        r = requests.get(url, headers=_HDR, timeout=timeout, verify=False,
                         allow_redirects=True, stream=True)
        body = r.raw.read(max_bytes, decode_content=True).decode("utf-8", "ignore")
        r.close()
        return body
    except requests.RequestException:
        return ""


def fetch_page_text(url: str, max_scripts: int = 6) -> str:
    """Fetch the page HTML plus its linked external JS (bounded). The clipboard
    command often lives in a linked script, so we concatenate them."""
    host = urlparse(url).hostname or ""
    scheme = urlparse(url).scheme or "https"
    html = _fetch(url)
    if not html and url.startswith("https://"):
        html = _fetch("http://" + url[len("https://"):])
    text = html or ""
    for m in list(re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', text, re.I))[:max_scripts]:
        src = m.group(1)
        if src.startswith("//"):
            src = scheme + ":" + src
        elif src.startswith("/"):
            src = "%s://%s%s" % (scheme, host, src)
        elif not src.startswith("http"):
            src = "%s://%s/%s" % (scheme, host, src)
        js = _fetch(src)
        if js:
            text += "\n" + js
    return text


def recover_from_url(url: str) -> dict:
    """Fetch + statically extract. Returns the best recovered command record."""
    text = fetch_page_text(url)
    cmds = cg.recover_commands(text)
    host = urlparse(url).hostname
    return {"url": url, "domain": host, "bytes": len(text),
            "command": cmds[0]["text"] if cmds else None,
            "method": cmds[0]["method"] if cmds else None,
            "all_commands": cmds}


def harvest(max_urls: int = 30, use_gist: bool = True, use_urlhaus: bool = True) -> list:
    """Collect live candidates and statically recover commands. Returns records
    shaped for the catcher's detonation path (text/domain/url/source)."""
    recovered = []
    for url, src in collect_live(max_urls, use_gist, use_urlhaus):
        res = recover_from_url(url)
        if res["command"]:
            recovered.append({"text": res["command"], "method": res["method"],
                              "domain": res["domain"], "url": url, "source": "live:%s" % src,
                              "uuid": ""})
    return recovered


if __name__ == "__main__":
    import argparse
    import json
    p = argparse.ArgumentParser(description="Live ClickFix feed harvest + static extract")
    p.add_argument("--max", type=int, default=30)
    p.add_argument("--no-urlhaus", action="store_true")
    p.add_argument("--no-gist", action="store_true")
    args = p.parse_args()
    cands = collect_live(args.max, not args.no_gist, not args.no_urlhaus)
    print("live candidates: %d" % len(cands))
    got = 0
    for url, src in cands:
        res = recover_from_url(url)
        if res["command"]:
            got += 1
        tag = "CMD " if res["command"] else "----"
        detail = res["command"] if res["command"] else "(%d B)" % res["bytes"]
        print("  [%s] %-10s %-30.30s %s" % (tag, src, res["domain"] or "?", str(detail)[:90]))
    print("\nrecovered %d / %d" % (got, len(cands)))
