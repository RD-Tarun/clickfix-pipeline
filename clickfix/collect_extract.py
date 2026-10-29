"""Steps 1-4, standalone:

  1. query the urlscan API
  2. get the list of URLs
  3. load each URL in a (Windows-UA) headless browser
  4. extract the ClickFix command from it

No triage, no CAPE, no detonation here -- just discovery + browser extraction.
The browser presents a Windows identity (many lures OS-gate), clicks the
fake-captcha/verify elements, and captures whatever gets written to the
clipboard. The recovered command is DATA: it is printed, never executed.

Run with the Playwright env, e.g.:
  PLAYWRIGHT_BROWSERS_PATH=~/clickfix-cape/eval_staging/pwbrowsers \
  ~/clickfix-cape/eval_staging/pwenv/bin/python collect_extract.py --max 10
"""

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from config import load_config                 # noqa: E402
from urlscan_source import search_candidates   # noqa: E402
from browser_extractor import browser_extract, HAVE_PLAYWRIGHT  # noqa: E402
from extractor import is_plausible_command     # noqa: E402
import clickgrab_extract as cg                 # noqa: E402

# Click targets for the fake-captcha / "I'm not a robot" / verify UIs.
_INTERACTIONS = (
    'input[type=checkbox]', '[class*="robot"]', '[class*="verify"]', '[class*="captcha"]',
    "text=/i.?m not a robot/i", "text=/verify/i", "text=/human/i", "text=/continue/i",
    "text=/copy/i", "text=/fix/i", 'button', 'a[role="button"]',
)


def collect_urls(cfg, max_urls: int):
    """Steps 1-2: query urlscan and return the candidate URLs."""
    cands = search_candidates(cfg.urlscan, max_results=max_urls)
    return cands


def extract_from_url(url: str, proxy=None):
    """Steps 3-4: load one URL in the Windows-UA browser and extract a command.

    A clipboard capture only counts as a command if it actually looks like one
    (is_plausible_command) -- a page copying its own CSS/JS to the clipboard is
    NOT a ClickFix command, so those are rejected. `proxy` (optional) routes the
    fetch through a residential/clean IP to beat IP-cloaking lures."""
    r = browser_extract(url, interactions=_INTERACTIONS, max_clicks=6,
                        nav_timeout_ms=25000, settle_ms=1500, post_click_ms=1200,
                        final_settle_ms=4000, overall_timeout_ms=70000, proxy=proxy)
    # Recover from THREE places, not just the clipboard: (1) clipboard captures,
    # (2) the rendered post-JS DOM, (3) command-bearing network responses. The
    # command is often present on the page even when the copy didn't fire for us.
    candidates = [c["text"] for c in (r.all_captures or []) if c.get("text")]
    method = "clipboard"
    for body in ([r.rendered_dom] if r.rendered_dom else []) + list(r.network_bodies or []):
        candidates.extend(x["text"] for x in cg.recover_commands(body))
    plausible = [t for t in candidates if is_plausible_command(t)]
    command = max(plausible, key=len) if plausible else None
    if command and not any(command == c.get("text") for c in (r.all_captures or [])):
        method = "page/network"
    return {"url": url, "command": command, "method": method if command else r.method,
            "via_interaction": r.via_interaction, "clicked": r.clicked_selectors,
            "captures": len(r.all_captures), "failure": r.failure_reason}


def run(max_urls: int, lookback_min=None, proxy=None):
    cfg = load_config()
    if lookback_min is not None:
        cfg.urlscan.lookback_minutes = lookback_min

    print("STEP 1-2: querying urlscan (query=%r, lookback=%dm)"
          % (cfg.urlscan.query, cfg.urlscan.lookback_minutes))
    cands = collect_urls(cfg, max_urls)
    print("  -> %d URL(s):" % len(cands))
    for c in cands:
        print("     %s" % c.page_url)

    if not HAVE_PLAYWRIGHT:
        print("\n[!] Playwright not available in this interpreter -- run with the pwenv python")
        return []

    print("\nSTEP 3-4: loading each URL in the Windows-UA browser%s and extracting..."
          % (" via proxy" if proxy else ""))
    results = []
    for c in cands:
        res = extract_from_url(c.page_url, proxy=proxy)
        results.append(res)
        tag = "CMD " if res["command"] else "----"
        detail = res["command"] if res["command"] else "(%s)" % (res["failure"] or "no command")
        print("  [%s] %-30.30s %s" % (tag, c.domain or "?", str(detail)[:110]))

    got = sum(1 for r in results if r["command"])
    print("\nextracted a command from %d / %d URL(s)" % (got, len(results)))
    return results


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="collect_extract",
                                description="urlscan -> URLs -> browser -> extract command (steps 1-4)")
    p.add_argument("--max", type=int, default=10, help="max URLs to pull and load (default 10)")
    p.add_argument("--lookback-min", type=int, default=None, help="override urlscan lookback minutes")
    p.add_argument("--proxy", default=None,
                   help="route the browser through a proxy (e.g. http://user:pass@host:port) "
                        "to beat IP-cloaking lures; default off")
    args = p.parse_args(argv)
    run(args.max, lookback_min=args.lookback_min, proxy=args.proxy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
