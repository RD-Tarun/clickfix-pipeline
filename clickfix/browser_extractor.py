"""Browser-backed ClickFix extractor (Playwright/Chromium).

Separate from the static extractor: it RENDERS the page in a real headless
Chromium and recovers clipboard text that is only produced at runtime (direct,
click-triggered, delayed, or fetched-from-a-secondary-endpoint writes) -- the
interaction-dependent cases the static extractor structurally cannot reach.

Design (deliberately NOT the failed CAPE CDP approach):
  * Clipboard APIs are instrumented via add_init_script, which runs BEFORE any
    page script on a real navigation (goto). We never rely on the OS clipboard.
    navigator.clipboard.writeText, document.execCommand('copy') (textarea
    fallback), and the 'copy' event (dataTransfer.setData) are all captured
    into window.__clipcap with NO execution of the captured text.
  * Network responses are observed (bounded) so a command fetched from a
    secondary endpoint is corroborated.
  * Interactions are BOUNDED and EXPLICITLY configured (an ordered selector
    list, one click each, capped) -- no arbitrary clicking, no live-site visits
    here (tests drive it against a local fixture server only).

Captured clipboard text is DATA: it is validated/classified and attached to the
existing provenance schema, never executed, decoded-to-run, or submitted.
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("clickfix.browser")

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    HAVE_PLAYWRIGHT = True
except Exception:
    HAVE_PLAYWRIGHT = False

# Instrumentation injected before any page script (add_init_script).
INSTRUMENT_JS = r"""
(() => {
  window.__clipcap = [];
  const push = (via, text) => {
    try { if (text != null && String(text).length) window.__clipcap.push({via, text: String(text)}); }
    catch (e) {}
  };
  // navigator.clipboard.writeText (define a stub if the API is absent, e.g. http://)
  try {
    const stub = { writeText: (t) => { push('writeText', t); return Promise.resolve(); },
                   readText: () => Promise.resolve('') };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText = (t) => { push('writeText', t); return Promise.resolve(); };
    } else {
      Object.defineProperty(navigator, 'clipboard', { value: stub, configurable: true });
    }
  } catch (e) {}
  // document.execCommand('copy') -> capture focused input/textarea value or selection
  try {
    const od = document.execCommand ? document.execCommand.bind(document) : null;
    document.execCommand = function (cmd) {
      try {
        if (String(cmd).toLowerCase() === 'copy') {
          let t = '';
          const el = document.activeElement;
          if (el && ('value' in el) && el.value) t = el.value;
          if (!t) { const s = window.getSelection && window.getSelection(); if (s) t = s.toString(); }
          push('execCommand', t);
          return true;
        }
      } catch (e) {}
      return od ? od.apply(document, arguments) : false;
    };
  } catch (e) {}
  // 'copy' event -> dataTransfer.setData('text/plain', ...)
  try {
    document.addEventListener('copy', (e) => {
      try {
        const dt = e.clipboardData;
        if (dt) { const t = dt.getData('text') || dt.getData('text/plain'); if (t) push('copyEvent', t); }
      } catch (x) {}
    }, true);
  } catch (e) {}
})();
"""

# Many ClickFix lures OS-gate their payload and will not serve the fake-captcha
# flow to a non-Windows client. Our host is Linux, so present a Windows Chrome
# identity: UA string, matching Client Hints, and a navigator.platform override.
WINDOWS_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
WINDOWS_PLATFORM_JS = r"""
(() => {
  try { Object.defineProperty(navigator, 'platform', {get: () => 'Win32'}); } catch (e) {}
  try {
    Object.defineProperty(navigator, 'userAgentData',
      {get: () => ({platform: 'Windows', mobile: false,
                    brands: [{brand: 'Chromium', version: '124'}]})});
  } catch (e) {}
})();
"""

# Default, explicit interaction selectors (ordered). Bounded by max_clicks.
DEFAULT_INTERACTIONS = (
    '[class*="im-not-a-robot"]',
    '[data-fkrc-instance] [class*="im-not-a-robot"]',
    '[class*="verifywin-verify-button"]',
    '[class*="verify"]',
    'button',
)


@dataclass
class BrowserResult:
    command_text: Optional[str] = None
    method: Optional[str] = None          # writeText | execCommand | copyEvent | network
    via_interaction: bool = False
    clicked_selectors: List[str] = field(default_factory=list)
    all_captures: List[dict] = field(default_factory=list)
    network_hits: List[str] = field(default_factory=list)
    failure_reason: Optional[str] = None
    elapsed_ms: int = 0
    extraction_layer: str = "browser_playwright"
    rendered_dom: Optional[str] = None     # final post-JS DOM, for static extraction
    network_bodies: List[str] = field(default_factory=list)  # command-bearing response bodies


_CMD_MARKERS = ("powershell", "pwsh", "mshta", "msiexec", "cmd.exe", "cmd /c",
                "iex", "irm", "iwr", "-enc", "-nop", "-w hidden", "curl ",
                "certutil", "bitsadmin", "rundll32", "regsvr32", "invoke-")


def _looks_cmd(t: str) -> bool:
    tl = (t or "").lower()
    return any(m in tl for m in _CMD_MARKERS)


def parse_proxy(spec):
    """Turn a proxy spec into Playwright's proxy dict, or None.

    Accepts a dict (returned as-is), or a string like
    'http://user:pass@host:port', 'user:pass@host:port', or 'host:port'.
    A residential/clean-IP proxy makes the fetch look like a real victim so
    IP/ASN-cloaking ClickFix sites serve the overlay instead of a decoy."""
    if not spec:
        return None
    if isinstance(spec, dict):
        return spec
    s = str(spec).strip()
    scheme = "http://"
    if "://" in s:
        scheme, s = s.split("://", 1)
        scheme += "://"
    user = pwd = None
    if "@" in s:
        creds, s = s.rsplit("@", 1)
        user, _, pwd = creds.partition(":")
    out = {"server": scheme + s}
    if user:
        out["username"] = user
    if pwd:
        out["password"] = pwd
    return out


def _pick_best(caps: List[dict]) -> Optional[dict]:
    if not caps:
        return None
    cmdish = [c for c in caps if _looks_cmd(c["text"])]
    pool = cmdish or caps
    return max(pool, key=lambda c: len(c["text"]))


def browser_extract(
    url: str,
    *,
    interactions=DEFAULT_INTERACTIONS,
    user_agent: str = WINDOWS_UA,
    max_clicks: int = 3,
    nav_timeout_ms: int = 15000,
    settle_ms: int = 800,
    post_click_ms: int = 800,
    final_settle_ms: int = 2500,
    overall_timeout_ms: int = 45000,
    browsers_path: Optional[str] = None,
    capture_network: bool = True,
    proxy=None,
) -> BrowserResult:
    """Render `url` in headless Chromium and recover runtime clipboard text.

    `url` must be a local/synthetic fixture in tests -- no live-site visits here.
    Never raises; failures are recorded in `failure_reason`.
    """
    res = BrowserResult()
    if not HAVE_PLAYWRIGHT:
        res.failure_reason = "playwright_unavailable"
        return res

    start = time.time()
    net_bodies: List[str] = []

    def _deadline_left():
        return overall_timeout_ms - int((time.time() - start) * 1000)

    try:
        with sync_playwright() as p:
            launch_kw = {"headless": True}
            browser = p.chromium.launch(**launch_kw)
            ctx_kw = {"user_agent": user_agent, "locale": "en-US",
                      "extra_http_headers": {"sec-ch-ua-platform": '"Windows"'}}
            prox = parse_proxy(proxy)
            if prox:                                   # opt-in: default off = no change
                ctx_kw["proxy"] = prox
            context = browser.new_context(**ctx_kw)
            page = context.new_page()
            page.add_init_script(WINDOWS_PLATFORM_JS)
            page.add_init_script(INSTRUMENT_JS)

            if capture_network:
                def _on_response(resp):
                    try:
                        ct = (resp.headers or {}).get("content-type", "")
                        if any(x in ct for x in ("javascript", "json", "text/", "ecmascript")) or not ct:
                            body = resp.text()
                            if body and _looks_cmd(body) and len(body) < 200000:
                                net_bodies.append(body)
                    except Exception:
                        pass
                page.on("response", _on_response)

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout_ms)
            except PWTimeout:
                # Heavy / compromised pages (e.g. a bloated WordPress site with a
                # ClickFix overlay) often never reach 'domcontentloaded' inside the
                # window -- yet the clipboard-building JS has already run. Do NOT
                # abandon: fall through and capture whatever rendered + any clipboard
                # write. The page handle stays usable after a goto timeout, and the
                # overall deadline + per-op timeouts keep this bounded.
                res.failure_reason = "nav_timeout"
            except Exception as exc:
                res.failure_reason = "nav_error:%s" % exc.__class__.__name__
                browser.close()
                res.elapsed_ms = int((time.time() - start) * 1000)
                return res

            # direct / delayed writes before any interaction
            page.wait_for_timeout(settle_ms)

            def _collect():
                try:
                    return page.evaluate("window.__clipcap || []") or []
                except Exception:
                    return []

            def _have_cmd(caps):
                best = _pick_best(caps)
                return bool(best and _looks_cmd(best.get("text", "")))

            pre_caps = _collect()

            # Poll-and-click loop: the ClickFix overlay often injects LATE, so a
            # single early click misses it. Across the time budget we re-check
            # for a command and (re)click the interaction selectors as elements
            # appear, bounded by max_clicks and the overall deadline.
            clicks, rounds = 0, 0
            while not _have_cmd(_collect()) and rounds < 8 and _deadline_left() > 4000:
                rounds += 1
                for sel in interactions:
                    if clicks >= max_clicks or _deadline_left() < 4000:
                        break
                    try:
                        loc = page.locator(sel).first
                        if loc.count() == 0 or not loc.is_visible(timeout=400):
                            continue
                        loc.click(timeout=1500, no_wait_after=True)
                        res.clicked_selectors.append(sel)
                        clicks += 1
                        page.wait_for_timeout(post_click_ms)
                        if _have_cmd(_collect()):
                            break
                    except Exception:
                        continue
                if _have_cmd(_collect()):
                    break
                page.wait_for_timeout(min(settle_ms, max(0, _deadline_left())))  # let a late overlay inject

            # allow delayed/post-click writes to land
            page.wait_for_timeout(min(final_settle_ms, max(0, _deadline_left())))
            caps = _collect()

            # Merge pre- and post-interaction captures: a command written at
            # load can be wiped from window.__clipcap by a later navigation, so
            # we must not rely solely on the final read.
            merged = list(pre_caps)
            for c in caps:
                if c not in merged:
                    merged.append(c)

            res.all_captures = merged
            res.network_hits = net_bodies[:5]
            res.network_bodies = net_bodies[:10]
            try:
                res.rendered_dom = page.content()      # post-JS DOM for static extraction
            except Exception:
                pass
            best = _pick_best(merged)
            if best is None and net_bodies:
                best = {"via": "network", "text": max(net_bodies, key=len)}
            if best is not None:
                res.command_text = best["text"]
                res.method = best["via"]
                res.via_interaction = bool(res.clicked_selectors) and best not in pre_caps
            browser.close()
    except Exception as exc:
        res.failure_reason = "browser_error:%s" % exc.__class__.__name__

    res.elapsed_ms = int((time.time() - start) * 1000)
    if res.command_text is None and res.failure_reason is None:
        res.failure_reason = "no_clipboard_text"
    return res


def browser_recover(url: str, validate_fn, classify_fn, sanitize_fn, **kw) -> dict:
    """Run browser_extract and map the result onto the existing validator /
    provenance schema. Captured text is treated strictly as DATA."""
    r = browser_extract(url, **kw)
    out = {
        "extraction_layer": r.extraction_layer,
        "extraction_method": r.method,
        "via_interaction": r.via_interaction,
        "clicked_selectors": r.clicked_selectors,
        "failure_reason": r.failure_reason,
        "elapsed_ms": r.elapsed_ms,
        "command_text": r.command_text,
        "command_sha256": None,
        "validation_status": None,
        "validation_reason": None,
        "payload_type": None,
        "cape_package": None,
    }
    if r.command_text:
        sres = sanitize_fn(r.command_text)
        v = validate_fn(r.command_text)
        c = classify_fn(r.command_text)
        out["command_sha256"] = sres.sha256
        out["validation_status"] = v.status
        out["validation_reason"] = v.reason
        out["payload_type"] = c.payload_type
        out["cape_package"] = c.cape_package
    return out
