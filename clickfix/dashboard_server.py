#!/usr/bin/env python3
"""Local live dashboard for the ClickFix -> CAPE pipeline.

Pure stdlib (no pip installs). Binds to 127.0.0.1 only -- it is reached over an
SSH tunnel, exactly like the CAPE web UI, so the live malware IOCs it shows never
touch the public internet:

    ssh -L 8077:127.0.0.1:8077 maldex@<vps>   # then open http://localhost:8077

Reads collection.db + the catcher log + the CAPE API live on each request. Times
are shown in IST (Asia/Kolkata) per the operator's preference.
"""
import datetime
import html
import json
import os
import sqlite3
import subprocess
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(_HERE, "storage", "collection.db")
LOG = os.path.join(_HERE, "storage", "catcher.log")
CAPE = "http://127.0.0.1:8000"
HOST, PORT = "127.0.0.1", int(os.getenv("CLICKFIX_DASH_PORT", "8077"))
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


# ---- data gatherers (all failure-tolerant; the page renders even if one fails) ----
def _ist(iso):
    """UTC ISO string (as collection.db stores) -> 'YYYY-MM-DD HH:MM IST'."""
    if not iso:
        return ""
    try:
        dt = datetime.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M IST")
    except Exception:
        return str(iso)


def _db():
    conn = sqlite3.connect("file:%s?mode=ro" % DB, uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def service_status():
    out = {"active": "unknown", "since": "", "pid": ""}
    try:
        out["active"] = subprocess.run(["systemctl", "is-active", "clickfix-catcher"],
                                       capture_output=True, text=True, timeout=5).stdout.strip()
        show = subprocess.run(["systemctl", "show", "clickfix-catcher",
                               "-p", "ActiveEnterTimestamp", "-p", "MainPID"],
                              capture_output=True, text=True, timeout=5).stdout
        for line in show.splitlines():
            if line.startswith("MainPID="):
                out["pid"] = line.split("=", 1)[1]
            elif line.startswith("ActiveEnterTimestamp=") and "=" in line:
                out["since"] = line.split("=", 1)[1]
    except Exception:
        pass
    return out


def cape_tasks(limit=10):
    try:
        with urllib.request.urlopen("%s/apiv2/tasks/list/%d/" % (CAPE, limit), timeout=8) as r:
            data = json.load(r).get("data", [])
        return [{"id": t.get("id"), "status": t.get("status"), "package": t.get("package") or "-",
                 "machine": t.get("machine") or "-"} for t in data]
    except Exception:
        return None  # None => CAPE unreachable (distinct from empty list)


def payloads():
    try:
        with _db() as c:
            return c.execute(
                "SELECT pa.notes AS cmd, pa.sha256, pa.artifact_type AS pkg, pa.cape_task_id AS task, "
                "pa.first_seen, "
                "(SELECT COUNT(DISTINCT s.domain) FROM artifact_sources s "
                " WHERE s.artifact_key = pa.artifact_key) AS sites "
                "FROM payload_artifacts pa WHERE pa.source='catcher' AND pa.notes IS NOT NULL "
                "ORDER BY pa.first_seen DESC LIMIT 50").fetchall()
    except Exception:
        return []


def domains():
    try:
        with _db() as c:
            return c.execute(
                "SELECT fqdn, status, first_seen FROM domains WHERE source='catcher' "
                "ORDER BY first_seen DESC LIMIT 50").fetchall()
    except Exception:
        return []


def consumed():
    """(per-source counts, recent URLs, grand total) from the intake ledger."""
    try:
        with _db() as c:
            counts = c.execute(
                "SELECT COALESCE(source,'?') AS source, COUNT(*) AS urls, "
                "SUM(times_seen) AS sightings FROM consumed_urls GROUP BY source "
                "ORDER BY urls DESC").fetchall()
            recent = c.execute(
                "SELECT url, source, last_seen FROM consumed_urls "
                "ORDER BY last_seen DESC LIMIT 40").fetchall()
            total = c.execute("SELECT COUNT(*) AS n FROM consumed_urls").fetchone()
        return counts, recent, (total["n"] if total else 0)
    except Exception:
        return [], [], 0


def recoveries():
    """(decision counts, recent recoveries) from the full activity ledger."""
    try:
        with _db() as c:
            counts = c.execute(
                "SELECT decision, COUNT(*) AS n, SUM(times_seen) AS sightings FROM recoveries "
                "GROUP BY decision ORDER BY n DESC").fetchall()
            recent = c.execute(
                "SELECT decision, domain, source, package, cape_task_id, command, last_seen "
                "FROM recoveries ORDER BY last_seen DESC LIMIT 40").fetchall()
        return counts, recent
    except Exception:
        return [], []


def recent_log(n=14):
    try:
        with open(LOG, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.readlines()[-n:]
    except Exception:
        return []


# ---- rendering ----
CSS = """
:root{--bg:#070a0f;--panel:#10151e;--panel2:#141b27;--line:#1f2836;
--fg:#e8eef6;--mut:#8a97a8;--dim:#596575;--accent:#5eead4;--accent2:#38bdf8;
--ok:#34d399;--bad:#fb7185;--warn:#fbbf24;
--shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px -12px rgba(0,0,0,.6);
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--fg);font-family:var(--sans);font-size:14px;line-height:1.55;
padding:28px clamp(16px,4vw,44px);background:
radial-gradient(1100px 560px at 85% -12%,rgba(56,189,248,.07),transparent),
radial-gradient(820px 480px at -5% 0%,rgba(94,234,212,.06),transparent),var(--bg)}
.top{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px;margin-bottom:26px}
.brand{display:flex;align-items:center;gap:14px}
.logo{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;font-size:22px;font-weight:800;
color:#04131a;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 8px 22px -8px var(--accent)}
.brand h1{font-size:19px;margin:0;font-weight:750;letter-spacing:-.01em}
.brand .sub{margin:0;color:var(--mut);font-size:12px}
.meta{display:flex;align-items:center;gap:9px;color:var(--mut);font-size:12px;font-family:var(--mono);
background:var(--panel);border:1px solid var(--line);padding:8px 15px;border-radius:999px;box-shadow:var(--shadow)}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.dot.ok{background:var(--ok);animation:pulse 2s infinite}.dot.bad{background:var(--bad)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.5)}70%{box-shadow:0 0 0 7px rgba(52,211,153,0)}100%{box-shadow:0 0 0 0 rgba(52,211,153,0)}}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:14px;margin-bottom:26px}
.tile{position:relative;overflow:hidden;background:linear-gradient(180deg,var(--panel2),var(--panel));
border:1px solid var(--line);border-radius:14px;padding:15px 18px;box-shadow:var(--shadow)}
.tile::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}
.tile.bad::before{background:var(--bad)}.tile.warn::before{background:var(--warn)}.tile.ok::before{background:var(--ok)}
.tile .ico{font-size:15px;opacity:.65}
.tile .n{font-size:26px;font-weight:800;letter-spacing:-.02em;margin-top:5px;font-family:var(--mono)}
.tile .n.ok{color:var(--ok)}.tile .n.bad{color:var(--bad)}.tile .n.warn{color:var(--warn)}
.tile .l{color:var(--mut);font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;margin-top:2px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;margin-bottom:20px;
box-shadow:var(--shadow);overflow:hidden}
details.panel>summary{list-style:none;cursor:pointer;user-select:none;font-size:11.5px;
text-transform:uppercase;letter-spacing:.08em;color:var(--mut);margin:0;padding:14px 20px;
display:flex;align-items:center;gap:11px;background:linear-gradient(180deg,var(--panel2),transparent);
transition:color .12s}
details.panel>summary::-webkit-details-marker{display:none}
details.panel>summary:hover{color:var(--fg)}
details.panel[open]>summary{border-bottom:1px solid var(--line)}
.chev{width:7px;height:7px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;
transform:rotate(-45deg);transition:transform .18s;flex:none;opacity:.7}
details.panel[open]>summary .chev{transform:rotate(45deg)}
.ptitle{flex:1}
.count{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--accent2);
background:rgba(56,189,248,.14);padding:2px 10px;border-radius:999px;letter-spacing:0}
.pbody{animation:fade .2s ease}
@keyframes fade{from{opacity:0}to{opacity:1}}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:11px 20px;font-size:13px;vertical-align:top}
th{color:var(--dim);font-weight:650;text-transform:uppercase;font-size:10.5px;letter-spacing:.06em;
border-bottom:1px solid var(--line)}
tbody tr{border-bottom:1px solid var(--line);transition:background .12s}
tbody tr:last-child{border-bottom:0}tbody tr:hover{background:rgba(94,234,212,.035)}
td.cmd{font-family:var(--mono);font-size:12px;color:var(--accent);word-break:break-all;max-width:660px}
.dom{font-family:var(--mono)}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;font-family:var(--mono)}
.pill.ok{background:rgba(52,211,153,.14);color:var(--ok)}
.pill.bad{background:rgba(251,113,133,.14);color:var(--bad)}
.pill.warn{background:rgba(251,191,36,.14);color:var(--warn)}
.pill.neutral{background:rgba(138,151,168,.13);color:var(--mut)}
.sites{text-align:center}.sites .b{display:inline-block;min-width:30px;padding:2px 9px;border-radius:8px;
font-family:var(--mono);font-weight:800;color:var(--accent2);background:rgba(56,189,248,.15)}
a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}
.empty{padding:16px 20px;color:var(--dim)}
pre.log{margin:0;padding:15px 20px;font-family:var(--mono);font-size:11.5px;line-height:1.75;
color:var(--mut);white-space:pre-wrap;word-break:break-word;max-height:360px;overflow:auto}
.foot{color:var(--dim);font-size:11px;margin:14px 0 0;text-align:center}
@media(max-width:640px){th,td{padding:9px 13px}body{padding:18px 14px}.meta{font-size:11px}}
"""


def _esc(x):
    return html.escape("" if x is None else str(x))


def _status_cls(st):
    st = str(st)
    if st == "reported":
        return "ok"
    if "fail" in st:
        return "bad"
    return "warn"


def _colorlog(lines):
    out = []
    for ln in lines:
        e = _esc(ln.rstrip("\n"))
        e = e.replace("det=submitted", '<b style="color:var(--ok)">det=submitted</b>')
        for t in ("det=dup_command", "det=dup_domain"):
            e = e.replace(t, '<b style="color:var(--warn)">%s</b>' % t)
        for t in ("skipped_unclassified", "skipped_invalid"):
            e = e.replace(t, '<span style="color:var(--dim)">%s</span>' % t)
        out.append(e)
    return "\n".join(out) or "(no log yet)"


def render():
    svc = service_status()
    tasks = cape_tasks()
    pl = payloads()
    dom = domains()
    ccounts, crecent, ctotal = consumed()
    total_sites = sum((r["sites"] or 0) for r in pl)
    now = datetime.datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    active = svc["active"] == "active"

    tiles = [
        ("&#128737;", "service", svc["active"], "ok" if active else "bad"),
        ("&#128229;", "urls consumed", ctotal, ""),
        ("&#129516;", "distinct payloads", len(pl), ""),
        ("&#127760;", "domains", len(dom), ""),
        ("&#128200;", "total sites served", total_sites, ""),
        ("&#128421;", "cape tasks", "n/a" if tasks is None else len(tasks),
         "ok" if tasks else "warn"),
    ]
    T = "".join(
        '<div class="tile %s"><div class="ico">%s</div><div class="n %s">%s</div><div class="l">%s</div></div>'
        % (cls, ico, cls, _esc(v), _esc(l)) for ico, l, v, cls in tiles)

    # CAPE tasks
    if tasks is None:
        tasks_html = '<p class="empty">CAPE API unreachable.</p>'
    elif not tasks:
        tasks_html = '<p class="empty">No tasks yet &mdash; waiting for the next detonatable payload.</p>'
    else:
        rows = "".join(
            '<tr><td class="dom">%s</td><td><span class="pill %s">%s</span></td>'
            '<td><span class="pill neutral">%s</span></td><td class="dom">%s</td></tr>' % (
                _esc(t["id"]), _status_cls(t["status"]), _esc(t["status"]),
                _esc(t["package"]), _esc(t["machine"]))
            for t in tasks)
        tasks_html = ("<table><thead><tr><th>Task</th><th>Status</th><th>Package</th>"
                      "<th>Machine</th></tr></thead><tbody>" + rows + "</tbody></table>")

    # payloads + SITES
    if pl:
        rows = "".join(
            '<tr><td class="cmd">%s</td><td class="sites"><span class="b">%s</span></td>'
            '<td><span class="pill neutral">%s</span></td><td>%s</td><td class="dom">%s</td></tr>' % (
                _esc((r["cmd"] or "")[:300]), _esc(r["sites"]), _esc(r["pkg"] or "-"),
                ('<a href="%s/analysis/%s/">#%s</a>' % (CAPE, r["task"], r["task"])) if r["task"] else "&mdash;",
                _esc(_ist(r["first_seen"])))
            for r in pl[:20])
        pl_html = ("<table><thead><tr><th>Payload</th><th>Sites</th><th>Pkg</th>"
                   "<th>CAPE task</th><th>First observed</th></tr></thead><tbody>"
                   + rows + "</tbody></table>")
    else:
        pl_html = '<p class="empty">No payloads recorded yet.</p>'

    # domains
    if dom:
        rows = "".join(
            '<tr><td class="dom">%s</td><td><span class="pill bad">%s</span></td><td class="dom">%s</td></tr>' % (
                _esc(r["fqdn"]), _esc(r["status"] or "-"), _esc(_ist(r["first_seen"])))
            for r in dom[:20])
        dom_html = ("<table><thead><tr><th>Domain</th><th>Status</th><th>First observed</th>"
                    "</tr></thead><tbody>" + rows + "</tbody></table>")
    else:
        dom_html = '<p class="empty">No domains recorded yet.</p>'

    # intake: URLs consumed by source
    if ccounts:
        srcrows = "".join(
            '<tr><td><span class="pill neutral">%s</span></td><td class="sites"><span class="b">%s</span></td>'
            '<td class="dom">%s</td></tr>' % (_esc(r["source"]), _esc(r["urls"]), _esc(r["sightings"]))
            for r in ccounts)
        consumed_html = ('<table><thead><tr><th>Source</th><th>Distinct URLs</th>'
                         '<th>Total sightings</th></tr></thead><tbody>' + srcrows + "</tbody></table>")
    else:
        consumed_html = '<p class="empty">No URLs consumed yet (restart the catcher to start logging intake).</p>'

    if crecent:
        rr = "".join(
            '<tr><td class="dom">%s</td><td><span class="pill neutral">%s</span></td><td class="dom">%s</td></tr>' % (
                _esc((r["url"] or "")[:95]), _esc(r["source"]), _esc(_ist(r["last_seen"])))
            for r in crecent[:20])
        recent_urls_html = ('<table><thead><tr><th>URL</th><th>Source</th><th>Last seen</th>'
                            '</tr></thead><tbody>' + rr + "</tbody></table>")
    else:
        recent_urls_html = '<p class="empty">none yet</p>'

    log_html = _colorlog(recent_log())
    since = _ist(svc["since"]) if svc["since"] and svc["since"] != "n/a" else (svc["since"] or "?")

    def panel(title, body, count=None, is_open=False, limited=False):
        cnt = '<span class="count">%s</span>' % _esc(count) if count is not None else ""
        note = ' &middot; showing 20' if (limited and isinstance(count, int) and count > 20) else ""
        return ('<details class="panel"%s><summary><span class="chev"></span>'
                '<span class="ptitle">%s%s</span>%s</summary><div class="pbody">%s</div></details>'
                % (" open" if is_open else "", title, note, cnt, body))

    # Order: payloads first (open), then the ledgers (collapsed), CAPE + log last.
    panels = "".join([
        panel("ClickFix payloads &middot; SITES = distinct sites serving it", pl_html, len(pl),
              is_open=True, limited=True),
        panel("Detonated domains", dom_html, len(dom), limited=True),
        panel("Intake &mdash; URLs consumed by source", consumed_html, ctotal, is_open=True),
        panel("Recent consumed URLs", recent_urls_html, ctotal, limited=True),
        panel("CAPE execution &mdash; latest tasks", tasks_html,
              None if tasks is None else len(tasks)),
        panel("Recent sweeps (log)", '<pre class="log">%s</pre>' % log_html),
    ])

    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30"><title>ClickFix &rarr; CAPE</title>
<style>%s</style></head><body>
<header class="top">
  <div class="brand"><div class="logo">&#9672;</div>
    <div><h1>ClickFix &rarr; CAPE</h1><p class="sub">live detonation pipeline</p></div></div>
  <div class="meta"><span class="dot %s"></span>service %s &middot; pid %s &middot; since %s &middot; %s</div>
</header>
<section class="tiles">%s</section>
%s
<p class="foot">bound to 127.0.0.1 &middot; viewed over SSH tunnel &middot; auto-refresh 30s &middot; tables show 20 (open a panel for more)</p>
</body></html>""" % (CSS, "ok" if active else "bad", _esc(svc["active"]), _esc(svc["pid"]),
                     _esc(since), _esc(now), T, panels)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        try:
            body = render().encode("utf-8", "replace")
        except Exception as exc:
            body = ("<pre>dashboard error: %s</pre>" % html.escape(repr(exc))).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # quiet
        pass


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("ClickFix dashboard on http://%s:%d  (SSH-tunnel: ssh -L %d:127.0.0.1:%d <vps>)"
          % (HOST, PORT, PORT, PORT))
    srv.serve_forever()


if __name__ == "__main__":
    main()
