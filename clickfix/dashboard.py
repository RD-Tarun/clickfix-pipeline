"""Render a local HTML dashboard of every ClickFix payload the catcher handled.

Reads the catcher's detonations JSONL (recovered commands + their CAPE
detonation status) and, with --live, enriches each CAPE task with its status,
malscore, and top signatures from the local CAPE API. Writes a single
self-contained HTML file you open in a browser.

Deliberately LOCAL-only: it contains real malware commands/IOCs, so it is never
published to a hosted service. Commands are shown defanged in the table.
"""

import argparse
import datetime
import html
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from config import load_config          # noqa: E402
from sanitize import defang_preview     # noqa: E402

# Times are stored as UTC ISO strings; the dashboard shows them in IST.
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30), "IST")


def _ist(iso) -> str:
    """Render a stored ISO timestamp (naive = UTC) as 'YYYY-MM-DD HH:MM:SS' IST."""
    if not iso:
        return ""
    try:
        dt = datetime.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return str(iso)[:19]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")


_STATUS_COLOR = {
    "submitted": "#3b82f6", "reported": "#22c55e", "dry_run": "#9ca3af",
    "skipped_unclassified": "#9ca3af",
}


def load_records(path: str) -> list:
    """Load detonation records (latest per sha256/url wins)."""
    rows = {}
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            key = r.get("sha256") or r.get("url") or r.get("text", "")[:64]
            rows[key] = r           # later sweep overwrites earlier
    return list(rows.values())


def enrich_live(records: list, cfg) -> list:
    """Attach CAPE status / malscore / top signatures for detonated tasks."""
    from cape_client import CapeClient
    client = CapeClient(cfg.cape)
    for r in records:
        tid = r.get("cape_task_id")
        if not tid:
            continue
        try:
            r["cape_status"] = client.get_status(tid)
        except Exception as exc:
            r["cape_status"] = "status_error:%s" % exc.__class__.__name__
            continue
        if r["cape_status"] == "reported":
            try:
                rep = client.get_report(tid)
                r["malscore"] = rep.get("malscore")
                sigs = [s.get("name") for s in (rep.get("signatures") or [])
                        if isinstance(s, dict)]
                r["signatures"] = sigs[:6]
            except Exception as exc:
                r["report_error"] = exc.__class__.__name__
    return records


def _counts(records: list) -> dict:
    c = {"total": len(records), "detonated": 0, "held": 0, "reported": 0, "other": 0}
    for r in records:
        d = (r.get("detonation") or "")
        if d == "submitted":
            c["detonated"] += 1
        elif d.startswith("held"):
            c["held"] += 1
        else:
            c["other"] += 1
        if r.get("cape_status") == "reported":
            c["reported"] += 1
    return c


def render_html(records: list, cfg) -> str:
    generated = datetime.datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    c = _counts(records)
    base = cfg.cape.base_url.rstrip("/")
    rows = sorted(records, key=lambda r: r.get("swept_at", ""), reverse=True)

    def cell(x):
        return html.escape("" if x is None else str(x))

    tr = []
    for r in rows:
        det = r.get("detonation") or ""
        color = _STATUS_COLOR.get(det, "#eab308" if det.startswith(("held", "skipped")) else "#ef4444")
        tid = r.get("cape_task_id")
        task_link = ('<a href="%s/analysis/%s/" target="_blank">%s</a>' % (base, tid, tid)) if tid else "—"
        sigs = ", ".join(r.get("signatures") or []) or "—"
        tr.append(
            "<tr>"
            "<td class='t'>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td>"
            "<td><span class='pill' style='background:%s'>%s</span></td>"
            "<td>%s</td><td>%s</td><td class='sc'>%s</td><td>%s</td>"
            "<td class='cmd'><code>%s</code></td>"
            "</tr>" % (
                cell(_ist(r.get("swept_at"))), cell(r.get("domain")), cell(r.get("source")),
                cell(r.get("cape_package")), color, cell(det), cell(r.get("route")),
                task_link, cell(r.get("malscore")), cell(sigs),
                cell(defang_preview(r.get("text", ""), 220)),
            ))
    body_rows = "\n".join(tr) or ("<tr><td colspan='10' class='empty'>No ClickFix payloads caught yet. "
                                  "The catcher logs here as lures are found.</td></tr>")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClickFix Detonations</title>
<style>
:root {{ color-scheme: dark; --bg:#0b0f17; --panel:#121826; --line:#243143; --fg:#e6edf3; --mut:#9aa7b4; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif; }}
header {{ padding:20px 24px; border-bottom:1px solid var(--line); }}
h1 {{ margin:0 0 4px; font-size:19px; }} .sub {{ color:var(--mut); font-size:13px; }}
.cards {{ display:flex; gap:12px; flex-wrap:wrap; padding:16px 24px; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px 16px; min-width:120px; }}
.card .n {{ font-size:24px; font-weight:700; }} .card .l {{ color:var(--mut); font-size:12px; }}
.wrap {{ padding:0 24px 32px; overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; min-width:900px; }}
th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--mut); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
td.t {{ white-space:nowrap; color:var(--mut); }} td.sc {{ text-align:right; }}
code {{ font:12px/1.4 ui-monospace,Menlo,Consolas,monospace; color:#cbd5e1; }}
td.cmd {{ max-width:420px; }} td.cmd code {{ white-space:pre-wrap; word-break:break-all; }}
.pill {{ color:#06121f; border-radius:999px; padding:2px 8px; font-size:11px; font-weight:700; }}
.empty {{ text-align:center; color:var(--mut); padding:28px; }}
a {{ color:#60a5fa; }}
</style></head><body>
<header><h1>ClickFix Detonations</h1>
<div class="sub">generated {generated} · CAPE {html.escape(base)} · commands shown defanged</div></header>
<div class="cards">
  <div class="card"><div class="n">{c['total']}</div><div class="l">payloads caught</div></div>
  <div class="card"><div class="n">{c['detonated']}</div><div class="l">detonated</div></div>
  <div class="card"><div class="n">{c['reported']}</div><div class="l">reported</div></div>
  <div class="card"><div class="n">{c['held']}</div><div class="l">held (no route)</div></div>
  <div class="card"><div class="n">{c['other']}</div><div class="l">skipped/other</div></div>
</div>
<div class="wrap"><table>
<thead><tr><th>Caught (IST)</th><th>Domain</th><th>Via</th><th>Pkg</th><th>Detonation</th>
<th>Route</th><th>Task</th><th>Score</th><th>Signatures</th><th>Command (defanged)</th></tr></thead>
<tbody>
{body_rows}
</tbody></table></div>
</body></html>"""


def build(records_path: str, out_path: str, cfg, live: bool = False) -> dict:
    records = load_records(records_path)
    if live:
        records = enrich_live(records, cfg)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render_html(records, cfg))
    return {"records": len(records), "out": out_path, "counts": _counts(records)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="dashboard",
                                description="Render the ClickFix detonations dashboard (local HTML).")
    p.add_argument("--records", default=os.path.join(_HERE, "storage", "detonations.jsonl"))
    p.add_argument("--out", default=os.path.join(_HERE, "storage", "dashboard.html"))
    p.add_argument("--live", action="store_true", help="enrich with live CAPE status/score/signatures")
    args = p.parse_args(argv)
    cfg = load_config()
    res = build(args.records, args.out, cfg, live=args.live)
    print("dashboard: %d record(s) -> %s" % (res["records"], res["out"]))
    print("counts:", json.dumps(res["counts"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
