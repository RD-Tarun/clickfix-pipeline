"""Take a recovered ClickFix command -> write it as a script file -> execute it
in CAPE.

Steps (what the user asked for):
  1. classify the command (PowerShell one-liner like 'IRM ... | IEX' -> ps1)
  2. write it to a script file: storage/commands/clickfix_<sha12>.ps1 (or .bat)
  3. submit that file to CAPE, which drops it in the Windows VM and runs it

Dry-run by default (shows the file + plan, submits nothing). `--commit` actually
submits. No-spill guard: it NEVER submits with route=internet (which egresses out
the host's real uplink); the default route is the isolated dirty line (vpn) if
one is up, otherwise 'drop' (contained) -- both keep malware off the physical
network. The recovered command is DATA here; it is only executed inside CAPE.
"""

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from config import load_config                       # noqa: E402
from classify import classify_payload                # noqa: E402
from sanitize import evaluate as sanitize_eval       # noqa: E402
from cape_client import CapeClient                   # noqa: E402
from clickfix_catcher import isolated_route_ready    # noqa: E402  (reuse the no-spill guard)

_EXT = {"ps1": ".ps1", "batch": ".bat", "exe": ".exe"}


def build_script_file(command: str, cfg, commands_dir: str) -> dict:
    """Step 1-2: classify the command and write it to a script file on disk."""
    cls = classify_payload(command)
    san = sanitize_eval(command, cfg.sanitize)
    package = cls.cape_package or "ps1"              # default a bare one-liner to PowerShell
    fname = "clickfix_%s%s" % (san.sha256[:12], _EXT.get(package, ".bin"))
    os.makedirs(commands_dir, exist_ok=True)
    path = os.path.join(commands_dir, fname)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(san.normalized_text)
    return {"path": path, "filename": fname, "package": package,
            "payload_type": cls.payload_type, "sha256": san.sha256,
            "content": san.normalized_text}


def _resolve_route(requested, cfg) -> str:
    """Default to an isolated route: the dirty-line VPN if ready, else 'drop'
    (contained). Never silently 'internet'."""
    if requested:
        return requested
    iso, _ = isolated_route_ready()
    return iso or "drop"


def detonate(command: str, cfg, *, route=None, commit: bool = False,
             custom: str = "", client=None) -> dict:
    """Step 3: submit the script file to CAPE. Dry-run unless commit=True.
    `route` is used as given (incl. 'internet' for full second-stage); the CAPE
    VM is the network-isolated sandbox, so route choice is the operator's call."""
    info = build_script_file(command, cfg, cfg.pipeline.commands_dir)
    route = _resolve_route(route, cfg)
    out = {**info, "route": route}
    del out["content"]
    if not commit:
        out["status"] = "dry_run"
        return out
    cfg.cape.route = route
    try:
        client = client or CapeClient(cfg.cape)
        res = client.submit_payload(info["filename"], info["content"].encode("utf-8", "replace"),
                                    info["package"], custom=custom or "clickfix")
        out["status"] = "submitted"
        out["cape_task_id"] = res.task_id
        out["cape_url"] = "%s/analysis/%s/" % (cfg.cape.base_url.rstrip("/"), res.task_id)
    except Exception as exc:
        out["status"] = "submit_error"
        out["error"] = exc.__class__.__name__
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="detonate",
                                description="Recovered command -> .ps1 file -> execute in CAPE "
                                            "(dry-run unless --commit; never egresses out the host line).")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--cmd", help="the recovered command text")
    src.add_argument("--from-log", help="JSONL (catcher detonations log); submit each recovered command")
    p.add_argument("--commit", action="store_true", help="actually submit to CAPE (default: dry run)")
    p.add_argument("--route", choices=["drop", "vpn", "tor", "inetsim", "internet"], default=None,
                   help="CAPE route (default: dirty-line VPN if up, else 'drop')")
    p.add_argument("--log", default=os.path.join(_HERE, "storage", "detonations.jsonl"),
                   help="JSONL log of detonations (read by dashboard.py)")
    args = p.parse_args(argv)
    cfg = load_config()

    cmds = []
    if args.cmd:
        cmds = [args.cmd]
    else:
        with open(args.from_log, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("text") or rec.get("command"):
                    cmds.append(rec.get("text") or rec.get("command"))

    import datetime
    results = [detonate(c, cfg, route=args.route, commit=args.commit) for c in cmds]
    # Log submitted detonations so dashboard.py shows them.
    submitted = [r for r in results if r.get("status") == "submitted"]
    if submitted:
        os.makedirs(os.path.dirname(args.log), exist_ok=True)
        with open(args.log, "a", encoding="utf-8") as fh:
            for r, c in zip(results, cmds):
                if r.get("status") != "submitted":
                    continue
                fh.write(json.dumps({
                    "swept_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "text": c, "domain": None, "source": "detonate",
                    "cape_package": r.get("package"), "detonation": "submitted",
                    "route": r.get("route"), "cape_task_id": r.get("cape_task_id"),
                    "sha256": r.get("sha256")}, default=str) + "\n")
    print(json.dumps({"detonations": results}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
