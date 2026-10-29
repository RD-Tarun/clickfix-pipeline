# Automated ClickFix Payload Collection & Analysis at Scale

A continuous, hands-off pipeline that discovers live **ClickFix** lures from
multiple threat feeds, recovers the command each lure tries to trick a victim
into running, and detonates the Windows payloads in a CAPE sandbox — fully
automated, deduplicated, and surfaced on a live dashboard.

> ⚠️ **Defensive security tooling.** This repository contains **source code only**.
> No malware samples, captured payloads, IOC database, or credentials are included
> (see `.gitignore`). Running it detonates live malware and must only be done in an
> isolated, authorized sandbox.

## What it does

```
sources ──► recover ──► validate ──► classify ──► dedup ──► detonate ──► record
```

1. **Collect** candidate lure URLs from three sources each sweep:
   - **urlscan.io** (search API + captured DOM + headless-browser fallback)
   - **URLhaus** (abuse.ch authenticated tag API)
   - a curated **ClickFix domain gist**
2. **Recover** the command: headless Chromium with a Windows identity drives the
   fake-captcha UI and captures the clipboard write; static extraction handles the
   rest (incl. JSON per-OS command arrays and obfuscated loaders).
3. **Validate & classify** — content-aware length gating, PowerShell/MSI/batch/exe
   detection; non-Windows (macOS `bash`) lures are recorded but not detonated.
4. **Deduplicate** on both the **payload hash** (never run the same command twice)
   and the **source domain/IP** (polymorphic hosts that repack per request run once).
5. **Detonate** in a CAPE Windows VM (submits a `.ps1` named after the source domain).
6. **Record** every domain, payload, consumed URL and recovery outcome in a SQLite
   intel store, viewable via a terminal snapshot (`status.sh`) or a local web
   dashboard (`dashboard_server.py`, served over an SSH tunnel).

## Layout

| Path | Purpose |
|---|---|
| `clickfix/clickfix_catcher.py` | the engine — sweep → recover → detonate |
| `clickfix/livefeeds.py` | URLhaus + ClickFix-gist sources |
| `clickfix/browser_extractor.py` | headless-Chromium clipboard recovery |
| `clickfix/clickgrab_extract.py` | static command extraction |
| `clickfix/validate.py` · `classify.py` · `sanitize.py` | pre-submission gates |
| `clickfix/cape_client.py` | CAPE API client |
| `clickfix/collection.py` | SQLite intel/dedup store |
| `clickfix/dashboard_server.py` · `status.sh` | live views |
| `clickfix-*.service` | systemd units for continuous operation |
| `tests/` | offline unit tests |

## Requirements

Python 3.12, `requests`, Playwright (Chromium) for the browser path, and a reachable
CAPE v2 instance. Secrets (urlscan / URLhaus API keys) are read from the environment,
never committed.
