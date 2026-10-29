#!/usr/bin/env bash
# Wrapper for the continuous ClickFix catcher (used by the systemd service).
# Loads the urlscan key + Playwright env, then runs the catcher in a loop.
set -euo pipefail
cd /home/maldex/clickfix-cape/eval_staging/clickfix
set -a; . /home/maldex/.clickfix-env; set +a
export PLAYWRIGHT_BROWSERS_PATH=/home/maldex/clickfix-cape/eval_staging/pwbrowsers
exec /home/maldex/clickfix-cape/eval_staging/pwenv/bin/python clickfix_catcher.py \
  --source both --submit --route internet --max 20 --loop 1500 "$@"
