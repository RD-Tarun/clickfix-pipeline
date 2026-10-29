#!/usr/bin/env bash
# Read-only snapshot of the ClickFix -> CAPE pipeline. Safe to run anytime by
# anyone with shell access; it changes nothing (no sudo, no submits).
set -uo pipefail
HERE="/home/maldex/clickfix-cape/eval_staging/clickfix"
DB="$HERE/storage/collection.db"
LOG="$HERE/storage/catcher.log"
CAPE="http://127.0.0.1:8000"

line(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

line "1. Service"
systemctl status clickfix-catcher --no-pager 2>/dev/null | grep -E "Active|Main PID" | sed 's/^/  /' \
  || echo "  (service not installed)"

line "2. Recent sweeps (last 12 log lines)"
tail -n 12 "$LOG" 2>/dev/null | sed 's/^/  /' || echo "  (no log yet)"

# IST = UTC + 5:30; the DB stores UTC ISO strings, so shift them for display.
IST="datetime(%s, '+330 minutes') || ' IST'"

line "3. CAPE execution — latest catcher tasks in the Windows VM"
curl -s -m 8 "$CAPE/apiv2/tasks/list/10/" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin).get('data',[])
if not d: print('  (no tasks yet)')
for t in d:
    print('  task=%-4s status=%-10s package=%-4s machine=%s'%(t['id'],t['status'],t.get('package') or '-',t.get('machine') or '-'))
" 2>/dev/null || echo "  (CAPE API unreachable)"

line "4. SQL store — catcher-detonated domains"
sqlite3 -column -header "$DB" \
  "SELECT fqdn, status, $(printf "$IST" first_seen) AS 'FIRST OBSERVED' \
   FROM domains WHERE source='catcher' ORDER BY first_seen DESC LIMIT 15;" 2>/dev/null \
  | sed 's/^/  /' || echo "  (none yet)"

line "5. SQL store — catcher payloads (command hash + CAPE task)"
sqlite3 -column -header "$DB" \
  "SELECT substr(sha256,1,12) AS sha, served_by_domain, cape_task_id, $(printf "$IST" first_seen) AS 'FIRST OBSERVED' \
   FROM payload_artifacts WHERE source='catcher' ORDER BY first_seen DESC LIMIT 15;" 2>/dev/null \
  | sed 's/^/  /' || echo "  (none yet)"

line "6. ClickFix payloads (SITES = how many distinct websites served this payload)"
sqlite3 -column -header "$DB" \
  "SELECT substr(pa.notes,1,90) AS 'PAYLOAD', \
          (SELECT COUNT(DISTINCT s.domain) FROM artifact_sources s WHERE s.artifact_key = pa.artifact_key) AS 'SITES', \
          $(printf "$IST" pa.first_seen) AS 'FIRST OBSERVED' \
   FROM payload_artifacts pa WHERE pa.source='catcher' AND pa.notes IS NOT NULL \
   ORDER BY pa.first_seen DESC LIMIT 20;" 2>/dev/null \
  | sed 's/^/  /' || echo "  (none yet)"

line "7. URLs consumed, by source (total intake across all sweeps)"
sqlite3 -column -header "$DB" \
  "SELECT source AS SOURCE, COUNT(*) AS URLS, SUM(times_seen) AS SIGHTINGS \
   FROM consumed_urls GROUP BY source \
   UNION ALL SELECT 'TOTAL', COUNT(*), SUM(times_seen) FROM consumed_urls \
   ORDER BY (SOURCE='TOTAL'), URLS DESC;" 2>/dev/null \
  | sed 's/^/  /' || echo "  (none yet)"

line "8. Recent consumed URLs (url -> source)"
sqlite3 -column -header "$DB" \
  "SELECT substr(url,1,70) AS URL, source AS SOURCE, $(printf "$IST" last_seen) AS 'LAST SEEN' \
   FROM consumed_urls ORDER BY last_seen DESC LIMIT 20;" 2>/dev/null \
  | sed 's/^/  /' || echo "  (none yet)"

line "9. All recoveries by decision (full activity ledger, incl. skipped)"
sqlite3 -column -header "$DB" \
  "SELECT decision AS DECISION, COUNT(*) AS 'CMDS', SUM(times_seen) AS SIGHTINGS \
   FROM recoveries GROUP BY decision ORDER BY CMDS DESC;" 2>/dev/null \
  | sed 's/^/  /' || echo "  (none yet)"

line "10. Recent recoveries (what we saw + what happened to it)"
sqlite3 -column -header "$DB" \
  "SELECT decision AS DECISION, domain AS DOMAIN, source AS SOURCE, \
          substr(command,1,55) AS COMMAND, cape_task_id AS TASK \
   FROM recoveries ORDER BY last_seen DESC LIMIT 20;" 2>/dev/null \
  | sed 's/^/  /' || echo "  (none yet)"

echo
echo "  Dashboard:  cd $HERE && python3 dashboard.py --live  (then open storage/dashboard.html)"
echo "  CAPE UI:    $CAPE/analysis/<task_id>/"
