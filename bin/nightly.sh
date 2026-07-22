#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Nightly verification.  Deliberately cheap on everything external:
#
#   * the 110k offline gate is pure local CPU (~80 s) -- run it every night
#   * blocklists refresh WEEKLY, with conditional GET, so an unchanged week
#     costs no bandwidth instead of ~110 MB a night
#   * services are restarted only when the curated regex list actually changed
#   * the live sample covers the blocked categories broadly (those never reach
#     an engine, so they are free) but caps the benign terms, which are the
#     only ones that generate upstream traffic, and spreads them ~80 s apart
#     with jitter, so the whole run trickles across roughly an hour
#
# Measured here: 40 queries at 3 s spacing produced 4 CAPTCHA + 4 access-denied
# events; one isolated query produced none.  So the limit is rate-based, and a
# CAPTCHA costs 15 days of engine suspension -- which would land in the daytime
# when the site is actually used.  Hence the trickle.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${SAFEGUARD_PYTHON:-/usr/local/searxng/searx-pyenv/bin/python}"
LOG="$ROOT/reports/nightly.log"
HOSTS_YML=/etc/searxng/blocked-hosts.yml
cd "$ROOT"
mkdir -p reports
exec >>"$LOG" 2>&1

echo "===== $(date -Is) nightly start ====="

# --- blocklist refresh: Sundays only (lists move slowly) --------------------
if [ "$(date +%u)" = "7" ] || [ "${FORCE_REFRESH:-0}" = "1" ]; then
  before=$(sha256sum "$HOSTS_YML" 2>/dev/null | cut -d' ' -f1)
  "$PY" bin/refresh_blocklists.py || echo "WARN refresh failed, keeping the previous list"
  after=$(sha256sum "$HOSTS_YML" 2>/dev/null | cut -d' ' -f1)

  if [ "$before" != "$after" ]; then
    # The guard hot-reloads data/blocked-hosts.txt on its own; only SearXNG's
    # curated regex list is read at start-up.
    echo "curated host list changed -- restarting searxng-safe"
    systemctl restart searxng-safe && sleep 20
  else
    echo "curated host list unchanged -- no restart"
  fi
else
  echo "not Sunday -- skipping blocklist refresh"
fi

# --- offline gate: free, so always ------------------------------------------
rc=0
bash bin/ci_gate.sh || rc=$?
echo "offline gate rc=$rc"

# --- live sample: broad on blocked terms, thrifty on upstream ---------------
[ -f reports/live-latest.json ] && cp reports/live-latest.json reports/live-previous.json
"$PY" harness/run_harness.py --mode live \
  --sample "${LIVE_SAMPLE:-900}" \
  --benign-sample "${LIVE_BENIGN:-40}" \
  --delay "${LIVE_DELAY:-80}" --jitter "${LIVE_JITTER:-0.4}" \
  --report reports/live-latest.json \
  --failures reports/live-failures.jsonl \
  --previous reports/live-previous.json
live_rc=$?
echo "live gate rc=$live_rc"

[ "$rc" -ne 0 ] || [ "$live_rc" -ne 0 ] && \
  echo "RED: see reports/failures.jsonl and reports/live-failures.jsonl"

echo "===== $(date -Is) nightly end (offline=$rc live=$live_rc) ====="
