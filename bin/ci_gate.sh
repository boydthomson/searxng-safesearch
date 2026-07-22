#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Merge gate.  Rebuilds every generated artefact from source, then runs the
# full offline harness.  Non-zero exit blocks the deploy.
#
#   Tier-1 leaks        must be 0
#   Tier-2 pass rate    >= 99.9%
#   Crisis coverage     100%
#   Benign control      >= 98%
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${SAFEGUARD_PYTHON:-/usr/local/searxng/searx-pyenv/bin/python}"
cd "$ROOT"

echo "== rebuilding generated lexicons =="
"$PY" bin/build_vocab.py
"$PY" bin/build_phrases.py

echo "== regenerating the corpus =="
"$PY" harness/gen_corpus.py

echo "== acceptance harness =="
mkdir -p reports
[ -f reports/latest.json ] && cp reports/latest.json reports/previous.json

"$PY" harness/run_harness.py \
  --report reports/latest.json \
  --failures reports/failures.jsonl \
  --previous reports/previous.json
