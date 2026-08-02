#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARTIFACTS=${ORDIVON_SECURITY_ARTIFACTS:-"$ROOT/artifacts/round1"}

python3 -m unittest discover -v
python3 "$ROOT/scripts/run_adversarial_experiment.py" --actor greedy --output "$ARTIFACTS/micro-greedy"
python3 "$ROOT/scripts/run_adversarial_experiment.py" --actor opponent-aware --output "$ARTIFACTS/micro-opponent-aware"
python3 "$ROOT/scripts/analyze_adversarial_results.py" \
  "$ARTIFACTS"/micro-*/trial-index.json --output "$ARTIFACTS/micro-comparison.json"

printf 'round1_artifacts=%s\n' "$ARTIFACTS"
