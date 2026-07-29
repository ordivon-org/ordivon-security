#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARTIFACTS=${ORDIVON_SECURITY_ARTIFACTS:-"$ROOT/artifacts/round1"}

python3 -m unittest discover -v
python3 "$ROOT/scripts/run_adversarial_experiment.py" \
  --actor greedy \
  --output "$ARTIFACTS/micro-greedy"
python3 "$ROOT/scripts/run_adversarial_experiment.py" \
  --actor opponent-aware \
  --output "$ARTIFACTS/micro-opponent-aware"
python3 "$ROOT/scripts/run_adversarial_experiment.py" \
  --actor committee-compromised-naive \
  --output "$ARTIFACTS/micro-committee-compromised-naive"
python3 "$ROOT/scripts/run_adversarial_experiment.py" \
  --actor committee-compromised-compartmentalized \
  --output "$ARTIFACTS/micro-committee-compromised-compartmentalized"
python3 "$ROOT/scripts/analyze_adversarial_results.py" \
  "$ARTIFACTS"/micro-*/trial-index.json \
  --output "$ARTIFACTS/micro-comparison.json"

if [[ ${RUN_CAGE4:-0} == 1 ]]; then
  bootstrap=$($ROOT/scripts/bootstrap_cage4.sh)
  source_path=$(printf '%s\n' "$bootstrap" | sed -n 's/^CAGE4_SOURCE=//p')
  python_path=$(printf '%s\n' "$bootstrap" | sed -n 's/^CAGE4_PYTHON=//p')
  eval "source_path=$source_path"
  eval "python_path=$python_path"
  PYTHONPATH="$source_path" "$python_path" "$ROOT/scripts/run_cage4_baseline.py" \
    --source "$source_path" \
    --output "$ARTIFACTS/cage4"
fi

if [[ ${RUN_MODEL_ACTORS:-0} == 1 ]]; then
  python3 "$ROOT/scripts/run_adversarial_experiment.py" \
    --actor hermes-transcript \
    --seeds 101 \
    --opponents adaptive-counter \
    --max-turns 6 \
    --output "$ARTIFACTS/hermes-transcript"
  python3 "$ROOT/scripts/run_adversarial_experiment.py" \
    --actor hermes-strategic \
    --seeds 101 \
    --opponents adaptive-counter \
    --max-turns 6 \
    --output "$ARTIFACTS/hermes-strategic"
fi

printf 'round1_artifacts=%s\n' "$ARTIFACTS"
