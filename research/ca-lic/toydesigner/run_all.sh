#!/usr/bin/env bash
# ToyDesigner V0-V3 harness: baseline must hold, then every attack must land.
set -u
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)"   # attack scripts live in attacks/; the package is one level up
PY=${PY:-/root/projects/ordivon-security/.venv/bin/python}
mkdir -p runs
[ -f keys/vendor_priv.pem ] || { echo "== keygen =="; "$PY" vendor.py keygen; }

echo "================ baseline (gates must hold) ================"
"$PY" verify_baseline.py || { echo "BASELINE FAILED - aborting"; exit 1; }

for a in v0_plain_flip v1_patch_verify v2_spoof_binding v3_hunt_gates; do
    echo
    echo "================ attack: $a ================"
    "$PY" "attacks/$a.py" || { echo "ATTACK $a FAILED"; exit 1; }
done

echo
echo "================ all attacks landed ================"
