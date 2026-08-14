#!/usr/bin/env bash
# ToyDesigner V0-V8 harness: each defense baseline must hold before its falsifier/attack treatment.
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
echo "================ advanced baseline V4-V8 ================"
"$PY" verify_advanced_baseline.py || { echo "ADVANCED BASELINE FAILED - aborting"; exit 1; }

for a in v4_bypass_integrity v5_asset_boundary v6_remote_entitlement v7_external_primitive v8_remote_capability; do
    echo
    echo "================ treatment: $a ================"
    "$PY" "attacks/$a.py" || { echo "TREATMENT $a FAILED"; exit 1; }
done

echo
echo "================ V0-V8 ladder complete ================"
