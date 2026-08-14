#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)"
PY=${PY:-/root/projects/ordivon-security/.venv/bin/python}
mkdir -p runs
[ -f keys/vendor_priv.pem ] || "$PY" vendor.py keygen
"$PY" r1_authority_economics.py | tee runs/r1-authority-economics.json
