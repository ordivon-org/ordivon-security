#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE=${ORDIVON_CAGE4_SOURCE:-"$ROOT/.cache/cage4"}
VENV=${ORDIVON_CAGE4_VENV:-"$ROOT/.venv-cage4"}
REVISION=8c3c50ca54b176c2de199847944e8dcc035497e3
REPOSITORY=https://github.com/cage-challenge/cage-challenge-4.git

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required" >&2
  exit 1
fi

if [[ ! -d "$SOURCE/.git" ]]; then
  rm -rf "$SOURCE"
  git clone "$REPOSITORY" "$SOURCE"
fi

git -C "$SOURCE" fetch origin "$REVISION"
git -C "$SOURCE" checkout --detach "$REVISION"
actual=$(git -C "$SOURCE" rev-parse HEAD)
[[ "$actual" == "$REVISION" ]] || { echo "unexpected CAGE 4 revision: $actual" >&2; exit 1; }

uv venv "$VENV" --python 3.12
uv pip install --python "$VENV/bin/python" \
  'typing_extensions==4.9.0' \
  'PyYAML==6.0.1' \
  'gym==0.26.2' \
  'gymnasium==0.28.1' \
  'pettingzoo==1.24.3' \
  'prettytable==3.9.0' \
  'networkx==3.2.1' \
  'numpy==1.26.4' \
  'rich==15.0.0' \
  'pygame==2.5.2'

printf 'CAGE4_SOURCE=%q\n' "$SOURCE"
printf 'CAGE4_PYTHON=%q\n' "$VENV/bin/python"
printf 'CAGE4_REVISION=%s\n' "$REVISION"
