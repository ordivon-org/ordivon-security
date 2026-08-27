#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE=${ORDIVON_CAGE4_SOURCE:-"$ROOT/.cache/cage4"}
REVISION=8c3c50ca54b176c2de199847944e8dcc035497e3
REPOSITORY=https://github.com/cage-challenge/cage-challenge-4.git

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required" >&2
  exit 1
fi

if [[ ! -d "$SOURCE/.git" ]]; then
  rm -rf "$SOURCE"
  git clone --filter=blob:none "$REPOSITORY" "$SOURCE"
fi

git -C "$SOURCE" fetch origin "$REVISION"
git -C "$SOURCE" checkout --detach "$REVISION"
actual=$(git -C "$SOURCE" rev-parse HEAD)
[[ "$actual" == "$REVISION" ]] || {
  echo "unexpected CAGE 4 revision: $actual" >&2
  exit 1
}

cd "$ROOT"
"$ROOT/scripts/owner-environment" bootstrap-cage
"$ROOT/scripts/owner-environment" doctor-cage

printf 'ORDIVON_CAGE4_SOURCE=%q\n' "$SOURCE"
printf 'CAGE4_REVISION=%s\n' "$REVISION"
