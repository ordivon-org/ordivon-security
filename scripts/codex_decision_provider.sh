#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 PROMPT" >&2
  exit 2
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=$(mktemp)
trap 'rm -f "$output"' EXIT

codex exec \
  --ephemeral \
  --sandbox read-only \
  --skip-git-repo-check \
  --output-schema "$ROOT/schemas/decision.schema.json" \
  --output-last-message "$output" \
  "$1" >/dev/null
cat "$output"
