#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 PROMPT" >&2
  exit 2
fi

exec hermes --safe-mode --oneshot "$1"
