#!/usr/bin/env bash
# Offline supervisor; no curl, git, gh, Docker or application-service operations.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
HOME_DIR=${WATCHDOG_HOME:-$ROOT}
PYTHON=${WATCHDOG_PYTHON:-$ROOT/../update/venv/Scripts/python.exe}
DRY=()
case "${1:-}" in -n) DRY=(--dry);; '') :;; *) exit 2;; esac
[[ $# -le 1 ]] || exit 2
timeout -k 5 120 "$PYTHON" "$ROOT/watchdog_pipeline.py" guard \
  --home "$(cygpath -w "$HOME_DIR")" --root "$(cygpath -w "$ROOT")" \
  --bash "$(cygpath -w "$BASH")" "${DRY[@]}"
