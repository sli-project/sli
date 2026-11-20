#!/usr/bin/env bash
# Keep the PR gate and the .NET packet test routing on the same path decision.
set -euo pipefail

# A move out of server/ must count its old path too.
files=$(git diff --name-only --no-renames "$1...$2")
other=$(printf '%s\n' "$files" | grep -vE '^(frontend/|docs/)|\.md$' || true)
if [ -n "$files" ] && [ -z "$other" ]; then
  echo false
else
  echo true
fi
