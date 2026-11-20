#!/usr/bin/env bash
# L06-1: admitted, deterministic evidence review. Model execution is deferred
# to L06-3; this entrypoint never transmits evidence or invokes a model.
# Usage: scripts/dev/ui_audit/run_review.sh RUN_DIR
# Requires the same SLI_AUDIT_* admission environment as crawl.cjs.
set -eu
RUN_DIR="${1:?usage: run_review.sh RUN_DIR}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
PY="${SLI_AUDIT_PYTHON:-python}"
cd "$REPO_ROOT"
exec "$PY" -m scripts.dev.ui_audit.stand review --base "${SLI_AUDIT_ORIGIN:-}" --out "$RUN_DIR"
