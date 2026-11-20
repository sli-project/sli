#!/usr/bin/env python3
"""Execute one owner-authorized frozen PostgreSQL hot-retention manifest.

The executor never calculates a moving retention set. It accepts only the
published binary manifest produced by ``tier_retention_delete_plan.py --full``
and rechecks identity, policy, cutoff, hashes and restrictive references
before every bounded commit.

The real implementation lives in
``server.sli.storage.tier_retention_delete_executor_runtime`` (production-grade
module, shared by ``scripts/runtime/storage_lifecycle_worker.py``). This
file is a thin CLI wrapper kept for manual/acceptance use and backward
compatibility; it holds no logic of its own.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.storage.tier_retention_delete_executor_runtime import (  # noqa: E402,F401
    APPROVED_OWNER,
    CONFIRMATION,
    DEFAULT_OUTPUT,
    DEFAULT_PLAN,
    MAX_BATCH,
    RECORD,
    _atomic_json,
    _connect_write,
    _manifest_records,
    _sha256,
    _windows_account,
    execute,
    main,
    validate_package,
)

if __name__ == "__main__":
    raise SystemExit(main())
