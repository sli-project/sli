#!/usr/bin/env python3
"""Build a read-only gate for a future PostgreSQL hot-tier deletion.

The command verifies policy, the durable full-payload backup, warm placement,
and restrictive foreign-key references. It never mutates PostgreSQL,
ClickHouse, the archive, or the backup, and it never grants deletion authority.

The real implementation lives in
``server.sli.storage.tier_retention_delete_plan_runtime`` (production-grade module,
shared by ``scripts/runtime/storage_lifecycle_worker.py``). This file is a
thin CLI wrapper kept for manual/acceptance use and backward compatibility;
it holds no logic of its own.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.storage.tier_retention_delete_plan_runtime import (  # noqa: E402,F401
    BACKUP_MANIFEST,
    BACKUP_ROOT,
    COPY_EVIDENCE,
    DEFAULT_CANDIDATE_LIMIT,
    DEFAULT_FULL_MANIFEST,
    FULL_PAGE_ROWS,
    GateInputs,
    _candidate_rows,
    _chunks,
    _restrictive_references,
    _sha256,
    _verify_warm_page,
    assemble_gate,
    build_full_plan,
    build_plan,
    main,
    verify_backup,
    verify_warm,
)

if __name__ == "__main__":
    raise SystemExit(main())
