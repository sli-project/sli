#!/usr/bin/env python3
"""Plan one exact gap-safe warm-tier batch without changing any storage.

The planner never treats ``max(event_id)`` as a copy cursor: source IDs follow
ingestion order while event timestamps can arrive out of order.  It scans the
bounded time interval that has matured out of the seven-day hot window, asks
ClickHouse which exact source IDs are already present, and freezes only the
missing IDs.  A legacy recovery anchor covers batches published by the former
max-ID planner.

It does not copy rows, start workers, change routing, or authorize deletion.

The real implementation lives in
``server.sli.storage.warm_tier_incremental_plan_runtime`` (production-grade module,
shared by ``server.sli.storage.warm_tier_incremental_copy_runtime``'s
``drain_warm_tier_backlog``). This file is a thin CLI wrapper kept for
manual/acceptance use and backward compatibility; it holds no logic of its
own.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.storage.warm_tier_incremental_plan_runtime import (  # noqa: E402,F401
    CURSOR_OVERLAP,
    DEFAULT_BATCH_LIMIT,
    DEFAULT_OUTPUT,
    DEFAULT_SCAN_LIMIT,
    LEGACY_SELECTION_MODE,
    MAX_BATCH_LIMIT,
    MAX_SCAN_LIMIT,
    SCAN_PAGE_ROWS,
    SELECTION_MODE,
    IncrementalInputs,
    _archive_coverage,
    _batch_identity,
    _candidate_page,
    _connect,
    _container_port,
    _http_query,
    _json_row,
    _parse_utc,
    _scan_missing,
    _selection_lower,
    _source_summary,
    _warm_present_ids,
    _warm_state,
    assess_incremental,
    build_plan,
    main,
    plan_and_record,
    select_missing_rows,
)

if __name__ == "__main__":
    raise SystemExit(main())
