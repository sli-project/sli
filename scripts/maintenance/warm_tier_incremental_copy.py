#!/usr/bin/env python3
"""Publish one exact Stage 7 batch to the isolated warm tier.

The source PostgreSQL transaction is REPEATABLE READ / READ ONLY.  The command
accepts only the exact batch frozen by ``warm_tier_incremental_plan.py`` and
re-verifies every canonical archive block before writing ClickHouse.  Session
boundary events use the accepted append-only lifecycle overlay; prior session
rows and event placements are never updated or deleted.

The published ClickHouse batch is append-only.  A single INSERT publishes all
placement rows, and the immutable manifest row is written last.  A retry can
finalize a fully written batch after an interruption, but partial or mismatched
state fails closed.  This command never changes routing and never deletes hot
PostgreSQL rows.

The real implementation lives in
``server.sli.storage.warm_tier_incremental_copy_runtime`` (production-grade module,
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

from server.sli.storage.warm_tier_incremental_copy_runtime import (  # noqa: E402,F401
    ARCHIVE_STREAM_CHUNK_BYTES,
    CONFIRMATION,
    CONTAINER,
    CREATE_INCREMENTAL_MANIFEST,
    CREATE_PLACEMENT_INPUT,
    CREATE_SESSION_PLACEMENT_INPUT,
    CREATE_SESSION_REVISION_INPUT,
    DATABASE,
    DEFAULT_PLAN,
    EVIDENCE_ROOT,
    HEX64,
    MAX_ARCHIVE_BLOCKS,
    MAX_ARCHIVE_COMPRESSED_BYTES,
    MAX_ARCHIVE_RAW_BYTES,
    MAX_BATCH_ROWS,
    MAX_PENDING_SESSIONS,
    SELECTION_MODE,
    SESSION_EVENT_IDS,
    SESSION_OPEN_EVENT_IDS,
    SESSION_SCHEMA,
    SessionBoundary,
    SessionRevision,
    _apply_session_schema,
    _archive_blocks,
    _archive_placements,
    _canonical_session_placement,
    _canonical_session_revision,
    _clickhouse_json,
    _compatible_prior,
    _connect,
    _container_port,
    _drop_database,
    _ensure_incremental_manifest_schema,
    _existing_rows,
    _format_utc,
    _hash_file_streamed,
    _http_insert_json_rows,
    _http_query,
    _identity,
    _iter_archive_lines_streamed,
    _manifest_rows,
    _parse_utc,
    _pending_sessions,
    _session_actual,
    _session_boundaries,
    _session_plan,
    _session_schema_present,
    _source_batch,
    _stage_rows,
    _stage_session_rows,
    _write_manifest,
    classify_existing,
    classify_session_existing,
    drain_warm_tier_backlog,
    execute_and_record,
    legacy_base_revision,
    load_session_contract,
    main,
    plan_revision,
    run,
)

if __name__ == "__main__":
    raise SystemExit(main())
