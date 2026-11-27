from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import importlib

import pytest


def _scope(*, status: str = "completed", truncated: bool = False) -> dict[str, object]:
    return {
        "collection_run_id": 11,
        "raw_log_file_id": 22,
        "raw_log_sha256": "a" * 64,
        "server_id": 7,
        "log_source_id": 3,
        "descriptor_source": "sli.windows.ad-dc",
        "descriptor_stream": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel_value": "Security",
        "channel_generation_identity": "generation-stable",
        "capture_status": status,
        "cursor_strategy": "record_id",
        "capture_after_record_id": 99,
        "capture_latest_record_id": 102,
        "selector_event_ids": [4672, 4634, 4624, 4608, 4624],
        "query_exhausted": True,
        "truncated": truncated,
        "source_events": [
            {"id": 101, "record_id": 100, "event_key": 4608, "normalized_hash": "1" * 64},
            {"id": 102, "record_id": 101, "event_key": 4624, "normalized_hash": "2" * 64},
            {"id": 103, "record_id": 102, "event_key": 4634, "normalized_hash": "3" * 64},
        ],
        "recorded_at_utc": datetime(2026, 8, 23, tzinfo=timezone.utc),
    }


def test_stage6s_migration_is_independent_of_future_stage12_trust_schema() -> None:
    from pathlib import Path

    migration = Path("config/postgres_migrations/088_source_capture_continuity_declarations.sql").read_text(
        encoding="utf-8",
    )

    assert "version=87 and name='ad_group_membership_warm_facts'" in migration
    assert "ad_infrastructure_trust_warm_facts" not in migration
    assert "migration 088 requires migration 087" in migration
    assert "selector_event_ids jsonb not null" in migration
    assert "query_exhausted boolean not null" in migration
    assert "jsonb_array_length(covered_source_events) > 0" not in migration
    assert "first_event_record_id = capture_after_record_id + 1" in migration
    assert "last_event_record_id = capture_latest_record_id" in migration


def test_stage6s_migration_grants_only_the_required_fk_and_runtime_access() -> None:
    from pathlib import Path

    migration = Path("config/postgres_migrations/088_source_capture_continuity_declarations.sql").read_text(
        encoding="utf-8",
    )

    assert (
        "grant references on table collection_runs, raw_log_files, servers, log_sources\n"
        "    to adlog_storage_owner;"
    ) in migration
    assert (
        "grant select, insert on table source_capture_continuity_declarations\n"
        "    to adlog_user;"
    ) in migration
    assert (
        "grant usage, select on sequence source_capture_continuity_declarations_id_seq\n"
        "    to adlog_user;"
    ) in migration
