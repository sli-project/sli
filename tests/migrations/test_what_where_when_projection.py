from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

import pytest


def _computer(guid: str, name: str, *, dns: str | None = None, ips=None, device_type="workstation"):
    return {
        "objectGuid": guid,
        "name": name,
        "dnsHostName": dns or name,
        "ipv4s": list(ips or []),
        "ipv6s": [],
        "deviceType": device_type,
    }


class _ArchiveCursor:
    def __init__(
        self,
        blocks,
        hot_events=(),
        domain_controller_server_ids=(101,),
        domain_controllers=None,
    ):
        self.blocks = list(blocks)
        self.hot_events = list(hot_events)
        self.domain_controllers = list(domain_controllers) if domain_controllers is not None else [
            {"id": server_id, "hostname": f"dc-{server_id}", "fqdn": None}
            for server_id in domain_controller_server_ids
        ]
        self.rows = []
        self.hot_queries = 0
        self.dc_lookup_queries = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, sql, params):
        if "from servers" in sql:
            self.dc_lookup_queries += 1
            domain_id = int(params[0])
            limit = int(params[1])
            assert domain_id == 7
            self.rows = self.domain_controllers[:limit]
        elif "storage_v2_archive_blocks" in sql:
            after_id = int(params[0])
            self.rows = [block for block in self.blocks if block["last_event_id"] > after_id][:9]
        elif "from events_v2_core event" in sql:
            self.hot_queries += 1
            after_id = int(params[2])
            limit = int(params[3])
            self.rows = [event for event in self.hot_events if event["source_event_id"] > after_id][:limit]
        else:
            raise AssertionError(sql)

    def fetchall(self):
        return list(self.rows)


class _ArchiveConnection:
    def __init__(self, cursor):
        self.cursor_instance = cursor

    def cursor(self):
        return self.cursor_instance


def _archive_block(tmp_path: Path, block_index: int, rows: list[dict]) -> dict:
    raw = b"\n".join(
        json.dumps({"kind": "event", "row": row}, sort_keys=True).encode("utf-8")
        for row in rows
    ) + b"\n"
    compressed = gzip.compress(raw, mtime=0)
    location = tmp_path / f"block-{block_index}.jsonl.gz"
    location.write_bytes(compressed)
    return {
        "object_location": str(location),
        "row_count": len(rows),
        "raw_bytes": len(raw),
        "compressed_bytes": len(compressed),
        "raw_sha256": hashlib.sha256(raw).digest(),
        "archive_sha256": hashlib.sha256(compressed).digest(),
        "first_event_id": min(row["id"] for row in rows),
        "last_event_id": max(row["id"] for row in rows),
        "block_index": block_index,
    }


def _archive_event(
    event_id: int,
    *,
    observed="2026-08-31T00:00:00Z",
    domain_id=7,
    channel="Security",
    server_id=101,
    computer=None,
    windows_event_id=0,
) -> dict:
    return {
        "id": event_id,
        "server_id": server_id,
        "domain_id": domain_id,
        "channel": channel,
        "computer": computer,
        "event_id": windows_event_id,
        "time_created_utc": observed,
        "target_user_name": "ignored",
    }


def test_hourly_observation_key_is_local_to_novosibirsk_and_casefolds_user() -> None:
    from server.sli.entities.what_where_when_projection import _hourly_observation_key

    first = {
        "computer_object_guid": "11111111-1111-1111-1111-111111111111",
        "user_name": "EXAMPLE\\Ivanov",
        "observed_at_utc": datetime(2026, 9, 1, 23, 5, tzinfo=timezone.utc),
    }
    later_same_hour = {**first, "user_name": "example\\ivanov", "observed_at_utc": datetime(2026, 9, 1, 23, 55, tzinfo=timezone.utc)}

    assert _hourly_observation_key(first) == (
        "11111111-1111-1111-1111-111111111111",
        "example\\ivanov",
        datetime(2026, 9, 2, 6, 0),
    )
    assert _hourly_observation_key(later_same_hour) == _hourly_observation_key(first)


def test_migration_130_compacts_only_hourly_report_observations() -> None:
    forward = Path("config/postgres_migrations/130_what_where_when_hourly_compaction.sql").read_text(encoding="utf-8").casefold()
    rollback = Path("config/postgres_migrations/130_what_where_when_hourly_compaction.rollback.sql").read_text(encoding="utf-8").casefold()

    assert "add column if not exists user_key text" in forward
    assert "add column if not exists observed_hour_local timestamp without time zone" in forward
    assert "at time zone 'asia/novosibirsk'" in forward
    assert "row_number() over" in forward
    assert "delete from public.what_where_when_observations" in forward
    assert "what_where_when_observations_hourly_identity" in forward
    assert "values(130,'what_where_when_hourly_compaction')" in forward
    assert "events_v2_core" not in forward
    assert "delete from public.schema_migrations" in rollback
    assert "version=130" in rollback
    assert "drop constraint if exists what_where_when_observations_hourly_identity" in rollback


def test_archive_normalization_uses_storage_v2_source_core_identity() -> None:
    from server.sli.storage.storage_v2_models import EVENT_ARCHIVE_COLUMNS, event_source_core_sha256
    from server.sli.entities.what_where_when_projection import _normalize_source_event

    row = {column: None for column in EVENT_ARCHIVE_COLUMNS}
    row.update({
        "id": 42,
        "raw_log_file_id": 10,
        "server_id": 11,
        "domain_id": 7,
        "log_source_id": 12,
        "event_record_id": 13,
        "event_id": 0,
        "version": 2,
        "level": 0,
        "task": 12544,
        "opcode": 0,
        "keywords": "0x8020000000000000",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "dc-01.example.test",
        "time_created_utc": "2026-08-31T00:00:00Z",
        "target_user_sid": "S-1-5-21-1-2-3-1001",
        "target_user_name": "ivanov",
        "target_domain_name": "EXAMPLE",
        "ip_address": "10.0.0.7",
        "workstation_name": "PC-01",
        "logon_id": "0x123",
        "correlation_id": "correlation-1",
        "normalized_at": "2026-08-31T00:00:01Z",
        "normalized_hash": "AA" * 32,
        "event_data_json": {"LogonType": "2"},
    })

    normalized = _normalize_source_event(row)

    assert normalized["source_event_hash"] == event_source_core_sha256(row)
    assert normalized["source_event_hash"] != bytes.fromhex(row["normalized_hash"])

    supplied_hash = b"already-normalized-source-identity"
    supplied = _normalize_source_event({**row, "source_event_hash": supplied_hash})
    assert supplied["source_event_hash"] == supplied_hash


def test_reconciliation_query_excludes_persisted_observation_ids() -> None:
    from server.sli.entities.what_where_when_projection import _load_reconciliation_events

    class Cursor:
        def execute(self, sql, params):
            self.sql = " ".join(sql.casefold().split())
            self.params = params

        def fetchall(self):
            return []

    cursor = Cursor()
    _load_reconciliation_events(cursor, domain_id=7, high_water=42, limit=100)

    assert "not exists" in cursor.sql
    assert "from what_where_when_observations observation" in cursor.sql
    assert "observation.source_event_id=event.id" in cursor.sql
    assert cursor.params[0] == 7


def test_migration_125_creates_separate_bounded_projection_storage() -> None:
    forward = Path("config/postgres_migrations/125_what_where_when_projection.sql").read_text(encoding="utf-8").casefold()
    rollback = Path("config/postgres_migrations/125_what_where_when_projection.rollback.sql").read_text(encoding="utf-8").casefold()
    assert "what_where_when_observations" in forward
    assert "source_event_id" in forward and "unique" in forward
    assert "observed_at_utc" in forward
    assert "what_where_when_projection_state" in forward
    assert "what_where_when_projection" in forward
    assert "365 days" in forward
    assert "drop table if exists what_where_when_observations" in rollback


def test_match_index_normalizes_names_ips_and_rejects_conflicts() -> None:
    from server.sli.entities.what_where_when_projection import load_computer_match_index, project_event

    snapshot = {"objects": [
        _computer("11111111-1111-1111-1111-111111111111", " PC-01. ", dns="pc-01.example.test.", ips=["10.0.0.7"]),
        _computer("22222222-2222-2222-2222-222222222222", "PC-02", ips=["10.0.0.8"]),
        _computer("33333333-3333-3333-3333-333333333333", "SERVER-01", device_type="server"),
    ]}
    index = load_computer_match_index(snapshot)
    base = {
        "source_event_id": 42,
        "source_event_hash": b"x" * 32,
        "observed_at_utc": datetime(2026, 8, 31, tzinfo=timezone.utc),
        "target_user_sid": "S-1-5-21-1-2-3-1001",
        "target_user_name": "ivanov",
        "target_domain_name": "EXAMPLE",
        "logon_type": "2",
    }
    matched = project_event({**base, "workstation_name": "pc-01."}, index, {"ivanov": False})
    assert matched["status"] == "observation"
    assert matched["observation"]["computer_object_guid"] == "11111111-1111-1111-1111-111111111111"

    ambiguous = project_event(
        {**base, "workstation_name": "PC-01", "ip_address": "10.0.0.8"},
        index,
        {"ivanov": False},
    )
    assert ambiguous == {"status": "ambiguous", "reason": "name_ip_conflict"}


def test_projection_filters_machine_system_service_unknown_and_non_success_logons() -> None:
    from server.sli.entities.what_where_when_projection import load_computer_match_index, project_event

    index = load_computer_match_index({"objects": [_computer(
        "11111111-1111-1111-1111-111111111111", "PC-01", ips=["10.0.0.7"]
    )]})
    base = {
        "source_event_id": 1,
        "source_event_hash": b"h" * 32,
        "observed_at_utc": datetime(2026, 8, 31, tzinfo=timezone.utc),
        "workstation_name": "PC-01",
        "target_domain_name": "EXAMPLE",
        "logon_type": "2",
    }
    assert project_event({**base, "target_user_name": "PC-01$"}, index, {})["status"] == "filtered"
    assert project_event({**base, "target_user_name": "SYSTEM", "target_user_sid": "S-1-5-18"}, index, {})["status"] == "filtered"
    assert project_event({**base, "target_user_name": "svc_backup"}, index, {"svc_backup": True})["status"] == "filtered"
    assert project_event({**base, "target_user_name": "unknown"}, index, {})["reason"] == "classification_unknown"
    assert project_event({**base, "target_user_name": "ivanov", "logon_type": "0"}, index, {"ivanov": False})["status"] == "filtered"


def test_projection_component_is_supervised_visible_and_30_seconds() -> None:
    from server.sli.ops.runtime_component_registry import get

    component = get("what_where_when_projection")
    assert component.script == "what_where_when_projection_worker.py"
    assert component.expected_interval_seconds == 30
    assert component.supervised is True
    assert component.visible_in_operations is True




def test_archive_backfill_does_not_switch_hot_before_more_than_eight_blocks_are_exhausted(tmp_path: Path) -> None:
    from server.sli.entities.what_where_when_projection import run_backfill_batch

    blocks = [_archive_block(tmp_path, index, [_archive_event(index)]) for index in range(1, 10)]
    cursor = _ArchiveCursor(blocks)
    state = {"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0}

    first = run_backfill_batch(_ArchiveConnection(cursor), state=state, domain_id=7, limit=100)

    assert [event["source_event_id"] for event in first.events] == list(range(1, 9))
    assert first.scanned_through == 8
    assert first.archive_exhausted is False
    assert first.backfill_completed is False
    assert cursor.hot_queries == 0

    second = run_backfill_batch(
        _ArchiveConnection(cursor),
        state={**state, "high_water_event_id": first.scanned_through},
        domain_id=7,
        limit=100,
    )
    assert [event["source_event_id"] for event in second.events] == [9]
    assert second.archive_exhausted is True
    assert second.hot_exhausted is True
    assert cursor.hot_queries == 1


def test_archive_backfill_emits_only_domain_controller_events_and_advances_scan(tmp_path: Path) -> None:
    from server.sli.entities.what_where_when_projection import run_backfill_batch

    archive = _archive_block(
        tmp_path,
        1,
        [
            _archive_event(40, server_id=101),
            _archive_event(41, server_id=202),
        ],
    )
    cursor = _ArchiveCursor([archive], domain_controller_server_ids=(101,))

    batch = run_backfill_batch(
        _ArchiveConnection(cursor),
        state={"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0},
        domain_id=7,
        limit=10,
    )

    assert [event["source_event_id"] for event in batch.events] == [40]
    assert batch.scanned_through == 41
    assert batch.archive_exhausted is True
    assert batch.hot_exhausted is True
    assert cursor.dc_lookup_queries == 1

    no_dc_cursor = _ArchiveCursor([archive], domain_controller_server_ids=())
    no_dc_batch = run_backfill_batch(
        _ArchiveConnection(no_dc_cursor),
        state={"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0},
        domain_id=7,
        limit=10,
    )
    assert no_dc_batch.events == []
    assert no_dc_batch.scanned_through == 41
    assert no_dc_batch.archive_exhausted is True
    assert no_dc_cursor.dc_lookup_queries == 1


def test_archive_backfill_resolves_stale_ids_only_by_unique_current_dc_name(tmp_path: Path) -> None:
    from server.sli.entities.what_where_when_projection import run_backfill_batch

    archive = _archive_block(
        tmp_path,
        1,
        [
            _archive_event(
                40,
                domain_id=70,
                server_id=1001,
                computer="DC-01.example.test.",
                windows_event_id=4624,
            ),
            _archive_event(
                41,
                domain_id=70,
                server_id=1002,
                computer="dc-01.other-domain.example",
                windows_event_id=4624,
            ),
            _archive_event(
                42,
                domain_id=70,
                server_id=1003,
                computer="not-a-dc.example.test",
                windows_event_id=4624,
            ),
        ],
    )
    cursor = _ArchiveCursor(
        [archive],
        domain_controllers=[{"id": 101, "hostname": "dc-01", "fqdn": None}],
    )

    batch = run_backfill_batch(
        _ArchiveConnection(cursor),
        state={"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0},
        domain_id=7,
        limit=10,
    )

    assert [event["source_event_id"] for event in batch.events] == [40]
    assert batch.scanned_through == 42


def test_archive_backfill_rejects_ambiguous_current_dc_short_name(tmp_path: Path) -> None:
    from server.sli.entities.what_where_when_projection import run_backfill_batch

    archive = _archive_block(
        tmp_path,
        1,
        [
            _archive_event(
                40,
                domain_id=70,
                server_id=1001,
                computer="dc-shared.example.test",
                windows_event_id=4624,
            )
        ],
    )
    cursor = _ArchiveCursor(
        [archive],
        domain_controllers=[
            {"id": 101, "hostname": "DC-SHARED", "fqdn": None},
            {"id": 102, "hostname": "dc-shared", "fqdn": None},
        ],
    )

    batch = run_backfill_batch(
        _ArchiveConnection(cursor),
        state={"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0},
        domain_id=7,
        limit=10,
    )

    assert batch.events == []
    assert batch.scanned_through == 40


def test_archive_scan_advances_across_old_blocks_without_querying_hot_early(tmp_path: Path) -> None:
    from server.sli.entities.what_where_when_projection import run_backfill_batch

    blocks = [
        _archive_block(tmp_path, index, [_archive_event(index, observed="2025-01-01T00:00:00Z")])
        for index in range(1, 10)
    ]
    cursor = _ArchiveCursor(blocks)
    state = {"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0}

    batch = run_backfill_batch(_ArchiveConnection(cursor), state=state, domain_id=7, limit=100)

    assert batch.events == []
    assert batch.scanned_through == 8
    assert batch.archive_exhausted is False
    assert batch.backfill_completed is False
    assert cursor.hot_queries == 0


def test_incomplete_eligible_archive_batch_with_later_block_is_not_complete(tmp_path: Path) -> None:
    from server.sli.entities.what_where_when_projection import run_backfill_batch

    blocks = [
        _archive_block(
            tmp_path,
            index,
            [_archive_event(index, observed="2026-08-31T00:00:00Z" if index == 1 else "2025-01-01T00:00:00Z")],
        )
        for index in range(1, 10)
    ]
    cursor = _ArchiveCursor(blocks)

    batch = run_backfill_batch(
        _ArchiveConnection(cursor),
        state={"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0},
        domain_id=7,
        limit=10,
    )

    assert [event["source_event_id"] for event in batch.events] == [1]
    assert batch.scanned_through == 8
    assert batch.archive_exhausted is False
    assert batch.backfill_completed is False
    assert cursor.hot_queries == 0


def test_archive_to_hot_transition_requires_both_sources_to_be_proven_exhausted(tmp_path: Path) -> None:
    from server.sli.entities.what_where_when_projection import run_backfill_batch

    archive = _archive_block(tmp_path, 1, [_archive_event(10)])
    hot = {
        "source_event_id": 11,
        "source_event_hash": b"h" * 32,
        "observed_at_utc": datetime(2026, 8, 31, tzinfo=timezone.utc),
        "event_id": 0,
        "target_user_name": "ignored",
    }
    cursor = _ArchiveCursor([archive], [hot])

    batch = run_backfill_batch(
        _ArchiveConnection(cursor),
        state={"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0},
        domain_id=7,
        limit=10,
    )

    assert [event["source_event_id"] for event in batch.events] == [10, 11]
    assert batch.scanned_through == 11
    assert batch.archive_exhausted is True
    assert batch.hot_exhausted is True
    assert batch.backfill_completed is True


def test_full_archive_batch_does_not_claim_hot_exhaustion_or_skip_unread_rows(tmp_path: Path) -> None:
    from server.sli.entities.what_where_when_projection import run_backfill_batch

    archive = _archive_block(tmp_path, 1, [_archive_event(20), _archive_event(21), _archive_event(22)])
    cursor = _ArchiveCursor([archive])

    batch = run_backfill_batch(
        _ArchiveConnection(cursor),
        state={"initial_cutoff_utc": datetime(2026, 1, 1, tzinfo=timezone.utc), "high_water_event_id": 0},
        domain_id=7,
        limit=2,
    )

    assert [event["source_event_id"] for event in batch.events] == [20, 21]
    assert batch.scanned_through == 21
    assert batch.archive_exhausted is False
    assert batch.hot_exhausted is False
    assert batch.backfill_completed is False
    assert cursor.hot_queries == 0


def test_persist_observation_collapses_later_events_in_the_same_user_computer_hour() -> None:
    from server.sli.entities.what_where_when_projection import _persist_observation

    observation = {
        "source_event_id": 42,
        "source_event_hash": b"h" * 32,
        "computer_object_guid": "11111111-1111-1111-1111-111111111111",
        "computer_name": "PC-01",
        "user_name": "EXAMPLE\\ivanov",
        "observed_at_utc": datetime(2026, 8, 31, tzinfo=timezone.utc),
    }

    class Cursor:
        def __init__(self):
            self.executions: list[tuple[str, tuple]] = []

        def execute(self, sql, params):
            self.executions.append((sql, params))

        def fetchone(self):
            if len(self.executions) == 1:
                return None
            if len(self.executions) == 2:
                return None
            return {"source_event_id": 41}

    cursor = Cursor()
    assert _persist_observation(cursor, observation, computer_snapshot_id=100, user_snapshot_id=200) == "collapsed"
    assert "on conflict (computer_object_guid,user_key,observed_hour_local)" in cursor.executions[1][0]


def test_same_id_and_hash_with_different_projected_values_is_identity_conflict() -> None:
    from server.sli.entities.what_where_when_projection import _persist_observation

    observation = {
        "source_event_id": 42,
        "source_event_hash": b"h" * 32,
        "computer_object_guid": "11111111-1111-1111-1111-111111111111",
        "computer_name": "PC-01",
        "user_name": "EXAMPLE\\ivanov",
        "observed_at_utc": datetime(2026, 8, 31, tzinfo=timezone.utc),
    }

    class Cursor:
        def execute(self, _sql, _params):
            return None

        def fetchone(self):
            return {
                **observation,
                "computer_name": "DIFFERENT-PC",
                "computer_source_snapshot_id": 100,
                "user_snapshot_id": 200,
            }

    with pytest.raises(RuntimeError, match="what_where_when_source_event_identity_conflict"):
        _persist_observation(Cursor(), observation, computer_snapshot_id=100, user_snapshot_id=200)


def test_same_id_hash_projected_values_and_snapshots_is_duplicate() -> None:
    from server.sli.entities.what_where_when_projection import _persist_observation

    observation = {
        "source_event_id": 42,
        "source_event_hash": b"h" * 32,
        "computer_object_guid": "11111111-1111-1111-1111-111111111111",
        "computer_name": "PC-01",
        "user_name": "EXAMPLE\\ivanov",
        "observed_at_utc": datetime(2026, 8, 31, tzinfo=timezone.utc),
    }

    class Cursor:
        def execute(self, _sql, _params):
            return None

        def fetchone(self):
            return {
                **observation,
                "computer_source_snapshot_id": 100,
                "user_snapshot_id": 200,
            }

    assert _persist_observation(Cursor(), observation, computer_snapshot_id=100, user_snapshot_id=200) == "duplicate"
