from __future__ import annotations

import inspect
import json
import threading
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

import pytest


ROOT = Path(__file__).resolve().parents[2]


class _HeartbeatTicks:
    """Release one heartbeat interval at a time, independent of wall time."""

    def __init__(self) -> None:
        self.condition = threading.Condition()
        self.intervals: list[float] = []
        self.pending = False
        self.stopped = False
        self.finished = False

    def wait(self, interval: float) -> bool:
        with self.condition:
            self.intervals.append(interval)
            self.condition.notify_all()
            self.condition.wait_for(lambda: self.pending or self.stopped)
            self.pending = False
            return self.stopped

    def set(self) -> None:
        with self.condition:
            self.stopped = True
            self.condition.notify_all()

    def finish(self) -> None:
        with self.condition:
            self.finished = True
            self.condition.notify_all()

    def tick(self) -> None:
        with self.condition:
            assert self.condition.wait_for(lambda: self.intervals or self.finished, timeout=5)
            assert not self.finished, "heartbeat exited before the requested renewal"
            previous = len(self.intervals)
            self.pending = True
            self.condition.notify_all()
            assert self.condition.wait_for(
                lambda: len(self.intervals) > previous or self.finished, timeout=5,
            ), "heartbeat did not finish the requested renewal"


def _event(index: int) -> dict:
    return {
        "id": index,
        "raw_log_file_id": 1,
        "server_id": 1,
        "domain_id": 1,
        "site_id": 1,
        "log_source_id": 1,
        "event_record_id": 10_000 + index,
        "event_id": 4624,
        "version": 0,
        "level": 0,
        "task": 12544,
        "opcode": 0,
        "keywords": "0x8020000000000000",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "provider_guid": None,
        "channel": "Security",
        "computer": "DC1.host13.example.invalid",
        "time_created_utc": f"2026-07-13T10:00:{index % 60:02d}.1234567Z",
        "time_created_local": None,
        "record_xml": f"<Event><Id>{index}</Id></Event>",
        "message_text": None,
        "event_data_json": json.dumps({"TargetUserName": f"user-{index % 3}"}),
        "subject_user_sid": "S-1-5-18",
        "subject_user_name": "SYSTEM",
        "subject_domain_name": "EXAMPLE",
        "target_user_sid": f"S-1-5-21-{index}",
        "target_user_name": f"user-{index % 3}",
        "target_domain_name": "EXAMPLE",
        "ip_address": "192.0.2.2",
        "workstation_name": "WS1",
        "logon_id": hex(index),
        "correlation_id": None,
        "normalized_at": "2026-07-13T10:01:00+00:00",
        "normalized_hash": f"{index:064x}"[-64:],
    }


def _entity(index: int) -> dict:
    return {
        "id": index,
        "entity_type": "account",
        "natural_key": f"example\\user-{index}",
        "display_name": f"user-{index}",
        "domain_id": 1,
        "server_id": 1,
        "first_seen_utc": "2026-07-13T10:00:00Z",
        "last_seen_utc": "2026-07-13T10:05:00Z",
        "attributes_json": json.dumps({"sid": f"S-1-5-21-{index}"}),
    }


def _link(event_id: int, entity_id: int) -> dict:
    return {
        "event_id": event_id,
        "entity_id": entity_id,
        "link_role": "target",
        "confidence": 1.0,
        "evidence_json": json.dumps({"field": "TargetUserName"}),
        "extracted_from": "event_data_json",
        "attributes_json": "{}",
        "created_at": "2026-07-13T10:05:00Z",
    }


def test_migrations_are_source_only_versioned_and_do_not_modify_v1_rows() -> None:
    migration_dir = ROOT / "config/postgres_migrations"
    for version, name in ((9, "storage_v2_foundation"), (10, "storage_v2_backfill_support"), (11, "storage_v2_runtime_routing")):
        text = (migration_dir / f"{version:03d}_{name}.sql").read_text(encoding="utf-8").lower()
        assert f"values ({version}, '{name}')" in text
        assert "update events set" not in text
        assert "delete from events" not in text
        assert "alter table events " not in text
        assert (migration_dir / f"{version:03d}_{name}.rollback.sql").is_file()
    schema = (ROOT / "config/postgres_schema.sql").read_text(encoding="utf-8")
    assert "(9, 'storage_v2_foundation')" not in schema
    roles = (migration_dir / "storage_v2_roles.sql").read_text(encoding="utf-8").lower()
    assert "adlog_storage_migrator nologin nosuperuser nocreatedb nobypassrls" in roles
    assert "adlog_storage_drill nologin nosuperuser createdb nobypassrls" in roles
    assert "adlog_storage_worker nologin nosuperuser nocreatedb nobypassrls" in roles
    assert "password" not in roles
    assert "grant usage, create on schema public to adlog_storage_owner" in roles
    assert "grant select, insert, update, delete on table schema_migrations to adlog_storage_owner" in roles
    assert "grant usage, select on sequence schema_migrations_id_seq to adlog_storage_owner" in roles
    assert "grant select on table events, observed_entities, event_entity_links to adlog_storage_owner" in roles
    for version in (9, 10, 11):
        migration = (migration_dir / next(path.name for path in migration_dir.glob(f"{version:03d}_*.sql") if ".rollback." not in path.name)).read_text(encoding="utf-8").lower()
        assert "set local role adlog_storage_owner" in migration
    migration10 = (migration_dir / "010_storage_v2_backfill_support.sql").read_text(encoding="utf-8").lower()
    assert "grant select on table events, observed_entities, event_entity_links to adlog_storage_worker" in roles
    assert "storage_v2_outbox_id_seq, storage_v2_shadow_results_id_seq" in migration10
    assert "all sequences in schema public" not in migration10
    assert "event_ids bigint[] not null" in migration10
    assert "cardinality(event_ids) = event_count" in migration10
    assert "storage_v2_outbox_range_unique" not in migration10
    migration11 = (migration_dir / "011_storage_v2_runtime_routing.sql").read_text(encoding="utf-8").lower()
    assert "grant usage, select on sequence storage_v2_outbox_id_seq, storage_v2_shadow_results_id_seq to adlog_user" in migration11
