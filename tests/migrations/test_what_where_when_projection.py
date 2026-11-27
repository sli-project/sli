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
