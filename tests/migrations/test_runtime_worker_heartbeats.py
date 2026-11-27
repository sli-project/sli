from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


class Cursor:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.executed = []

    def execute(self, sql, params=()):
        self.executed.append((" ".join(sql.split()), params))

    def fetchall(self):
        return self.rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class Conn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_migration_32_is_payload_free_and_least_privilege() -> None:
    forward = Path("config/postgres_migrations/032_runtime_worker_heartbeats.sql").read_text(encoding="utf-8").casefold()
    rollback = Path("config/postgres_migrations/032_runtime_worker_heartbeats.rollback.sql").read_text(encoding="utf-8").casefold()

    assert "migration 032 requires schema migration 031" in forward
    assert "runtime_worker_heartbeats" in forward
    assert "details_json jsonb" in forward
    assert "event_data" not in forward
    assert "message_text" not in forward
    assert "grant select, insert, update" in forward
    assert "drop table if exists runtime_worker_heartbeats" in rollback


def _write_plugin_heartbeat(directory: Path, component_id: str, **overrides) -> None:
    """Write a real heartbeat file in the exact shape
    scripts/runtime/remote_access_plugin_host.py's _write_heartbeat writes,
    so tests exercise the real on-disk contract, not a stand-in shape."""
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "plugin_id": "sli.remote-access",
        "component_id": component_id,
        "worker_instance_id": f"{component_id}-test-host-4242",
        "process_pid": 4242,
        "status": "running",
        "phase": "cycle",
        "expected_interval_seconds": 300,
        "heartbeat_at_utc": datetime.now(timezone.utc).isoformat(),
        "last_result": {"status": "ok", "worker_result": {"claimed": 3}},
        "contains_secret_material": False,
    }
    payload.update(overrides)
    (directory / f"plugin-{component_id}.json").write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8",
    )
