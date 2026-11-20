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


def test_worker_heartbeat_is_an_upsert_without_payload(monkeypatch) -> None:
    from server.sli.ops import runtime_workers as module

    cursor = Cursor()
    result = module.record_worker_heartbeat(
        worker_name="collection",
        worker_id="collection-host-42",
        status="idle",
        phase="sleep",
        expected_interval_seconds=600,
        started_at=datetime(2026, 7, 19, tzinfo=timezone.utc),
        details={"completed": 1},
        connection_factory=lambda: Conn(cursor),
    )

    assert result == {"status": "ok"}
    sql, params = cursor.executed[0]
    assert "on conflict(worker_name) do update" in sql.casefold()
    assert params[0:2] == ("collection", "collection-host-42")
    assert "completed" in params[6]


def test_worker_overview_separates_fresh_stale_and_unregistered(monkeypatch) -> None:
    from server.sli.ops import runtime_workers as module

    now = datetime.now(timezone.utc)
    rows = [
        {
            "worker_name": "collection",
            "worker_id": "collection-host-42",
            "process_pid": 42,
            "status": "idle",
            "phase": "sleep",
            "expected_interval_seconds": 600,
            "details_json": {},
            "started_at": now - timedelta(hours=1),
            "heartbeat_at": now - timedelta(seconds=20),
        },
        {
            "worker_name": "entity_state",
            "worker_id": "entity-host-43",
            "process_pid": 43,
            "status": "idle",
            "phase": "sleep",
            "expected_interval_seconds": 30,
            "details_json": {},
            "started_at": now - timedelta(hours=1),
            "heartbeat_at": now - timedelta(minutes=10),
        },
    ]
    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor(rows)))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)

    result = module.get_runtime_workers_overview()
    items = {item["worker_name"]: item for item in result["items"]}

    assert result["status"] == "ok"
    assert items["collection"]["state"] == "active"
    assert "ad_context_snapshot" not in items
    assert items["entity_state"]["state"] == "stale"
    assert items["post_collection"]["state"] == "not_registered"
    assert items["semantic"]["status"] == "not_observed"
    assert items["semantic"]["feature_enabled"] is True


def test_semantic_uses_durable_heartbeat_without_web_process_secrets(monkeypatch) -> None:
    from server.sli.ops import runtime_workers as module

    now = datetime.now(timezone.utc)
    rows = [{
        "worker_name": "semantic",
        "worker_id": "semantic-production-host-44",
        "process_pid": 44,
        "status": "idle",
        "phase": "sleep",
        "expected_interval_seconds": 30,
        "details_json": {
            "allowed_modes": ["shadow", "enabled"],
            "finding_creation": True,
            "manual_runtime": False,
        },
        "started_at": now - timedelta(days=2),
        "heartbeat_at": now - timedelta(days=1),
    }]
    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor(rows)))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["semantic"]

    assert item["state"] == "stale"
    assert item["status"] == "idle"
    assert item["feature_enabled"] is True


def test_hidden_computers_v5_ignores_historical_stale_heartbeat(monkeypatch) -> None:
    from server.sli.ops import runtime_workers as module

    now = datetime.now(timezone.utc)
    rows = [{
        "worker_name": "computers_v5_snapshot",
        "worker_id": "computers-v5-old-44",
        "process_pid": 44,
        "status": "idle",
        "phase": "sleep",
        "expected_interval_seconds": 43200,
        "details_json": {},
        "started_at": now - timedelta(days=3),
        "heartbeat_at": now - timedelta(days=2),
    }]
    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor(rows)))

    items = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }

    assert "computers_v5_snapshot" not in items


def test_lifecycle_heartbeat_is_authority_even_without_web_process_env(monkeypatch) -> None:
    from server.sli.ops import runtime_workers as module

    now = datetime.now(timezone.utc)
    rows = [{
        "worker_name": "storage_lifecycle",
        "worker_id": "storage-lifecycle-77",
        "process_pid": 77,
        "status": "idle",
        "phase": "sleep",
        "expected_interval_seconds": 21600,
        "details_json": {"policy": "7/365/no archive auto-delete"},
        "started_at": now - timedelta(minutes=5),
        "heartbeat_at": now - timedelta(seconds=20),
    }]
    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor(rows)))
    monkeypatch.delenv("ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED", raising=False)
    monkeypatch.delenv("ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION", raising=False)

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["storage_lifecycle"]

    assert item["feature_enabled"] is True
    assert item["state"] == "active"
    assert item["status"] == "idle"


def test_both_radius_plugin_components_appear_in_the_overview(
    monkeypatch, plugin_heartbeat_dir: Path
) -> None:
    from server.sli.ops import runtime_workers as module

    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor([])))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)

    items = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }

    assert "plugin_radius_acquisition" in items
    assert "plugin_radius_session_observation" in items
    assert items["plugin_radius_acquisition"]["state"] == "not_registered"
    assert items["plugin_radius_acquisition"]["feature_enabled"] is True


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


@pytest.fixture()
def plugin_heartbeat_dir(tmp_path, monkeypatch) -> Path:
    from server.sli.sources import plugin_runtime_heartbeat as heartbeat_module

    directory = tmp_path / "runtime"
    monkeypatch.setattr(heartbeat_module, "HEARTBEAT_DIR", directory)
    return directory


def test_active_radius_host_shows_active_and_fresh_in_the_overview(monkeypatch, plugin_heartbeat_dir: Path) -> None:
    """R08 (#89 review item 2): a genuinely running RADIUS host writes its
    own JSON heartbeat -- with the fix, Operations must read that file for
    a plugin component instead of only ever querying
    runtime_worker_heartbeats (which RADIUS never writes to)."""
    from server.sli.ops import runtime_workers as module

    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor([])))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)
    _write_plugin_heartbeat(
        plugin_heartbeat_dir, "radius-acquisition",
        status="running", phase="cycle",
        heartbeat_at_utc=datetime.now(timezone.utc).isoformat(),
    )

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["plugin_radius_acquisition"]

    assert item["state"] == "active"
    assert item["status"] == "running"
    assert item["feature_enabled"] is True
    assert item["heartbeat_age_seconds"] is not None and item["heartbeat_age_seconds"] < 10
    assert item["process_pid"] == 4242


def test_idle_radius_host_between_cycles_also_shows_active(monkeypatch, plugin_heartbeat_dir: Path) -> None:
    """The host writes status="idle" while sleeping between cycles -- that
    is still a healthy, running worker, not a warning/stale state."""
    from server.sli.ops import runtime_workers as module

    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor([])))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)
    _write_plugin_heartbeat(
        plugin_heartbeat_dir, "radius-session-observation",
        status="idle", phase="sleep", expected_interval_seconds=30,
        heartbeat_at_utc=datetime.now(timezone.utc).isoformat(),
    )

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["plugin_radius_session_observation"]

    assert item["state"] == "active"
    assert item["status"] == "idle"


def test_stopped_radius_host_shows_stale_not_active(monkeypatch, plugin_heartbeat_dir: Path) -> None:
    """R09: a host that stopped writing heartbeats (crashed, or was killed
    without a clean shutdown) must not look active once its last heartbeat
    ages past the freshness window -- exactly the same staleness rule the
    PostgreSQL-backed workers already get."""
    from server.sli.ops import runtime_workers as module

    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor([])))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)
    stale_stamp = datetime.now(timezone.utc) - timedelta(hours=2)
    _write_plugin_heartbeat(
        plugin_heartbeat_dir, "radius-acquisition",
        status="idle", phase="sleep", expected_interval_seconds=300,
        heartbeat_at_utc=stale_stamp.isoformat(),
    )

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["plugin_radius_acquisition"]

    assert item["state"] == "stale"
    assert item["status"] == "idle"


def test_disabled_radius_component_does_not_look_active(monkeypatch, plugin_heartbeat_dir: Path) -> None:
    """R10: a component the host cleanly stopped because it was disabled
    (status="stopped", phase="disabled", per
    scripts/runtime/remote_access_plugin_host.py's _write_heartbeat call at
    loop exit) must read as disabled, not active or stale."""
    from server.sli.ops import runtime_workers as module

    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor([])))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)
    _write_plugin_heartbeat(
        plugin_heartbeat_dir, "radius-acquisition",
        status="stopped", phase="disabled",
        heartbeat_at_utc=datetime.now(timezone.utc).isoformat(),
    )

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["plugin_radius_acquisition"]

    assert item["state"] == "disabled"


def test_blocked_radius_host_shows_blocked(monkeypatch, plugin_heartbeat_dir: Path) -> None:
    from server.sli.ops import runtime_workers as module

    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor([])))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)
    _write_plugin_heartbeat(
        plugin_heartbeat_dir, "radius-acquisition",
        status="blocked", phase="cycle_failed",
        heartbeat_at_utc=datetime.now(timezone.utc).isoformat(),
        last_result={"status": "failed", "failure_stage": "connect", "error_type": "OperationalError", "error_code": "connect_timeout"},
    )

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["plugin_radius_acquisition"]

    assert item["state"] == "blocked"
    assert item["status"] == "blocked"


def test_plugin_heartbeat_contains_no_event_payload_or_secret_fields(monkeypatch, plugin_heartbeat_dir: Path) -> None:
    """R12: the Operations row built from the plugin heartbeat carries only
    the same allowlisted, payload-free shape the PostgreSQL-backed rows
    already guarantee -- no raw event/message/credential field is ever
    forwarded from the heartbeat file into the overview."""
    from server.sli.ops import runtime_workers as module

    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor([])))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)
    _write_plugin_heartbeat(plugin_heartbeat_dir, "radius-acquisition")

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["plugin_radius_acquisition"]

    serialized = json.dumps(item, default=str)
    assert "event_data" not in serialized
    assert "message_text" not in serialized
    assert "record_xml" not in serialized
    assert "password" not in serialized.lower()
    assert "dsn" not in serialized.lower()


def test_missing_or_corrupt_plugin_heartbeat_file_fails_open_to_not_registered(monkeypatch, plugin_heartbeat_dir: Path) -> None:
    """A read failure (file briefly mid-replace, permission error, garbage
    content) must never raise into Operations -- it degrades to the same
    not_registered/not_observed row a never-started component already gets."""
    from server.sli.ops import runtime_workers as module

    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor([])))
    monkeypatch.delenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", raising=False)
    plugin_heartbeat_dir.mkdir(parents=True, exist_ok=True)
    (plugin_heartbeat_dir / "plugin-radius-acquisition.json").write_text("not valid json{{{", encoding="utf-8")

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["plugin_radius_acquisition"]

    assert item["state"] == "not_registered"
    assert item["status"] == "not_observed"


def test_worker_guard_and_overview_read_the_same_heartbeat_file(monkeypatch, plugin_heartbeat_dir: Path) -> None:
    """R13: worker_guard.py's launch-gating check and runtime_workers.py's
    Operations overview must not silently drift onto two different files
    for the same component -- both go through
    server.sli.sources.plugin_runtime_heartbeat, so prove they agree on one write."""
    from scripts.maintenance import worker_guard

    _write_plugin_heartbeat(
        plugin_heartbeat_dir, "radius-acquisition",
        status="blocked", phase="cycle_failed",
        heartbeat_at_utc=datetime.now(timezone.utc).isoformat(),
    )

    block = worker_guard._recent_plugin_block("radius-acquisition")
    assert block is not None
    assert block["phase"] == "cycle_failed"


def test_semantic_queue_overview_is_payload_free_and_reports_operational_state() -> None:
    from server.sli.ops import runtime_workers as module

    rows = [
        {
            "queue_name": "processing",
            "queue_status": "queued",
            "depth": 4,
            "retries": 2,
            "expired_leases": 0,
            "oldest_ready_age_seconds": 90,
        },
        {
            "queue_name": "dispatch",
            "queue_status": "quarantined",
            "depth": 1,
            "retries": 4,
            "expired_leases": 0,
            "oldest_ready_age_seconds": 0,
        },
    ]
    cursor = Cursor(rows)

    result = module.get_semantic_queue_overview(
        connection_factory=lambda: Conn(cursor)
    )

    assert result["status"] == "ok"
    assert result["contains_event_payload"] is False
    assert result["items"] == rows
    sql = cursor.executed[3][0].casefold()
    assert "expired_leases" in sql
    assert "oldest_ready_age_seconds" in sql
    assert "event_data" not in sql
    assert "message_text" not in sql


def test_lifecycle_overview_keeps_fresh_failed_process_up_and_service_degraded(monkeypatch) -> None:
    from server.sli.ops import runtime_workers as module

    now = datetime.now(timezone.utc)
    rows = [{
        "worker_name": "storage_lifecycle",
        "worker_id": "storage-lifecycle-77",
        "process_pid": 77,
        "status": "failed",
        "phase": "error",
        "expected_interval_seconds": 900,
        "details_json": {
            "last_cycle_status": "failed",
            "last_cycle_started_at": (now - timedelta(minutes=2)).isoformat(),
            "last_cycle_completed_at": (now - timedelta(minutes=1)).isoformat(),
            "last_success_at": (now - timedelta(hours=1)).isoformat(),
            "last_error_type": "RuntimeError",
        },
        "started_at": now - timedelta(hours=1),
        "heartbeat_at": now - timedelta(seconds=20),
    }]
    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor(rows)))

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["storage_lifecycle"]

    assert item["status"] == "failed"
    assert item["phase"] == "error"
    assert item["process_status"] == "up"
    assert item["service_outcome"] == "degraded"
    assert item["result_age_seconds"] is not None
    assert item["result_is_stale"] is False


def test_lifecycle_overview_marks_old_cycle_result_stale(monkeypatch) -> None:
    from server.sli.ops import runtime_workers as module

    now = datetime.now(timezone.utc)
    rows = [{
        "worker_name": "storage_lifecycle",
        "worker_id": "storage-lifecycle-77",
        "process_pid": 77,
        "status": "idle",
        "phase": "sleep",
        "expected_interval_seconds": 900,
        "details_json": {
            "last_cycle_status": "success",
            "last_cycle_completed_at": (now - timedelta(hours=1)).isoformat(),
        },
        "started_at": now - timedelta(hours=2),
        "heartbeat_at": now - timedelta(seconds=20),
    }]
    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor(rows)))

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["storage_lifecycle"]

    assert item["process_status"] == "up"
    assert item["service_outcome"] == "degraded"
    assert item["result_age_seconds"] is not None
    assert item["result_is_stale"] is True

    rows[0]["details_json"] = {"last_cycle_status": "success"}
    missing_completed_at = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["storage_lifecycle"]
    assert missing_completed_at["service_outcome"] == "degraded"


def test_lifecycle_overview_keeps_legacy_heartbeat_backward_compatible_and_unknown(monkeypatch) -> None:
    from server.sli.ops import runtime_workers as module

    now = datetime.now(timezone.utc)
    rows = [{
        "worker_name": "storage_lifecycle",
        "worker_id": "storage-lifecycle-77",
        "process_pid": 77,
        "status": "idle",
        "phase": "sleep",
        "expected_interval_seconds": 900,
        "details_json": {"policy": "7/365/no archive auto-delete"},
        "started_at": now - timedelta(minutes=5),
        "heartbeat_at": now - timedelta(seconds=20),
    }]
    monkeypatch.setattr(module, "connect", lambda: Conn(Cursor(rows)))

    item = {
        value["worker_name"]: value
        for value in module.get_runtime_workers_overview()["items"]
    }["storage_lifecycle"]

    assert item["state"] == "active"
    assert item["status"] == "idle"
    assert item["phase"] == "sleep"
    assert item["process_status"] == "up"
    assert item["service_outcome"] == "unknown"
    assert item["result_age_seconds"] is None
    assert item["result_is_stale"] is None


def test_lifecycle_outcomes_distinguish_failed_stalled_not_due_and_completed() -> None:
    from server.sli.ops import runtime_workers as module

    now = datetime.now(timezone.utc)
    digest = "a" * 64
    failed = module._storage_lifecycle_additions(
        details={
            "last_cycle_status": "failed",
            "last_result_digest": digest,
            "last_result_phase": "failed",
        },
        fresh=True,
        expected_interval_seconds=900,
        generated=now,
    )
    stalled = module._storage_lifecycle_additions(
        details={
            "last_cycle_status": "success",
            "last_result_digest": digest,
            "last_result_phase": "completed",
            "last_successful_watermark": "20260903T010203000000Z",
            "watermark_updated_at": (now - timedelta(hours=1)).isoformat(),
        },
        fresh=True,
        expected_interval_seconds=900,
        generated=now,
    )
    not_due = module._storage_lifecycle_additions(
        details={
            "last_cycle_status": "success",
            "last_result_digest": digest,
            "last_result_phase": "completed",
            "last_successful_watermark": "20260903T010203000000Z",
            "watermark_updated_at": (now - timedelta(hours=1)).isoformat(),
            "lifecycle_phase": "not_due",
        },
        fresh=True,
        expected_interval_seconds=900,
        generated=now,
    )
    completed = module._storage_lifecycle_additions(
        details={
            "last_cycle_status": "success",
            "last_result_digest": digest,
            "last_result_phase": "completed",
            "last_successful_watermark": "20260903T020304000000Z",
            "watermark_updated_at": (now - timedelta(seconds=10)).isoformat(),
        },
        fresh=True,
        expected_interval_seconds=900,
        generated=now,
    )

    assert failed["process_status"] == "up"
    assert failed["service_outcome"] == "degraded"
    assert failed["lifecycle_progress_status"] == "failed"
    assert stalled["service_outcome"] == "degraded"
    assert stalled["lifecycle_progress_status"] == "stalled"
    assert not_due["service_outcome"] == "ok"
    assert not_due["lifecycle_progress_status"] == "not_due"
    assert completed["service_outcome"] == "ok"
    assert completed["lifecycle_progress_status"] == "completed"
