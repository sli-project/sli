from __future__ import annotations

from datetime import datetime, timezone

import pytest


MANIFEST_ID = "00000000-0000-4000-8000-000000000701"


class _CoordinatorCursor:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.executed: list[tuple[str, object]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql: str, params=None) -> None:
        self.executed.append((str(sql), params))
        if "expire_ad_snapshot_confirmed_ring_v165" in str(sql).casefold():
            self.events.append("retention")

    def fetchall(self):
        return [{"id": 7, "domain_sid": "S-1-5-21-1", "fqdn": "example.test"}]


class _CoordinatorConnection:
    def __init__(self, events: list[str]) -> None:
        self.cursor_value = _CoordinatorCursor(events)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self.cursor_value

    def commit(self):
        self.cursor_value.events.append("commit")


def _scheduled_slot(coordinator):
    return coordinator.ScheduledSlot(
        schedule_timezone="Asia/Novosibirsk",
        scheduled_local_at="2026-09-01T18:00:00",
        slot_start_utc="2026-09-01T11:00:00Z",
    )


def test_coordinator_expires_one_manifest_after_its_projection_completes(monkeypatch) -> None:
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
    from server.sli.sources import ad_gpo_jobs

    monkeypatch.setattr(ad_gpo_jobs, "gpo_snapshot_enabled", lambda: True)

    monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "example.test")
    events: list[str] = []
    connections: list[_CoordinatorConnection] = []
    projection_connections: list[object] = []

    def connect():
        connection = _CoordinatorConnection(events)
        connections.append(connection)
        return connection

    def project(connection, **kwargs):
        projection_connections.append(connection)
        assert kwargs == {"manifest_id": MANIFEST_ID, "worker_id": "coordinator-test"}
        events.append("projection")
        return {
            "status": "completed",
            "manifest_id": MANIFEST_ID,
            "projection_results": {"ad.users.v2": {"status": "completed"}},
        }

    monkeypatch.setattr(coordinator, "connect", connect)
    monkeypatch.setattr(
        coordinator,
        "run_one_shot",
        lambda **_kwargs: {"status": "published", "manifest_id": MANIFEST_ID,
                           "composition": {"version": 1, "parts": ["base_ad", "gpo"]}},
    )
    monkeypatch.setattr(coordinator, "run_exact_manifest_projection_cycle", project)
    monkeypatch.setattr(coordinator.ad_history.ch, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(coordinator.ad_history, "ensure_schema", lambda *_: None)

    def publish(*_):
        events.append("history")
        return {"status": "confirmed", "records_published": 0}

    monkeypatch.setattr(coordinator.ad_history, "publish_manifest", publish)

    result = coordinator._default_cycle(
        datetime(2026, 9, 1, 11, tzinfo=timezone.utc),
        domain_dns="example.test",
        scheduled_slot=_scheduled_slot(coordinator),
        worker_id="coordinator-test",
    )

    retention_connection = connections[-1]
    assert projection_connections == [retention_connection]
    assert events == ["projection", "history", "commit", "retention"]
    assert result["retention_execution"] == {
        "status": "executed",
        "procedure": "public.expire_ad_snapshot_confirmed_ring_v165",
        "manifest_id": MANIFEST_ID,
    }
    assert retention_connection.cursor_value.executed == [
        (
            "call public.expire_ad_snapshot_confirmed_ring_v165(%s::uuid)",
            (MANIFEST_ID,),
        )
    ]


def test_coordinator_never_expires_when_projection_raises(monkeypatch) -> None:
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
    from server.sli.sources import ad_gpo_jobs

    monkeypatch.setattr(ad_gpo_jobs, "gpo_snapshot_enabled", lambda: True)

    monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "example.test")
    events: list[str] = []
    connections: list[_CoordinatorConnection] = []

    def connect():
        connection = _CoordinatorConnection(events)
        connections.append(connection)
        return connection

    monkeypatch.setattr(coordinator, "connect", connect)
    monkeypatch.setattr(
        coordinator,
        "run_one_shot",
        lambda **_kwargs: {"status": "replayed_existing", "manifest_id": MANIFEST_ID},
    )
    monkeypatch.setattr(
        coordinator,
        "run_exact_manifest_projection_cycle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("projection failed")),
    )

    with pytest.raises(RuntimeError, match="projection failed"):
        coordinator._default_cycle(
            datetime(2026, 9, 1, 11, tzinfo=timezone.utc),
            domain_dns="example.test",
            scheduled_slot=_scheduled_slot(coordinator),
        )

    assert events == []
    assert connections[-1].cursor_value.executed == []


@pytest.mark.parametrize("history_port", [None, 8123])
def test_coordinator_never_expires_when_history_is_unavailable(monkeypatch, history_port) -> None:
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
    from server.sli.sources import ad_gpo_jobs

    monkeypatch.setattr(ad_gpo_jobs, "gpo_snapshot_enabled", lambda: True)
    monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "example.test")
    events = []
    monkeypatch.setattr(coordinator, "connect", lambda: _CoordinatorConnection(events))
    monkeypatch.setattr(coordinator, "run_one_shot", lambda **kw: {
        "status": "published", "manifest_id": MANIFEST_ID,
        "composition": {"version": 1, "parts": ["base_ad", "gpo"]}})
    monkeypatch.setattr(coordinator, "run_exact_manifest_projection_cycle", lambda *a, **kw: {
        "status": "completed", "projection_results": {}})
    monkeypatch.setattr(coordinator.ad_history.ch, "configured_read_port", lambda: history_port)
    monkeypatch.setattr(coordinator.ad_history, "ensure_schema", lambda *_: None)
    monkeypatch.setattr(coordinator.ad_history, "publish_manifest", lambda *_: (_ for _ in ()).throw(RuntimeError("history_readback_failed")))

    def cycle():
        return coordinator._default_cycle(datetime(2026, 9, 1, 11, tzinfo=timezone.utc),
            domain_dns="example.test", scheduled_slot=_scheduled_slot(coordinator))

    if history_port is None:
        assert cycle()["retention_execution"] == {
            "status": "skipped", "reason": "history_clickhouse_port_missing"}
    else:
        with pytest.raises(RuntimeError, match="history_readback_failed"):
            cycle()
    assert "retention" not in events


def test_coordinator_skips_retention_when_exact_manifest_projection_is_not_completed(
    monkeypatch,
) -> None:
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
    from server.sli.sources import ad_gpo_jobs

    monkeypatch.setattr(ad_gpo_jobs, "gpo_snapshot_enabled", lambda: True)

    monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "example.test")
    events: list[str] = []
    connections: list[_CoordinatorConnection] = []
    projection_connections: list[object] = []

    def connect():
        connection = _CoordinatorConnection(events)
        connections.append(connection)
        return connection

    def project(connection, **kwargs):
        projection_connections.append(connection)
        assert kwargs == {"manifest_id": MANIFEST_ID, "worker_id": "coordinator-test"}
        events.append("projection")
        return {
            "status": "partial",
            "manifest_id": MANIFEST_ID,
            "projection_results": {"ad.users.v2": {"status": "completed"}},
        }

    monkeypatch.setattr(coordinator, "connect", connect)
    monkeypatch.setattr(
        coordinator,
        "run_one_shot",
        lambda **_kwargs: {"status": "published", "manifest_id": MANIFEST_ID},
    )
    monkeypatch.setattr(coordinator, "run_exact_manifest_projection_cycle", project)

    result = coordinator._default_cycle(
        datetime(2026, 9, 1, 11, tzinfo=timezone.utc),
        domain_dns="example.test",
        scheduled_slot=_scheduled_slot(coordinator),
        worker_id="coordinator-test",
    )

    assert projection_connections == [connections[-1]]
    assert events == ["projection"]
    assert result["retention_execution"]["status"] == "skipped"
    assert not any(
        "call public.expire_ad_snapshot_confirmed_ring_v165" in sql.casefold()
        for connection in connections
        for sql, _params in connection.cursor_value.executed
    )


class _UsersCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []
        self.phase = ""
        self.payload_hash = b""
        self.user_count = 0
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql: str, params=None) -> None:
        self.executed.append((str(sql), params))
        folded = " ".join(str(sql).casefold().split())
        if "insert into users_report_v2_snapshots" in folded:
            self.phase = "insert"
            assert params is not None
            self.user_count = int(params[8])
            self.payload_hash = bytes(params[10])
        elif "select user_count,payload_sha256" in folded:
            self.phase = "readback"
        elif "delete from users_report_v2_snapshots" in folded:
            self.phase = "delete"
            self.rowcount = 3

    def fetchone(self):
        if self.phase == "insert":
            return {"snapshot_id": 44}
        if self.phase == "readback":
            return {"user_count": self.user_count, "payload_sha256": self.payload_hash}
        return None


class _UsersConnection:
    def __init__(self, cursor: _UsersCursor) -> None:
        self.cursor_value = cursor

    def cursor(self):
        return self.cursor_value


def test_users_snapshot_persistence_never_deletes_source_rows() -> None:
    from scripts.runtime import users_report_v2_snapshot_worker as users_worker

    cursor = _UsersCursor()
    result = users_worker.persist_users_v2_snapshot(
        _UsersConnection(cursor),
        snapshot={
            "metadata": {
                "contract_id": users_worker.CONTRACT_ID,
                "collection_status": "complete",
                "observed_at": "2026-09-01T11:00:00Z",
            },
            "users": [{"sam_account_name": "example"}],
        },
        domain_id=7,
        captured_at=datetime(2026, 9, 1, 11, tzinfo=timezone.utc),
    )

    assert not hasattr(users_worker, "RETENTION_DAYS")
    assert result == {
        "status": "captured",
        "snapshot_id": 44,
        "user_count": 1,
        "retired_snapshots": 0,
    }
    assert not any(
        "delete from users_report_v2_snapshots" in sql.casefold()
        for sql, _params in cursor.executed
    )
