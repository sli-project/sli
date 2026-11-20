from __future__ import annotations

from contextlib import nullcontext
import os
from types import SimpleNamespace
from threading import Event, Thread
import uuid
import time

import pytest

from server.source_packs.radius import accounting_manual_control as control
from server.source_packs.radius.collection_routes import load_radius_collection_routes


@pytest.fixture
def disposable_pg_dsn():
    """A UUID database for lock-only checks; never the runtime database."""
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.environ.get("SLI_TEST_ADMIN_DSN")
    if not source:
        pytest.skip("explicit disposable PostgreSQL admin DSN required")
    parts = conninfo_to_dict(source)
    assert parts.get("host") in {"127.0.0.1", "localhost", "::1"}
    name = "sli_radius_acl_test_" + uuid.uuid4().hex
    parts["dbname"] = "postgres"
    with psycopg.connect(make_conninfo(**parts), autocommit=True, connect_timeout=5) as admin:
        admin.execute(sql.SQL("create database {} template template0").format(sql.Identifier(name)))
        try:
            parts["dbname"] = name
            yield make_conninfo(**parts)
        finally:
            admin.execute(sql.SQL("drop database {} ").format(sql.Identifier(name)))


class _RoleCursor:
    def __init__(self) -> None:
        self.connection = SimpleNamespace(info=SimpleNamespace(dbname="sli_local"))
        self.executed: list[str] = []

    def __enter__(self) -> "_RoleCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: object, _params: object = None) -> None:
        self.executed.append(repr(query).casefold())


class _RoleConnection:
    def __init__(self, cursor: _RoleCursor) -> None:
        self._cursor = cursor

    def transaction(self):
        return nullcontext()

    def cursor(self) -> _RoleCursor:
        return self._cursor


def _state(
    *,
    source: str = "disabled",
    subscription: str = "disabled",
    migration_58: bool = True,
    migration_59: bool = True,
) -> control.RadiusManualState:
    return control.RadiusManualState(
        source_activation=source,
        subscription_activation=subscription,
        cursor_revision=0,
        migration_58=migration_58,
        migration_59=migration_59,
    )


def test_manual_contract_is_single_bounded_invocation() -> None:
    value = control.load_manual_control_contract()
    assert value["source_instance_id"] == load_radius_collection_routes()["source_instance_id"]
    assert value["subscription_id"] == (
        "vpn-radius-session-observations-radius01-v1"
    )
    lease = value["lease"]
    assert lease["maximum_runs_per_invocation"] == 1
    assert lease["maximum_records_per_run"] == 1000
    assert lease["maximum_runtime_seconds"] == 120
    assert lease["continuous_worker_enabled"] is False
    assert lease["worker_autostart_enabled"] is False
    assert lease["worker_admin_db_access_enabled"] is False
    assert lease["required_final_state"] == "disabled"


def test_manual_contract_host_runtime_may_be_long_running_and_autostart() -> None:
    """The contract itself, not just the ADR, must say the host may run

    continuously and start automatically -- that is the whole point of the
    host/lease split: a reader of the JSON alone gets the full picture.
    """
    value = control.load_manual_control_contract()
    host_runtime = value["host_runtime"]
    assert host_runtime["sole_runtime_owner"] is True
    assert host_runtime["long_running_supervised_host"] is True
    assert host_runtime["autostart_enabled"] is True
    assert host_runtime["runtime_owner"] == (
        "scripts/runtime/remote_access_plugin_host.py"
    )
    assert value["schema_version"] == 2


def test_manual_control_refuses_non_disabled_or_missing_migration() -> None:
    with pytest.raises(
        control.RadiusManualControlError,
        match="manual_activation_not_disabled",
    ):
        control.require_ready_disabled(_state(source="manual_enabled"))
    with pytest.raises(
        control.RadiusManualControlError,
        match="manual_required_migration_missing",
    ):
        control.require_ready_disabled(_state(migration_59=False))


def test_manual_ephemeral_login_gets_and_revokes_direct_database_connect() -> None:
    cursor = _RoleCursor()
    conn = _RoleConnection(cursor)

    role, _password = control._create_ephemeral_login(conn)
    control._drop_ephemeral_login(conn, role)

    assert "pg_advisory_xact_lock" in cursor.executed[1]
    assert "grant connect on database" in cursor.executed[4]
    assert "sli_local" in cursor.executed[4]
    assert role in cursor.executed[4]
    assert "pg_advisory_xact_lock" in cursor.executed[6]
    assert "revoke connect on database" in cursor.executed[7]
    assert role in cursor.executed[7]
    assert "drop role if exists" in cursor.executed[8]


def test_database_connect_acl_lock_serializes_two_postgres_connections(disposable_pg_dsn) -> None:
    """A second role ACL transaction cannot pass until the first commits."""
    import psycopg

    first_ready = Event()
    second_acquired = Event()
    second_ready = Event()
    second_pid: list[int] = []
    failure: list[BaseException] = []
    with psycopg.connect(disposable_pg_dsn, connect_timeout=5) as first:
        with first.transaction():
            control.lock_ephemeral_database_connect_acl(first.cursor())
            first_ready.set()

            def wait_for_same_database_connect_acl_lock() -> None:
                try:
                    with psycopg.connect(disposable_pg_dsn, connect_timeout=5) as second:
                        with second.transaction():
                            assert first_ready.wait(1)
                            second_pid.append(second.info.backend_pid)
                            second_ready.set()
                            control.lock_ephemeral_database_connect_acl(second.cursor())
                            second_acquired.set()
                except BaseException as exc:  # surfaced in the parent assertion
                    failure.append(exc)

            waiter = Thread(target=wait_for_same_database_connect_acl_lock, daemon=True)
            waiter.start()
            assert second_ready.wait(3)
            deadline = time.monotonic() + 2
            waiting = False
            while time.monotonic() < deadline:
                waiting = bool(first.execute(
                    "select exists(select 1 from pg_locks where pid=%s and locktype='advisory' and not granted)",
                    (second_pid[0],),
                ).fetchone()[0])
                if waiting:
                    break
                time.sleep(0.02)
            assert waiting, "second connection was not blocked on the shared ACL lock"
            assert not second_acquired.is_set()
        waiter.join(3)
    assert not waiter.is_alive()
    assert not failure
    assert second_acquired.is_set()


def test_manual_scope_disables_and_drops_login_after_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None]] = []
    monkeypatch.setattr(control, "inspect_manual_state", lambda _conn: _state())
    monkeypatch.setattr(
        control,
        "_create_ephemeral_login",
        lambda _conn: ("adlog_radius_manual_a1", "secret"),
    )
    monkeypatch.setattr(
        control,
        "_set_activation",
        lambda _conn, target: calls.append(("activation", target)),
    )
    monkeypatch.setattr(
        control,
        "_drop_ephemeral_login",
        lambda _conn, role: calls.append(("drop", role)),
    )

    result = control.run_one_bounded_operation(
        object(),
        lambda lease: (
            lease.login_role,
            lease.maximum_records,
            lease.maximum_runtime_seconds,
        ),
    )

    assert result == ("adlog_radius_manual_a1", 1000, 120)
    assert calls == [
        ("activation", "manual_enabled"),
        ("activation", "disabled"),
        ("drop", "adlog_radius_manual_a1"),
    ]


def test_manual_scope_disables_and_drops_login_after_worker_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None]] = []
    monkeypatch.setattr(control, "inspect_manual_state", lambda _conn: _state())
    monkeypatch.setattr(
        control,
        "_create_ephemeral_login",
        lambda _conn: ("adlog_radius_manual_a2", "secret"),
    )
    monkeypatch.setattr(
        control,
        "_set_activation",
        lambda _conn, target: calls.append(("activation", target)),
    )
    monkeypatch.setattr(
        control,
        "_drop_ephemeral_login",
        lambda _conn, role: calls.append(("drop", role)),
    )

    def fail(_lease: control.RadiusManualLease) -> None:
        raise RuntimeError("injected_worker_failure")

    with pytest.raises(RuntimeError, match="injected_worker_failure"):
        control.run_one_bounded_operation(object(), fail)
    assert calls == [
        ("activation", "manual_enabled"),
        ("activation", "disabled"),
        ("drop", "adlog_radius_manual_a2"),
    ]


def test_manual_scope_drops_login_if_activation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None]] = []
    monkeypatch.setattr(control, "inspect_manual_state", lambda _conn: _state())
    monkeypatch.setattr(
        control,
        "_create_ephemeral_login",
        lambda _conn: ("adlog_radius_manual_a3", "secret"),
    )

    def fail_activation(_conn: object, target: str) -> None:
        calls.append(("activation", target))
        raise RuntimeError("injected_activation_failure")

    monkeypatch.setattr(control, "_set_activation", fail_activation)
    monkeypatch.setattr(
        control,
        "_drop_ephemeral_login",
        lambda _conn, role: calls.append(("drop", role)),
    )

    with pytest.raises(RuntimeError, match="injected_activation_failure"):
        control.run_one_bounded_operation(object(), lambda _lease: None)
    assert calls == [
        ("activation", "manual_enabled"),
        ("drop", "adlog_radius_manual_a3"),
    ]
