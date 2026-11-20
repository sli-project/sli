from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

from scripts.maintenance import stage9_radius_manual_worker as acquisition
from scripts.maintenance import stage9_radius_session_consumer_manual as consumer
from server.sli.sources import radius_plugin_runtime as runtime
from server.sli.sources.plugin_runtime_admission import ACQUISITION, CONSUMER
from server.source_packs.radius.accounting_postgres import RadiusPostgresRuntimeState
from server.source_packs.radius.accounting_runtime_contract import initial_cursor
from server.source_packs.radius.accounting_tail import RadiusTailBatch


class Connection:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class _ConsumerRoleCursor:
    def __init__(self, response: tuple[object, ...]) -> None:
        self.connection = SimpleNamespace(info=SimpleNamespace(dbname="sli_local"))
        self._response = response
        self.executed: list[str] = []
        self.raise_on: str | None = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, query, _params=None):
        text = repr(query).casefold()
        self.executed.append(text)
        if self.raise_on and self.raise_on in text:
            raise RuntimeError("injected_connect_grant_failure")

    def fetchone(self):
        return self._response


class _ConsumerRoleConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.transactions: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def cursor(self):
        return self._cursor

    @contextmanager
    def transaction(self):
        self.transactions.append("begin")
        try:
            yield
        except Exception:
            self.transactions.append("rollback")
            raise
        else:
            self.transactions.append("commit")


def test_acquisition_gets_permission_before_source_contact(monkeypatch) -> None:
    state = {"inside": False, "component": None}
    cursor = initial_cursor(source_instance_id="fixture-radius", transport_binding="fixture-tail",
                            file_generation="fixture-generation")

    @contextmanager
    def scope(_conn, *, component_id, holder_key):
        state.update(inside=True, component=component_id)
        assert holder_key.startswith("radius-acquisition:")
        try:
            yield object()
        finally:
            state["inside"] = False

    def source():
        assert state["inside"] is True
        return "directory", "N. Central Asia Standard Time", 420

    monkeypatch.setattr(
        runtime,
        "verify_collection_identity",
        lambda: {"status": "ok"},
    )
    monkeypatch.setattr(runtime, "connect_acquisition_worker", Connection)
    monkeypatch.setattr(runtime, "component_lease_scope", scope)
    monkeypatch.setattr(runtime, "require_accounting_source", source)
    monkeypatch.setattr(
        runtime,
        "load_runtime_state",
        lambda *_args, **_kwargs: RadiusPostgresRuntimeState(
            cursor=cursor, revision=7, cursor_epoch=uuid4(), class_cache={},
            exact_boundary_recovery=False,
        ),
    )
    monkeypatch.setattr(
        runtime,
        "read_bounded_tail",
        lambda *_args, **_kwargs: RadiusTailBatch(
            file_generation=cursor.file_generation, start_offset=0, end_offset=0,
            previous_generation_eof=False, records=(),
            candidate_count=0,
            bytes_read=0,
            partial_trailing_bytes=0,
            rotation_backlog_generations=0,
            cursor_generation_recovered=False,
        ),
    )

    result = acquisition.run_internal()
    assert state["component"] == ACQUISITION
    assert result["status"] == "no_new_complete_records"


def test_consumer_gets_permission_before_claim(monkeypatch) -> None:
    state = {"inside": False, "component": None}

    @contextmanager
    def scope(_conn, *, component_id, holder_key):
        state.update(inside=True, component=component_id)
        assert holder_key.startswith("radius-session-observation:")
        try:
            yield object()
        finally:
            state["inside"] = False

    def claim(_conn, *, limit):
        assert state["inside"] is True
        assert limit == 50
        return []

    monkeypatch.setattr(runtime, "connect_consumer_worker", Connection)
    monkeypatch.setattr(runtime, "component_lease_scope", scope)
    monkeypatch.setattr(runtime, "claim_radius_deliveries", claim)

    result = consumer.run_internal()
    assert state["component"] == CONSUMER
    assert result == {
        "status": "completed",
        "claimed": 0,
        "processed": 0,
        "outcomes": {},
    }


def test_consumer_ephemeral_login_revokes_direct_connect_before_drop_on_failure(
    monkeypatch,
) -> None:
    create = _ConsumerRoleCursor((False,))
    cleanup = _ConsumerRoleCursor((0,))
    create_connection = _ConsumerRoleConnection(create)
    cleanup_connection = _ConsumerRoleConnection(cleanup)
    connections = iter((create_connection, cleanup_connection))
    monkeypatch.setattr(runtime, "connect_consumer_admin", lambda: next(connections))

    import pytest

    with pytest.raises(RuntimeError, match="injected"):
        with runtime.consumer_ephemeral_login():
            raise RuntimeError("injected")

    assert "pg_advisory_xact_lock" in create.executed[2]
    assert "grant connect on database" in create.executed[5]
    assert "sli_local" in create.executed[5]
    assert "pg_advisory_xact_lock" in cleanup.executed[2]
    assert "revoke connect on database" in cleanup.executed[4]
    assert "drop role" in cleanup.executed[5]
    assert create_connection.transactions == ["begin", "commit"]
    assert cleanup_connection.transactions == ["begin", "commit"]


def test_consumer_ephemeral_login_rolls_back_create_if_connect_grant_fails(
    monkeypatch,
) -> None:
    create = _ConsumerRoleCursor((False,))
    create.raise_on = "grant connect on database"
    connection = _ConsumerRoleConnection(create)
    monkeypatch.setattr(runtime, "connect_consumer_admin", lambda: connection)

    import pytest

    with pytest.raises(RuntimeError, match="injected_connect_grant_failure"):
        with runtime.consumer_ephemeral_login():
            pass

    assert "create role" in create.executed[3]
    assert "grant connect on database" in create.executed[5]
    assert connection.transactions == ["begin", "rollback"]
