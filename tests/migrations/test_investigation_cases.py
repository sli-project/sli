from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest


def test_investigation_repeat_read_includes_bounded_audit(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    audit_rows = [{"id": 3, "action": "created", "actor": "analyst"}]

    class Cursor:
        def execute(self, query: str, parameters: tuple[object, ...]) -> None:
            assert "from investigation_audit" in query
            assert "limit 200" in query
            assert parameters == (17,)

        def fetchall(self) -> list[dict[str, object]]:
            return audit_rows

        def __enter__(self) -> "Cursor":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    class Connection:
        def cursor(self) -> Cursor:
            return Cursor()

        def __enter__(self) -> "Connection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: {"id": 17, "title": "Проверка"})

    result = cases.get_case(17)

    assert result["audit"] == audit_rows


def test_investigation_status_update_is_parameterized_and_audited(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def execute(self, query: str, parameters: tuple[object, ...]) -> None:
            calls.append((query, parameters))

        def __enter__(self) -> "Cursor":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    class Connection:
        def cursor(self) -> Cursor:
            return Cursor()

        def __enter__(self) -> "Connection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    rows = iter(({"id": 9, "status": "active"}, {"id": 9, "status": "closed"}))
    monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: next(rows))

    updated = cases.update_case_status(investigation_id=9, status="closed", actor="analyst")

    assert updated["status"] == "closed"
    update_query, update_parameters = calls[0]
    assert "closed_at=case when %s = 'closed' then now() else null end" in update_query
    assert update_parameters == ("closed", "closed", 9)
    assert calls[1][1] == (9, "analyst", "active", "closed")


def test_investigation_case_migration_has_durable_evidence_and_notes_tables() -> None:
    from pathlib import Path

    migration = (Path(__file__).resolve().parents[2] / "config" / "postgres_migrations" / "015_investigation_cases.sql").read_text(encoding="utf-8")

    assert "create table if not exists investigations" in migration
    assert "create table if not exists investigation_events" in migration
    assert "create table if not exists investigation_notes" in migration
    assert "event_db_id bigint not null references events(id) on delete restrict" in migration

    v2_migration = (Path(__file__).resolve().parents[2] / "config" / "postgres_migrations" / "016_investigation_evidence_v2.sql").read_text(encoding="utf-8")
    assert "drop constraint if exists investigation_events_event_db_id_fkey" in v2_migration
    assert "investigation_evidence_v2" in v2_migration


def test_investigation_event_validation_reads_storage_v2_only() -> None:
    from server.sli.semantic import investigation_cases as cases

    class Cursor:
        def __init__(self, present: bool) -> None:
            self.present = present
            self.parameters = None

        def execute(self, query: str, parameters: tuple[int, int]) -> None:
            assert "from events_v2_core" in query
            assert "from events " not in query  # V1 relation dropped by migration 097
            self.parameters = parameters

        def fetchone(self) -> dict[str, bool]:
            return {"present": self.present}

    cursor = Cursor(True)
    assert cases._event_exists(cursor, 3696224) is True
    assert cursor.parameters == (3696224,)


def test_investigation_v2_route_executes_no_v1_event_sql(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    statements: list[str] = []

    class Cursor:
        def __init__(self) -> None:
            self.last_query = ""

        def execute(self, query: str, parameters=()) -> None:
            self.last_query = " ".join(query.lower().split())
            statements.append(self.last_query)

        def fetchone(self):
            return {"present": True, "server_id": 1, "domain_id": 2, "channel": "Security"}

        def fetchall(self):
            if "from investigation_evidence_refs" in self.last_query:
                return []
            return [{"investigation_id": 7, "event_db_id": 11, "server_id": 1, "domain_id": 2, "channel": "Security"}]

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    authorization = object()
    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(cases, "resolve_storage_route", lambda **_kwargs: {"route": "v2"}, raising=False)

    assert cases._event_exists(Cursor(), 11, authorization=authorization)
    assert cases._resource_groups_for_case_ids(Cursor(), [7], authorization=authorization)[7]
    assert cases.event_resource_group(11, authorization=authorization)

    combined = "\n".join(statements)
    assert "events_v2_core" in combined
    assert "from events " not in combined


def test_investigation_domain_error_is_not_malformed_id_error() -> None:
    from server.sli.semantic import investigation_cases as cases

    assert not issubclass(cases.InvestigationCaseError, ValueError)


def test_investigation_creation_accepts_v2_only_event(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def __enter__(self) -> "Cursor":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: str, parameters: tuple[object, ...] = ()) -> None:
            calls.append((query, parameters))

        def fetchone(self) -> dict[str, object]:
            query = calls[-1][0]
            if query == "show transaction_isolation":
                return {"transaction_isolation": "read committed"}
            if "select exists" in query:
                return {"present": True}
            return {"id": 23}

    class Connection:
        def __enter__(self) -> "Connection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def cursor(self) -> Cursor:
            return Cursor()

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(
        cases,
        "_case_row",
        lambda _cur, _id: {"id": 23, "events": [{"event_db_id": 3_796_849}]},
    )

    created = cases.create_case(
        title="V2 evidence",
        actor="analyst",
        event_db_id=3_796_849,
    )

    assert created["events"] == [{"event_db_id": 3_796_849}]
    assert calls[0][0] == "show transaction_isolation"
    assert calls[1][0] == "lock table investigation_events in row exclusive mode"
    validation_query, validation_parameters = calls[2]
    assert "from events_v2_core" in validation_query
    assert validation_parameters == (3_796_849,)
    evidence_insert = next(
        (query, parameters)
        for query, parameters in calls
        if "insert into investigation_events" in query
    )
    assert evidence_insert[1] == (23, 3_796_849, "analyst")


def test_investigation_creation_preserves_optional_owner(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def __enter__(self) -> "Cursor":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: str, parameters: tuple[object, ...] = ()) -> None:
            calls.append((query, parameters))

        def fetchone(self) -> dict[str, int]:
            return {"id": 17}

    class Connection:
        def __enter__(self) -> "Connection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def cursor(self) -> Cursor:
            return Cursor()

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: {"id": 17, "owner": "SOC L2"})

    created = cases.create_case(title="Проверка учётной записи", owner="  SOC L2  ", actor="analyst")

    assert created["owner"] == "SOC L2"
    public_id, title, owner, actor = calls[0][1]
    assert UUID(str(public_id))
    assert (title, owner, actor) == ("Проверка учётной записи", "SOC L2", "analyst")


def test_duplicate_evidence_is_idempotent_without_duplicate_audit(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, query, parameters=()): calls.append((query, parameters))
        def fetchone(self):
            query = calls[-1][0]
            if query == "show transaction_isolation":
                return {"transaction_isolation": "read committed"}
            if "do nothing" in query:
                return None
            if "from investigation_events" in query:
                return {"event_db_id": 42, "relation_status": "confirmed", "added_by": "first"}
            return {"present": True}

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return Cursor()

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: {"id": 7})
    monkeypatch.setattr(cases, "_event_exists", lambda _cur, _id: True)

    result = cases.add_event(investigation_id=7, event_db_id=42, actor="again")

    assert result["idempotent_replay"] is True
    assert not any("insert into investigation_audit" in query for query, _ in calls)
    assert not any("update investigations" in query for query, _ in calls)


def test_add_event_audit_types_relation_status_for_postgresql(monkeypatch) -> None:
    """A JSONB variadic value has no column context for a Python str."""
    from server.sli.semantic import investigation_cases as cases

    calls: list[tuple[str, tuple[object, ...]]] = []
    authorizations: list[object | None] = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, query, parameters=()): calls.append((query, parameters))
        def fetchone(self):
            if calls[-1][0] == "show transaction_isolation":
                return {"transaction_isolation": "read committed"}
            if "on conflict" in calls[-1][0]:
                return {"event_db_id": 42, "relation_status": "excluded", "added_by": "analyst"}
            return None

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return Cursor()

    authorization = object()
    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: {"id": 7})
    monkeypatch.setattr(
        cases,
        "_event_exists_for_route",
        lambda _cur, _id, received_authorization: authorizations.append(received_authorization) or True,
    )

    result = cases.add_event(
        investigation_id=7,
        event_db_id=42,
        actor="analyst",
        relation_status="excluded",
        authorization=authorization,
    )

    audit_query, audit_parameters = next(
        (query, parameters)
        for query, parameters in calls
        if "insert into investigation_audit" in query
    )
    assert "'relation_status', %s::text" in audit_query
    assert audit_parameters == (7, "analyst", 42, "excluded")
    assert authorizations == [authorization]
    assert result == {"event_db_id": 42, "relation_status": "excluded", "added_by": "analyst"}


def test_audit_jsonb_string_values_are_explicitly_typed_for_postgresql() -> None:
    """Every Python str inside jsonb_build_object needs a concrete SQL type."""
    import inspect

    from server.sli.semantic import investigation_cases as cases

    expected_fragments = {
        "add_event": ("'relation_status', %s::text",),
        "add_evidence_ref": (
            "'evidence_kind',%s::text",
            "'reference_id',%s::text",
            "'relation_status',%s::text",
        ),
        "assign_owner": ("'old_owner', %s::text", "'new_owner', %s::text"),
        "update_case_status": ("'old_status', %s::text", "'new_status', %s::text"),
    }

    for operation, fragments in expected_fragments.items():
        source = inspect.getsource(getattr(cases, operation))
        for fragment in fragments:
            assert fragment in source, f"{operation} must type {fragment} in audit JSONB SQL"


@pytest.mark.postgres_integration
def test_add_event_audit_payload_reaches_real_disposable_postgresql(monkeypatch) -> None:
    """Run the exact JSONB audit call through psycopg and PostgreSQL, not a fake cursor."""
    dsn = str(os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")

    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.rows import dict_row
    from tests.postgres_integration_guard import assert_disposable_database
    from server.sli.semantic import investigation_cases as cases

    schema_name = f"investigation_audit_{uuid4().hex}"
    schema = sql.Identifier(schema_name)
    try:
        with psycopg.connect(dsn, row_factory=dict_row) as setup_connection:
            assert_disposable_database(setup_connection)
            with setup_connection.cursor() as cur:
                cur.execute(sql.SQL("create schema {} ").format(schema))
                cur.execute(sql.SQL("create table {}.investigations (").format(schema) + sql.SQL(
                    "id bigint primary key, updated_at timestamptz not null default now())"
                ))
                cur.execute(sql.SQL("create table {}.investigation_events (").format(schema) + sql.SQL(
                    "investigation_id bigint not null, event_db_id bigint not null, "
                    "relation_status text not null, added_by text not null, "
                    "added_at timestamptz not null default now(), "
                    "primary key (investigation_id, event_db_id))"
                ))
                cur.execute(sql.SQL("create table {}.investigation_audit (").format(schema) + sql.SQL(
                    "investigation_id bigint not null, action text not null, actor text not null, "
                    "payload jsonb not null)"
                ))
                cur.execute(sql.SQL("insert into {}.investigations(id) values (1)").format(schema))

        def scoped_connect():
            connection = psycopg.connect(dsn, row_factory=dict_row)
            with connection.cursor() as cur:
                cur.execute(sql.SQL("set search_path to {}, pg_catalog").format(schema))
            return connection

        received_authorizations: list[object | None] = []
        authorization = object()
        monkeypatch.setattr(cases, "connect", scoped_connect)
        monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: {"id": 1})
        monkeypatch.setattr(
            cases,
            "_event_exists_for_route",
            lambda _cur, _id, received_authorization: received_authorizations.append(
                received_authorization
            ) or True,
        )

        result = cases.add_event(
            investigation_id=1,
            event_db_id=42,
            actor="analyst",
            relation_status="excluded",
            authorization=authorization,
        )

        with psycopg.connect(dsn, row_factory=dict_row) as readback_connection:
            assert_disposable_database(readback_connection)
            with readback_connection.cursor() as cur:
                cur.execute(
                    sql.SQL(
                        "select payload->>'event_db_id' as event_db_id, "
                        "payload->>'relation_status' as relation_status "
                        "from {}.investigation_audit where action='event_linked'"
                    ).format(schema)
                )
                payload = dict(cur.fetchone())

        assert result["event_db_id"] == 42
        assert result["relation_status"] == "excluded"
        assert received_authorizations == [authorization]
        assert payload == {"event_db_id": "42", "relation_status": "excluded"}
    finally:
        with psycopg.connect(dsn, autocommit=True) as cleanup_connection:
            assert_disposable_database(cleanup_connection)
            cleanup_connection.execute(sql.SQL("drop schema if exists {} cascade").format(schema))


def test_status_transition_rejects_invalid_jump_without_update(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases
    import pytest

    calls: list[str] = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, query, parameters=()): calls.append(query)

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return Cursor()

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: {"id": 7, "status": "new"})

    with pytest.raises(cases.InvestigationCaseError, match="not allowed") as caught:
        cases.update_case_status(investigation_id=7, status="confirmed", actor="analyst")

    assert caught.value.code == "conflict"
    assert not any("update investigations" in query for query in calls)


def test_remove_evidence_is_parameterized_and_audited(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, query, parameters=()): calls.append((query, parameters))
        def fetchone(self): return {"event_db_id": 42}

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return Cursor()

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: {"id": 7})

    result = cases.remove_event(investigation_id=7, event_db_id=42, actor="analyst")

    assert result == {"event_db_id": 42, "removed": True}
    delete = next((query, params) for query, params in calls if "delete from investigation_events" in query)
    assert delete[1] == (7, 42)
    assert any("event_unlinked" in query for query, _ in calls)


def test_public_uuid_migration_is_additive_and_reversible() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    forward = (root / "config/postgres_migrations/018_investigation_public_identity.sql").read_text(encoding="utf-8")
    rollback = (root / "config/postgres_migrations/018_investigation_public_identity.rollback.sql").read_text(encoding="utf-8")
    assert "add column if not exists public_id uuid" in forward
    assert "investigations_public_id_uidx" in forward
    assert "values (18, 'investigation_public_identity')" in forward
    assert "drop column if exists public_id" in rollback


def test_infosec_role_can_mutate_investigations_but_not_operations() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    source = (root / "server/api/http_server.py").read_text(encoding="utf-8")
    investigations_source = (root / "server/api/routes/investigations.py").read_text(encoding="utf-8")
    investigation_gate = investigations_source[
        investigations_source.index('if path == "/api/v1/investigations" or'):
        investigations_source.index('def _investigation_report_key')
    ]
    assert '_authorize_mutation(required_role="viewer")' in investigation_gate
    assert 'if not self._authorize_mutation():' in source


def test_case_resource_groups_resolve_server_domain_and_channel_once(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    class Cursor:
        def __init__(self): self.last_query = ""
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, query, params):
            self.last_query = query
            assert "from investigation_events linked" in query or "from investigation_evidence_refs" in query
            assert params == ([7, 8],)
        def fetchall(self):
            if "from investigation_evidence_refs" in self.last_query:
                return [{"investigation_id": 7, "source_domain_id": 2}]
            return [
                {"investigation_id": 7, "event_db_id": 41, "server_id": 3, "domain_id": 2, "channel": "Security"},
                {"investigation_id": 7, "event_db_id": 41, "server_id": 3, "domain_id": 2, "channel": "Security"},
                {"investigation_id": 8, "event_db_id": 42, "server_id": 4, "domain_id": 2, "channel": "System"},
            ]

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return Cursor()

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    result = cases.case_resource_groups_batch([8, 7])
    assert result[7][0] == [
        {"kind": "server", "id": 3},
        {"kind": "domain", "id": 2},
        {"kind": "channel", "value": "Security"},
    ]
    assert result[8][0][0] == {"kind": "server", "id": 4}
    assert result[7][-1] == [{"kind": "domain", "id": 2}]


def test_add_vpn_accounting_evidence_ref_is_exact_idempotent_and_audited(monkeypatch) -> None:
    from server.sli.semantic import investigation_cases as cases

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def execute(self, query, parameters=()): calls.append((query, parameters))
        def fetchone(self):
            query = calls[-1][0]
            if query == "show transaction_isolation":
                return {"transaction_isolation": "read committed"}
            if "select exists" in query:
                return {"present": True}
            if "returning evidence_kind" in query:
                return {
                    "evidence_kind": "vpn_accounting_session",
                    "source_domain_id": 5,
                    "reference_id": "radius-session-row:" + "a" * 64,
                    "relation_status": "confirmed",
                    "added_by": "analyst",
                }
            return None
        def __enter__(self): return self
        def __exit__(self, *_args): return None

    class Connection:
        def cursor(self): return Cursor()
        def __enter__(self): return self
        def __exit__(self, *_args): return None

    monkeypatch.setattr(cases, "connect", lambda: Connection())
    monkeypatch.setattr(cases, "_case_row", lambda _cur, _id: {"id": 7})

    result = cases.add_evidence_ref(
        investigation_id=7,
        evidence_kind="vpn_accounting_session",
        source_domain_id=5,
        reference_id="radius-session-row:" + "a" * 64,
        actor="analyst",
    )

    assert result["reference_id"] == "radius-session-row:" + "a" * 64
    assert any("from radius_vpn_session_rows_v1" in query for query, _ in calls)
    assert any("evidence_ref_linked" in query for query, _ in calls)
    assert any("update investigations" in query for query, _ in calls)


def test_add_vpn_accounting_evidence_ref_rejects_untyped_reference_before_database(monkeypatch) -> None:
    import pytest
    from server.sli.semantic import investigation_cases as cases

    monkeypatch.setattr(cases, "connect", lambda: (_ for _ in ()).throw(AssertionError("database must not be read")))
    with pytest.raises(cases.InvestigationCaseError) as caught:
        cases.add_evidence_ref(
            investigation_id=7,
            evidence_kind="windows_event",
            source_domain_id=5,
            reference_id="42",
            actor="analyst",
        )
    assert caught.value.code == "invalid_evidence_kind"


def test_vpn_accounting_evidence_route_denies_before_case_write(monkeypatch) -> None:
    from http import HTTPStatus
    from server.api.routes import investigations as routes

    class Handler:
        _principal = {"username": "analyst"}
        def _access_decision(self): return {"reports": [], "capabilities": []}
        def _read_json_body(self): return {
            "evidence_kind": "vpn_accounting_session",
            "source_domain_id": 5,
            "reference_id": "radius-session-row:" + "a" * 64,
        }
        def _send_json(self, payload, status=HTTPStatus.OK): self.sent = (payload, status)

    handler = Handler()
    monkeypatch.setattr(routes, "_require_investigation_module", lambda *_args: True)
    monkeypatch.setattr(routes, "_require_investigation_access", lambda *_args: True)
    monkeypatch.setattr(routes, "_case_resources", lambda *_args: [])
    monkeypatch.setattr(routes, "get_vpn_session_evidence", lambda *_args, **_kwargs: {"state": "not_authorized"})
    monkeypatch.setattr(
        routes,
        "add_investigation_evidence_ref",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("case write must not run")),
    )

    routes._handle_v1_investigation_evidence_ref(
        handler, "/api/v1/investigations/7/evidence-refs"
    )

    assert handler.sent[1] == HTTPStatus.NOT_FOUND
    assert handler.sent[0]["error"] == "not_found"


def test_vpn_accounting_evidence_route_persists_exact_authorized_reference(monkeypatch) -> None:
    from http import HTTPStatus
    from server.api.routes import investigations as routes

    stored: list[dict[str, object]] = []

    class Handler:
        _principal = {"username": "analyst"}
        def _access_decision(self): return {"reports": [], "capabilities": []}
        def _read_json_body(self): return {
            "evidence_kind": "vpn_accounting_session",
            "source_domain_id": 5,
            "reference_id": "radius-session-row:" + "b" * 64,
            "relation_status": "confirmed",
        }
        def _send_json(self, payload, status=HTTPStatus.OK): self.sent = (payload, status)

    handler = Handler()
    monkeypatch.setattr(routes, "_require_investigation_module", lambda *_args: True)
    monkeypatch.setattr(routes, "_require_investigation_access", lambda *_args: True)
    monkeypatch.setattr(routes, "_case_resources", lambda *_args: [])
    monkeypatch.setattr(routes, "get_vpn_session_evidence", lambda *_args, **_kwargs: {"state": "available"})
    monkeypatch.setattr(
        routes,
        "add_investigation_evidence_ref",
        lambda **kwargs: stored.append(kwargs) or kwargs,
    )

    routes._handle_v1_investigation_evidence_ref(
        handler, "/api/v1/investigations/7/evidence-refs"
    )

    assert handler.sent[1] == HTTPStatus.CREATED
    assert stored == [{
        "investigation_id": "7",
        "evidence_kind": "vpn_accounting_session",
        "source_domain_id": 5,
        "reference_id": "radius-session-row:" + "b" * 64,
        "relation_status": "confirmed",
        "actor": "analyst",
    }]


def test_case_response_hides_typed_evidence_without_vpn_evidence_right(monkeypatch) -> None:
    from server.api.routes import investigations as routes

    class Handler:
        def _access_decision(self): return {}

    monkeypatch.setattr(routes, "plugin_evidence_allowed", lambda *_args, **_kwargs: False)
    result = routes._visible_case_result(Handler(), {
        "id": 7,
        "evidence_refs": [{
            "evidence_kind": "vpn_accounting_session",
            "source_domain_id": 5,
            "reference_id": "radius-session-row:" + "c" * 64,
        }],
    })

    assert result["evidence_refs"] == []
    assert result["evidence_refs_state"] == "partially_authorized"


def test_investigation_detail_scoped_denial_after_module_pass_is_404_not_403(monkeypatch) -> None:
    """R10: once the module check passes, a resource-scoped denial (case
    exists but outside the caller's grant scope) must answer exactly like a
    missing case — 404 not_found — not the 403 required_capability/
    required_report form that would confirm the case exists."""
    from http import HTTPStatus

    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes_investigations

    access = {
        "capabilities": ["investigations.view"],
        "resource_bound_capabilities": [],
        "reports": [{
            "report_key": "investigations.workspace",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "scope": {"kind": "server", "ids": [7]},
                "allowed_actions": ["view"],
                "field_categories": ["security"],
            }],
        }],
    }

    def run(case_lookup):
        handler = object.__new__(RequestHandler)
        handler._effective_access_cache = access
        sent: list[tuple[dict, HTTPStatus]] = []
        handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
        monkeypatch.setattr(routes_investigations, "case_resource_groups", case_lookup)
        monkeypatch.setattr(routes_investigations, "get_case", lambda _id: (_ for _ in ()).throw(
            AssertionError("get_case must not run when the resource-scoped check denies")
        ))
        routes_investigations._handle_v1_investigation_case_api(handler, "/api/v1/investigations/42")
        assert len(sent) == 1
        return sent[0]

    # Case 42 exists, but its resources (server 9) are outside the caller's
    # grant scope (server 7 only) -- module check already passed.
    out_of_scope_payload, out_of_scope_status = run(lambda _id: [[{"kind": "server", "id": 9}]])
    assert out_of_scope_status == HTTPStatus.NOT_FOUND
    assert out_of_scope_payload["error"] == "not_found"
    assert "required_capability" not in out_of_scope_payload
    assert "required_report" not in out_of_scope_payload

    # Case does not exist at all.
    from server.sli.semantic.investigation_cases import InvestigationCaseError

    def missing(_id):
        raise InvestigationCaseError("not_found", "Investigation 42 was not found")

    missing_payload, missing_status = run(missing)

    assert missing_status == out_of_scope_status == HTTPStatus.NOT_FOUND
    assert missing_payload["error"] == out_of_scope_payload["error"] == "not_found"


def test_investigation_event_add_scoped_denial_with_case_and_event_is_404(monkeypatch) -> None:
    """R10 also holds for a mutation whose resource is case+event together:
    a scoped denial there must not be distinguishable from not_found either,
    proving the fix isn't tied to a single-resource-group shape."""
    from http import HTTPStatus

    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes_investigations

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {
        "capabilities": ["investigations.manage"],
        "resource_bound_capabilities": [],
        "reports": [{
            "report_key": "investigations.workspace",
            "allowed": True,
            "allowed_actions": ["start_case"],
            "grants": [{
                "scope": {"kind": "server", "ids": [7]},
                "allowed_actions": ["start_case"],
                "field_categories": ["security"],
            }],
        }],
    }
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler._read_json_body = lambda: {"event_db_id": 99, "relation_status": "confirmed"}
    monkeypatch.setattr(routes_investigations, "case_resource_groups", lambda _id: [[{"kind": "server", "id": 9}]])
    monkeypatch.setattr(routes_investigations, "event_resource_group", lambda _id: [{"kind": "server", "id": 9}])
    monkeypatch.setattr(
        routes_investigations,
        "add_investigation_event",
        lambda **_k: (_ for _ in ()).throw(AssertionError("add_event must not run when the scoped check denies")),
    )

    routes_investigations._handle_v1_investigation_event(handler, "/api/v1/investigations/42/events")

    assert len(sent) == 1
    payload, status = sent[0]
    assert status == HTTPStatus.NOT_FOUND
    assert payload["error"] == "not_found"
    assert "required_capability" not in payload
    assert "required_report" not in payload


def test_case_list_filters_each_case_by_report_and_capability_scope(monkeypatch) -> None:
    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes_investigations

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {
        "capabilities": ["investigations.view"],
        "resource_bound_capabilities": [],
        "capability_policies": [{
            "capability_key": "investigations.view",
            "effect": "deny",
            "scope": {"kind": "server", "ids": [9]},
            "valid": True,
        }],
        "reports": [{
            "report_key": "investigations.workspace",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "scope": {"kind": "server", "ids": [7, 9]},
                "allowed_actions": ["view"],
                "field_categories": ["security"],
            }],
        }],
    }
    sent: list[dict[str, object]] = []
    handler._send_json = lambda payload, _status=200: sent.append(payload)
    monkeypatch.setattr(routes_investigations, "list_cases", lambda limit=50: [
        {"id": 1, "title": "Разрешённое дело"},
        {"id": 2, "title": "Закрытое дело"},
    ])
    monkeypatch.setattr(routes_investigations, "case_resource_groups_batch", lambda _ids: {
        1: [[{"kind": "server", "id": 7}]],
        2: [[{"kind": "server", "id": 9}]],
    })

    routes_investigations._handle_v1_investigation_cases_api(handler, {})

    assert [item["id"] for item in sent[0]["items"]] == [1]
    assert sent[0]["scope_filtered"] is True
