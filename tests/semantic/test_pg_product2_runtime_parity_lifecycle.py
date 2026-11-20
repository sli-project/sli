from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


class _FakeFindingsPg:
    """In-memory PostgreSQL stand-in for the findings lifecycle SQL (findings + finding_status_history)."""

    def __init__(self) -> None:
        self.finding = {
            "id": 1, "status": "new", "assigned_to": None, "status_reason": None,
            "closed_at": None, "updated_at": datetime.now(timezone.utc),
        }
        self.history: list[dict[str, Any]] = []

    def install(self, monkeypatch) -> None:
        from server.sli.semantic import findings
        from server.sli.core import postgres_runtime_pipeline

        fake = self

        class Cursor:
            row: dict[str, Any] | None = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
                normalized = " ".join(sql.split()).lower()
                self.row = None
                if normalized.startswith("select * from findings"):
                    self.row = dict(fake.finding)
                elif normalized.startswith("update findings"):
                    status, assigned_to, reason, closed_at, _fid = params
                    fake.finding.update(status=status, assigned_to=assigned_to, status_reason=reason, closed_at=closed_at)
                    self.row = dict(fake.finding)
                elif normalized.startswith("insert into finding_status_history"):
                    _fid, old, new, by, note = params
                    fake.history.insert(0, {"old_status": old, "new_status": new, "changed_by": by, "note": note})
                else:
                    raise AssertionError(f"unexpected SQL: {normalized}")

            def fetchone(self):
                return self.row

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def cursor(self):
                return Cursor()

        monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
        monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Connection())
        monkeypatch.setattr(findings, "query_rows", lambda *a, **k: [dict(item) for item in fake.history])


def test_findings_lifecycle_is_audited_and_validated(monkeypatch) -> None:
    from server.sli.semantic.findings import FindingLifecycleError, get_finding_status_history, update_finding_lifecycle

    fake = _FakeFindingsPg()
    fake.install(monkeypatch)

    result = update_finding_lifecycle(
        1,
        new_status="review",
        changed_by="security.operator",
        note="manual triage",
        assigned_to="soc-team",
        status_reason="needs evidence review",
    )
    assert result["status"] == "ok"
    assert result["changed"] is True
    assert result["finding"]["status"] == "review"
    assert result["finding"]["assigned_to"] == "soc-team"
    history = get_finding_status_history(1)
    assert history[0]["old_status"] == "new"
    assert history[0]["new_status"] == "review"
    assert history[0]["changed_by"] == "security.operator"

    with pytest.raises(FindingLifecycleError) as exc:
        update_finding_lifecycle(1, new_status="repeated", changed_by="fixture-operator")
    assert exc.value.code == "invalid_transition"

    closed = update_finding_lifecycle(1, new_status="closed", changed_by="security.operator", note="fixture resolution")
    assert closed["finding"]["closed_at"]
    reopened = update_finding_lifecycle(1, new_status="active", changed_by="security.operator", note="fixture new evidence")
    assert reopened["finding"]["closed_at"] is None


def test_findings_lifecycle_requires_postgres(monkeypatch, tmp_path: Path) -> None:
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: False)
    with pytest.raises(RuntimeError, match="PostgreSQL-only"):
        findings.update_finding_lifecycle(1, new_status="review", changed_by="fixture-operator")


def test_findings_lifecycle_postgres_does_not_open_sqlite(monkeypatch) -> None:
    from server.sli.semantic import findings
    from server.sli.core import postgres_runtime_pipeline

    class Cursor:
        def __init__(self) -> None:
            self.row: dict[str, Any] | None = None
            self.executed: list[str] = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            normalized = " ".join(sql.split()).lower()
            self.executed.append(normalized)
            if normalized.startswith("select * from findings"):
                self.row = {"id": 7, "status": "new", "assigned_to": None, "status_reason": None}
            elif "update findings" in normalized and "returning" in normalized:
                self.row = {
                    "id": 7,
                    "status": "review",
                    "assigned_to": "soc",
                    "status_reason": "triage",
                    "closed_at": None,
                    "updated_at": datetime.now(timezone.utc),
                }
            else:
                self.row = None

        def fetchone(self):
            return self.row

    class Connection:
        def __init__(self, cursor: Cursor) -> None:
            self._cursor = cursor

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def cursor(self):
            return self._cursor

    cursor = Cursor()
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    assert not hasattr(findings, "sqlite3")
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Connection(cursor))
    monkeypatch.setattr(
        findings,
        "get_finding_status_history",
        lambda *a, **k: [{"old_status": "new", "new_status": "review", "changed_by": "operator"}],
    )

    result = findings.update_finding_lifecycle(7, new_status="review", changed_by="fixture-operator", assigned_to="soc", status_reason="triage")
    assert result["backend"] == "postgres"
    assert result["finding"]["status"] == "review"
    assert isinstance(result["finding"]["updated_at"], str)
    assert any("insert into finding_status_history" in sql for sql in cursor.executed)


def test_ai_reports_use_postgres_runtime_without_sqlite(monkeypatch, tmp_path: Path) -> None:
    from server.sli.ai import ai_reports
    from server.sli.core import postgres_runtime_pipeline

    class Cursor:
        def __init__(self) -> None:
            self.row = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            assert "insert into ai_api_runs" in " ".join(sql.split()).lower()
            assert params[10] is True
            self.row = {"id": 42}

        def fetchone(self):
            return self.row

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def cursor(self):
            return Cursor()

    now = datetime.now(timezone.utc)
    rows = [{
        "id": 42,
        "provider": "openai_api",
        "model": "gpt-test",
        "prompt_version": "v1",
        "redaction_level": "strict",
        "status": "completed",
        "query_summary_json": "{}",
        "prompt_file_path": None,
        "request_file_path": None,
        "result_file_path": None,
        "report_file_path": None,
        "ai_call_performed": True,
        "validation_errors_json": "[]",
        "created_at": now,
        "completed_at": now,
    }]

    monkeypatch.setattr(ai_reports, "is_postgres_runtime_db", lambda: True)
    assert not hasattr(ai_reports, "sqlite3")
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Connection())
    monkeypatch.setattr(ai_reports, "query_rows", lambda *a, **k: [dict(rows[0])])

    run_id = ai_reports.record_ai_run(
        {"provider": "openai_api", "model": "gpt-test", "prompt_version": "v1", "redaction_level": "strict"},
        {"status": "completed", "ai_call_performed": True, "validation_errors": []},
        {},
    )
    assert run_id == 42
    listed = ai_reports.list_ai_runs()
    assert listed["items"][0]["created_at"] == now.isoformat()
    detail = ai_reports.get_ai_run(run_id=42)
    assert detail and detail["completed_at"] == now.isoformat()
    json.dumps(detail)


def test_ai_reports_require_postgres(monkeypatch, tmp_path: Path) -> None:
    from server.sli.ai import ai_reports

    monkeypatch.setattr(ai_reports, "is_postgres_runtime_db", lambda: False)
    with pytest.raises(RuntimeError, match="PostgreSQL-only"):
        ai_reports.record_ai_run({}, {}, {})
    with pytest.raises(RuntimeError, match="PostgreSQL-only"):
        ai_reports.list_ai_runs()
    with pytest.raises(RuntimeError, match="PostgreSQL-only"):
        ai_reports.get_ai_run(run_id=1)


def test_investigation_exposes_data_quality_boundaries(monkeypatch) -> None:
    from server.sli.semantic import investigation

    monkeypatch.setattr(
        investigation,
        "get_event_search_data",
        lambda **kwargs: {"total": 25, "items": [{"event_id": 4624, "time_created_utc": "2026-07-10T00:00:00Z"}] * 10},
    )
    monkeypatch.setattr(
        investigation,
        "get_findings_data",
        lambda **kwargs: {"backend": "postgres", "items": [{"id": 1}], "summary": []},
    )
    data = investigation.get_investigation_workspace_data(q="user", limit=10, scope="important")
    quality = data["data_quality"]
    assert quality["backend"] == "postgres"
    assert quality["evidence_policy"] == "evidence-first"
    assert quality["truncated"] is True
    assert len(quality["limitations"]) >= 2
    assert "Качество и границы данных" in investigation.render_investigation_workspace_report(data)


def test_postgres_operations_metrics_are_read_only(monkeypatch) -> None:
    from server.sli.ops import postgres_operations
    from server.sli.core import postgres_runtime_pipeline

    class Cursor:
        def __init__(self) -> None:
            self.rows: list[dict[str, Any]] = []
            self.one: dict[str, Any] | None = None
            self.sql: list[str] = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            normalized = " ".join(sql.split()).lower()
            self.sql.append(normalized)
            if "pg_database_size" in normalized:
                self.one = {"database_name": "adlog_reports", "database_bytes": 1024**3, "checked_at": datetime.now(timezone.utc)}
                self.rows = []
            elif "from pg_stat_user_tables" in normalized:
                self.one = None
                self.rows = [{"table_name": "events", "live_rows": 1000, "dead_rows": 10, "total_bytes": 2048, "last_analyze": None, "last_autoanalyze": None, "last_vacuum": None, "last_autovacuum": None}]
            elif "from pg_stat_activity" in normalized:
                self.one = None
                self.rows = []

        def fetchone(self):
            return self.one

        def fetchall(self):
            return self.rows

    class Connection:
        def __init__(self, cursor: Cursor) -> None:
            self._cursor = cursor

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def cursor(self):
            return self._cursor

    cursor = Cursor()
    monkeypatch.setattr(postgres_operations, "active_backend", lambda: "postgres")
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Connection(cursor))
    result = postgres_operations.get_postgres_operations_status()
    assert result["status"] == "ok"
    assert result["database"]["database_human"] == "1.0 GB"
    assert result["tables"][0]["table_name"] == "events"
    assert result["safety"]["vacuum_executed"] is False
    assert not any(sql.startswith("vacuum") or sql.startswith("analyze") for sql in cursor.sql)


def test_storage_report_includes_postgres_operations() -> None:
    from server.sli.storage.storage_health import render_storage_health_report

    html = render_storage_health_report({
        "status": "ok",
        "generated_at_utc": "2026-07-10T00:00:00Z",
        "sizes": {},
        "policy": {},
        "disk_pressure": {"disk": {}, "collection_allowed": True},
        "cleanup_preview": {},
        "capacity_plan": {},
        "warnings": [],
        "operator_guidance": [],
        "postgres_operations": {
            "status": "ok",
            "database": {"database_name": "adlog_reports", "database_human": "1.0 GB"},
            "tables": [{"table_name": "events", "total_human": "900 MB", "live_rows": 10, "dead_rows": 1, "dead_row_ratio": 0.09}],
            "long_running_queries": [],
        },
    })
    assert "PostgreSQL operations" in html
    assert "adlog_reports" in html
    assert "VACUUM/ANALYZE" in html


def test_pg_runtime_parity_audit_is_clean() -> None:
    from server.sli.ops.runtime_parity import audit_pg_runtime_parity

    result = audit_pg_runtime_parity(Path.cwd())
    assert result["status"] == "ok", result["failures"]
    assert result["failures"] == []


def test_http_server_exposes_finding_lifecycle_endpoint() -> None:
    source = Path("server/api/routes/findings.py").read_text(encoding="utf-8")
    assert 'path.startswith("/api/findings/") and path.endswith("/status")' in source
    assert "update_finding_lifecycle" in source


def test_findings_same_status_preserves_existing_assignment(monkeypatch) -> None:
    from server.sli.semantic.findings import update_finding_lifecycle

    _FakeFindingsPg().install(monkeypatch)
    update_finding_lifecycle(
        1,
        new_status="review",
        assigned_to="soc-team",
        status_reason="initial triage",
        changed_by="fixture-operator",
    )
    unchanged = update_finding_lifecycle(1, new_status="review", changed_by="fixture-operator")
    assert unchanged["changed"] is False
    assert unchanged["finding"]["assigned_to"] == "soc-team"
    assert unchanged["finding"]["status_reason"] == "initial triage"


def test_findings_same_status_records_case_note_and_assignment(monkeypatch) -> None:
    from server.sli.semantic.findings import update_finding_lifecycle

    _FakeFindingsPg().install(monkeypatch)
    result = update_finding_lifecycle(
        1,
        new_status="new",
        assigned_to="soc-team",
        note="Передано дежурной смене",
        changed_by="analyst",
    )
    assert result["changed"] is False
    assert result["finding"]["assigned_to"] == "soc-team"
    assert result["finding"]["status_history"][0]["changed_by"] == "analyst"
    assert result["finding"]["status_history"][0]["note"] == "Передано дежурной смене"


@pytest.mark.parametrize("assignment, expected_owner, history_count", [
    ({}, "fixture-team", 0),
    ({"assigned_to": None}, None, 1),
    ({"assigned_to": ""}, None, 1),
    ({"assigned_to": " fixture-other-team "}, "fixture-other-team", 1),
])
def test_finding_status_http_handler_preserves_or_clears_assignment(
    monkeypatch, assignment, expected_owner, history_count,
) -> None:
    from server.api.routes import findings as routes_findings

    fake = _FakeFindingsPg()
    fake.finding.update(assigned_to="fixture-team", status_reason="fixture reason")
    fake.install(monkeypatch)
    captured: dict[str, Any] = {}
    handler = SimpleNamespace(
        _principal={"username": "fixture-operator"},
        _authorize_mutation=lambda: True,
        _require_capability=lambda capability: capability == "investigations.manage",
        _read_json_body=lambda: {"status": "new", **({"status_reason": "fixture reason"} if assignment else {}), **assignment},
        _send_json=lambda payload, status: captured.update(payload=payload, status=status),
    )

    assert routes_findings.try_handle_post(handler, "/api/findings/1/status")
    assert captured["status"] == 200
    finding = captured["payload"]["finding"]
    assert finding["assigned_to"] == expected_owner
    assert finding["status_reason"] == "fixture reason"
    assert len(finding["status_history"]) == history_count
    if history_count:
        assert finding["status_history"][0]["old_status"] == "new"
        assert finding["status_history"][0]["new_status"] == "new"
        assert finding["status_history"][0]["changed_by"] == "fixture-operator"


@pytest.mark.parametrize("note, expected_note", [
    (None, "updated fixture reason"),
    ("fixture comment", "fixture comment"),
])
def test_findings_reason_change_is_audited_without_status_change(monkeypatch, note, expected_note) -> None:
    from server.sli.semantic.findings import update_finding_lifecycle

    fake = _FakeFindingsPg()
    fake.finding.update(status="review", assigned_to="fixture-team", status_reason="initial fixture reason")
    fake.install(monkeypatch)

    result = update_finding_lifecycle(
        1, new_status="review", status_reason=" updated fixture reason ",
        changed_by="fixture-operator", note=note,
    )
    assert result["finding"]["status_reason"] == "updated fixture reason"
    assert result["finding"]["assigned_to"] == "fixture-team"
    assert result["finding"]["status_history"] == [{
        "old_status": "review", "new_status": "review",
        "changed_by": "fixture-operator", "note": expected_note,
    }]

    unchanged = update_finding_lifecycle(1, new_status="review", changed_by="fixture-operator", status_reason="updated fixture reason")
    assert unchanged["finding"]["status_history"] == result["finding"]["status_history"]


def test_postgres_operations_redacts_query_literals(monkeypatch) -> None:
    from server.sli.ops import postgres_operations
    from server.sli.core import postgres_runtime_pipeline

    class Cursor:
        def __init__(self) -> None:
            self.mode = ""

        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False

        def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            normalized = " ".join(sql.split()).lower()
            if "pg_database_size" in normalized:
                self.mode = "database"
            elif "pg_stat_user_tables" in normalized:
                self.mode = "tables"
            elif "pg_stat_activity" in normalized:
                self.mode = "activity"

        def fetchone(self):
            if self.mode == "database":
                return {"database_name": "adlog_reports", "database_bytes": 1, "checked_at": datetime.now(timezone.utc)}
            return None

        def fetchall(self):
            if self.mode == "tables":
                return []
            if self.mode == "activity":
                return [{"pid": 1, "user_name": "u", "duration_seconds": 120, "query_preview": "select * from events where target_user_name='secret-user' and event_record_id=123456789"}]
            return []

    class Connection:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
        def cursor(self): return Cursor()

    monkeypatch.setattr(postgres_operations, "active_backend", lambda: "postgres")
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Connection())
    result = postgres_operations.get_postgres_operations_status()
    preview = result["long_running_queries"][0]["query_preview"]
    assert "secret-user" not in preview
    assert "123456789" not in preview
    assert "<redacted>" in preview
    assert "<number>" in preview


def test_finding_status_http_handler_maps_lifecycle_errors(monkeypatch) -> None:
    from http import HTTPStatus
    from server.api.routes import findings as routes_findings
    from server.sli.semantic.findings import FindingLifecycleError

    handler = SimpleNamespace()
    handler._read_json_body = lambda: {"status": "repeated"}
    captured: dict[str, Any] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    monkeypatch.setattr(
        routes_findings,
        "update_finding_lifecycle",
        lambda *a, **k: (_ for _ in ()).throw(FindingLifecycleError("invalid_transition", "not allowed")),
    )
    routes_findings._handle_finding_status_update(handler, "/api/findings/7/status")
    assert captured["status"] == HTTPStatus.CONFLICT
    assert captured["payload"]["error"] == "invalid_transition"


def test_finding_status_http_handler_uses_authenticated_principal(monkeypatch) -> None:
    from server.api.routes import findings as routes_findings

    handler = SimpleNamespace()
    handler._principal = {"username": "trusted.operator", "role": "operator"}
    handler._read_json_body = lambda: {"status": "review", "changed_by": "spoofed"}
    handler._send_json = lambda *a, **k: None
    captured: dict[str, Any] = {}
    monkeypatch.setattr(routes_findings, "update_finding_lifecycle", lambda *a, **k: captured.update(k) or {"status": "ok"})

    routes_findings._handle_finding_status_update(handler, "/api/findings/7/status")

    assert captured["changed_by"] == "trusted.operator"


def test_exact_event_api_returns_one_evidence_item(monkeypatch) -> None:
    from http import HTTPStatus
    from server.api.routes import events as routes_events

    handler = SimpleNamespace()
    captured: dict[str, Any] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    handler._require_capability = lambda capability: capability == "evidence.exact"
    monkeypatch.setattr(
        routes_events,
        "get_event_detail_report_data",
        lambda **filters: {"items": [{"event_db_id": filters["event_db_id"], "event_id": 140}]},
    )

    routes_events._handle_event_by_id_api(handler, "/api/v1/events/42")

    assert captured["status"] == HTTPStatus.OK
    assert captured["payload"]["api_version"] == "v1"
    assert captured["payload"]["item"]["event_db_id"] == 42
    assert captured["payload"]["item"]["event_id"] == 140
    assert captured["payload"]["item"]["semantics"]["title"] == "Событие пока не расшифровано каталогом"


def test_exact_event_api_rejects_non_numeric_identifier() -> None:
    from http import HTTPStatus
    from server.api.routes import events as routes_events

    handler = SimpleNamespace()
    captured: dict[str, Any] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    handler._require_capability = lambda capability: capability == "evidence.exact"

    routes_events._handle_event_by_id_api(handler, "/api/v1/events/not-an-id")

    assert captured["status"] == HTTPStatus.BAD_REQUEST
    assert captured["payload"] == {"error": "invalid_event_db_id"}


def test_event_relations_api_uses_exact_event_identifier(monkeypatch) -> None:
    from http import HTTPStatus
    from server.api.routes import events as routes_events
    from server.sli.events import event_relations

    handler = SimpleNamespace()
    captured: dict[str, Any] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    monkeypatch.setattr(event_relations, "get_event_relations", lambda event_db_id: {"event_db_id": event_db_id, "items": []})

    routes_events._handle_event_relations_api(handler, "/api/v1/events/42/relations")

    assert captured["status"] == HTTPStatus.OK
    assert captured["payload"] == {"event_db_id": 42, "items": []}


def test_v1_events_api_exposes_bounded_cursor_contract(monkeypatch) -> None:
    from http import HTTPStatus
    from server.api.routes import events as routes_events

    handler = SimpleNamespace()
    captured: dict[str, Any] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    monkeypatch.setattr(routes_events, "_event_search_filters", lambda _query: {"limit": 50})
    monkeypatch.setattr(
        routes_events,
        "get_event_search_data",
        lambda **_filters: {
            "items": [{"id": 42, "event_id": 140, "time_created_utc": "2026-07-16T00:00:00Z", "server": "DC1", "channel": "TaskScheduler", "provider_name": "Microsoft-Windows-TaskScheduler"}],
            "next_cursor": "opaque-cursor",
            "has_more": True,
            "query_status": "ok",
            "warning": None,
        },
    )
    monkeypatch.setattr(routes_events, "get_event_category_counts", lambda **_filters: {})

    routes_events._handle_v1_events_api(handler, {})

    assert captured["status"] == HTTPStatus.OK
    assert captured["payload"]["api_version"] == "v1"
    assert captured["payload"]["items"][0]["event_db_id"] == 42
    assert captured["payload"]["next_cursor"] == "opaque-cursor"


def test_ui_bootstrap_api_exposes_feature_flag_and_navigation(monkeypatch) -> None:
    from http import HTTPStatus
    from server.api import http_server
    from server.api.routes import workspace as routes_workspace

    handler = object.__new__(http_server.RequestHandler)
    captured: dict[str, Any] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    monkeypatch.setattr(routes_workspace, "auth_required", lambda: False)
    monkeypatch.setattr(http_server, "effective_access", lambda _principal: {
        "navigation": [
            {"id": "workspace", "label": "Рабочее пространство", "path": "/"},
            {"id": "events", "label": "События", "path": "/events"},
            {"id": "operations", "label": "Эксплуатация", "path": "/operations"},
        ],
        "capabilities": ["workspace.view", "events.view", "operations.view"],
        "packages": [{"key": "project_operations", "name": "Проект · эксплуатация"}],
        "allowed_report_count": 1,
    })

    routes_workspace._handle_ui_bootstrap_api(handler)

    assert captured["status"] == HTTPStatus.OK
    assert "ui_mode" not in captured["payload"]
    assert captured["payload"]["effective_role"] == "operator"
    assert {item["id"] for item in captured["payload"]["navigation"]} >= {"workspace", "events", "operations"}
    assert next(item for item in captured["payload"]["navigation"] if item["id"] == "events")["path"] == "/events"


@pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
def test_ui_bootstrap_preserves_authenticated_effective_role(monkeypatch, role: str) -> None:
    from http import HTTPStatus
    from server.api import http_server
    from server.api.routes import workspace as routes_workspace

    handler = object.__new__(http_server.RequestHandler)
    handler._principal = {"type": "session", "id": 1, "username": "user", "role": role}
    captured: dict[str, Any] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    monkeypatch.setattr(routes_workspace, "auth_required", lambda: True)
    monkeypatch.setattr(http_server, "effective_access", lambda _principal: {
        "navigation": [{"id": "workspace", "label": "Рабочее пространство", "path": "/"}],
        "capabilities": ["workspace.view"], "packages": [], "allowed_report_count": 0,
    })

    routes_workspace._handle_ui_bootstrap_api(handler)

    assert captured["payload"]["effective_role"] == role
    assert captured["payload"]["principal"]["role"] == role


def test_operations_v1_route_is_operator_only() -> None:
    from server.api.http_server import _required_read_role

    assert _required_read_role("/api/v1/operations/overview") == "operator"


def test_release_check_contains_pg_runtime_parity_gate() -> None:
    source = Path("scripts/maintenance/release_check.py").read_text(encoding="utf-8")
    assert "audit_pg_runtime_parity" in source
    assert 'durations["pg_runtime_parity_audit"]' in source
    assert '"pg_runtime_parity_audit": pg_runtime_parity_result' in source
