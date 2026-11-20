from __future__ import annotations

from pathlib import Path

import pytest

from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
    issue_controller_authorization,
)


def _controller_authorization() -> CutoverAuthorization:
    return issue_controller_authorization("a" * 64)


def test_dashboard_uses_controller_route_for_v2_activity(monkeypatch) -> None:
    """A V2 activity request must query V2 even when legacy feature settings say V1."""
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.reporting import dashboard_fast

    statements: list[str] = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=()):
            statements.append(str(sql))

        def fetchall(self):
            return []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(dashboard_fast, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Connection())

    dashboard_fast.get_overview_activity(
        time_from="2026-07-17T00:00:00Z",
        time_to="2026-07-17T01:00:00Z",
        authorization=_controller_authorization(),
    )

    assert any("events_v2_core" in statement for statement in statements)
    assert all("from events e" not in statement.lower() for statement in statements)


def test_authorized_dashboard_entity_summary_uses_no_v1_links(monkeypatch) -> None:
    """The public V2 dashboard entity summary must not query V1 entity or link relations."""
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.reporting import dashboard_fast

    statements: list[str] = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=()):
            statements.append(str(sql).lower())

        def fetchone(self):
            return {"estimated_rows": 0}

        def fetchall(self):
            return []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(dashboard_fast, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Connection())

    result = dashboard_fast.get_dashboard_entity_summary(
        authorization=_controller_authorization()
    )

    assert result["dashboard_mode"] == "postgres_v2_statistics_and_sample"
    assert any("entities_v2_active" in statement for statement in statements)
    assert any("event_entity_link_blocks_v2" in statement for statement in statements)
    assert all("observed_entities" not in statement for statement in statements)


def test_authorized_event_search_never_queries_v1_rows(monkeypatch) -> None:
    """A V2-selected event handler must not read V1 before or after its V2 page."""
    from server.sli.events import event_search

    queries: list[str] = []

    def query(sql, _params, **_kwargs):
        queries.append(str(sql).lower())
        if "event_entity_links_v2" in str(sql) or "event_entity_link_blocks_v2" in str(sql):
            return []
        return [{
            "id": 17, "server": "dc1", "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_id": 4624, "event_record_id": 41, "time_created_utc": "2026-07-17T00:30:00Z",
            "time_created_local": "2026-07-17T00:30:00Z", "subject_user_name": "alice",
            "subject_domain_name": "DOMAIN", "target_user_name": "bob", "target_domain_name": "DOMAIN",
            "ip_address": None, "workstation_name": None, "logon_id": None,
            "message_text": "logon", "event_data_json": "{}",
        }]

    monkeypatch.setattr("server.sli.core.database.is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", query)

    result = event_search.get_event_search_data(
        time_from="2026-07-17T00:00:00Z",
        time_to="2026-07-17T01:00:00Z",
        limit=1,
        authorization=_controller_authorization(),
    )

    assert result["returned_count"] == 1
    assert any("from events_v2_core e" in sql for sql in queries)
    assert all("from events e" not in sql for sql in queries)


def test_v2_route_does_not_fall_back_to_sqlite_v1(monkeypatch) -> None:
    """A selected V2 route on an unsupported backend returns an error, never V1 rows."""
    from server.sli.events import event_search

    monkeypatch.setattr("server.sli.core.database.is_postgres_runtime_db", lambda: False)
    monkeypatch.setattr("server.sli.core.database.query_rows_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("V1 query must not run")),
    )

    result = event_search.get_event_search_data(
        time_from="2026-07-17T00:00:00Z",
        time_to="2026-07-17T01:00:00Z",
        authorization=_controller_authorization(),
    )

    assert result["query_status"] == "timeout"
    assert result["warning"] == "storage_v2_route_requires_postgres"


def test_authorized_recommendation_report_uses_no_v1_events_or_links(monkeypatch, tmp_path: Path) -> None:
    """The public V2 report path must not execute legacy event or relation queries."""
    from server.sli.reports import analysis

    queries: list[str] = []

    def query(sql, _params=(), **_kwargs):
        statement = str(sql).lower()
        queries.append(statement)
        return [{"count": 1}] if "count(*) as count" in statement and "group by" not in statement else []

    monkeypatch.setattr(analysis, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(analysis, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(analysis, "query_rows", query)
    monkeypatch.setattr(analysis, "_write_collector_health_static_report", lambda: tmp_path / "collector-health.html")

    report = analysis.generate_recommendation_report(
        71,
        ["dc1"],
        authorization=_controller_authorization(),
    )

    assert report.exists()
    assert any("events_v2_core" in statement for statement in queries)
    assert all("from events e" not in statement for statement in queries)
    assert all("event_entity_links" not in statement for statement in queries)


def test_authorized_event_detail_does_not_fall_back_to_v1_rows(monkeypatch) -> None:
    """The public exact-detail reader must preserve V2-only ownership after cutover."""
    from server.sli.events import event_details

    def fail_v1(*_args, **_kwargs):
        raise AssertionError("V1 detail query must not run")

    monkeypatch.setattr(event_details, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(event_details, "query_rows", fail_v1)
    monkeypatch.setattr(
        event_details,
        "_get_v2_event_detail_by_id",
        lambda _filters, **_kwargs: {"id": 17, "event_id": 4624, "time_created_utc": "2026-07-17T00:30:00Z"},
    )

    result = event_details.get_event_detail_report_data(
        event_db_id=17,
        authorization=_controller_authorization(),
    )

    assert result["total"] == 1
    assert result["items"][0]["id"] == 17


def test_authorized_event_relations_do_not_query_v1_events_or_links(monkeypatch) -> None:
    """The public V2 relations reader must use only the V2 compact relation path."""
    from server.sli.events import event_relations

    queries: list[str] = []

    def query(sql, _params, **_kwargs):
        queries.append(str(sql).lower())
        return []

    monkeypatch.setattr(event_relations, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(event_relations, "query_rows_bounded", query)

    result = event_relations.get_event_relations(
        17,
        authorization=_controller_authorization(),
    )

    assert result["items"] == []
    assert any("events_v2_core" in statement for statement in queries)
    assert all("from event_links" not in statement for statement in queries)
    assert all("from event_entity_links " not in statement for statement in queries)


def test_authorized_event_relations_split_indexed_keys_without_monolithic_or(monkeypatch) -> None:
    """Each proven V2 key must enter through its own bounded, indexable query."""
    from server.sli.events import event_relations

    calls: list[tuple[str, tuple]] = []

    def query(sql, params, **_kwargs):
        normalized = " ".join(str(sql).lower().split())
        calls.append((normalized, tuple(params)))
        if "left join event_facts_v2 base_fact" in normalized:
            return [{
                "server_id": 7,
                "time_created_utc": "2026-07-17T07:15:51Z",
                "logon_id": "0x123",
                "task_name": r"\Microsoft\Windows\Example",
            }]
        if "other_event.logon_id = ?" in normalized:
            return [{
                "related_event_db_id": 90,
                "related_event_id": 4624,
                "related_time_utc": "2026-07-17T07:15:52Z",
                "entity_type": "auth_session",
                "entity": "0x123",
                "source_role": "context",
                "related_role": "context",
                "time_delta_seconds": 1,
                "relation_rule": "same_logon_id_same_server",
            }]
        if "from event_facts_v2 other_fact" in normalized:
            return [{
                "related_event_db_id": 92,
                "related_event_id": 140,
                "related_time_utc": "2026-07-17T07:15:53Z",
                "entity_type": "scheduled_task",
                "entity": r"\Microsoft\Windows\Example",
                "source_role": "context",
                "related_role": "context",
                "time_delta_seconds": 2,
                "relation_rule": "same_task_same_server_time_window",
            }]
        return []

    monkeypatch.setattr(event_relations, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(event_relations, "query_rows_bounded", query)

    result = event_relations.get_event_relations(
        91,
        authorization=_controller_authorization(),
    )

    assert [item["related_event_db_id"] for item in result["items"]] == [90, 92]
    assert len(calls) == 3
    base_sql, base_params = calls[0]
    logon_sql, logon_params = calls[1]
    task_sql, task_params = calls[2]
    assert "where base_event.id = ?" in base_sql
    assert base_params == (91,)
    assert "other_event.logon_id = ?" in logon_sql
    assert " or (" not in logon_sql
    assert "exists (" not in logon_sql
    assert logon_params == (
        "2026-07-17T07:15:51Z", "0x123", 7, 91,
        "2026-07-17T07:15:51Z", "2026-07-17T07:15:51Z", 101,
    )
    assert "other_fact.task_name = ?" in task_sql
    assert " or (" not in task_sql
    assert "exists (" not in task_sql
    assert task_params == (
        "2026-07-17T07:15:51Z", r"\Microsoft\Windows\Example", 7, 91,
        "2026-07-17T07:15:51Z", "2026-07-17T07:15:51Z", 101,
    )


def test_authorized_event_relations_skip_unproven_v2_keys(monkeypatch) -> None:
    """Sentinel LogonId and an absent task name must not broaden correlation."""
    from server.sli.events import event_relations

    calls: list[str] = []

    def query(sql, _params, **_kwargs):
        normalized = " ".join(str(sql).lower().split())
        calls.append(normalized)
        return [{
            "server_id": 7,
            "time_created_utc": "2026-07-17T07:15:51Z",
            "logon_id": "0x0",
            "task_name": None,
        }] if "left join event_facts_v2 base_fact" in normalized else []

    monkeypatch.setattr(event_relations, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(event_relations, "query_rows_bounded", query)

    result = event_relations.get_event_relations(
        91,
        authorization=_controller_authorization(),
    )

    assert result["items"] == []
    assert len(calls) == 1


def test_authorized_event_entities_do_not_query_v1_relations(monkeypatch) -> None:
    """The public V2 entity reader must not infer evidence from V1 relations."""
    from server.sli.reporting import ui_workspace

    queries: list[str] = []

    def query(sql, _params, **_kwargs):
        queries.append(str(sql).lower())
        return [{"present": 1}] if "select 1 as present" in str(sql).lower() else []

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows_bounded", query)

    result = ui_workspace.get_event_entities_data(
        event_db_id=17,
        authorization=_controller_authorization(),
    )

    assert result["event_found"] is True
    assert any("events_v2_core" in statement for statement in queries)
    assert any("event_entity_link_blocks_v2" in statement for statement in queries)
    assert all("event_entity_links " not in statement for statement in queries)


@pytest.mark.parametrize("event_db_id", [1_906_133, 2_147_483_648, 9_223_372_036_854_775_807])
def test_event_entities_query_filters_exact_blocks_before_entity_joins(monkeypatch, event_db_id) -> None:
    """Exact membership must be resolved before joins and the active-entity guard."""
    from server.sli.reporting import ui_workspace

    queries: list[tuple[str, tuple]] = []

    def query(sql, params, **_kwargs):
        normalized = " ".join(str(sql).lower().split())
        queries.append((normalized, tuple(params)))
        return [{"present": 1}] if "select 1 as present" in normalized else []

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows_bounded", query)

    result = ui_workspace.get_event_entities_data(event_db_id=event_db_id)

    assert result["event_found"] is True
    assert result["event_db_id"] == event_db_id
    assert queries[0][1] == (event_db_id,)
    entity_query, entity_params = queries[1]
    assert "with exact_blocks as materialized" in entity_query
    assert "from event_entity_link_blocks_v2" in entity_query
    assert "join entities_v2 entity on entity.id = block.entity_id" in entity_query
    assert "entity_v2_is_active(entity.id)" in entity_query
    assert "entities_v2_active" not in entity_query
    assert "cross join lateral unnest" not in entity_query
    assert "first_event_id <= ?" in entity_query
    assert "last_event_id >= ?" in entity_query
    assert "event_ids @> array[?]::bigint[]" in entity_query
    assert "role_ids[array_position(event_ids, ?)] as role_id" in entity_query
    assert entity_params == (event_db_id, event_db_id, event_db_id, event_db_id, 30)


def test_authorized_findings_status_reads_v2_watermark_without_v1_sql(monkeypatch) -> None:
    """V2 Findings status follows canonical V2 event identities after physical V1 drop."""
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.semantic import findings_pg_pipeline

    statements = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, _params=()):
            normalized = " ".join(str(sql).lower().split())
            statements.append(normalized)
            if "from findings_refresh_state" in normalized:
                self.row = {"last_event_id": 8, "last_status": "completed"}
            elif "max(id)" in normalized:
                self.row = {"max_event_id": 10}
            else:
                self.row = {}

        def fetchone(self):
            return self.row

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", Connection)

    authorization = _controller_authorization()
    status = findings_pg_pipeline.get_findings_refresh_status(authorization=authorization)

    assert status["status"] == "ok"
    assert status["max_event_id"] == 10
    assert status["event_id_gap_estimate"] == 2
    assert any("from events_v2_core" in sql for sql in statements)
    assert all("from events " not in sql for sql in statements)


def test_authorized_findings_startup_bootstraps_from_v2_core(monkeypatch) -> None:
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.ops import postgres_schema_guard
    from server.sli.semantic import findings_pg_pipeline

    statements = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def execute(self, sql, _params=()):
            normalized = " ".join(str(sql).lower().split())
            statements.append(normalized)
            self.row = (
                {"pipeline_name": findings_pg_pipeline.PIPELINE_NAME,
                 "last_event_id": 10, "last_status": "ready"}
                if normalized.startswith("select pipeline_name") else None
            )
        def fetchone(self): return self.row

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def cursor(self): return Cursor()

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", Connection)
    monkeypatch.setattr(postgres_schema_guard, "require_table_columns", lambda *_args, **_kwargs: None)

    result = findings_pg_pipeline.ensure_findings_pg_schema(
        bootstrap_to_current=True, authorization=_controller_authorization(),
    )

    assert result["last_event_id"] == 10
    assert any("from events_v2_core" in sql for sql in statements)
    assert all("from events " not in sql for sql in statements)


def test_dashboard_snapshot_propagates_v2_authorization_to_its_consumers(monkeypatch) -> None:
    """A V2 snapshot cannot let an inner dashboard reader default back to V1."""
    from server.sli.reporting import dashboard_snapshot

    authorization = _controller_authorization()
    received: list[tuple[str, object]] = []

    monkeypatch.setattr(
        dashboard_snapshot, "get_dashboard_event_summary",
        lambda **kwargs: received.append(("events", kwargs.get("authorization"))) or {},
    )
    monkeypatch.setattr(
        dashboard_snapshot, "get_dashboard_entity_summary",
        lambda **kwargs: received.append(("entities", kwargs.get("authorization"))) or {},
    )
    monkeypatch.setattr(
        dashboard_snapshot, "get_findings_dashboard_data",
        lambda **kwargs: received.append(("findings", kwargs.get("authorization"))) or {"items": []},
    )
    monkeypatch.setattr(
        dashboard_snapshot, "get_collector_health", lambda **_kwargs: {"summary": {}, "items": []})
    monkeypatch.setattr(dashboard_snapshot, "get_sources", lambda **_kwargs: [])
    monkeypatch.setattr(dashboard_snapshot, "list_ai_runs", lambda **_kwargs: {"items": []})
    monkeypatch.setattr(dashboard_snapshot, "list_jobs", list)
    monkeypatch.setattr(dashboard_snapshot, "list_reports", list)
    monkeypatch.setattr(dashboard_snapshot, "_archive_status_payload", dict)
    monkeypatch.setattr(
        dashboard_snapshot, "get_role_views_data",
        lambda **kwargs: received.append(("roles", kwargs.get("authorization"))) or {"views": [], "summary": {}},
    )

    dashboard_snapshot.build_dashboard_snapshot(
        force=True, authorization=authorization
    )

    assert {item for item in received if item[0] in {"events", "entities", "findings", "roles"}} == {
        ("events", authorization), ("entities", authorization),
        ("findings", authorization), ("roles", authorization),
    }


def test_overview_and_warmup_keep_the_server_v2_authorization(monkeypatch) -> None:
    """Overview's activity and asynchronous warmup receive the sealed route."""
    from server.sli.reporting import dashboard_snapshot, ui_workspace

    authorization = _controller_authorization()
    overview_received: dict[str, object] = {}
    snapshot = {
        "generated_at_utc": "2026-08-21T00:00:00Z", "status": "ok", "diagnostics": {},
        "events_summary": {}, "entity_summary": {}, "findings": {"items": []},
        "role_views": {}, "sources": {"items": []}, "collector_health": {"items": []},
    }
    monkeypatch.setattr(
        ui_workspace, "build_dashboard_snapshot",
        lambda **kwargs: overview_received.update(snapshot=kwargs.get("authorization")) or snapshot,
    )
    monkeypatch.setattr(ui_workspace, "get_overview_activity", lambda **kwargs: overview_received.update(activity=kwargs.get("authorization")) or {"items": [], "available": True, "exact": True})

    ui_workspace.get_overview_workspace_data(authorization=authorization)

    started: dict[str, object] = {}

    class Thread:
        def __init__(self, *, target, args=(), kwargs=None, **_kwargs):
            started.update(target=target, args=args, kwargs=kwargs or {})

        def start(self):
            return None

    monkeypatch.setattr(dashboard_snapshot.threading, "Thread", Thread)
    assert dashboard_snapshot.warm_dashboard_snapshot_async(authorization=authorization) is True

    assert overview_received == {"snapshot": authorization, "activity": authorization}
    assert started["kwargs"] == {"authorization": authorization}


def test_authorized_investigation_workspace_propagates_v2_route_to_evidence_readers(monkeypatch) -> None:
    """An anchored V2 investigation must not drop its sealed route between evidence readers."""
    from server.sli.reporting import ui_workspace

    authorization = _controller_authorization()
    received: list[tuple[str, object]] = []
    base = {"id": 17, "event_id": 4624, "time_created_utc": "2026-07-17T00:30:00Z"}

    monkeypatch.setattr(
        ui_workspace,
        "get_event_detail_report_data",
        lambda **kwargs: received.append(("detail", kwargs.get("authorization"))) or {"items": [base]},
    )
    monkeypatch.setattr(
        ui_workspace,
        "get_event_relations",
        lambda _event_id, **kwargs: received.append(("relations", kwargs.get("authorization"))) or {"items": []},
    )
    monkeypatch.setattr(
        ui_workspace,
        "get_event_details_by_ids",
        lambda _ids, **kwargs: received.append(("batch", kwargs.get("authorization"))) or {},
    )

    result = ui_workspace.get_investigations_workspace_data(
        q="alice",
        event_db_id=17,
        authorization=authorization,
    )

    assert result["state"] == "ok"
    assert received == [
        ("detail", authorization),
        ("relations", authorization),
        ("batch", authorization),
    ]


def test_authorized_unanchored_investigation_rejects_legacy_v1_fallback(monkeypatch) -> None:
    """A V2 controller route cannot silently use the V1 unanchored workspace."""
    from server.sli.reporting import ui_workspace
    from server.sli.storage.runtime_storage import StorageRouteAuthorizationError

    monkeypatch.setattr(
        ui_workspace,
        "get_investigation_workspace_data",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("legacy V1 workspace must not run")),
    )

    with pytest.raises(
        StorageRouteAuthorizationError,
        match="storage_v2_investigation_requires_exact_event_id",
    ):
        ui_workspace.get_investigations_workspace_data(
            q="alice",
            authorization=_controller_authorization(),
        )


def test_events_api_passes_only_server_owned_route_authorization(monkeypatch) -> None:
    """A query string cannot choose storage; only the handler-owned sealed value reaches consumers."""
    from server.api.routes import events

    authorization = _controller_authorization()
    received: dict[str, object] = {}

    class Handler:
        storage_route_authorization = authorization

        def _send_json(self, payload, *_args):
            received["payload"] = payload

    def search(**kwargs):
        received["authorization"] = kwargs.get("authorization")
        return {"items": [], "query_status": "ok"}

    monkeypatch.setattr(events, "get_event_search_data", search)

    events._handle_event_search_api(Handler(), {"route": ["v2"]})

    assert received["authorization"] is authorization
    assert received["payload"] == {"items": [], "query_status": "ok"}


def test_event_detail_api_passes_only_server_owned_route_authorization(monkeypatch) -> None:
    """The public event-detail API must pass the sealed route to its reader."""
    from server.api.routes import events

    authorization = _controller_authorization()
    received: dict[str, object] = {}

    class Handler:
        storage_route_authorization = authorization

        def _send_json(self, payload, *_args):
            received["payload"] = payload

    def details(**kwargs):
        received["authorization"] = kwargs.get("authorization")
        return {"items": [], "total": 0}

    monkeypatch.setattr(events, "get_event_detail_report_data", details)

    events._handle_event_details_api(Handler(), {})

    assert received["authorization"] is authorization
    assert received["payload"] == {"items": [], "total": 0}


def test_events_api_rejects_invalid_transition_authority(monkeypatch) -> None:
    """Invalid server authority must not degrade an events route to V1."""
    from server.api.routes import events
    from server.sli.storage.runtime_storage import StorageRouteAuthorizationError

    monkeypatch.setattr(
        events,
        "get_event_search_data",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("legacy V1 events read must not run")),
    )

    handler = type("Handler", (), {"storage_route_authorization": object()})()
    with pytest.raises(StorageRouteAuthorizationError, match="storage_transition_authorization_invalid"):
        events._handle_event_search_api(handler, {})


def test_event_relation_and_entity_apis_pass_only_server_owned_route(monkeypatch) -> None:
    """Relations and entities must receive the sealed server capability, never query input."""
    from server.api.routes import events

    authorization = _controller_authorization()
    received: list[tuple[str, object]] = []

    class Handler:
        storage_route_authorization = authorization

        def _send_json(self, payload, *_args):
            received.append(("payload", payload))

    monkeypatch.setattr(
        "server.sli.events.event_relations.get_event_relations",
        lambda _event_id, **kwargs: received.append(("relations", kwargs.get("authorization"))) or {"items": []},
    )
    monkeypatch.setattr(
        events,
        "get_event_entities_data",
        lambda **kwargs: received.append(("entities", kwargs.get("authorization"))) or {"event_db_id": 17, "event_found": True, "items": [], "limit": 30, "evidence_status": "zero_extracted"},
    )

    handler = Handler()
    events._handle_event_relations_api(handler, "/api/v1/events/17/relations")
    events._handle_event_entities_api(handler, "/api/v1/events/17/entities")

    assert ("relations", authorization) in received
    assert ("entities", authorization) in received


def test_investigations_api_passes_only_server_owned_route_authorization(monkeypatch) -> None:
    """The workspace endpoint must forward the sealed capability, not accept route input."""
    from server.api.routes import investigations

    authorization = _controller_authorization()
    received: dict[str, object] = {}

    class Handler:
        storage_route_authorization = authorization

        def _send_json(self, payload, *_args):
            received["payload"] = payload

    def workspace(**kwargs):
        received["authorization"] = kwargs.get("authorization")
        return {
            "query": "", "anchor_event_db_id": None, "scope": "important", "state": "query_required",
            "summary": {
                "events_returned": 0, "has_more": False, "attention_level": "unknown",
                "story": "", "why_it_matters": "",
            },
            "timeline": [], "findings": [], "next_checks": [], "limits": {},
        }

    monkeypatch.setattr(investigations, "_require_investigation_access", lambda *_args: True)
    monkeypatch.setattr(investigations, "get_investigations_workspace_data", workspace)

    investigations._handle_v1_investigations_api(Handler(), {"route": ["v1"]})

    assert received["authorization"] is authorization


def test_investigations_api_rejects_invalid_transition_authority_without_v1_fallback(monkeypatch) -> None:
    """A malformed server transition value must stop the workspace before any V1 read."""
    from server.api.routes import investigations

    received: dict[str, object] = {}

    class Handler:
        storage_route_authorization = object()

        def _send_json(self, payload, status=None):
            received["payload"] = payload
            received["status"] = status

    monkeypatch.setattr(investigations, "_require_investigation_access", lambda *_args: True)
    monkeypatch.setattr(
        investigations,
        "get_investigations_workspace_data",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("V1 fallback must not run")),
    )

    investigations._handle_v1_investigations_api(Handler(), {})

    assert received["payload"] == {"error": "storage_transition_authorization_invalid"}
    assert received["status"] is not None


def test_investigations_workspace_passes_its_consumer_through_evidence_readers(monkeypatch) -> None:
    """Nested readers must not substitute their own consumer ID."""
    from server.sli.reporting import ui_workspace

    authorization = _controller_authorization()
    received: dict[str, object] = {}
    monkeypatch.setattr(
        ui_workspace,
        "get_event_detail_report_data",
        lambda **kwargs: received.update(kwargs) or {"items": []},
    )

    result = ui_workspace.get_investigations_workspace_data(
        q="", event_db_id=17, authorization=authorization,
    )

    assert result["state"] == "empty"
    assert received["consumer"] == "investigations"
