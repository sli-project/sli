from __future__ import annotations

import io
from http import HTTPStatus
from types import SimpleNamespace

import pytest

from server.sli.reporting import reporting_v4
from server.api import http_server
from server.api.routes import reports as routes_reports


def _events_access(*, capabilities: list[str] | None = None, actions: list[str] | None = None) -> dict[str, object]:
    allowed_actions = actions or ["view"]
    return {
        "capabilities": capabilities or [],
        "reports": [{
            "report_key": "events.test", "version": 1, "allowed": True,
            "allowed_actions": allowed_actions,
            "grants": [{
                "scope": {"kind": "channel", "values": ["Security"]},
                "field_categories": ["security", "technical", "raw_evidence"],
                "allowed_actions": allowed_actions,
            }],
        }],
    }


def _patch_definition(
    monkeypatch: pytest.MonkeyPatch,
    definition_json: dict[str, object],
    *,
    dataset_key: str = "events.v2",
    fields_json: list[dict[str, object]] | None = None,
) -> None:
    class Cursor:
        def execute(self, _query: str, _params: tuple[object, ...]) -> None:
            return None

        def fetchone(self) -> dict[str, object]:
            return {
                "dataset_key": dataset_key,
                "definition_json": definition_json,
                "fields_json": fields_json or [
                    {"key": "id", "label": "ID", "category": "raw_evidence"},
                    {"key": "time_created_utc", "label": "UTC", "category": "security"},
                    {"key": "event_id", "label": "Event ID", "category": "security"},
                    {"key": "channel", "label": "Канал", "category": "technical"},
                ],
            }

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

    monkeypatch.setattr(reporting_v4, "_connect", lambda: Connection())


def _privileged_access(field_categories: list[str]) -> dict[str, object]:
    return {
        "capabilities": [],
        "reports": [{
            "report_key": "events.test", "version": 1, "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "scope": {"kind": "domain", "ids": [7]},
                "field_categories": field_categories,
                "allowed_actions": ["view"],
            }],
        }],
    }


def _security_queue_access() -> dict[str, object]:
    return {
        "capabilities": [],
        "reports": [{
            "report_key": "events.test",
            "version": 1,
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "scope": {"kind": "all"},
                "field_categories": ["security"],
                "allowed_actions": ["view"],
            }],
        }],
    }


def test_security_queue_alias_matches_server_owned_filter_and_sort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fields = [
        {"key": "title", "label": "Проблема", "category": "security"},
        {"key": "severity", "label": "Важность", "category": "security"},
        {"key": "status", "label": "Статус", "category": "security"},
        {"key": "evidence_event_id", "label": "Событие", "category": "security"},
    ]
    _patch_definition(
        monkeypatch,
        {
            "columns": [item["key"] for item in fields],
            "filters": [{"field": "severity", "op": "eq", "value": "high"}],
            "default_sort": [],
            "actions": ["view"],
        },
        dataset_key="security.problems",
        fields_json=fields,
    )
    calls: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(
        reporting_v4,
        "query_rows_bounded",
        lambda sql, params=(), **_kwargs: (
            calls.append((sql, params))
            or ([{"total_items": 0}] if "count(*)" in sql else [])
        ),
    )

    reporting_v4.execute_report(
        "events.test",
        None,
        access=_security_queue_access(),
    )

    assert len(calls) == 2
    for sql, _params in calls:
        assert "from findings_active findings" in sql
        assert "findings.severity" in sql
    assert "order by findings.id desc" in calls[0][0]


def test_unhandled_get_failure_writes_internal_trace_id_without_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = object.__new__(http_server.RequestHandler)
    handler.path = "/api/v1/reports/security.queue/data?q=secret"
    handler._admit_request = lambda: True
    handler._do_GET = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    sent: list[tuple[dict[str, object], HTTPStatus]] = []
    handler._send_json = (
        lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    )
    released: list[bool] = []
    handler.server = SimpleNamespace(
        request_slots=SimpleNamespace(release=lambda: released.append(True))
    )
    captured: dict[str, object] = {}

    def log_error(*_args, **kwargs):
        captured.update(kwargs)
        return "INT-TEST"

    monkeypatch.setattr(http_server, "log_internal_error", log_error)
    handler.do_GET()

    assert captured["path"] == "/api/v1/reports/security.queue/data"
    assert isinstance(captured["exc"], RuntimeError)
    assert sent == [(
        {"error": "internal_server_error", "internal_error_id": "INT-TEST"},
        HTTPStatus.INTERNAL_SERVER_ERROR,
    )]
    assert released == [True]


def test_report_executor_applies_stored_filters_sort_and_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_definition(monkeypatch, {
        "columns": ["id", "time_created_utc", "event_id", "channel"],
        "filters": [
            {"field": "event_id", "op": "in", "value": "4624, 4625"},
            {"field": "time_created_utc", "op": "gte", "value": "2026-07-20T00:00:00Z"},
        ],
        "sort": [{"field": "time_created_utc", "direction": "asc"}],
        "actions": ["view"],
    })
    calls: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(
        reporting_v4, "query_rows_bounded",
        lambda sql, params=(), **_kwargs: calls.append((sql, params)) or [{"id": 7, "event_id": 4624, "channel": "Security", "time_created_utc": "2026-07-20T01:00:00Z"}],
    )

    result = reporting_v4.execute_report("events.test", None, access=_events_access())

    sql, params = calls[-1]
    assert "channel.value=any(?)" in sql
    assert "event.event_id=any(?)" in sql
    assert "event.time_created_utc>=?" in sql
    assert "order by event.time_created_utc asc" in sql
    assert params == (["Security"], [4624, 4625], "2026-07-20T00:00:00Z", 51)
    assert result["items"][0]["id"] == 7


def test_seed_filter_schema_is_not_mistaken_for_a_predicate() -> None:
    clauses, params, order = reporting_v4._compile_definition_query("events.v2", {
        "filters": [{"key": "event_id", "ops": ["eq", "in"]}],
        "default_sort": [],
    })

    assert clauses == []
    assert params == []
    assert order == "event.time_created_utc desc,event.id desc"

    with pytest.raises(ValueError, match="invalid_filter_value"):
        reporting_v4._compile_definition_query("events.v2", {
            "filters": [{"field": "event_id", "op": "eq", "value": "not-a-number"}],
        })


def test_interactive_event_query_is_exact_bounded_and_cursor_based() -> None:
    clauses, params = reporting_v4._compile_interactive_event_query({
        "q": "4624", "server": "DC1", "time_from": "2026-07-20T00:00:00Z",
    }, order_sql=reporting_v4.DEFAULT_ORDERS["events.v2"])

    assert any("event.subject_user_name" in clause for clause in clauses)
    assert any("server.hostname" in clause for clause in clauses)
    assert any("event.event_id=?" in clause for clause in clauses)
    assert params.count("4624") == 5
    assert params[-3:] == [4624, "DC1", "2026-07-20T00:00:00Z"]

    _account_clauses, account_params = reporting_v4._compile_interactive_event_query(
        {"q": "CORP\\ivanov"}, order_sql=reporting_v4.DEFAULT_ORDERS["events.v2"],
    )
    assert account_params.count("CORP\\ivanov") == 5
    assert account_params.count("ivanov") == 2

    cursor = reporting_v4._report_cursor({"id": 19, "time_created_utc": "2026-07-20T01:02:03Z"})
    cursor_clauses, cursor_params = reporting_v4._compile_interactive_event_query(
        {"cursor": cursor}, order_sql=reporting_v4.DEFAULT_ORDERS["events.v2"],
    )
    assert cursor_clauses == ["(event.time_created_utc<? or (event.time_created_utc=? and event.id<?))"]
    assert cursor_params == ["2026-07-20T01:02:03Z", "2026-07-20T01:02:03Z", 19]

    with pytest.raises(ValueError, match="unknown_report_query_filter"):
        reporting_v4._compile_interactive_event_query(
            {"sql": "select 1"}, order_sql=reporting_v4.DEFAULT_ORDERS["events.v2"],
        )


def test_event_view_is_allowlisted_bounded_and_composed_after_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert routes_reports._v4_report_query_filters(
        {"view": ["authentication"]}
    ) == {"view": "authentication"}
    with pytest.raises(ValueError, match="unknown_report_query_filter"):
        routes_reports._v4_report_query_filters({"tier": ["critical"]})
    with pytest.raises(ValueError, match="invalid_report_query_filter"):
        reporting_v4._compile_interactive_event_query(
            {"view": "invented"}, order_sql=reporting_v4.DEFAULT_ORDERS["events.v2"],
        )

    _patch_definition(monkeypatch, {
        "columns": ["id"], "filters": [], "default_sort": [], "actions": ["view"],
    })
    calls: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(
        reporting_v4, "query_rows_bounded",
        lambda sql, params=(), **_kwargs: calls.append((sql, params)) or [],
    )
    reporting_v4.execute_report(
        "events.test", None, fields=["id"], access=_events_access(),
        query_filters={"view": "authentication"},
    )

    sql, params = calls[-1]
    assert sql.index("channel.value=any(?)") < sql.index("event.event_id=any(?)")
    assert params == (
        ["Security"], reporting_v4.EVENT_VIEW_EVENT_IDS["authentication"], 51,
    )


def test_privileged_account_state_reuses_lateral_and_keeps_field_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fields = [
        {"key": "object_id", "category": "identity_basic"},
        {"key": "enabled", "category": "security"},
    ]
    _patch_definition(monkeypatch, {
        "columns": fields, "filters": [], "default_sort": [], "actions": ["view"],
    })
    original_fetchone = reporting_v4._connect().cursor().fetchone

    class PrivilegedCursor:
        def execute(self, _query: str, _params: tuple[object, ...]) -> None:
            return None
        def fetchone(self) -> dict[str, object]:
            row = original_fetchone()
            return {**row, "dataset_key": "ad.accounts.privileged", "fields_json": fields}
        def __enter__(self) -> "PrivilegedCursor":
            return self
        def __exit__(self, *_args: object) -> None:
            return None

    class PrivilegedConnection:
        def cursor(self) -> PrivilegedCursor:
            return PrivilegedCursor()
        def __enter__(self) -> "PrivilegedConnection":
            return self
        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(reporting_v4, "_connect", lambda: PrivilegedConnection())
    with pytest.raises(PermissionError, match="report_field_access_denied"):
        reporting_v4.execute_report(
            "events.test", None, fields=["enabled"],
            access=_privileged_access(["identity_basic"]),
        )

    calls: list[tuple[str, tuple[object, ...]]] = []
    def query(sql: str, params: tuple[object, ...] = (), **_kwargs: object):
        calls.append((sql, params))
        if "count(*) as total_relations" in sql:
            return [{"disabled_subjects": 2, "inactive_subjects": 1}]
        return [{"enabled": False}] if "as object_id" in sql else []
    monkeypatch.setattr(reporting_v4, "query_rows_bounded", query)
    result = reporting_v4.execute_report(
        "events.test", None, fields=["enabled"],
        access=_privileged_access(["identity_basic", "security"]),
    )

    row_sql, row_params = next(item for item in calls if "as object_id" in item[0])
    assert reporting_v4.VPN_ACCOUNT_ATTRIBUTES_LATERAL in row_sql
    assert "source_entity.domain_id=any(?)" in row_sql
    assert row_params == ([7], 51)
    assert result["items"] == [{"enabled": False}]
    assert result["summary"]["disabled_subjects"] == 2
    assert result["summary"]["inactive_subjects"] == 1
    assert reporting_v4.RUNTIME_SORT_FIELDS["ad.accounts.privileged"]["locked_out"] == "locked_out"


def test_ad_snapshot_computer_controls_use_stored_context_and_keep_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, tuple[object, ...]]] = []

    def query(sql: str, params: tuple[object, ...] = (), **_kwargs: object):
        calls.append((sql, params))
        if "from ad_context_runs run" in sql:
            return []
        if "without_observation_count" in sql:
            return [{"without_observation_count": 0}]
        return [{
            "observed_users": 3,
            "observed_computers": 2,
            "disabled_computers": 1,
            "inactive_computers": 1,
            "computers_with_operating_system": 2,
            "operating_system_distribution": [{
                "operating_system": "Windows 11 Pro",
                "operating_system_version": "10.0 (26100)",
                "count": 2,
            }],
        }]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", query)
    summary = reporting_v4._ad_snapshot_summary(
        " where (entity.domain_id=any(?))", ([7],), {"security"},
    )

    assert summary["computer_controls"] == {
        "observed_computers": 2,
        "disabled_computers": 1,
        "inactive_computers": 1,
        "computers_with_operating_system": 2,
        "operating_system_distribution": [{
            "operating_system": "Windows 11 Pro",
            "operating_system_version": "10.0 (26100)",
            "count": 2,
        }],
    }
    control_sql, control_params = next(
        item for item in calls if "operating_system_distribution" in item[0]
    )
    assert "version.attributes_json->'attributes'" in control_sql
    assert "entity.domain_id=any(?)" in control_sql
    assert "unsupported" not in control_sql.casefold()
    assert control_params == ([7],)


def test_privileged_state_migration_updates_both_column_authorities() -> None:
    from pathlib import Path
    forward = Path(
        "config/postgres_migrations/056_privileged_account_state_fields.sql"
    ).read_text(encoding="utf-8")
    rollback = Path(
        "config/postgres_migrations/056_privileged_account_state_fields.rollback.sql"
    ).read_text(encoding="utf-8")
    for key in (
        "enabled", "is_inactive", "password_never_expires", "locked_out",
        "last_logon_utc",
    ):
        assert key in forward
        assert key in rollback
    assert "update report_datasets_v4" in forward
    assert "update report_registry_v4" in forward
    assert "version=55" in forward
    assert "delete from schema_migrations" in rollback


def test_interactive_report_sort_is_allowlisted_and_stable() -> None:
    order = reporting_v4._compile_interactive_sort(
        "ad.accounts.vpn",
        {"sort": "display_name", "direction": "desc"},
        default_order_sql=reporting_v4.DEFAULT_ORDERS["ad.accounts.vpn"],
    )

    assert order.startswith("source_entity.display_name desc nulls last,")
    assert order.endswith(reporting_v4.DEFAULT_ORDERS["ad.accounts.vpn"])

    with pytest.raises(ValueError, match="incomplete_report_sort"):
        reporting_v4._compile_interactive_sort(
            "ad.accounts.vpn",
            {"sort": "display_name"},
            default_order_sql=reporting_v4.DEFAULT_ORDERS["ad.accounts.vpn"],
        )
    with pytest.raises(ValueError, match="report_sort_not_executable"):
        reporting_v4._compile_interactive_sort(
            "ad.accounts.vpn",
            {"sort": "raw_sql", "direction": "asc"},
            default_order_sql=reporting_v4.DEFAULT_ORDERS["ad.accounts.vpn"],
        )


def test_http_report_query_accepts_one_validated_sort_pair() -> None:
    parsed = routes_reports._v4_report_query_filters({
        "limit": ["200"],
        "sort": ["display_name"],
        "direction": ["asc"],
    })

    assert parsed == {"sort": "display_name", "direction": "asc"}

    with pytest.raises(ValueError, match="duplicate_report_query_filter"):
        routes_reports._v4_report_query_filters({
            "sort": ["display_name", "last_seen_utc"],
            "direction": ["asc"],
        })


def test_interactive_vpn_filters_are_allowlisted_and_typed() -> None:
    clauses, params = reporting_v4._compile_interactive_report_query(
        "ad.accounts.vpn",
        {"activity_state": "inactive", "privileged_overlap": "true"},
    )

    assert len(clauses) == 2
    assert "last_logon_utc" in clauses[0]
    assert "is_inactive" not in clauses[0]
    assert "filter_privileged" in clauses[1]
    assert params == ["inactive", True]

    with pytest.raises(ValueError, match="invalid_report_query_filter"):
        reporting_v4._compile_interactive_report_query(
            "ad.accounts.vpn", {"activity_state": "invented"},
        )
    with pytest.raises(ValueError, match="unknown_report_query_filter"):
        reporting_v4._compile_interactive_report_query(
            "ad.accounts.vpn", {"sql": "select 1"},
        )


def test_interactive_ad_entity_filter_is_server_owned() -> None:
    clauses, params = reporting_v4._compile_interactive_report_query(
        "ad.audit.snapshot", {"entity_type": "ad_computer"},
    )

    assert clauses == ["entity_type.value=?"]
    assert params == ["ad_computer"]

    with pytest.raises(ValueError, match="invalid_report_query_filter"):
        reporting_v4._compile_interactive_report_query(
            "ad.audit.snapshot", {"entity_type": "invented"},
        )


def test_interactive_gpo_search_is_bounded_server_query() -> None:
    clauses, params = reporting_v4._compile_interactive_report_query(
        "ad.gpo.governance", {"q": "контроллеры"},
    )

    assert len(clauses) == 1
    assert "entity.display_name" in clauses[0]
    assert "gpo_settings" in clauses[0]
    assert "review_reason" not in clauses[0]
    assert params and set(params) == {"%контроллеры%"}

    with pytest.raises(ValueError, match="invalid_report_query_filter"):
        reporting_v4._compile_interactive_report_query(
            "ad.gpo.governance", {"q": "x" * 257},
        )


def test_gpo_projection_returns_null_instead_of_human_placeholders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_fields = [
        "priority", "owner", "application_state", "link_count", "scope", "purpose",
        "review_reason", "signals", "next_steps",
    ]
    fields = [
        {"key": key, "category": "identity_basic"}
        for key in ["object_id", "display_name", "natural_key", *missing_fields, "observed_at"]
    ]
    fields.append({"key": "settings", "category": "security"})
    _patch_definition(
        monkeypatch,
        {"columns": fields, "filters": [], "default_sort": [], "actions": ["view"]},
        dataset_key="ad.gpo.governance",
        fields_json=fields,
    )
    calls: list[str] = []

    def query(sql: str, *_args: object, **_kwargs: object) -> list[dict[str, object]]:
        calls.append(sql)
        if "as object_id" in sql:
            return [{
                "object_id": "1", "display_name": "Baseline", "natural_key": "{GPO}",
                **dict.fromkeys(missing_fields), "settings": [],
                "observed_at": "2026-07-30T00:00:00Z",
            }]
        return []

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", query)
    result = reporting_v4.execute_report(
        "events.test", None,
        access=_privileged_access(["identity_basic", "security"]),
    )

    row_sql = next(sql for sql in calls if "as object_id" in sql)
    assert not any(sentence in row_sql for sentence in (
        "Требует ручной оценки", "Не указан", "Не определено",
        "Область применения не собрана", "Назначение не подтверждено",
        "Требуется ручная оценка",
    ))
    assert "gpo_settings" in row_sql
    assert "jsonb_array_elements_text" not in row_sql
    assert all(result["items"][0][key] is None for key in missing_fields)
    assert result["items"][0]["settings"] == []
    assert "priority" not in reporting_v4.RUNTIME_FILTER_FIELDS["ad.gpo.governance"]


def test_multi_grant_rows_follow_requested_field_sort_and_keep_missing_values_last() -> None:
    rows = reporting_v4._sort_combined_report_items([
        {"display_name": "Яна", "natural_key": "3"},
        {"natural_key": "hidden"},
        {"display_name": "Анна", "natural_key": "1"},
    ], {"sort": "display_name", "direction": "asc"})

    assert [row.get("display_name") for row in rows] == ["Анна", "Яна", None]

    descending = reporting_v4._sort_combined_report_items(
        rows, {"sort": "display_name", "direction": "desc"},
    )
    assert [row.get("display_name") for row in descending] == ["Яна", "Анна", None]


def test_broad_grant_prunes_redundant_narrow_assignment_without_cross_product() -> None:
    broad = {
        "scope": {"kind": "all"},
        "field_categories": ["identity_basic", "security"],
        "allowed_actions": ["view", "export"],
        "source_type": "platform_owner",
    }
    narrow = {
        "scope": {"kind": "server", "ids": [1]},
        "field_categories": ["identity_basic"],
        "allowed_actions": ["view"],
        "source_type": "direct",
    }
    independent = {
        "scope": {"kind": "server", "ids": [2]},
        "field_categories": ["technical"],
        "allowed_actions": ["view"],
        "source_type": "direct",
    }

    assert reporting_v4._prune_subsumed_grants([broad, narrow]) == [broad]
    assert reporting_v4._prune_subsumed_grants([narrow, independent]) == [
        narrow,
        independent,
    ]


def test_event_report_returns_next_cursor_without_exposing_hidden_cursor_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_definition(monkeypatch, {
        "columns": ["event_id", "channel"], "filters": [], "default_sort": [], "actions": ["view"],
    })
    monkeypatch.setattr(reporting_v4, "query_rows_bounded", lambda *_args, **_kwargs: [
        {"id": 20, "time_created_utc": "2026-07-20T02:00:00Z", "event_id": 4624, "channel": "Security"},
        {"id": 19, "time_created_utc": "2026-07-20T01:00:00Z", "event_id": 4625, "channel": "Security"},
    ])

    result = reporting_v4.execute_report("events.test", None, limit=1, access=_events_access())

    assert result["items"] == [{"event_id": 4624, "channel": "Security"}]
    assert result["has_more"] is True
    assert reporting_v4._decode_report_cursor(result["next_cursor"]) == ("2026-07-20T02:00:00Z", 20)
    assert "grants" not in result["report"]
    assert result["report"]["allowed_actions"] == ["view"]


def test_report_export_requires_definition_capability_and_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_definition(monkeypatch, {
        "columns": ["event_id"], "filters": [], "sort": [],
        "actions": ["view", "export"], "export_policy": "controlled",
    })
    monkeypatch.setattr(reporting_v4, "query_rows_bounded", lambda *_args, **_kwargs: [{"event_id": 4624}])

    with pytest.raises(PermissionError, match="report_export_denied"):
        reporting_v4.execute_report(
            "events.test", None, action="export",
            access=_events_access(actions=["view", "export"]),
        )
    with pytest.raises(PermissionError, match="report_access_denied"):
        reporting_v4.execute_report(
            "events.test", None, action="export",
            access=_events_access(capabilities=["reports.export"], actions=["view"]),
        )


def test_csv_export_uses_allowed_fields_and_neutralizes_formulas(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporting_v4, "execute_report", lambda *_args, **kwargs: {
        "fields": [{"key": "name", "label": "Имя"}, {"key": "value", "label": "Значение"}],
        "items": [{"name": "=2+2", "value": {"safe": True}}],
    })

    rendered = reporting_v4.export_report_csv("events.test", None, access={})

    assert rendered.startswith("Имя,Значение\r\n")
    assert "'=2+2" in rendered
    assert '"{""safe"":true}"' in rendered


def test_csv_export_exact_limit_is_not_falsely_marked_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reporting_v4, "execute_report", lambda *_args, **kwargs: {
        "fields": [{"key": "id", "label": "ID"}],
        "items": [{"id": index} for index in range(reporting_v4.REPORT_LIMIT_MAX)],
        "has_more": False,
        "limits": {"total_count": reporting_v4.REPORT_LIMIT_MAX},
        "next_cursor": None,
    })

    document = reporting_v4.export_report_csv_document(
        "events.test", None, access={}
    )

    assert document["row_count"] == reporting_v4.REPORT_LIMIT_MAX
    assert document["truncated"] is False


def test_http_report_export_returns_bom_csv_attachment(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        routes_reports, "export_v4_report_csv_document",
        lambda report_key, _principal, **kwargs: (
            captured.update(report_key=report_key, **kwargs)
            or {
                "csv": "Имя\r\nИванов\r\n",
                "row_count": 1,
                "row_limit": reporting_v4.REPORT_LIMIT_MAX,
                "truncated": False,
                "has_more": False,
                "total_count": 1,
            }
        ),
    )
    handler = object.__new__(http_server.RequestHandler)
    handler._principal = {"id": 7}
    handler._access_decision = lambda: {"capabilities": ["reports.export"]}
    statuses: list[HTTPStatus] = []
    headers: dict[str, str] = {}
    handler.send_response = lambda status: statuses.append(status)
    handler.send_header = lambda name, value: headers.__setitem__(name, value)
    handler.end_headers = lambda: None
    handler.wfile = io.BytesIO()

    routes_reports._handle_v4_report_export_api(
        handler,
        "/api/v1/reports/events.test/export.csv",
        {"field": ["event_id,channel"], "q": ["4624"], "server": ["DC1"]},
    )

    assert statuses == [HTTPStatus.OK]
    assert headers["Content-Type"] == "text/csv; charset=utf-8"
    assert headers["Content-Disposition"] == 'attachment; filename="sli-report-events.test-complete-1-rows.csv"'
    assert handler.wfile.getvalue().startswith(b"\xef\xbb\xbf")
    assert captured["report_key"] == "events.test"
    assert captured["fields"] == ["event_id", "channel"]
    assert captured["query_filters"] == {"q": "4624", "server": "DC1"}


@pytest.fixture(autouse=True)
def _hygiene_settings(monkeypatch):
    from server.sli.core import platform_settings

    monkeypatch.setattr(platform_settings, "_stored_row", lambda _key: None)
