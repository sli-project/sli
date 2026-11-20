from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.sli.access.access_control_v4 import _optional_utc, route_capability
from server.sli.access import object_facade_v4
from server.sli.reporting import reporting_v4
from server.sli.reporting.reporting_v4 import _definition_has_unsafe_text
from server.sli.reporting.ui_api_models import UiBootstrapResponse, V4ObjectDetailResponse


ROOT = Path(__file__).resolve().parents[2]


def test_v4_route_capabilities_cover_existing_sensitive_read_paths() -> None:
    assert route_capability("/api/v1/events") == "events.view"
    assert route_capability("/api/v1/investigations/42") == "investigations.view"
    assert route_capability("/api/v1/semantic/scenarios") == "semantic.review"
    assert route_capability("/api/v1/operations/overview") == "operations.view"
    assert route_capability("/api/v1/operations/sources/DC2") == "operations.view"
    assert route_capability("/api/auth/users") == "access.manage"


def test_builder_rejects_sql_structure_but_allows_bound_user_text() -> None:
    assert _definition_has_unsafe_text({"raw_sql": "select * from events"})
    assert _definition_has_unsafe_text({"filter": {"expression": "event_id > 0"}})
    assert not _definition_has_unsafe_text({"filter": {"value": "select account in SQL Server"}})
    assert not _definition_has_unsafe_text({"name": "copy operation", "actions": ["view"]})


def test_dashboard_metric_contract_is_bounded_and_expression_free() -> None:
    metric = {
        "key": "ad.vpn_disabled_accounts",
        "label": "Отключённые VPN-учётные записи",
        "caption": "в назначенных VPN-группах",
        "kind": "optional",
        "value_path": "summary.disabled_users",
        "freshness_path": "summary.latest_observed_at_utc",
        "icon": "lock",
        "tone": "warn",
        "priority": 30,
        "target_path": "/vpn-report",
        "filters": {"activity_state": "disabled"},
        "default_selected": True,
    }

    assert reporting_v4._dashboard_metric_definitions([metric])[0]["default_selected"] is True
    with pytest.raises(ValueError, match="invalid_dashboard_metrics"):
        reporting_v4._dashboard_metric_definitions([{**metric, "value_path": "sql.count(*)"}])
    with pytest.raises(ValueError, match="required_dashboard_metric_capacity_exceeded"):
        reporting_v4._dashboard_metric_definitions([
            {**metric, "key": f"metric.{index}", "kind": "required"}
            for index in range(5)
        ])


def test_workspace_focus_uses_only_visible_publisher_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    report = {
        "report_key": "vpn.audit",
        "dataset_key": "ad.accounts.vpn",
        "dashboard_metrics": [{
            "key": "ad.vpn_disabled_accounts", "label": "Отключённые VPN-учётные записи",
            "caption": "в назначенных VPN-группах", "kind": "optional",
            "value_path": "summary.disabled_users",
            "freshness_path": "summary.latest_observed_at_utc",
            "unit": None, "icon": "lock", "tone": "warn", "priority": 30,
            "target_path": "/vpn-report", "filters": {"activity_state": "disabled"},
            "default_selected": True,
        }],
        "selected_optional_metric_keys": [],
        "focus_preference_configured": False,
    }
    monkeypatch.setattr(reporting_v4, "execute_report", lambda *_args, **_kwargs: {
        "state": "available", "items": [],
        "summary": {
            "disabled_users": 12,
            "latest_observed_at_utc": "2026-07-23T04:00:00Z",
            "collection": {"vpn_membership": {"state": "partial"}},
        },
    })

    metrics = reporting_v4._workspace_focus_metrics(None, {"reports": [report]}, [report])

    assert metrics == [{
        "key": "ad.vpn_disabled_accounts",
        "label": "Отключённые VPN-учётные записи",
        "caption": "в назначенных VPN-группах",
        "kind": "optional",
        "value": 12,
        "unit": None,
        "state": "partial",
        "freshness": "2026-07-23T04:00:00Z",
        "source": "ad.accounts.vpn",
        "priority": 30,
        "report_key": "vpn.audit",
        "target_path": "/vpn-report",
        "filters": {"activity_state": "disabled"},
        "icon": "lock",
        "tone": "warn",
    }]
    report["focus_preference_configured"] = True
    assert reporting_v4._workspace_focus_metrics(None, {"reports": [report]}, [report]) == []


def test_workspace_focus_does_not_drop_required_metrics_from_later_reports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reports = []
    for index in range(6):
        reports.append({
            "report_key": f"report.{index}",
            "dataset_key": "entities.v2",
            "dashboard_metrics": [{
                "key": f"metric.{index}", "label": f"Метрика {index}",
                "caption": "", "kind": "required", "value_path": "items.count",
                "freshness_path": None, "unit": None, "icon": "report",
                "tone": "accent", "priority": index,
                "target_path": f"/reports/report.{index}", "filters": {},
                "default_selected": False,
            }],
        })
    monkeypatch.setattr(reporting_v4, "execute_report", lambda *_args, **_kwargs: {
        "state": "available", "items": [{"id": 1}], "summary": {},
    })

    metrics = reporting_v4._workspace_focus_metrics(None, {"reports": reports}, reports)

    assert [metric["key"] for metric in metrics] == [f"metric.{index}" for index in range(6)]


def test_ad_snapshot_summary_is_scoped_and_respects_field_categories(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple]] = []

    def fake_query(sql: str, params: tuple = (), **_kwargs):
        calls.append((sql, params))
        if "from ad_context_runs run" in sql:
            return [{
                "section_name": "directory_accounts", "domain_count": 1,
                "complete_domain_count": 1, "partial_domain_count": 0,
                "failed_domain_count": 0, "skipped_domain_count": 0,
                "latest_observed_at_utc": "2026-07-20T10:00:00Z",
            }]
        if "group by entity_type.value" in sql:
            return [{"entity_type": "ad_user", "object_count": 7}, {"entity_type": "ad_computer", "object_count": 3}]
        if "without_observation_count" in sql:
            return [{"without_observation_count": 2, "latest_observed_at_utc": "2026-07-20T10:00:00Z"}]
        return [{"total_objects": 10}]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_query)
    summary = reporting_v4._ad_snapshot_summary(
        " where (entity.domain_id=any(?))", [[41]], {"identity_basic", "security"},
    )

    assert summary["total_objects"] == 10
    assert summary["by_entity_type"] == [
        {"entity_type": "ad_user", "count": 7},
        {"entity_type": "ad_computer", "count": 3},
    ]
    assert summary["without_observation_count"] == 2
    assert summary["latest_observed_at_utc"] == "2026-07-20T10:00:00Z"
    assert len(calls) == 5
    coverage_call = next((sql, params) for sql, params in calls if "from ad_context_runs run" in sql)
    assert coverage_call[1] == (["directory_accounts", "privileged_membership", "vpn_membership", "gpo_governance"], [41])
    assert all(params == ([41],) for sql, params in calls if "from ad_context_runs run" not in sql)
    assert all("valid_to_utc is null" in sql for sql, _params in calls if "from ad_context_runs run" not in sql)
    account_controls_sql = next(sql for sql, _params in calls if "observed_users" in sql)
    assert "from ad_context_entity_versions version" in account_controls_sql
    assert "join lateral" not in account_controls_sql
    assert summary["collection"]["directory_accounts"]["state"] == "complete"


def test_ad_snapshot_summary_does_not_expose_observation_aggregates_without_security_category(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def fake_query(sql: str, _params: tuple = (), **_kwargs):
        queries.append(sql)
        if "from ad_context_runs run" in sql:
            return []
        return [{"total_objects": 4}] if "count(*) as total_objects" in sql else []

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_query)
    summary = reporting_v4._ad_snapshot_summary("", [], {"identity_basic"})

    assert summary["total_objects"] == 4
    assert "without_observation_count" not in summary
    assert "latest_observed_at_utc" not in summary
    assert len(queries) == 3
    assert any("from ad_context_runs run" in sql for sql in queries)


def test_privileged_account_summary_is_scoped_and_category_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple]] = []

    def fake_query(sql: str, params: tuple = (), **_kwargs):
        calls.append((sql, params))
        return [{
            "total_relations": 12,
            "unique_subjects": 7,
            "unique_target_groups": 3,
            "latest_observed_at_utc": "2026-07-20T11:00:00Z",
        }]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_query)
    summary = reporting_v4._privileged_account_summary(
        " where (source_entity.server_id=any(?))", [[9]], {"identity_basic", "privilege"},
    )

    assert summary["total_relations"] == 12
    assert summary["unique_subjects"] == 7
    assert summary["unique_target_groups"] == 3
    assert "latest_observed_at_utc" not in summary
    assert calls[0][1] == ([9],)
    assert "relation.valid_to_utc is null" in calls[0][0]
    assert "relation.relation_kind='member_of'" in calls[0][0]
    assert summary["collection"]["privileged_membership"]["state"] == "scope_not_applicable"


def test_gpo_governance_summary_is_scoped_and_does_not_claim_external_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple]] = []

    def fake_query(sql: str, params: tuple = (), **_kwargs):
        calls.append((sql, params))
        if "from ad_context_runs run" in sql:
            return [{
                "section_name": "gpo_governance", "domain_count": 1,
                "complete_domain_count": 0, "partial_domain_count": 1,
                "failed_domain_count": 0, "skipped_domain_count": 0,
                "latest_observed_at_utc": "2026-07-20T12:00:00Z",
            }]
        return [{
            "total_gpo": 6,
            "missing_owner_count": 2,
            "unlinked_policy_count": 2,
            "disabled_policy_count": 1,
            "partially_enabled_policy_count": 1,
            "executable_component_policy_count": 2,
            "executable_component_total_count": 3,
            "manual_review_count": 2,
            "latest_observed_at_utc": "2026-07-20T12:00:00Z",
        }]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_query)
    summary = reporting_v4._gpo_governance_summary(
        " where (entity.domain_id=any(?))", [[5]], {"identity_basic", "security"},
    )

    assert summary["total_gpo"] == 6
    assert summary["missing_owner_count"] == 2
    assert summary["manual_review_count"] == 2
    assert summary["manual_review_basis"] == [
        "link_count_zero", "application_state_disabled",
    ]
    assert summary["executable_component_policy_count"] == 2
    assert summary["executable_component_risk_qualified"] is False
    assert summary["latest_observed_at_utc"] == "2026-07-20T12:00:00Z"
    assert calls[0][1] == ([5],)
    assert "version.valid_to_utc is null" in calls[0][0]
    assert "from ad_context_entity_versions version" in calls[0][0]
    assert "left join lateral" not in calls[0][0]
    assert any("GPMC" in item and "эффективный доступ" in item for item in summary["limitations"])
    assert any("SYSVOL" in item and "резервной копии" in item for item in summary["limitations"])
    assert calls[1][1] == (["gpo_governance"], [5])
    assert summary["collection"]["gpo_governance"]["state"] == "partial"


def test_vpn_account_summary_uses_exact_collector_sections_and_separates_hygiene(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple]] = []

    def fake_query(sql: str, params: tuple = (), **_kwargs):
        calls.append((sql, params))
        if "from ad_context_runs run" in sql:
            return [
                {"section_name": "directory_accounts", "domain_count": 1, "complete_domain_count": 1, "partial_domain_count": 0, "failed_domain_count": 0, "skipped_domain_count": 0, "latest_observed_at_utc": "2026-07-20T12:00:00Z"},
                {"section_name": "vpn_membership", "domain_count": 1, "complete_domain_count": 0, "partial_domain_count": 1, "failed_domain_count": 0, "skipped_domain_count": 0, "latest_observed_at_utc": "2026-07-20T12:00:00Z"},
            ]
        return [{
            "total_users": 430, "enabled_users": 418, "active_users": 383, "disabled_users": 12,
            "unknown_account_state_users": 3,
            "inactive_users": 35, "password_never_expires_users": 428,
            "privileged_overlap_users": 9, "inactive_threshold_days": 180,
            "latest_observed_at_utc": "2026-07-20T12:00:00Z",
        }]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_query)
    summary = reporting_v4._vpn_account_summary(
        " where (source_entity.domain_id=any(?))", [[5]],
        {"identity_basic", "security", "privilege"},
    )

    assert summary["total_users"] == 430
    assert summary["enabled_users"] == 418
    assert summary["active_users"] == 383
    assert f"{reporting_v4.runtime_filter_expression('ad.accounts.vpn', 'activity_state')} as activity_state" in calls[0][0]
    assert "count(*) filter(where activity_state='active') as active_users" in calls[0][0]
    assert summary["disabled_users"] == 12
    assert summary["unknown_account_state_users"] == 3
    assert summary["inactive_users"] == 35
    assert summary["privileged_overlap_users"] == 9
    assert summary["inactive_threshold_days"] == 90
    assert calls[0][1] == ([5],)
    assert calls[1][1] == (["vpn_membership", "directory_accounts", "privileged_membership"], [5])
    assert "relation.source_section='vpn_membership'" in calls[0][0]
    assert "privileged.source_section='privileged_membership'" in calls[0][0]
    assert "current.source_section in ('directory_accounts','vpn_membership')" in calls[0][0]
    assert "when 'directory_accounts' then 0 else 1" in calls[0][0]
    assert "interval '90 days'" in calls[0][0]
    assert "is_inactive" not in calls[0][0]
    assert "attributes->>'enabled')::boolean is false" in calls[0][0]
    assert summary["collection"]["vpn_membership"]["state"] == "partial"
    assert summary["collection"]["directory_accounts"]["state"] == "complete"
    assert summary["collection"]["privileged_membership"]["state"] == "not_collected"
    assert any("гигиены" in item for item in summary["limitations"])
    assert any("снимка участника VPN-группы" in item for item in summary["limitations"])


def test_vpn_account_attribute_fallback_prefers_directory_snapshot() -> None:
    sql = reporting_v4.VPN_ACCOUNT_ATTRIBUTES_LATERAL

    assert "current.source_section in ('directory_accounts','vpn_membership')" in sql
    assert "when 'directory_accounts' then 0 else 1" in sql
    assert "current.valid_to_utc is null" in sql


def test_context_section_coverage_preserves_failed_and_skipped_states(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_query(_sql: str, _params: tuple = (), **_kwargs):
        return [
            {"section_name": "vpn_membership", "domain_count": 2, "complete_domain_count": 0, "partial_domain_count": 0, "failed_domain_count": 2, "skipped_domain_count": 0, "latest_observed_at_utc": "2026-07-20T12:00:00Z"},
            {"section_name": "directory_accounts", "domain_count": 1, "complete_domain_count": 0, "partial_domain_count": 0, "failed_domain_count": 0, "skipped_domain_count": 1, "latest_observed_at_utc": "2026-07-20T12:00:00Z"},
        ]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_query)
    coverage = reporting_v4._context_section_coverage(
        ("vpn_membership", "directory_accounts", "privileged_membership"), "", [],
    )

    assert coverage["vpn_membership"]["state"] == "failed"
    assert coverage["directory_accounts"]["state"] == "skipped"
    assert coverage["privileged_membership"]["state"] == "not_collected"

    server_scoped = reporting_v4._context_section_coverage(
        ("vpn_membership",), " where (run.server_id=any(?))", [[9]],
    )
    assert server_scoped["vpn_membership"]["state"] == "scope_not_applicable"


def test_report_definition_registry_supports_bounded_repeat_read(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{
        "report_key": "security.events", "version": 3, "name": "События", "owner_name": "ИБ",
        "purpose": "Анализ", "sensitivity": "restricted", "status": "draft",
        "dataset_key": "events.v2", "dataset_version": 2,
    }]

    class Cursor:
        def execute(self, query: str, params: tuple[int]) -> None:
            assert "from report_registry_v4" in query
            assert params == (500,)

        def fetchall(self) -> list[dict[str, object]]:
            return rows

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

    monkeypatch.setattr(reporting_v4, "effective_access", lambda _principal: {"capabilities": ["reports.design"]})
    monkeypatch.setattr(reporting_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(reporting_v4, "_connect", lambda: Connection())

    result = reporting_v4.report_definitions(None, limit=900)

    assert result["limit"] == 500
    assert [{k: v for k, v in item.items() if k != "code_defined"} for item in result["items"]] == rows


def test_report_catalog_excludes_working_and_administrative_tools() -> None:
    access = {
        "capabilities": ["reports.catalog"],
        "allowed_report_count": 3,
        "reports": [
            {"report_key": "ad.state", "target_path": "/ad-report", "allowed": True},
            {"report_key": "events.explorer", "target_path": "/events", "allowed": True},
            {"report_key": "operations.readiness", "target_path": "/app/operations", "allowed": True},
        ],
    }

    result = reporting_v4.report_catalog(None, access=access)

    assert [item["report_key"] for item in result["items"]] == ["ad.state"]
    assert result["allowed_count"] == 1
    assert result["total_count"] == 1


def test_report_catalog_adds_vpn_connections_surface_from_existing_vpn_access() -> None:
    access = {
        "capabilities": ["reports.catalog", "vpn.sessions.view"],
        "allowed_report_count": 1,
        "reports": [
            {
                "report_key": "vpn.audit",
                "version": 1,
                "name": "VPN audit",
                "owner": "AD / IT",
                "purpose": "VPN membership",
                "dataset_key": "ad.access.vpn",
                "dataset_version": 1,
                "sensitivity": "Personal data",
                "status": "published",
                "target_path": "/vpn-report",
                "allowed": True,
                "explanation": "assigned",
                "missing_capabilities": [],
                "requestable": False,
                "access_state": "available",
                "field_categories": ["identity_basic"],
                "allowed_actions": ["view", "export"],
                "scopes": [{"kind": "domain", "ids": [7]}],
                "sources": [{"source_type": "direct", "source": "assignment"}],
                "pinned": True,
            },
        ],
    }

    result = reporting_v4.report_catalog(None, access=access)

    assert [item["report_key"] for item in result["items"]] == ["vpn.connections"]
    report = result["items"][0]
    assert report["name"] == "VPN — подключения и доступы"
    assert report["dataset_key"] == "vpn.sessions"
    assert report["target_path"] == "/report/vpn.connections"
    assert report["allowed"] is True
    assert report["allowed_actions"] == ["view"]
    assert report["preference_supported"] is False
    assert report["pinned"] is False
    assert result["allowed_count"] == 1


def test_vpn_connections_catalog_surface_fails_closed_without_session_capability() -> None:
    access = {
        "capabilities": ["reports.catalog"],
        "allowed_report_count": 1,
        "reports": [
            {
                "report_key": "vpn.audit",
                "target_path": "/vpn-report",
                "allowed": True,
                "missing_capabilities": [],
            },
        ],
    }

    report = reporting_v4.report_catalog(None, access=access)["items"][0]

    assert report["report_key"] == "vpn.connections"
    assert report["allowed"] is False
    assert report["access_state"] == "request_unavailable"
    assert report["missing_capabilities"] == ["vpn.sessions.view"]


def test_report_preference_persists_only_for_allowed_session_report(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.access import access_control_v4

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def execute(self, query: str, params: tuple[object, ...] = ()) -> None:
            calls.append((query, params))

        def fetchone(self) -> dict[str, object]:
            return {
                "user_id": 7, "report_key": "ad.state", "pinned": True,
                "view_json": {}, "updated_at": "2026-07-23T04:00:00Z",
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

    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(access_control_v4, "effective_access", lambda _actor: {
        "reports": [{"report_key": "ad.state", "allowed": True}],
    })
    monkeypatch.setattr(access_control_v4, "_connect", lambda: Connection())

    result = access_control_v4.update_user_report_preference(
        "ad.state", {"pinned": True},
        actor={"type": "session", "id": 7, "username": "platform-owner"},
        remote_address="127.0.0.1",
    )

    assert result["pinned"] is True
    assert any("insert into user_report_preferences" in query for query, _params in calls)
    assert any("report_preference_updated" in query for query, _params in calls)

    monkeypatch.setattr(access_control_v4, "effective_access", lambda _actor: {
        "reports": [{
            "report_key": "ad.state", "allowed": True,
            "dashboard_metrics": [{"key": "optional.metric", "kind": "optional"}],
        }],
    })
    access_control_v4.update_user_report_preference(
        "ad.state", {"focus_metric_keys": ["optional.metric"]},
        actor={"type": "session", "id": 7, "username": "platform-owner"},
    )
    assert any(
        '"focus_metric_keys": ["optional.metric"]' in str(param)
        for query, params in calls if "insert into user_report_preferences" in query
        for param in params
    )

    monkeypatch.setattr(access_control_v4, "effective_access", lambda _actor: {
        "reports": [{"report_key": "ad.state", "allowed": False}],
    })
    with pytest.raises(PermissionError, match="report_access_denied"):
        access_control_v4.update_user_report_preference(
            "ad.state", {"pinned": True},
            actor={"type": "session", "id": 7, "username": "platform-owner"},
        )

    monkeypatch.setattr(access_control_v4, "effective_access", lambda _actor: {
        "reports": [{
            "report_key": "ad.state", "allowed": True,
            "dashboard_metrics": [{"key": "required.metric", "kind": "required"}],
        }],
    })
    with pytest.raises(ValueError, match="invalid_report_preference"):
        access_control_v4.update_user_report_preference(
            "ad.state", {"focus_metric_keys": ["required.metric"]},
            actor={"type": "session", "id": 7, "username": "platform-owner"},
        )


def test_stage6_dashboard_metric_migration_has_bounded_rollback() -> None:
    migration = (ROOT / "config/postgres_migrations/039_stage6_dashboard_metrics.sql").read_text(encoding="utf-8")
    rollback = (ROOT / "config/postgres_migrations/039_stage6_dashboard_metrics.rollback.sql").read_text(encoding="utf-8")

    assert "dashboard_metrics" in migration
    assert "security.open_problems" in migration
    assert "ad.vpn_disabled_accounts" in migration
    assert "insert into schema_migrations(version,name)" in migration
    assert "definition_json - 'dashboard_metrics'" in rollback
    assert "drop " not in rollback.lower()


def test_report_grant_options_are_limited_by_the_report_definition(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.access import access_control_v4

    rows = [{
        "report_key": "security.events", "version": 4, "name": "События", "purpose": "Разбор",
        "sensitivity": "restricted", "dataset_key": "events.v2",
        "definition_json": {"field_categories": ["security"], "actions": ["view"]},
        "fields_json": [{"key": "event_id", "category": "security"}, {"key": "raw", "category": "raw_evidence"}],
        "actions_json": ["view", "export", "start_case"],
    }]

    class Cursor:
        def execute(self, query: str) -> None:
            assert "distinct on (r.report_key)" in query

        def fetchall(self) -> list[dict[str, object]]:
            return rows

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

    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(access_control_v4, "_connect", lambda: Connection())

    result = access_control_v4.list_report_grant_options()

    assert result["items"][0]["allowed_actions"] == ["view"]
    assert result["items"][0]["field_categories"] == [{"key": "security", "label": "security"}]
    assert result["items"][0]["scope_kinds"] == ["all", "server", "domain", "channel"]


def test_report_assignment_mutation_requires_admin_role_and_assignment_capability() -> None:
    source = (ROOT / "server" / "api" / "routes" / "access.py").read_text(encoding="utf-8")
    start = source.index('if path == "/api/v1/access/assignments"', source.index("def try_handle_post"))
    route = source[start:source.index('if path == "/api/v1/access/report-requests"', start)]
    assert '_authorize_mutation(required_role="admin")' in route
    assert '_require_capability("reports.assign")' in route


def test_package_assignment_mutation_requires_admin_role_and_access_capability() -> None:
    source = (ROOT / "server" / "api" / "routes" / "access.py").read_text(encoding="utf-8")
    route = source[source.index('if path == "/api/v1/access/package-assignments"'):source.index('if path.startswith("/api/v1/reports/") and path.endswith("/preference")')]
    assert '_authorize_mutation(required_role="admin")' in route
    assert '_require_capability("access.manage")' in route


def test_package_assignment_route_dispatches_only_after_both_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api import http_server
    from server.api.routes import access as routes_access

    handler = object.__new__(http_server.RequestHandler)
    handler.path = "/api/v1/access/package-assignments"
    required: list[str] = []
    capabilities: list[str] = []
    called: list[str] = []
    handler._authorize_mutation = lambda *, required_role="operator": required.append(required_role) or True
    handler._require_capability = lambda capability: capabilities.append(capability) or True
    monkeypatch.setattr(routes_access, "_handle_package_assignment_create", lambda h: called.append("create"))

    handler._do_POST()

    assert required == ["admin"]
    assert capabilities == ["access.manage"]
    assert called == ["create"]


def test_package_assignment_handler_returns_created_item(monkeypatch: pytest.MonkeyPatch) -> None:
    from http import HTTPStatus
    from types import SimpleNamespace
    from server.api.routes import access as routes_access

    handler = SimpleNamespace()
    handler._principal = {"type": "session", "id": 1}
    handler.client_address = ("127.0.0.1", 50432)
    handler._read_json_body = lambda: {"package_key": "security_analyst"}
    responses: list[tuple[dict[str, object], HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: responses.append((payload, status))
    monkeypatch.setattr(
        routes_access,
        "create_package_assignment",
        lambda payload, *, actor, remote_address: {
            "id": 41, "package_key": payload["package_key"], "actor_id": actor["id"],
            "remote_address": remote_address,
        },
    )

    routes_access._handle_package_assignment_create(handler)

    assert responses == [({"item": {
        "id": 41, "package_key": "security_analyst", "actor_id": 1,
        "remote_address": "127.0.0.1",
    }}, HTTPStatus.CREATED)]


def test_temporary_package_assignment_requires_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.access import access_control_v4

    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: None)
    with pytest.raises(ValueError, match="temporary_assignment_requires_expiry"):
        access_control_v4.create_package_assignment({
            "subject_type": "user", "subject_id": 7, "package_key": "security_analyst",
            "effect": "allow", "source_type": "temporary", "business_reason": "Рабочая функция",
        }, actor={"type": "session", "id": 1})


def test_package_assignment_is_written_with_audit_record(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.access import access_control_v4

    responses = iter((
        {"id": 3, "name": "ИБ · аналитики"},
        {"present": 1},
        {
            "id": 41, "subject_type": "user", "subject_id": 7, "package_id": 3,
            "effect": "allow", "valid_from": None, "valid_until": None,
            "business_reason": "Рабочая функция", "approved_by": "Начальник ИБ",
            "source_type": "direct", "created_at": "2026-07-22T10:00:00+07:00",
        },
        {"id": 52, "created_at": datetime(2026, 8, 3, tzinfo=timezone.utc)},
    ))
    executed: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def execute(self, query: str, parameters: tuple[object, ...]) -> None:
            executed.append((query, parameters))

        def fetchone(self) -> dict[str, object]:
            return next(responses)

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

    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(access_control_v4, "_connect", lambda: Connection())

    result = access_control_v4.create_package_assignment({
        "subject_type": "user", "subject_id": 7, "package_key": "security_analyst",
        "effect": "allow", "source_type": "direct", "business_reason": "Рабочая функция",
        "approved_by": "Начальник ИБ",
    }, actor={"type": "session", "id": 1}, remote_address="127.0.0.1")

    assert result["id"] == 41
    assert result["package_key"] == "security_analyst"
    assert any("insert into access_subject_packages" in query for query, _ in executed)
    assert any(
        "insert into access_audit_v4" in query
        and "package_assignment_created" in parameters
        for query, parameters in executed
    )


def test_report_assignment_cannot_grant_action_outside_report_definition(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.access import access_control_v4

    responses = iter(({
        "definition_json": {"field_categories": ["security"], "actions": ["view"]},
        "dataset_key": "events.v2",
        "fields_json": [{"key": "event_id", "category": "security"}],
        "actions_json": ["view", "export"],
    }, {"present": 1}))
    executed: list[str] = []

    class Cursor:
        def execute(self, query: str, _parameters: tuple[object, ...]) -> None:
            executed.append(query)

        def fetchone(self) -> dict[str, object]:
            return next(responses)

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

    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(access_control_v4, "_connect", lambda: Connection())

    with pytest.raises(ValueError, match="unknown_report_action"):
        access_control_v4.create_report_assignment({
            "subject_type": "user", "subject_id": 7, "report_key": "security.events",
            "effect": "allow", "source_type": "direct", "scope": {"kind": "all"},
            "field_categories": ["security"], "allowed_actions": ["view", "export"],
            "business_reason": "Рабочая функция",
        }, actor={"type": "session", "id": 1})

    assert not any("insert into access_report_assignments" in query for query in executed)


def test_assignment_time_contract_requires_timezone() -> None:
    assert _optional_utc("2026-07-19T10:00:00+07:00", "bad") is not None
    with pytest.raises(ValueError, match="bad"):
        _optional_utc("2026-07-19T10:00:00", "bad")


def test_bootstrap_exposes_server_authoritative_v4_policy_metadata() -> None:
    model = UiBootstrapResponse(
        principal=None,
        effective_role="operator",
        navigation=[{"id": "workspace", "label": "Рабочее пространство", "path": "/"}],
        capabilities=["workspace.view"],
        packages=[{"key": "security_analyst", "name": "ИБ · аналитики"}],
        allowed_report_count=1,
    )
    assert model.access_model == "composite_v4"
    assert model.capabilities == ["workspace.view"]


def test_object_detail_contract_includes_real_findings_collection() -> None:
    model = V4ObjectDetailResponse(
        api_version="v4",
        state="available",
        object={"object_type": "ad_user", "object_id": "1258"},
        identity_links=[],
        identity_contract="employee_and_account_are_distinct_objects",
        tabs=[{"id": "overview", "label": "Обзор", "available": True}],
        current_states=[],
        directory_context={"resolution": "not_observed", "items": []},
        findings=[{"id": 7, "title": "Проверка", "severity": "high"}],
        events=[],
        events_state="available",
        has_more_events=False,
        actions=["copy_link"],
        provenance=[],
        limitations=[],
    )
    assert model.findings[0]["id"] == 7


def test_object_facade_accepts_the_physical_storage_v2_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(object_facade_v4, "effective_access", lambda _principal: {
        "capabilities": ["objects.view", "field.security", "tasks.create", "investigations.manage"],
    })
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 1258, "entity_type": "ad_user", "domain_id": None, "server_id": None},
    )
    monkeypatch.setattr(object_facade_v4, "get_entity_workspace_detail_data", lambda **_kwargs: {
        "entity": {
            "id": 1258,
            "type": "ad_user",
            "natural_key": "example\\account",
            "display_name": "Учётная запись",
            "first_seen_utc": None,
            "last_seen_utc": None,
            "latest_state": None,
        },
        "current_states": [],
        "ad_context": {"resolution": "not_observed", "items": []},
        "events": [],
        "events_state": "available",
        "has_more": False,
    })
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", lambda *_args, **_kwargs: [])

    result = object_facade_v4.object_detail(None, object_type="ad_user", object_id="1258")

    assert result["object"]["object_type"] == "ad_user"
    assert result["actions"] == ["copy_link"]


def test_object_facade_exposes_timed_out_events_as_a_limitation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(object_facade_v4, "effective_access", lambda _principal: {
        "capabilities": ["objects.view", "field.security", "evidence.exact"],
    })
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 1472, "entity_type": "asset", "domain_id": None, "server_id": None},
    )
    monkeypatch.setattr(object_facade_v4, "get_entity_workspace_detail_data", lambda **_kwargs: {
        "entity": {"id": 1472, "type": "asset", "display_name": "Узел", "natural_key": "host"},
        "current_states": [], "ad_context": {"resolution": "not_observed", "items": []},
        "events": [], "events_state": "temporarily_unavailable", "has_more": False,
    })
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", lambda *_args, **_kwargs: [])

    result = object_facade_v4.object_detail(None, object_type="asset", object_id="1472")

    assert result["state"] == "available"
    assert result["events_state"] == "temporarily_unavailable"
    assert any("Лента событий временно недоступна" in item for item in result["limitations"])


def test_object_search_filters_each_row_by_resource_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    access = {
        "capabilities": ["objects.view", "field.technical"],
        "resource_bound_capabilities": [],
        "capability_policies": [{
            "capability_key": "objects.view", "effect": "deny",
            "scope": {"kind": "server", "ids": [9]}, "valid": True,
        }],
    }
    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", lambda *_args, **_kwargs: [
        {"id": 7, "object_type": "ad_user", "display_name": "Разрешённый объект", "natural_key": "allowed", "server_id": 7, "domain_id": 1},
        {"id": 9, "object_type": "ad_user", "display_name": "Закрытый объект", "natural_key": "denied", "server_id": 9, "domain_id": 1},
    ])

    result = object_facade_v4.search_objects(None, access=access)

    assert [item["object_id"] for item in result["items"]] == ["7"]
    assert result["items"][0]["natural_key"] == "allowed"
    assert result["scope_filtered"] is True


def test_object_detail_applies_scoped_fields_and_explicit_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 7, "entity_type": "ad_user", "domain_id": 1, "server_id": 7},
    )
    monkeypatch.setattr(object_facade_v4, "get_entity_workspace_detail_data", lambda **_kwargs: {
        "entity": {"id": 7, "type": "ad_user", "display_name": "Рабочая учётная запись", "natural_key": "project\\account"},
        "ad_context": {"resolution": "resolved", "items": [{"context_kind": "entity", "attributes": {"department": "ИБ", "object_sid": "S-1"}}]},
        "events": [], "events_state": "available", "has_more": False, "current_states": [],
    })

    def rows(sql: str, *_args, **_kwargs):
        if "storage_v2_observed_at_utc" in sql:
            return [{
                "domain_id": 1,
                "server_id": 7,
                "storage_v2_observed_at_utc": None,
            }]
        return []

    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", rows)
    scoped_access = {
        "capabilities": [],
        "resource_bound_capabilities": ["objects.view", "field.hr"],
        "capability_policies": [
            {"capability_key": "objects.view", "effect": "allow", "scope": {"kind": "server", "ids": [7]}, "valid": True},
            {"capability_key": "field.hr", "effect": "allow", "scope": {"kind": "server", "ids": [7]}, "valid": True},
            {"capability_key": "field.technical", "effect": "deny", "scope": {"kind": "server", "ids": [7]}, "valid": True},
        ],
    }

    result = object_facade_v4.object_detail(None, object_type="ad_user", object_id="7", access=scoped_access)
    assert result["directory_context"]["items"][0]["attributes"] == {"department": "ИБ"}
    assert result["object"]["natural_key"] is None

    denied_access = {
        "capabilities": ["objects.view"],
        "resource_bound_capabilities": [],
        "capability_policies": [{
            "capability_key": "objects.view", "effect": "deny",
            "scope": {"kind": "server", "ids": [7]}, "valid": True,
        }],
    }
    with pytest.raises(ValueError, match="object_not_found"):
        object_facade_v4.object_detail(None, object_type="ad_user", object_id="7", access=denied_access)

    # Same principal, base module check missing entirely (not just out of
    # resource scope): distinct signal from the scoped-deny case above, so
    # objects.py's exception mapping keeps 403 for "no objects.view at all"
    # while the scoped-deny case above now maps to the same 404 as a missing
    # object, per R10 (no existence leak once objects.view is granted).
    no_capability_access = {"capabilities": [], "resource_bound_capabilities": [], "capability_policies": []}
    with pytest.raises(PermissionError, match="objects_view_required"):
        object_facade_v4.object_detail(None, object_type="ad_user", object_id="7", access=no_capability_access)


def test_object_detail_projects_nested_ad_context_fields_by_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 11, "entity_type": "ad_computer", "domain_id": 1, "server_id": None},
    )
    monkeypatch.setattr(object_facade_v4, "get_entity_workspace_detail_data", lambda **_kwargs: {
        "entity": {
            "id": 11,
            "type": "ad_computer",
            "display_name": "Рабочий сервер",
            "natural_key": "ad:domain:computer",
        },
        "ad_context": {
            "resolution": "shared_entity_id",
            "items": [{
                "context_kind": "entity",
                "attributes": {
                    "record_key": "ad:domain:computer",
                    "identity": {
                        "kind": "ad_computer",
                        "object_sid": "S-1-5-21-11",
                    },
                    "attributes": {
                        "display_name": "Рабочий сервер",
                        "operating_system": "Windows Server",
                        "dns_host_name": "server.host13.example.invalid",
                        "unknown_secret": "hidden",
                    },
                },
            }],
        },
        "events": [],
        "events_state": "available",
        "has_more": False,
        "current_states": [],
    })

    def rows(sql: str, *_args, **_kwargs):
        if "storage_v2_observed_at_utc" in sql:
            return [{
                "domain_id": 1,
                "server_id": None,
                "storage_v2_observed_at_utc": None,
            }]
        return []

    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", rows)
    access = {
        "capabilities": [
            "objects.view",
            "field.identity_basic",
            "field.security",
            "field.technical",
        ],
    }

    result = object_facade_v4.object_detail(
        None,
        object_type="ad_computer",
        object_id="11",
        access=access,
    )

    assert result["directory_context"]["items"][0]["attributes"] == {
        "display_name": "Рабочий сервер",
        "operating_system": "Windows Server",
        "dns_host_name": "server.host13.example.invalid",
        "kind": "ad_computer",
        "object_sid": "S-1-5-21-11",
        "record_key": "ad:domain:computer",
    }


def test_migration_035_contains_composite_access_and_registered_reports() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "035_sli_v4_access_reports_objects.sql").read_text(encoding="utf-8").lower()
    for table in (
        "access_packages", "access_group_members", "access_subject_packages",
        "access_capability_assignments", "access_report_assignments",
        "report_datasets_v4", "report_registry_v4", "access_audit_v4",
        "object_identity_links",
    ):
        assert f"create table if not exists {table}" in sql
    assert "reports.export" in sql
    assert "on conflict" in sql


def test_migration_036_registers_vpn_dataset_report_and_ad_auditor_access() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "036_ad_audit_vpn_gpo_source.sql").read_text(encoding="utf-8").lower()
    rollback = (ROOT / "config" / "postgres_migrations" / "036_ad_audit_vpn_gpo_source.rollback.sql").read_text(encoding="utf-8").lower()
    assert "'ad.accounts.vpn'" in sql
    assert "'vpn.audit'" in sql
    assert "package.package_key='ad_auditor'" in sql
    assert "array['identity_basic','technical','security','privilege','hr','contact']" in sql
    assert "insert into schema_migrations(version,name) values(36" in sql
    assert "delete from schema_migrations where version=36" in rollback


def test_migration_037_registers_exact_platform_owner_without_role_widening() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "037_platform_owner_access.sql").read_text(encoding="utf-8").lower()
    rollback = (ROOT / "config" / "postgres_migrations" / "037_platform_owner_access.rollback.sql").read_text(encoding="utf-8").lower()
    assert "create table if not exists access_platform_owners" in sql
    assert "lower(username)='platform-owner'" in sql
    assert "owner_key='primary'" in sql
    assert "insert into schema_migrations(version,name) values(37,'platform_owner_access')" in sql
    assert "access_role_packages" not in sql
    assert "delete from schema_migrations where version=37" in rollback


def test_stage6_access_request_migration_is_bounded_and_reversible() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "040_stage6_report_access_requests.sql").read_text(encoding="utf-8").lower()
    rollback = (ROOT / "config" / "postgres_migrations" / "040_stage6_report_access_requests.rollback.sql").read_text(encoding="utf-8").lower()
    assert "create table if not exists report_access_requests_v4" in sql
    assert "report_access_requests_v4_active_unique" in sql
    assert "requested_scope_json" in sql
    assert "request_profile_json" in sql
    assert "insert into schema_migrations(version,name)" in sql
    assert "drop table if exists report_access_requests_v4" in rollback
    assert "delete from schema_migrations" in rollback


def test_stage6_report_workspace_migration_registers_entity_links_and_gpo_sections() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "041_stage6_report_workspaces.sql").read_text(encoding="utf-8").lower()
    rollback = (ROOT / "config" / "postgres_migrations" / "041_stage6_report_workspaces.rollback.sql").read_text(encoding="utf-8").lower()
    assert sql.count('"key":"object_id"') == 4
    for field in (
        "application_state", "link_count", "scope", "purpose",
        "review_reason", "settings", "signals", "next_steps",
    ):
        assert f'"key":"{field}"' in sql
    assert "report.report_key in ('ad.state','ad.privileged','vpn.audit','ad.gpo.review')" in sql
    assert "values(41,'stage6_report_workspaces')" in sql
    assert "delete from schema_migrations" in rollback


def test_stage6_report_runtime_exposes_registered_entity_and_gpo_fields() -> None:
    assert reporting_v4.RUNTIME_SORT_FIELDS["ad.accounts.privileged"]["object_id"] == "source_entity.id"
    assert reporting_v4.RUNTIME_SORT_FIELDS["ad.accounts.vpn"]["object_id"] == "source_entity.id"
    assert reporting_v4.RUNTIME_SORT_FIELDS["ad.audit.snapshot"]["object_id"] == "entity.id"
    assert {
        "object_id", "natural_key", "application_state", "link_count", "scope",
        "purpose", "review_reason", "settings", "signals", "next_steps",
    } <= reporting_v4.RUNTIME_SORT_FIELDS["ad.gpo.governance"].keys()


def test_access_request_reviewer_can_only_narrow_scope() -> None:
    from server.sli.access.access_requests_v4 import _scope_is_subset

    assert _scope_is_subset({"kind": "server", "ids": ["DC1"]}, {"kind": "all"})
    assert _scope_is_subset(
        {"kind": "server", "ids": ["DC1"]},
        {"kind": "server", "ids": ["DC1", "DC2"]},
    )
    assert not _scope_is_subset(
        {"kind": "server", "ids": ["DC1", "DC2"]},
        {"kind": "server", "ids": ["DC1"]},
    )
    assert not _scope_is_subset(
        {"kind": "domain", "ids": ["host12.example.invalid"]},
        {"kind": "server", "ids": ["DC1"]},
    )


def test_vite_build_is_staged_before_python_server_publish() -> None:
    config = (ROOT / "frontend" / "vite.config.ts").read_text(encoding="utf-8")
    static_routes = (ROOT / "server" / "api" / "routes" / "static.py").read_text(encoding="utf-8")
    assert 'outDir: "../artifacts/frontend/react-build"' in config
    assert 'outDir: "../web/app/react"' not in config
    assert "fingerprintTree" in config
    assert "productSourceFingerprint" in config
    assert "entryFileNames" in config
    assert 'def _react_web_root() -> Path:' in static_routes
    assert 'override = os.environ.get("ADLOG_REACT_WEB_DIR", "").strip()' in static_routes
    assert 'return Path(override).resolve() if override else (WEB_DIR / "react").resolve()' in static_routes


def test_production_object_route_redirects_to_the_single_entity_card() -> None:
    source = (ROOT / "frontend" / "src" / "product-main.tsx").read_text(encoding="utf-8")
    assert "sli-parity" not in source
    assert "styles.css" not in source
    assert "product-parity.css" not in source
    assert "ObjectDetailV4ExactPage" not in source
    assert "ObjectDetailV4Page" not in source
    assert 'path: "/entities/$entityId", component: EntityCardPage' in source
    assert 'path: "/objects/$objectType/$objectId", beforeLoad' in source
    assert "objectRouteRedirect(params.objectId, location.search" in source


def test_prototype_object_identifiers_are_isolated_from_live_page_source() -> None:
    live_pages = "".join(
        (ROOT / "frontend" / "src" / "app" / name).read_text(encoding="utf-8")
        for name in ("reports-catalog.tsx", "report-viewer.tsx", "report-labels.ts")
    ).casefold()
    fixture_entry = (ROOT / "frontend" / "src" / "sli-v4" / "fixture-main.tsx").read_text(encoding="utf-8").casefold()

    for marker in ("ivanov", "vpnl2tp", "adm-kuznetsov", "svc-backup"):
        assert marker not in live_pages
        assert marker in fixture_entry
    objects_page = (ROOT / "frontend" / "src" / "app" / "objects.tsx").read_text(encoding="utf-8").casefold()
    for marker in ("ivanov", "vpnl2tp", "adm-kuznetsov", "svc-backup"):
        assert marker not in objects_page
    assert "__sli_v4_fixture_presentation__" not in live_pages
    assert "__sli_v4_fixture_presentation__" not in objects_page
    assert "__sli_v4_fixture_presentation__" in fixture_entry


@pytest.fixture(autouse=True)
def _hygiene_settings(monkeypatch):
    from server.sli.core import platform_settings

    monkeypatch.setattr(platform_settings, "_stored_row", lambda _key: None)
