from __future__ import annotations

from pathlib import Path

import pytest

from server.api.routes.reports import _v4_report_query_filters
from server.sli.reporting import reporting_v4


def test_gpo_runtime_filters_are_server_owned_and_typed() -> None:
    fields = reporting_v4.RUNTIME_FILTER_FIELDS["ad.gpo.governance"]
    assert set(fields) == {"application_state", "link_count"}
    assert "attributes_json" in fields["application_state"]
    assert "attributes_json" in fields["link_count"]

    clauses, params, _ = reporting_v4._compile_definition_query(
        "ad.gpo.governance",
        {
            "filters": [
                {"field": "application_state", "op": "eq", "value": "disabled"},
                {"field": "link_count", "op": "eq", "value": "0"},
            ],
            "sort": [],
        },
    )
    assert clauses == [
        f"{fields['application_state']}=?",
        f"{fields['link_count']}=?",
    ]
    assert params == ["disabled", 0]

    with pytest.raises(ValueError, match="invalid_filter_value"):
        reporting_v4._compile_definition_query(
            "ad.gpo.governance",
            {
                "filters": [
                    {"field": "link_count", "op": "eq", "value": "many"}
                ],
                "sort": [],
            },
        )


def test_gpo_summary_counts_full_scope_conditions_without_inventing_risk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, tuple]] = []

    def fake_query(sql: str, params: tuple = (), **_kwargs):
        calls.append((sql, params))
        if "from ad_context_runs run" in sql:
            return []
        return [{
            "total_gpo": 72,
            "missing_owner_count": 72,
            "unlinked_policy_count": 13,
            "disabled_policy_count": 14,
            "partially_enabled_policy_count": 1,
            "executable_component_policy_count": 7,
            "executable_component_total_count": 11,
            "setting_policy_count": 9,
            "setting_total_count": 37,
            "sensitive_value_policy_count": 2,
            "manual_review_count": 22,
            "latest_observed_at_utc": "2026-08-02T00:00:00Z",
        }]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_query)
    summary = reporting_v4._gpo_governance_summary(
        " where (entity.domain_id=any(?))",
        [[7]],
        {"identity_basic", "security"},
    )

    assert summary["total_gpo"] == 72
    assert summary["owner_observation_state"] == "not_collected"
    assert summary["unlinked_policy_count"] == 13
    assert summary["disabled_policy_count"] == 14
    assert summary["partially_enabled_policy_count"] == 1
    assert summary["manual_review_count"] == 22
    assert summary["manual_review_basis"] == [
        "link_count_zero",
        "application_state_disabled",
    ]
    assert summary["executable_component_policy_count"] == 7
    assert summary["executable_component_total_count"] == 11
    assert summary["executable_component_risk_qualified"] is False
    assert summary["setting_policy_count"] == 9
    assert summary["setting_total_count"] == 37
    assert summary["sensitive_value_policy_count"] == 2

    aggregate_sql = calls[0][0]
    assert "as unlinked_policy_count" in aggregate_sql
    assert "as disabled_policy_count" in aggregate_sql
    assert "as manual_review_count" in aggregate_sql
    assert "gpo_startup_script_count" in aggregate_sql
    assert "gpo_scheduled_task_count" in aggregate_sql
    assert "missing_owner_count" not in aggregate_sql.split(
        "as manual_review_count", 1
    )[0].rsplit("count(*) filter", 1)[-1]


def test_gpo_summary_does_not_expose_restricted_aggregates() -> None:
    # The category check is also the disclosure boundary for aggregates.
    aggregate = {
        "total_gpo": 1,
        "missing_owner_count": 1,
        "unlinked_policy_count": 1,
        "manual_review_count": 1,
    }

    def fake_query(sql: str, *_args, **_kwargs):
        if "from ad_context_runs run" in sql:
            return []
        return [aggregate]

    original = reporting_v4.query_rows_bounded
    reporting_v4.query_rows_bounded = fake_query
    try:
        summary = reporting_v4._gpo_governance_summary("", [], set())
    finally:
        reporting_v4.query_rows_bounded = original

    assert "total_gpo" not in summary
    assert "manual_review_count" not in summary


def test_gpo_interactive_filter_api_is_narrow_and_fail_closed() -> None:
    parsed = _v4_report_query_filters({
        "application_state": ["disabled"],
        "link_count": ["0"],
    })
    assert parsed == {"application_state": "disabled", "link_count": "0"}
    clauses, params = reporting_v4._compile_interactive_report_query(
        "ad.gpo.governance", parsed
    )
    assert clauses == [
        f"{reporting_v4.GPO_APPLICATION_STATE_SQL}=?",
        f"{reporting_v4.GPO_LINK_COUNT_SQL}=?",
    ]
    assert params == ["disabled", 0]

    with pytest.raises(ValueError, match="duplicate_report_query_filter"):
        _v4_report_query_filters({"link_count": ["0", "1"]})
    with pytest.raises(ValueError, match="invalid_report_query_filter"):
        reporting_v4._compile_interactive_report_query(
            "ad.gpo.governance", {"application_state": "dangerous"}
        )
    for value in ("-1", "many", "1000001"):
        with pytest.raises(ValueError, match="invalid_report_query_filter"):
            reporting_v4._compile_interactive_report_query(
                "ad.gpo.governance", {"link_count": value}
            )


def test_gpo_runtime_contract_publishes_observed_evidence_not_fiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "display_name", "natural_key", "application_state", "computer_enabled",
        "user_enabled", "link_count", "link_enabled_count", "link_enforced_count",
        "links", "wmi_filter_present", "wmi_filter_id", "permission_count",
        "permission_custom_count", "security_filtering_sids",
        "security_filtering_deny_sids", "startup_script_count",
        "logon_script_count", "scheduled_task_count", "service_count",
        "local_group_count", "modified_utc", "observed_at",
        "settings",
    }
    assert expected <= set(reporting_v4.DATASET_FIELDS["ad.gpo.governance"])
    assert {
        "priority", "owner", "purpose", "review_reason", "signals",
        "next_steps",
    }.isdisjoint(reporting_v4.DATASET_FIELDS["ad.gpo.governance"])

    captured: list[str] = []

    def fake_query(sql: str, _params: tuple = (), **_kwargs):
        captured.append(sql)
        if "from ad_context_runs run" in sql:
            return []
        if "select count(*) as total_gpo" in sql:
            return [{"total_gpo": 0}]
        return []

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_query)
    monkeypatch.setattr(reporting_v4, "_connect", lambda: (_ for _ in ()).throw(AssertionError("registry fixture required")))

    # The row projection itself is a stable public contract even when registry
    # access is tested separately: it must read values produced by the collector.
    row_sql = reporting_v4.GPO_GOVERNANCE_SELECT_SQL
    for attribute in (
        "gpo_computer_enabled", "gpo_user_enabled", "gpo_link_enabled_count",
        "gpo_link_enforced_count", "links", "gpo_wmi_filter_present",
        "gpo_permission_count", "gpo_startup_script_count",
        "gpo_scheduled_task_count", "gpo_settings", "modified_utc",
    ):
        assert attribute in row_sql
    for fiction in ("priority", "purpose", "review_reason", "next_steps"):
        assert fiction not in row_sql
    assert "^[0-9]{4}-[0-9]{2}-[0-9]{2}T" in row_sql


def test_gpo_interactive_filters_cover_every_actionable_aggregate() -> None:
    parsed = _v4_report_query_filters({
        "application_state": ["partial"],
        "has_executable_components": ["true"],
    })
    assert parsed == {
        "application_state": "partial",
        "has_executable_components": "true",
    }
    clauses, params = reporting_v4._compile_interactive_report_query(
        "ad.gpo.governance", parsed
    )
    assert clauses == [
        f"{reporting_v4.GPO_APPLICATION_STATE_SQL} in (?,?)",
        f"({reporting_v4.GPO_EXECUTABLE_COUNT_SQL})>0",
    ]
    assert params == ["computer_only", "user_only"]

    with pytest.raises(ValueError, match="invalid_report_query_filter"):
        reporting_v4._compile_interactive_report_query(
            "ad.gpo.governance", {"has_executable_components": "sometimes"}
        )


def test_gpo_migration_republishes_evidence_contract_and_controlled_export() -> None:
    root = Path(__file__).resolve().parents[2]
    migration = (root / "config/postgres_migrations/104_gpo_evidence_first_v1.sql").read_text(encoding="utf-8")
    rollback = (root / "config/postgres_migrations/104_gpo_evidence_first_v1.rollback.sql").read_text(encoding="utf-8")

    for field in (
        "security_filtering_sids", "scheduled_task_count", "modified_utc",
        "has_executable_components",
    ):
        assert field in migration
    assert "'{export_policy}'" in migration
    assert "'\"controlled\"'::jsonb" in migration
    assert "allowed_actions || array['export']" in migration
    assert "priority" not in migration
    assert "review_reason" not in migration
    assert "array_remove(allowed_actions,'export')" in rollback


def test_gpo_settings_migration_publishes_nested_evidence_without_new_grants() -> None:
    root = Path(__file__).resolve().parents[2]
    migration = (root / "config/postgres_migrations/105_gpo_settings_evidence_v2.sql").read_text(encoding="utf-8")
    rollback = (root / "config/postgres_migrations/105_gpo_settings_evidence_v2.rollback.sql").read_text(encoding="utf-8")

    assert '"key":"settings"' in migration
    assert '"category":"security"' in migration
    assert "access_package_reports" not in migration
    assert "access_subject_report_grants" not in migration
    assert "updated_at_utc" not in migration
    assert "updated_at_utc" not in rollback
    assert "report_registry_v4" in migration
    assert "report_definitions_v4" not in migration
    assert "applied_at_utc" not in migration
    assert "105_gpo_settings_evidence_v2" in migration
    assert "field->>'key' <> 'settings'" in rollback
