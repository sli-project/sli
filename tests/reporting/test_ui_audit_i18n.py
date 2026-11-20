from __future__ import annotations

import pytest

from server.sli.access.access_control_v4 import _access_explanation_code
from server.sli.reporting.v2.reports import ad_state, security_problems
from server.sli.semantic.event_card_semantics import build_event_card


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ({"allowed": True, "is_platform_owner": True, "explicit_deny": True}, "platform_owner"),
        ({"allowed": True, "resource_context_required": True}, "resource_context"),
        ({"allowed": True}, "assignment_policy"),
        ({"explicit_deny": True, "missing": True}, "explicit_deny"),
        ({"missing": True, "has_assignment_source": True}, "missing_capabilities"),
        ({"has_assignment_source": True}, "version_review"),
        ({}, "not_assigned"),
    ],
)
def test_access_explanation_code_describes_the_existing_decision(flags, expected) -> None:
    options = dict.fromkeys((
        "allowed", "is_platform_owner", "resource_context_required", "explicit_deny",
        "missing", "has_assignment_source", "assigned",
    ), False)
    assert _access_explanation_code(**(options | flags)) == expected


def test_infrastructure_context_carries_codes_and_original_values() -> None:
    control = {
        "control_id": "dc.dns", "entity_id": 1, "actual_value": False,
        "authority": "collector_diagnostic", "object_context": {"site_name": "Fixture", "is_read_only": False},
    }
    row = ad_state._row(control)
    assert row["context"] == [
        {"code": "site_name", "label": "Сайт", "value": "Fixture", "presentation_messages": {
            "label": {"code": "reports.v2.ad.infrastructure.context_labels.site_name", "params": {}, "text": "Сайт"},
        }},
        {"code": "is_read_only", "label": "RODC", "value": "Нет", "presentation_messages": {
            "label": {"code": "reports.v2.ad.infrastructure.context_labels.is_read_only", "params": {}, "text": "RODC"},
            "value": {"code": "reports.boolean.no", "params": {}, "text": "Нет"},
        }},
    ]
    assert row["actual_value"] is False
    assert row["object_context"] == control["object_context"]


def test_problem_presentation_carries_code_without_changing_source_identity() -> None:
    finding = {"id": 1, "title": "Audit policy was changed", "actor": "sid:fixture:S-1-5-18"}
    row = security_problems._row(finding, {})
    assert row["presentation_code"] == "audit_policy_changed"
    assert row["actor"] == finding["actor"]
    assert row["title_text"] == "Изменена политика аудита Windows"
    unknown = security_problems.presentation({"id": 2, "title": "Fixture custom rule"})
    assert unknown["presentation_code"] is None
    assert unknown["title_text"] == "Fixture custom rule"



def test_builtin_l1_problems_have_plain_wording() -> None:
    for title, code, ru in (
        ("Member was added to a privileged group", "privileged_group", "Учётную запись добавили в группу администраторов"),
        ("Scheduled task was registered", "scheduled_task", "На компьютере создана задача планировщика"),
        ("Security event log was cleared", "eventlog_cleared", "Очищен журнал безопасности"),
    ):
        row = security_problems._row({"id": 3, "title": title}, {})
        assert row["presentation_code"] == code
        assert row["title_text"] == ru
        assert row["what_happened"] and row["next_text"]
        assert row["wording_limitation"] is None

def test_event_fact_and_check_codes_are_aligned_without_containing_source_values() -> None:
    card = build_event_card({
        "event_id": 4719, "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
        "server": "fixture-host", "event_data": {},
    })
    assert card["fact_label_codes"] == ["facts.event", "facts.server"]
    assert len(card["fact_label_codes"]) == len(card["facts"])
    assert card["check_codes"] == ["Security:Microsoft-Windows-Security-Auditing:4719.checks.0"]
    assert len(card["check_codes"]) == len(card["checks"])
    assert card["facts"][1][1] == "fixture-host"
    assert "fixture-host" not in str(card["fact_label_codes"] + card["check_codes"])


def test_metadata_timeline_title_code_preserves_unknown_classification() -> None:
    from server.sli.reporting.ui_api_models import InvestigationTimelineItem
    from server.sli.reporting.ui_workspace import (
        _metadata_timeline_source,
        _timeline_item,
    )

    source = _metadata_timeline_source({
        "event_db_id": 1, "event_id": 4624, "channel": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing", "time_created_utc": "2026-01-01T00:00:00Z",
    }, "Fixture inclusion reason")
    item = InvestigationTimelineItem.model_validate(_timeline_item(source))
    assert item.title_code == "Security:Microsoft-Windows-Security-Auditing:4624.title"
    assert item.severity == "unknown"
    assert item.classification_origin == "unavailable"
    assert item.summary_code is None
