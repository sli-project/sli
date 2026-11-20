from __future__ import annotations

import pytest


PROVIDER = "Microsoft-Windows-Security-Auditing"


@pytest.mark.parametrize(
    ("event_id", "expected"),
    [
        (4720, {
            "category": "account_management", "purpose_tier": "important",
            "base_risk": "medium", "final_risk": "medium", "noise_class": "signal",
        }),
        (4624, {
            "category": "authentication", "purpose_tier": "technical",
            "base_risk": "low", "final_risk": "low", "noise_class": "context",
        }),
    ],
)
def test_catalog_card_exposes_one_typed_machine_contract(event_id: int, expected: dict[str, str]) -> None:
    from server.sli.semantic.event_card_semantics import build_event_card

    card = build_event_card({
        "id": event_id, "event_id": event_id, "channel": "Security",
        "provider_name": PROVIDER, "server": "DC1", "event_data": {},
    })

    assert {key: card[key] for key in expected} == expected
    assert card["confidence"] in {"high", "medium", "low", "unknown"}
    assert card["severity"] == card["final_risk"]  # transitional machine alias
    assert card["tier"] == card["purpose_tier"]  # transitional machine alias
    assert card["risk"] == card["display_labels"]["risk"]
    assert card["final_security_severity"] == card["final_risk"]
    assert card["assessment_confidence"] == card["confidence"]
    assert card["assessment_confidence_label"] == card["display_labels"]["confidence"]
    assert card["catalog_match"] is True
    assert "catalog_rule_matched" in card["reasons"]


def test_unknown_event_is_explicit_without_invented_semantics() -> None:
    from server.sli.semantic.event_card_semantics import build_event_card

    card = build_event_card({
        "id": 91, "event_id": 999999, "channel": "Unknown",
        "provider_name": "Unknown", "server": "DC1", "event_data": {"raw": "kept"},
    })

    assert card["known"] is False
    assert {key: card[key] for key in (
        "category", "purpose_tier", "base_risk", "final_risk", "confidence", "noise_class"
    )} == {
        "category": "unknown", "purpose_tier": "technical", "base_risk": "unknown",
        "final_risk": "unknown", "confidence": "low", "noise_class": "unknown",
    }

    assert card["final_security_severity"] == "unknown"
    assert card["assessment_confidence"] == "low"
    assert card["catalog_match"] is False
    assert card["reasons"] == ["catalog_rule_missing"]
    assert card["evidence_fields"] == []

    from server.sli.reporting.ui_api_models import EventSemanticsContract
    serialized = EventSemanticsContract(**card).model_dump(mode="json")
    assert serialized["final_risk"] == "unknown"
    assert serialized["final_security_severity"] == "unknown"
    assert serialized["assessment_confidence"] == "low"
    assert serialized["catalog_match"] is False
    assert serialized["display_labels"]["risk"] == card["risk"]


def test_catalog_base_card_is_not_a_contextual_assessment() -> None:
    from server.sli.semantic.event_card_semantics import build_event_card

    card = build_event_card({
        "id": 517548, "event_id": 4624, "channel": "Security",
        "provider_name": PROVIDER, "server": "DC1", "event_data": {},
    })

    assert card["classification_origin"] == "catalog_base"
    assert card["card_completeness"] == "not_applicable"
    assert card["assessment_confidence"] == "unknown"
    assert card["final_risk"] == card["base_risk"] == "low"


def test_contextual_rule_keeps_its_distinct_provenance() -> None:
    from server.sli.semantic.event_card_semantics import build_event_card

    card = build_event_card({
        "event_id": 140,
        "provider_name": "Microsoft-Windows-TaskScheduler",
        "channel": "Microsoft-Windows-TaskScheduler/Operational",
        "server": "DC1",
        "event_data": {
            "TaskName": r"\Custom\Updater",
            "UserName": r"EXAMPLE\admin",
            "Action": r"C:\Temp\payload.ps1",
        },
    })

    assert card["classification_origin"] == "contextual_rule"
    assert card["card_completeness"] == "complete"


def test_contextual_semantics_expose_rule_reason_and_field_names_without_values() -> None:
    from server.sli.semantic.event_card_semantics import build_event_card

    card = build_event_card({
        "event_id": 140,
        "provider_name": "Microsoft-Windows-TaskScheduler",
        "channel": "Microsoft-Windows-TaskScheduler/Operational",
        "server": "DC1",
        "event_data": {
            "TaskName": r"\Custom\Updater",
            "UserName": r"EXAMPLE\admin",
            "Action": r"C:\Temp\payload.ps1",
        },
    })

    assert card["final_security_severity"] == "high"
    assert card["final_risk"] == "high"
    assert "contextual_rule_matched:0" in card["reasons"]
    assert "event_data" in card["evidence_fields"]
    assert "server" in card["evidence_fields"]
    assert all("payload.ps1" not in value for value in card["evidence_fields"])


@pytest.mark.parametrize("source_payload_state", [None, "expired"])
def test_event_list_uses_canonical_semantics_for_catalog_entry_without_card(source_payload_state) -> None:
    from server.sli.semantic.event_card_semantics import build_event_card
    from server.sli.events.event_search import _normalize_search_row
    from server.sli.reporting.ui_api_models import EventListResponse

    row = {
        "id": 4720,
        "event_id": 4720,
        "event_record_id": 17,
        "time_created_utc": "2026-07-17T01:00:00Z",
        "channel": "Security",
        "provider_name": PROVIDER,
        "server": "DC1",
        "event_data_json": "{}",
        "source_payload_state": source_payload_state,
    }
    canonical = build_event_card({**row, "event_data": {}})
    assert canonical["known"] is True
    assert canonical["has_card"] is False

    item = _normalize_search_row(row)
    serialized = EventListResponse(items=[item]).model_dump(mode="json")["items"][0]
    assert serialized["source_payload_state"] == source_payload_state

    for field in (
        "category", "purpose_tier", "base_risk", "final_risk", "confidence", "noise_class"
    ):
        assert item[field] == canonical[field]
        assert serialized[field] == canonical[field]
    assert item["severity"] == canonical["final_risk"] == "medium"
    assert item["tier"] == canonical["purpose_tier"] == "important"
    assert item["category"] == "account_management"


def test_event_list_preserves_legacy_fallback_for_uncatalogued_source() -> None:
    from server.sli.events.event_search import _normalize_search_row

    item = _normalize_search_row({
        "id": 72,
        "event_id": 4720,
        "event_record_id": 72,
        "time_created_utc": "2026-07-17T01:00:00Z",
        "channel": "Unknown",
        "provider_name": "Unknown",
        "server": "DC1",
        "event_data_json": "{}",
    })

    assert item["severity"] == "high"
    assert item["category"] == "account_lifecycle"
    assert item["tier"] is None
    assert item["final_risk"] == "unknown"


@pytest.mark.parametrize(("event_id", "risk"), [(4720, "medium"), (4624, "low")])
def test_investigation_timeline_uses_same_machine_risk_as_event_card(event_id: int, risk: str) -> None:
    from server.sli.semantic.event_card_semantics import build_event_card
    from server.sli.reporting.ui_api_models import InvestigationTimelineItem
    from server.sli.reporting.ui_workspace import _detail_timeline_source, _timeline_item

    event = {
        "id": event_id, "event_db_id": event_id, "event_id": event_id,
        "time_created_utc": "2026-07-17T01:00:00Z", "server": "DC1",
        "channel": "Security", "provider_name": PROVIDER, "event_data": {},
    }
    card = build_event_card(event)
    timeline = _timeline_item(_detail_timeline_source(event, "exact fixture"))
    serialized = InvestigationTimelineItem(**timeline).model_dump(mode="json")

    assert card["final_risk"] == risk
    assert timeline["severity"] == risk
    assert serialized["severity"] == risk
    assert serialized["category"] == card["category"]
    assert serialized["purpose_tier"] == card["purpose_tier"]
    assert serialized["base_risk"] == card["base_risk"]
    assert serialized["confidence"] == card["confidence"]
    assert serialized["noise_class"] == card["noise_class"]
