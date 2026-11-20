from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.support.pg_fake import FakePgStore


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> FakePgStore:
    return FakePgStore().install_security_monitor(monkeypatch)


def _add_event(store: FakePgStore, *, record_id: int, event_id: int, subject: str, target: str) -> int:
    ts = datetime.now(timezone.utc).isoformat()
    return store.add_event(
        event_id=event_id, time=ts, record_id=record_id, subject=subject, target=target,
        ip="192.0.2.2", workstation="WS01", message="test event",
        event_data={"TargetUserName": target},
    )


def test_24h_summary_is_not_limited_to_first_2000_rows(store: FakePgStore) -> None:
    from server.sli.events.security_events_monitor import get_security_events_24h_summary, get_security_events_monitor_data

    ts = datetime.now(timezone.utc).isoformat()
    for index in range(1, 2106):
        store.add_event(
            event_id=4625, time=ts, record_id=index, subject="user", target="user",
            ip="192.0.2.2", workstation="WS01", message="failed logon",
            event_data={"TargetUserName": "user"},
        )

    data = get_security_events_monitor_data(period="24h", limit=10)
    assert data["returned_count"] == 10
    assert data["matched_total"] == 2105
    assert data["truncated"] is True
    assert data["category_counts"]["failed_logons"] == 2105

    summary = get_security_events_24h_summary()
    assert summary["important_total"] == 2105
    assert summary["failed_logons"] == 2105


def test_4648_is_explicit_credentials_and_evidence_link_is_exact(store: FakePgStore) -> None:
    from server.sli.events.security_events_monitor import get_security_events_monitor_data

    event_db_id = _add_event(store, record_id=1, event_id=4648, subject="svc_backup", target="administrator")

    data = get_security_events_monitor_data(event_id=4648, limit=10)
    assert data["matched_total"] == 1
    item = data["items"][0]
    assert item["group"] == "explicit_credentials"
    assert item["severity"] == "info"
    assert item["service_candidate"] is True
    assert f"event_db_id={event_db_id}" in item["evidence_url"]


def test_service_filter_is_applied_before_row_limit(store: FakePgStore) -> None:
    from server.sli.events.security_events_monitor import get_security_events_monitor_data

    for record_id in range(1, 31):
        _add_event(store, record_id=record_id, event_id=4625, subject="ordinary_user", target="ordinary_user")
    _add_event(store, record_id=31, event_id=4625, subject="svc_backup", target="svc_backup")

    data = get_security_events_monitor_data(only_service=True, limit=1)
    assert data["matched_total"] == 1
    assert data["returned_count"] == 1
    assert data["items"][0]["service_candidate"] is True


def _add_task_scheduler_event(store: FakePgStore, record_id: int, task_name: str, user: str) -> int:
    return store.add_event(
        event_id=140, time=datetime.now(timezone.utc).isoformat(), record_id=record_id,
        provider="Microsoft-Windows-TaskScheduler",
        channel="Microsoft-Windows-TaskScheduler/Operational", message="task updated",
        subject=None, subject_domain=None, target=None, target_domain=None,
        event_data={"TaskName": task_name, "UserName": user},
    )


def test_task_scheduler_140_uses_catalog_context_in_monitor(store: FakePgStore) -> None:
    from server.sli.events.security_events_monitor import get_security_events_monitor_data

    _add_task_scheduler_event(
        store, 140,
        r"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant",
        r"EXAMPLE\DC1$",
    )

    data = get_security_events_monitor_data(event_id=140, limit=10)
    assert data["items"][0]["severity"] == "medium"
    assert data["items"][0]["tier"] == "important"
    # Storage V2 facts keep TaskName but not the 140 event's UserName, so the
    # catalog rule that needs the acting account cannot lower the confidence.
    assert data["items"][0]["assessment_confidence"] == "medium"
    assert data["items"][0]["assessment_confidence_label"] == "средняя"
    assert data["data_quality"]["semantic_projection"] == "catalog_event_card_v1"


def test_task_scheduler_140_risk_filter_matches_catalog_indicators(store: FakePgStore) -> None:
    from server.sli.semantic.event_card_semantics import build_event_card
    from server.sli.events.security_events_monitor import get_security_events_monitor_data

    _add_task_scheduler_event(store, 140, r"\Microsoft\Windows\ServerCeipAssistant", r"EXAMPLE\\DC1$")
    _add_task_scheduler_event(store, 141, r"\Temp\bad.ps1", r"EXAMPLE\\DC1$")

    high = get_security_events_monitor_data(event_id=140, risk="high", limit=10)
    medium = get_security_events_monitor_data(event_id=140, risk="medium", limit=10)
    normal_card = build_event_card(
        {
            "event_id": 140,
            "channel": "Microsoft-Windows-TaskScheduler/Operational",
            "provider_name": "Microsoft-Windows-TaskScheduler",
            "server": "DC1",
            "event_data": {"TaskName": r"\Microsoft\Windows\ServerCeipAssistant", "UserName": r"EXAMPLE\DC1$"},
        }
    )
    dangerous_card = build_event_card(
        {
            "event_id": 140,
            "channel": "Microsoft-Windows-TaskScheduler/Operational",
            "provider_name": "Microsoft-Windows-TaskScheduler",
            "server": "DC1",
            "event_data": {"TaskName": r"\Temp\bad.ps1", "UserName": r"EXAMPLE\DC1$"},
        }
    )

    assert high["matched_total"] == 1
    assert high["items"][0]["severity"] == dangerous_card["final_risk"] == "high"
    assert high["category_counts"]["high"] == 1
    assert medium["matched_total"] == 1
    assert medium["items"][0]["severity"] == normal_card["final_risk"] == "medium"
    assert medium["category_counts"]["medium"] == 1
    assert high["data_quality"]["semantic_filter_exact"] is True
    assert high["data_quality"]["semantic_filter_limitations"] == []


def test_4672_is_context_only_and_never_promoted_to_high_risk(store: FakePgStore) -> None:
    from server.sli.semantic.event_card_semantics import build_event_card
    from server.sli.events.security_events_monitor import get_security_events_monitor_data

    _add_event(store, record_id=4672, event_id=4672, subject="administrator", target="administrator")

    canonical = build_event_card(
        {
            "event_id": 4672,
            "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "server": "DC1",
            "event_data": {},
        }
    )
    info = get_security_events_monitor_data(event_id=4672, risk="info", limit=10)
    high = get_security_events_monitor_data(event_id=4672, risk="high", limit=10)

    assert canonical["final_risk"] == "info"
    assert info["matched_total"] == 1
    assert info["items"][0]["severity"] == canonical["final_risk"]
    assert info["category_counts"]["medium"] == 0
    assert info["category_counts"]["high"] == 0
    assert high["matched_total"] == 0
