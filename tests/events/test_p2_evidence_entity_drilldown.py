from __future__ import annotations

import pytest

from tests.support.pg_fake import FakePgStore


def _seed_event_with_entity(store: FakePgStore) -> None:
    event_db_id = store.add_event(
        event_id=4624, time="2026-07-07T10:00:00Z", time_local="2026-07-07 13:00:00", record_id=42,
        server="DCX", computer="DCX", subject="admin", target="alice",
        ip="192.0.2.5", workstation="WS01", logon_id="0x123", message="Successful logon",
        event_data={"LogonType": "10", "IpAddress": "192.0.2.5"},
    )
    entity_id = store.add_entity(
        entity_type="user", natural_key="example\\admin", display_name="EXAMPLE\\admin",
        first_seen="2026-07-07T10:00:00Z", last_seen="2026-07-07T10:00:00Z",
        attributes={"risk_tier": "important"},
    )
    store.add_link(
        event_id=event_db_id, entity_id=entity_id, role="actor",
        extracted_from="event_data.SubjectUserName", attributes={"field": "SubjectUserName"},
    )


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> FakePgStore:
    store = FakePgStore().install_security_monitor(monkeypatch).install_entity_details(monkeypatch)
    _seed_event_with_entity(store)
    return store


def test_event_detail_urls_keep_time_window_and_multi_event_ids() -> None:
    from server.sli.events.event_details import make_event_detail_url

    url = make_event_detail_url(event_ids=[4624, 4625], servers=["DCX"], time_from="2026-07-07T09:55:00Z")
    assert "event_id=4624%2C4625" in url
    assert "time_from=2026-07-07T09%3A55%3A00Z" in url


def test_event_details_serve_only_one_exact_storage_v2_event(monkeypatch: pytest.MonkeyPatch) -> None:
    """V1 relations are gone (plan 6.5): a filter list is refused, an exact ID is served."""
    from server.sli.events import event_details

    monkeypatch.setattr(event_details, "is_postgres_runtime_db", lambda: True)
    with pytest.raises(ValueError, match="storage_v2_detail_requires_exact_event_id"):
        event_details.get_event_detail_report_data(event_id="4624,4625", servers=["DCX"])

    monkeypatch.setattr(event_details, "_get_v2_event_detail_by_id", lambda filters, **_kwargs: {
        "id": filters["event_db_id"], "server": "DCX", "channel": "Security", "event_id": 4624,
        "event_record_id": 42, "time_created_utc": "2026-07-07T10:00:00Z", "subject_user_name": "admin",
        "target_user_name": "alice", "event_data_json": '{"LogonType": "10"}',
    })
    monkeypatch.setattr(event_details, "log_event", lambda *_a, **_k: None)
    data = event_details.get_event_detail_report_data(event_db_id=7)
    assert data["total"] == 1
    assert data["items"][0]["id"] == 7
    assert data["items"][0]["event_record_id"] == 42
    html = event_details.render_event_detail_report(data)
    assert 'target="_blank"' not in html


def test_entity_details_report_shows_entity_role_and_events(store: FakePgStore) -> None:
    from server.sli.entities.entity_details import get_entity_detail_report_data, render_entity_detail_report

    data = get_entity_detail_report_data(q="EXAMPLE\\admin", role="actor", event_id=4624)
    assert data["entity"]["display_name"] == "EXAMPLE\\admin"
    assert data["total"] == 1
    assert data["items"][0]["link_role"] == "actor"
    assert data["items"][0]["event_id"] == 4624

    html = render_entity_detail_report(data)
    assert "Entity drill-down" in html
    assert "actor" in html
    assert "EXAMPLE\\admin" in html
    assert "event_db_id=" in html


def test_event_card_uses_catalog_semantics_for_task_scheduler_140() -> None:
    from server.sli.semantic.event_card_semantics import build_event_card

    card = build_event_card(
        {
            "event_id": 140,
            "provider_name": "Microsoft-Windows-TaskScheduler",
            "channel": "Microsoft-Windows-TaskScheduler/Operational",
            "server": "DC1",
            "event_data": {
                "TaskName": r"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant",
                "UserName": r"EXAMPLE\DC1$",
            },
        }
    )

    assert card["known"] is True
    assert card["title"] == "Изменено задание планировщика Windows"
    assert card["risk"] == "Требует проверки"
    assert ("Задание", r"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant") in card["facts"]
    assert ("Кто выполнил изменение", r"EXAMPLE\DC1$") in card["facts"]
    assert "Регистрация задания успешно обновлена" in dict(card["facts"]).values()
    assert any("цифровую подпись" in value for value in card["checks"])
    assert card["assessment_confidence"] == "low"
    assert card["assessment_confidence_label"] == "низкая"


def test_fast_search_keeps_catalogue_action_name() -> None:
    """The list view must not discard a verified source-pack interpretation."""
    from server.sli.events.event_search import _normalize_search_row

    row = _normalize_search_row(
        {
            "id": 42,
            "event_id": 140,
            "provider_name": "Microsoft-Windows-TaskScheduler",
            "channel": "Microsoft-Windows-TaskScheduler/Operational",
            "server": "DC1",
            "event_data_json": '{"TaskName":"\\\\Microsoft\\\\Windows\\\\Task"}',
        }
    )

    assert row["label"] == "Изменено задание планировщика Windows"


def test_task_name_prefix_does_not_prove_builtin_scheduler_task() -> None:
    from server.sli.semantic.event_card_semantics import build_event_card

    card = build_event_card(
        {
            "event_id": 140,
            "provider_name": "Microsoft-Windows-TaskScheduler",
            "channel": "Microsoft-Windows-TaskScheduler/Operational",
            "server": "DC1",
            "event_data": {"TaskName": r"\Microsoft\Windows\FakeBackdoor", "UserName": r"EXAMPLE\DC1$"},
        }
    )

    assert card["severity"] == "medium"
    assert card["assessment_confidence"] == "low"
    assert card["assessment_confidence_label"] == "низкая"

    catalog = __import__("pathlib").Path("config/event_catalog.json").read_text(encoding="utf-8")
    analysis = __import__("pathlib").Path("server/sli/reports/analysis.py").read_text(encoding="utf-8")
    assert '"builtin_task"' not in catalog
    assert "системные задачи Windows" not in analysis


def test_event_card_unknown_event_is_honest_about_missing_catalog() -> None:
    from server.sli.semantic.event_card_semantics import build_event_card

    card = build_event_card({"event_id": 999999, "provider_name": "Unknown", "channel": "Unknown", "server": "DC1", "event_data": {"Field": "value"}})

    assert card["known"] is False
    assert card["title"] == "Событие пока не расшифровано каталогом"
    assert "Provider + Channel + Event ID" in card["technical_reason"]


def test_entity_extraction_uses_catalog_initiator_mapping_for_task_scheduler() -> None:
    from server.sli.entities.entity_model import extract_event_entities

    links = extract_event_entities(
        {
            "event_id": 140,
            "provider_name": "Microsoft-Windows-TaskScheduler",
            "channel": "Microsoft-Windows-TaskScheduler/Operational",
            "computer_name": "DC1",
        },
        {
            "TaskName": r"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant",
            "UserName": r"EXAMPLE\DC1$",
        },
    )

    assert any(link["entity_type"] == "scheduled_task" and link["link_role"] == "target" for link in links)
    actor = next(link for link in links if link["link_role"] == "actor")
    assert actor["entity_type"] == "ad_computer"
    assert actor["display_name"] == r"EXAMPLE\DC1$"


def test_catalogued_task_change_projects_an_entity_state() -> None:
    from server.sli.entities.entity_state_model import state_for_entity_link

    state = state_for_entity_link(
        {
            "event_id": 140,
            "provider_name": "Microsoft-Windows-TaskScheduler",
            "channel": "Microsoft-Windows-TaskScheduler/Operational",
            "time_created": "2026-07-16T00:00:00Z",
        },
        {"TaskName": r"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant"},
        {"link_role": "target"},
    )

    assert state is not None
    assert state["state_type"] == "scheduled_task.configuration"
    assert state["status"] == "changed"
    assert state["rule_id"] == "scheduled-task-changed-140"
    assert state["observed_at_utc"] == "2026-07-16T00:00:00Z"
    assert state["summary"] == "Изменено задание планировщика Windows"


def test_event_relations_never_return_self_link_as_related_evidence(monkeypatch) -> None:
    from server.sli.events import event_relations

    def rows(sql, _params, **_kwargs):
        if "left join event_facts_v2 base_fact" in sql:
            return [{"server_id": 7, "time_created_utc": "2026-07-17T07:15:51Z", "logon_id": "0x1", "task_name": None}]
        return [{"related_event_db_id": 20, "entity_type": "auth_session", "entity": "0x1",
                 "time_delta_seconds": 0, "relation_rule": "same_logon_id_same_server"}]

    monkeypatch.setattr(event_relations, "query_rows_bounded", rows)
    monkeypatch.setattr(event_relations, "is_postgres_runtime_db", lambda: True)
    assert event_relations.get_event_relations(20)["items"] == []


def test_event_relations_require_postgres_storage_v2(monkeypatch) -> None:
    from server.sli.events import event_relations

    monkeypatch.setattr(event_relations, "is_postgres_runtime_db", lambda: False)
    monkeypatch.setattr(event_relations, "query_rows_bounded", lambda *_a, **_k: pytest.fail("no read without PostgreSQL"))
    with pytest.raises(ValueError, match="storage_v2_route_requires_postgres"):
        event_relations.get_event_relations(20)


def test_event_relations_correlate_storage_v2_events_by_logon_id(monkeypatch) -> None:
    from server.sli.events import event_relations

    calls: list[str] = []

    def rows(sql, _params, **_kwargs):
        calls.append(sql)
        if "left join event_facts_v2 base_fact" in sql:
            return [{
                "server_id": 7,
                "time_created_utc": "2026-07-17T07:15:51Z",
                "logon_id": "0x123",
                "task_name": None,
            }]
        if "other_event.logon_id = ?" in sql:
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
        return []

    monkeypatch.setattr(event_relations, "query_rows_bounded", rows)
    monkeypatch.setattr(event_relations, "is_postgres_runtime_db", lambda: True)

    data = event_relations.get_event_relations(91)

    assert len(calls) == 2
    assert data["items"][0]["related_event_db_id"] == 90
    assert data["items"][0]["relation_rule"] == "same_logon_id_same_server"
    assert data["items"][0]["reason"] == "Совпали LogonId и сервер; разница во времени 1 с."


def test_event_entities_fall_back_to_storage_v2_for_fresh_event(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace
    from server.sli.entities.identity_resolution import разрешить_субъект

    expected_key = разрешить_субъект(sam="alice", домен="EXAMPLE").ключ
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        ui_workspace,
        "query_rows_bounded",
        lambda *_args, **_kwargs: [{
            "id": 7,
            "type": "ad_user",
            "natural_key": expected_key,
            "display_name": "EXAMPLE\\alice",
            "link_role": "target",
            "confidence": 1.0,
        }],
    )

    data = ui_workspace.get_event_entities_data(event_db_id=91)

    assert data["event_found"] is True
    assert data["evidence_status"] == "present"
    assert data["items"] == [{
        "id": 7,
        "type": "ad_user",
        "natural_key": expected_key,
        "display_name": "EXAMPLE\\alice",
        "link_role": "target",
        "confidence": 1.0,
    }]
    assert data["items"][0]["display_name"] == r"EXAMPLE\alice"


def test_event_entities_distinguish_missing_event_from_zero_extracted(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: False)

    with pytest.raises(RuntimeError, match="require PostgreSQL/Storage V2"):
        ui_workspace.get_event_entities_data(event_db_id=404)
