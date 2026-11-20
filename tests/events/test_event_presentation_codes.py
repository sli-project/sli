"""Presentation codes are additive and never replace retained source text."""
from __future__ import annotations

import pytest

from server.sli.events import event_relations
from server.sli.semantic import event_card_semantics


@pytest.mark.parametrize("rule,delta", [
    ("same_logon_id_same_server", 1),
    ("same_task_same_server_time_window", 42),
])
def test_relation_response_keeps_text_and_adds_reason_code(monkeypatch, rule, delta):
    monkeypatch.setattr(event_relations, "_query_v2_relation_rows", lambda *_a: [{
        "related_event_db_id": 2, "related_event_id": 4624,
        "relation_rule": rule, "time_delta_seconds": delta, "entity": "fixture",
    }])
    relation = event_relations._v2_relations_response(1, 100)["items"][0]
    assert relation["reason_code"] == rule
    assert relation["reason_params"] == {"time_delta_seconds": delta}
    assert relation["reason"].endswith(f"разница во времени {delta} с.")
    assert "fixture" in relation["explanation"]


def test_unknown_event_card_adds_codes_without_interpreting_message(monkeypatch):
    monkeypatch.setattr(event_card_semantics, "lookup_event_catalog", lambda *_a: None)
    monkeypatch.setattr(event_card_semantics, "resolve_source_pack", lambda *_a: None)
    card = event_card_semantics.build_event_card({"event_id": 999999, "message_text": "Исходное сообщение"})
    assert card["title_code"] == "uncatalogued.title"
    assert card["summary_code"] == "uncatalogued.summary"
    assert card["title"] == "Событие пока не расшифровано каталогом"
    assert "Исходное сообщение" not in card["summary"]


def test_catalog_card_codes_preserve_identity_and_contextual_assessment(monkeypatch):
    entry = {"event_id": 140, "channel": "Fixture", "provider_name": "FixtureProvider",
             "title": "Типовое событие", "why": "Типовое пояснение", "severity": "info",
             "card": {"action": "Типовое действие", "risk_rules": [
                 {"severity": "medium", "assessment": "Контекстное пояснение", "all": []},
             ]}}
    monkeypatch.setattr(event_card_semantics, "lookup_event_catalog", lambda *_a: entry)
    monkeypatch.setattr(event_card_semantics, "resolve_source_pack", lambda *_a: None)
    card = event_card_semantics.build_event_card({"event_id": 140})
    assert card["title_code"] == "Fixture:FixtureProvider:140.title"
    assert card["summary_code"] == "Fixture:FixtureProvider:140.summary.rule.0"
    assert card["title"] == "Типовое действие"
    assert card["summary"] == "Контекстное пояснение"
    entry["card"] = {}
    entry["provider_name"] = "OtherFixtureProvider"
    other = event_card_semantics.build_event_card({"event_id": 140})
    assert other["title_code"] != card["title_code"]
    assert other["summary_code"] == "Fixture:OtherFixtureProvider:140.summary"
    assert other["summary"] == "Типовое пояснение"
