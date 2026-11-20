from __future__ import annotations

from copy import deepcopy

import pytest

from server.sli.events.event_search import _normalize_search_row
from server.sli.events.event_search_projection import event_summary_projection
from server.sli.reporting.ui_labels import event_id_label
from server.sli.reporting.ui_workspace import _metadata_timeline_source, _timeline_item


def _service_event() -> dict:
    return {
        "id": 17,
        "event_id": 7036,
        "channel": "System",
        "provider_name": "Service Control Manager",
        "time_created_utc": "2026-01-01T00:00:00Z",
        "server": "fixture.example.test",
        "event_record_id": 42,
        "raw_xml": "<fixture />",
        "event_data_json": '{"param1":"Fixture service","param2":"running"}',
    }


@pytest.mark.parametrize("lang,expected", [
    ("ru", "Изменение состояния службы"),
    ("en", "Service state changed"),
])
def test_source_label_uses_exact_catalog_when_normalizer_has_no_short_label(lang, expected):
    assert event_id_label(
        7036, channel="System", provider_name="Service Control Manager",
        lang=lang, prefix=False,
    ) == expected


@pytest.mark.parametrize("lang,expected", [
    ("ru", "неизвестный тип события"), ("en", "Unknown event type"),
])
def test_wrong_provider_never_receives_scm_label(lang, expected):
    assert event_id_label(
        7036, channel="System", provider_name="Fixture provider", lang=lang, prefix=False,
    ) == expected


def test_summary_resolves_missing_label_from_source_without_exposing_or_mutating_evidence():
    source = _service_event()
    original = deepcopy(source)
    summary = event_summary_projection(source)
    assert summary["label"] == "Изменение состояния службы"
    assert summary["event_db_id"] == 17
    assert summary["event_id"] == 7036
    assert summary["channel"] == "System"
    assert summary["provider_name"] == "Service Control Manager"
    assert summary["event_record_id"] == 42
    assert "raw_xml" not in summary and "event_data_json" not in summary
    assert source == original


@pytest.mark.parametrize("event_id", [7036, 4740])
def test_search_normalization_does_not_drop_wrong_provider(event_id):
    source = {**_service_event(), "event_id": event_id, "provider_name": "Fixture provider"}
    summary = _normalize_search_row(source)
    assert summary["label"] == "неизвестный тип события"
    assert summary["catalog_match"] is False


def test_summary_keeps_existing_source_label():
    assert event_summary_projection({**_service_event(), "label": "Fixture source title"})["label"] == "Fixture source title"


@pytest.mark.parametrize("identity", [
    {}, {"channel": "System"},
    {"channel": "Security", "provider_name": "Service Control Manager"},
])
def test_missing_or_wrong_source_does_not_borrow_an_event_label(identity):
    assert event_summary_projection({"event_id": 4740, **identity})["label"] == "неизвестный тип события"


@pytest.mark.parametrize("provider", [" ", "\t"])
def test_whitespace_provider_is_missing_for_summary_search_and_metadata_timeline(provider):
    source = {**_service_event(), "event_id": 4740, "channel": "Security", "provider_name": provider}
    assert event_summary_projection(source)["label"] == "неизвестный тип события"
    assert _normalize_search_row(source)["label"] == "неизвестный тип события"
    item = _timeline_item({**source, "_metadata_only": True})
    assert item["title"] == "неизвестный тип события"
    assert item["title_code"] is None


@pytest.mark.parametrize("metadata_only", [False, True])
def test_timeline_resolves_missing_label_without_inventing_an_actor(metadata_only):
    source = {**_service_event(), "_metadata_only": metadata_only}
    original = deepcopy(source)
    item = _timeline_item(source)
    assert item["title"] == "Изменение состояния службы"
    assert item["title_code"] == "System:Service Control Manager:7036.title"
    assert item["actor"] is None
    assert item["target"] is None
    assert source == original
    if metadata_only:
        assert item["severity"] == "unknown"
        assert item["base_risk"] == "unknown"
        assert item["confidence"] == "unknown"
        assert item["assessment_confidence"] == "unknown"
        assert item["classification_origin"] == "unavailable"
        assert item["summary"] is None


def test_metadata_source_keeps_exact_title_and_unknown_assessment():
    item = _timeline_item(_metadata_timeline_source(_service_event(), "Fixture inclusion"))
    assert item["title"] == "Изменение состояния службы"
    assert item["title_code"] == "System:Service Control Manager:7036.title"
    assert item["actor"] is None
    assert item["assessment_confidence"] == "unknown"


@pytest.mark.parametrize("metadata_only", [False, True])
def test_unknown_timeline_source_never_gets_scm_semantics(metadata_only):
    item = _timeline_item({
        **_service_event(), "provider_name": "Fixture provider", "_metadata_only": metadata_only,
    })
    assert item["title"] == "неизвестный тип события"
    assert item["title_code"] is None
    assert item["actor"] is None
    assert item["assessment_confidence"] == "unknown"
