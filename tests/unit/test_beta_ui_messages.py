"""Beta presentation checks use bundled catalogues and synthetic rows only."""

import json
import re
from pathlib import Path

import pytest

from server.sli.core.messages import catalog, response_messages
from server.sli.reporting.ui_labels import event_id_label

ROOT = Path(__file__).resolve().parents[2]


def test_server_english_ui_catalog_has_no_cyrillic():
    assert not {key: value for key, value in catalog("en").items()
                if re.search(r"[\u0400-\u04ff]", value)}


@pytest.mark.parametrize("filename", ["event_catalog.json", "file_audit_event_catalog.json",
                                      "workstations_event_catalog.json", "radius_event_catalog.json"])
def test_bundled_event_labels_do_not_leak_russian_into_english(filename):
    data = json.loads((ROOT / "config" / filename).read_text(encoding="utf-8"))
    entries = data if isinstance(data, list) else data["entries"]
    for entry in entries:
        label = event_id_label(entry["event_id"], lang="en", prefix=False,
                               channel=entry["channel"], provider_name=entry["provider_name"])
        assert not re.search(r"[\u0400-\u04ff]", label), entry


@pytest.mark.parametrize(("event_id", "channel", "provider", "english"), [
    (7040, "System", "Service Control Manager", "Service startup type changed"),
    (4656, "Security", "Microsoft-Windows-Security-Auditing", "Access to an object requested"),
])
def test_known_catalog_titles_are_words(event_id, channel, provider, english):
    assert event_id_label(event_id, lang="en", prefix=False, channel=channel, provider_name=provider) == english


def test_file_audit_localizes_limitations_without_touching_source_values():
    limitation = {"code": "coverage_unverified", "text": "Полнота сбора за выбранный период не подтверждена."}
    payload = {"report_key": "file-audit.overview", "state": "partial",
               "limitations": [limitation], "state_details": {"limitations": [limitation]},
               "items": [{"path": "Синтетическая папка"}]}
    localized = response_messages(payload, "en", report=True)
    assert localized["limitations"][0]["text"] == "Collection completeness for the selected period is unconfirmed."
    assert localized["state_details"]["limitations"][0]["text"] == localized["limitations"][0]["text"]
    assert localized["items"] == payload["items"]
    assert payload["limitations"][0]["text"] == limitation["text"]
