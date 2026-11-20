"""Display text keeps the source values and qualifications intact; no database."""

import pytest

from server.sli.reporting.v2.reports.ad_state import _row


@pytest.mark.parametrize(
    ("value", "label"),
    [("passed", "Пройдено"), ("unknown", "Неизвестно"),
     ("inactive", "Неактивно"), ("BiDirectional", "Двустороннее"),
     ("Uplevel", "Доверие Active Directory")],
)
def test_ad_control_enum_presentation_preserves_evidence(value, label):
    control = {"entity_id": 1, "control_id": "replication.state", "actual_value": value,
               "qualification": "not_evaluated", "object_context": {"trust_partner": "unknown"}}
    row = _row(control)
    assert row["actual_text"] == label
    assert row["actual_value"] == value
    assert row["qualification"] == "not_evaluated"
    assert row["context"][0]["value"] == "unknown"
    assert control["actual_value"] == value


def test_ad_control_expected_condition_uses_human_words():
    row = _row({"expected_condition": "Сборщик должен вернуть passed"})
    assert row["expected_condition"] == "Проверка репликации должна завершиться успешно"


def test_ad_control_preserves_unknown_values_and_utc_instants():
    for value in ("future-enum", "2026-10-08T04:05:00Z", 0):
        row = _row({"actual_value": value})
        assert row["actual_value"] == value
        assert row["actual_text"] == str(value)
