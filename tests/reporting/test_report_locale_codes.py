"""AD reports and the problem queue send message codes: English responses carry no Russian text.

Synthetic fixtures only; no database, collector or directory.
"""
import json
import re
from copy import deepcopy
from pathlib import Path

import pytest

from server.sli.core.messages import catalog, response_messages
from server.sli.plugins.ad.reports.definitions import ad_state
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import security_problems
from tests.reporting.test_ad_review_checks import bundle, computer, user
from tests.reporting.test_ad_review_checks import rows as check_rows

CYRILLIC = re.compile("[А-Яа-яЁё]")
AD_REPORTS = ("ad.users.v2", "ad.computers.v6", "ad.infrastructure")
ROOT = Path(__file__).resolve().parents[2]
OBSERVED = "2026-10-17T03:00:00+00:00"


def cyrillic(value, path=""):
    """Every text leaf that still contains Russian, with its path."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from cyrillic(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from cyrillic(item, f"{path}[{index}]")
    elif isinstance(value, str) and CYRILLIC.search(value):
        yield path, value


def is_envelope_field(key):
    return key in {"presentation_messages", "labels_messages", "entity_messages"} or key.endswith("_message")


def codes(value, declared=False):
    """Every message code a response declares in a message envelope (not the report's own limitation codes)."""
    if isinstance(value, dict):
        if declared and isinstance(value.get("code"), str) and "params" in value:
            yield value["code"]
        for key, item in value.items():
            yield from codes(item, declared or is_envelope_field(key))
    elif isinstance(value, list):
        for item in value:
            yield from codes(item, declared)


def without_envelopes(value):
    if isinstance(value, dict):
        return {key: without_envelopes(item) for key, item in value.items() if not is_envelope_field(key)}
    if isinstance(value, list):
        return [without_envelopes(item) for item in value]
    return value


def definition(key):
    # Product declarations belong to .NET; the Python server is frozen.
    path = ROOT / "server-dotnet/src/Sli.Server/Ad/report-definitions.json"
    return json.loads(path.read_text(encoding="utf-8"))[key]["declaration"]


def result(key, **fields):
    return {"report_key": key, "contract_id": "sli.report-result.v2", "state": "ok",
            "items": [], "metrics": [], "limitations": [], "coverage": {}, **fields}


def state_result():
    """Shared synthetic locale input; native row composition is tested in .NET."""
    path = ROOT / "server-dotnet/tests/Sli.Server.Tests/Reporting/report-locale-vectors.json"
    return next(vector["input"] for vector in json.loads(path.read_text(encoding="utf-8"))
                if vector["name"] == "ad-state")


def checks_result(kind, compared=True):
    key = "ad.users.v2" if kind == "users" else "ad.computers.v6"
    make = user if kind == "users" else computer
    # With a previous snapshot nothing changed; without one there is nothing to compare.
    current = [make(1)]
    return result(key, items=check_rows(kind, [bundle(current, current, current) if compared else bundle(current)])["items"])


def queue_result():
    finding = {"id": 7, "status": "new", "severity": "high", "rule_code": "semantic.fixture", "entities": []}
    return {"report_key": "security.problems", "contract_id": "sli.report-result.v2", "state": "ok",
            "items": [security_problems._row(finding, {"new": ["active"]})]}


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_server_dictionary_has_every_key_in_both_languages(locale):
    ru, en = catalog("ru"), catalog(locale)
    assert set(ru) == set(en)
    for code, text in en.items():
        assert text.strip(), code
        assert sorted(re.findall(r"\{\w+\}", text)) == sorted(re.findall(r"\{\w+\}", ru[code])), code
    # English wording must not fall back to Russian text.
    if locale == "en":
        assert not [code for code, text in en.items() if CYRILLIC.search(text)]


@pytest.mark.parametrize("key", AD_REPORTS)
def test_report_definitions_are_english_without_russian(key):
    localized = response_messages(definition(key), "en", report=True)
    assert list(cyrillic(localized)) == []


@pytest.mark.parametrize("key", AD_REPORTS)
def test_report_definitions_localize_without_changing_column_bindings(key):
    original = definition(key)
    for locale in ("ru", "en"):
        localized = response_messages(original, locale, report=True)
        assert [column["key"] for column in localized["columns"]] == [column["key"] for column in original["columns"]]
        for before, after in zip(original["columns"], localized["columns"], strict=True):
            for field in ("path", "kind", "field_categories"):
                assert before.get(field) == after.get(field)
            assert after["label"].strip()
            envelope = after.get("presentation_messages", {}).get("label")
            if envelope:
                assert after["label"] == catalog(locale)[envelope["code"]]


@pytest.mark.parametrize("make", [lambda: checks_result("users"), lambda: checks_result("users", compared=False),
                                  lambda: checks_result("computers"), state_result, queue_result],
                         ids=["user-checks", "user-checks-uncompared", "computer-checks", "ad-state", "problem-queue"])
def test_report_rows_are_english_without_russian(make):
    payload = make()
    localized = response_messages(payload, "en", report=True)
    assert list(cyrillic(localized)) == []
    assert localized["items"], "the fixture must produce rows"
    for code in set(codes(localized)):
        assert code in catalog("ru") and code in catalog("en"), code


@pytest.mark.parametrize("make", [lambda: checks_result("users"), lambda: checks_result("computers"), state_result],
                         ids=["user-checks", "computer-checks", "ad-state"])
def test_report_rows_keep_the_russian_wording(make):
    payload = make()
    expected = without_envelopes(payload)
    # Localize display text while preserving observations and control codes.
    diagnostics = {
        "dc.advertising": ("Объявление контроллера", "Объявлен"),
        "dc.connectivity": ("Связь с контроллером", "Отвечает"),
        "dc.services": ("Обязательные службы", "Работают"),
        "dc.sysvol": ("SYSVOL", "Доступен"),
        "dc.netlogon": ("Доступность NETLOGON", "Доступен"),
        "dc.dns": ("DNS", "Пройдено"),
    }
    renamed_controls = {
        "dc.operating_system": "Версия ОС контроллера",
        "password.properties": "Сложность пароля",
        "password.lockout_observation_window": "Сброс счётчика блокировки через",
    }
    for row in expected["items"]:
        control = row.get("control_id")
        if control in diagnostics:
            row["label"], row["expected_condition"] = diagnostics[control]
        elif control in renamed_controls:
            row["label"] = renamed_controls[control]
    assert without_envelopes(response_messages(payload, "ru", report=True)) == expected


def test_check_names_severities_and_statuses_follow_the_locale():
    def by_key(payload, locale):
        return {row["key"]: row for row in response_messages(payload, locale, report=True)["items"]}
    compared, alone = checks_result("users"), checks_result("users", compared=False)
    english, russian = by_key(compared, "en"), by_key(compared, "ru")
    assert english["disabled_logon"]["severity_text"] == "High" and russian["disabled_logon"]["severity_text"] == "Высокая"
    assert english["disabled_logon"]["status_text"] == "Unchanged" and russian["disabled_logon"]["status_text"] == "Без изменений"
    assert by_key(alone, "en")["disabled_logon"]["status_text"] == "First check"
    assert by_key(alone, "ru")["disabled_logon"]["status_text"] == "Первая проверка"
    assert english["disabled_logon"]["title"] != russian["disabled_logon"]["title"]
    # The wire still carries the stable status and severity codes.
    assert english["disabled_logon"]["status"] == "unchanged" and english["disabled_logon"]["severity"] == "high"


def test_ad_state_row_keeps_observed_values_and_codes():
    row = next(row for row in response_messages(state_result(), "en", report=True)["items"] if row["control_id"] == "dc.advertising")
    assert row["label"] == "Controller advertising"
    assert row["authority_text"] == "Collector diagnostics"
    assert row["actual_text"] == "Passed" and row["actual_value"] == "passed"
    assert {entry["label"] for entry in row["context"]} >= {"Site", "Global Catalog"}
    assert next(entry for entry in row["context"] if entry["code"] == "is_global_catalog")["value"] == "Yes"


def test_unknown_message_code_keeps_source_text():
    payload = result("ad.infrastructure", limitations=[{"code": "from_a_newer_collector", "text": "Новое ограничение."}])
    assert response_messages(payload, "en", report=True)["limitations"] == payload["limitations"]


def test_response_is_json_serializable_in_both_locales():
    for locale in ("ru", "en"):
        json.dumps(response_messages(state_result(), locale, report=True), ensure_ascii=False)


@pytest.mark.parametrize("coverage, count", [
    ({}, 0),
    ({"partial": ["synthetic-section"]}, 1),
    ({"missing": ["a", "b"], "stale": ["c"], "failed": ["d"], "partial": ["e"]}, 5),
])
def test_infrastructure_coverage_count_is_emitted_by_query(monkeypatch, coverage, count):
    monkeypatch.setattr(ad_state, "get_active_directory_report", lambda **kwargs: {
        "state": "partial", "controls": [], "summary": {}, "coverage": coverage,
    })
    payload = ad_state._query(QueryContext({}, {}, domain_ids=[1]))
    limitations = [item for item in payload["limitations"] if item["code"] == "coverage"]
    if count == 0:
        assert limitations == []
        return
    assert limitations == [{
        "code": "coverage", "params": {"count": count},
        "text": f"Ограничений покрытия источников: {count}. Пустой список не доказывает безопасное состояние.",
    }]
    for locale in ("ru", "en"):
        translated = response_messages(payload, locale, report=True)
        limitation = next(item for item in translated["limitations"] if item["code"] == "coverage")
        assert limitation["params"] == {"count": count}
        assert str(count) in limitation["text"]
        assert "{count}" not in limitation["text"]
        if locale == "en":
            assert not CYRILLIC.search(limitation["text"])


def inventory_reasons():
    from server.sli.plugins.ad.reports.computers_v6_reporting_items import (
        _attention_reasons,
    )

    common = {"observed_at_utc": OBSERVED, "enabled": True, "computer_type": "unknown",
              "quality_issues": [{"code": "source_failed"}],
              "delegation": {"unconstrained": True},
              "laps": {"state": "expired", "expiration_utc": "2026-10-01T00:00:00Z"}}
    old = {**common, "operating_system": "Windows Server 2012 R2", "operating_system_version": "6.3",
           "last_logon_utc": "2026-01-01T00:00:00Z", "activity": {"age_days": 289},
           "evidence": {"source_states": {"os": {"status": "observed"}}}}
    missing = {**common, "activity": {"age_days": None}}
    return list({reason["code"]: reason for item in (old, missing)
                 for reason in _attention_reasons(item, 90)}.values())


def test_inventory_reason_details_are_english_and_keep_source_data():
    from server.sli.plugins.ad.reports.definitions.computers import _row

    reasons = inventory_reasons()
    assert {reason["code"] for reason in reasons} == {
        "unsupported_os", "unconstrained_delegation", "laps_expired", "source_error",
        "unknown_type", "stale_activity", "unavailable_activity", "unknown_os",
    }
    source = _row({"display_name": "Синтетический компьютер", "description": "Описание владельца",
                   "reasons": reasons})
    original = deepcopy(source)
    localized = response_messages(result("ad.computers.v6", items=[source]), "en", report=True)["items"][0]
    for reason in localized["reasons"]:
        fields = {field: reason[field] for field in ("label", "observed", "condition", "qualification", "limitation", "next_action")}
        assert list(cyrillic(fields)) == [], reason["code"]
        assert set(reason["presentation_messages"]) == set(fields)
    assert not CYRILLIC.search(localized["reason_text"])
    assert localized["display_name"] == "Синтетический компьютер"
    assert localized["description"] == "Описание владельца"
    stale = next(reason for reason in localized["reasons"] if reason["code"] == "stale_activity")
    assert "90" in stale["condition"] and "289" in stale["observed"]
    assert stale["observed"] == "Last approximate AD observation: Jan 1, 2026, 12:00 AM; age: 289 days."
    assert stale["presentation_messages"]["observed"]["params"]["last_logon_utc"] == "2026-01-01T00:00:00Z"
    assert stale["threshold_days"] == 90
    russian = response_messages(result("ad.computers.v6", items=[source]), "ru", report=True)["items"][0]
    expected_russian = without_envelopes(original)
    localized_observations = {
        "unsupported_os": "Windows Server 2012 R2; окончание расширенной поддержки Microsoft: 10.10.2023.",
        "laps_expired": "Плановый срок: 01.10.2026, 00:00.",
        "stale_activity": "Последнее приблизительное AD-наблюдение: 01.01.2026, 00:00; возраст: 289 дней.",
    }
    for reason in expected_russian["reasons"]:
        if reason["code"] in localized_observations:
            reason["observed"] = localized_observations[reason["code"]]
    assert without_envelopes(russian) == expected_russian
    for translated in (localized, russian):
        for actual, initial in zip(translated["reasons"], original["reasons"]):
            for field, message in initial["presentation_messages"].items():
                assert actual["presentation_messages"][field]["params"] == message["params"]
    assert source == original


def test_inventory_unknown_reason_and_cyrillic_os_are_not_guessed():
    from server.sli.plugins.ad.reports.computers_v6_reporting_items import _reason
    from server.sli.plugins.ad.reports.definitions.computers import _row

    unknown = _reason("future_reason", "Неизвестная причина", "Данные", "Условие", "Вывод", "Предел", "Шаг")
    coded = next(reason for reason in inventory_reasons() if reason["code"] == "unsupported_os")
    coded["operating_system"] = "Синтетическая ОС"
    # Source text in an explicitly declared parameter is data, not untranslated system vocabulary.
    coded["presentation_messages"]["observed"]["params"]["operating_system"] = "Синтетическая ОС"
    source = _row({"reasons": [unknown, coded]})
    localized = response_messages(result("ad.computers.v6", items=[source]), "en", report=True)["items"][0]
    assert localized["reasons"][0] == unknown
    assert localized["reasons"][1]["operating_system"] == "Синтетическая ОС"
    assert "Синтетическая ОС" in localized["reasons"][1]["observed"]
    assert localized["reason_text"].startswith("Неизвестная причина, ")


def test_inventory_stale_reason_missing_date_uses_explicit_message_variant():
    from server.sli.plugins.ad.reports.computers_v6_reporting_items import (
        _attention_reasons,
    )

    reason = next(reason for reason in _attention_reasons({
        "enabled": True, "activity": {"age_days": 91}, "last_logon_utc": None,
    }, 90) if reason["code"] == "stale_activity")
    localized = response_messages(result("ad.computers.v6", items=[{"reasons": [reason]}]), "en", report=True)
    assert localized["items"][0]["reasons"][0]["observed"] == "Last approximate AD observation: none; age: 91 days."
    assert not list(cyrillic(localized))
    russian = response_messages(result("ad.computers.v6", items=[{"reasons": [reason]}]), "ru", report=True)
    assert russian["items"][0]["reasons"][0]["observed"] == reason["observed"]
