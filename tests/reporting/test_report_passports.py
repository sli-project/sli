from __future__ import annotations

from dataclasses import fields, replace

import pytest

from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import ReportIntent
from server.sli.reporting.v2.reports.computers import REPORT


@pytest.fixture
def intent() -> ReportIntent:
    assert REPORT.intent is not None
    return REPORT.intent


def test_registry_load_validates_every_passport_without_queries(monkeypatch):
    def no_query(*args, **kwargs):
        pytest.fail("Passport discovery must not query a data source")

    # Registry discovery includes plugin-generated reports as well as modules.
    from server.sli.plugins.workstations import reports as workstations
    from server.sli.reporting.v2.reports import computers, new_logon_pairs

    monkeypatch.setattr(computers, "REPORT", replace(REPORT, query=no_query))
    monkeypatch.setattr(new_logon_pairs, "REPORT", replace(new_logon_pairs.REPORT, query=no_query))
    monkeypatch.setattr(workstations, "read_report", no_query)
    registry.registered_reports.cache_clear()
    try:
        definitions = registry.registered_reports(validate_intents=True)
        assert {f"workstations.{family}" for family in workstations.REPORTS} <= {item.key for item in definitions}
        assert all(item.intent is not None for item in definitions)
        for definition in definitions:
            assert definition.access.required_fields <= set(definition.intent.field_classes)
    finally:
        registry.registered_reports.cache_clear()


def test_transitional_allowlist_can_only_shrink():
    # Fixed ceiling at introduction. All current reports have migrated, so no
    # future report may be grandfathered in by growing the production allowlist.
    assert registry.UNMIGRATED_REPORT_INTENTS <= frozenset()


def test_rule_quality_passport_preserves_measurement_and_access_boundaries(monkeypatch):
    from server.sli.reporting.v2.reports import rule_quality

    monkeypatch.setattr(rule_quality.engine, "load_quality", lambda *args, **kwargs: pytest.fail("Passport discovery must not read findings"))
    registry.validate_report_intents((rule_quality.REPORT,))
    passport = rule_quality.REPORT.to_json()["intent"]
    assert passport["primary_archetype"] == "summary"
    assert passport["field_classes"] == ["security"]
    assert "semantic.review" in passport["rights"]
    assert "not_proven" in passport["completeness"]
    assert "FP + confirmed" in passport["denominator"]
    assert "число которых неизвестно" in passport["denominator"]
    assert "проверяются отдельно" in passport["freshness_expectation"]
    assert "policy-version attribution" in passport["exclusions"]


@pytest.mark.parametrize("name", [item.name for item in fields(ReportIntent) if item.name != "version"])
@pytest.mark.parametrize("value", [None, "", "  "])
def test_missing_or_empty_passport_field_fails(intent, name, value):
    with pytest.raises(ValueError, match=f"report_intent_invalid:{name}"):
        registry.validate_report_intents((replace(REPORT, intent=replace(intent, **{name: value})),))


@pytest.mark.parametrize("name", ["sources", "field_classes"])
@pytest.mark.parametrize("value", [(), ("",), ("valid", "  "), (None,), ["valid"], "valid"])
def test_source_and_field_class_lists_require_nonempty_entries(intent, name, value):
    with pytest.raises(ValueError, match=f"report_intent_invalid:{name}"):
        replace(intent, **{name: value}).validate()


@pytest.mark.parametrize("version", [0, -1, True, "1", None])
def test_invalid_intent_version_fails(intent, version):
    with pytest.raises(ValueError, match="report_intent_invalid:version"):
        replace(intent, version=version).validate()


@pytest.mark.parametrize("overrides", [{"question": ["one", "two"]}, {"primary_archetype": "unknown"}])
def test_question_is_one_value_and_primary_archetype_is_known(intent, overrides):
    with pytest.raises(ValueError, match="report_intent_invalid:"):
        replace(intent, **overrides).validate()


@pytest.mark.parametrize("module_name", ["computers", "new_logon_pairs"])
def test_missing_passport_fails_only_validation_load(monkeypatch, module_name):
    from importlib import import_module

    module = import_module(f"server.sli.reporting.v2.reports.{module_name}")
    definition = module.REPORT
    monkeypatch.setattr(module, "REPORT", replace(definition, intent=None))
    registry.registered_reports.cache_clear()
    try:
        # Runtime discovery stays available during a future incomplete migration.
        assert registry.get_report(definition.key).intent is None
        with pytest.raises(ValueError, match=f"report_intent_missing:{definition.key}"):
            registry.registered_reports(validate_intents=True)
    finally:
        registry.registered_reports.cache_clear()


def test_allowlist_only_exempts_absent_not_invalid_passports(monkeypatch, intent):
    monkeypatch.setattr(registry, "UNMIGRATED_REPORT_INTENTS", frozenset({REPORT.key}))
    registry.validate_report_intents((replace(REPORT, intent=None),))
    with pytest.raises(ValueError, match="report_intent_invalid:question"):
        registry.validate_report_intents((replace(REPORT, intent=replace(intent, question=" ")),))
    with pytest.raises(ValueError, match="report_intent_allowlist_obsolete"):
        registry.validate_report_intents((REPORT,))


def test_access_filtered_declaration_carries_the_same_versioned_passport(intent):
    access = {"reports": [{
        "report_key": REPORT.access.report_key, "allowed": True, "allowed_actions": ["view"],
        "grants": [{"allowed_actions": ["view"], "field_categories": list(REPORT.access.required_fields),
                    "scope": {"kind": "domain", "ids": [1]}}],
    }]}
    payload = ReportAccess(REPORT, access).declaration()
    assert payload["intent"] == intent.to_json()
    assert payload["intent"]["contract_id"] == "sli.report-intent.v1"
    assert payload["intent"]["version"] == 1
    assert payload["intent"]["sources"] == list(intent.sources)
    assert payload["intent"]["field_classes"] == list(intent.field_classes)
    assert payload["archetype"] == REPORT.archetype  # Product purpose remains separate.
