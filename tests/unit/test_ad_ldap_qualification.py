"""LDAP report rules recognize observed enums, never infer a safe fallback."""

import csv
import io
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from server.sli.plugins.ad.reports.active_directory_reporting import (
    build_active_directory_controls,
    evaluate_active_directory_risks,
    render_active_directory_report_csv,
)


@pytest.mark.parametrize(
    ("field", "control_id", "risk_key", "value", "expected", "risk_expected"),
    [
        ("ldap_signing_requirement", "domain.ldap_signing", "ldap_signing_not_required", "require_signing", "passed", "not_matched"),
        ("ldap_signing_requirement", "domain.ldap_signing", "ldap_signing_not_required", "not_required", "failed", "matched"),
        ("ldap_signing_requirement", "domain.ldap_signing", "ldap_signing_not_required", "  NOT_REQUIRED  ", "failed", "matched"),
        ("ldap_channel_binding_requirement", "domain.ldap_channel_binding", "ldap_channel_binding_never", "always", "passed", "not_matched"),
        ("ldap_channel_binding_requirement", "domain.ldap_channel_binding", "ldap_channel_binding_never", "when_supported", "passed", "not_matched"),
        ("ldap_channel_binding_requirement", "domain.ldap_channel_binding", "ldap_channel_binding_never", "never", "failed", "matched"),
        ("ldap_channel_binding_requirement", "domain.ldap_channel_binding", "ldap_channel_binding_never", "  NEVER  ", "failed", "matched"),
        ("ldap_signing_requirement", "domain.ldap_signing", "ldap_signing_not_required", "always", "not_evaluated", "not_evaluated"),
        ("ldap_channel_binding_requirement", "domain.ldap_channel_binding", "ldap_channel_binding_never", "require_signing", "not_evaluated", "not_evaluated"),
    ],
)
def test_ldap_known_values_keep_control_risk_and_csv_consistent(field, control_id, risk_key, value, expected, risk_expected):
    _assert_qualification(field, control_id, risk_key, value, expected, risk_expected)


@pytest.mark.parametrize(("field", "control_id", "risk_key"), [
    ("ldap_signing_requirement", "domain.ldap_signing", "ldap_signing_not_required"),
    ("ldap_channel_binding_requirement", "domain.ldap_channel_binding", "ldap_channel_binding_never"),
])
@pytest.mark.parametrize("value", [
    None, "", "  ", "unknown", "unavailable", "timeout", "not_collected", "not_evaluated",
    "partial", "parse_error", "future-enum", True, False, 0, 2, [], {}, ["require_signing"],
])
def test_ldap_unknown_or_malformed_evidence_never_passes(field, control_id, risk_key, value):
    _assert_qualification(field, control_id, risk_key, value, "not_evaluated", "not_evaluated")


def _assert_qualification(field, control_id, risk_key, value, expected, risk_expected):
    attributes = {field: value}
    original = deepcopy(attributes)
    item = {"entity_id": 1, "entity_type": "domain", "display_name": "example.test",
            "source_section": "domain_posture", "attributes": attributes}
    controls = build_active_directory_controls([item])
    control = next(row for row in controls if row["control_id"] == control_id)
    assert control["qualification"] == expected
    assert control["actual_value"] == value
    assert control["authority"] == "report_rule_v1"
    risks = evaluate_active_directory_risks("domain", attributes, datetime(2026, 10, 1, tzinfo=timezone.utc))
    risk = next(row for row in risks if row["risk_key"] == risk_key)
    assert risk["qualification"] == risk_expected
    assert risk["evidence"] == value
    exported = list(csv.reader(io.StringIO(render_active_directory_report_csv({"controls": [control]}).decode("utf-8-sig")), delimiter=";"))
    assert exported[1][6] == expected
    assert attributes == original


def test_ldap_missing_fields_keep_ledger_omission_and_unknown_risks():
    item = {"entity_id": 1, "entity_type": "domain", "display_name": "example.test",
            "source_section": "domain_posture", "attributes": {}}
    controls = build_active_directory_controls([item])
    assert controls == []
    risks = evaluate_active_directory_risks("domain", {}, datetime(2026, 10, 1, tzinfo=timezone.utc))
    assert {row["qualification"] for row in risks if row["risk_key"].startswith("ldap_")} == {"not_evaluated"}


@pytest.mark.parametrize(("value", "exported_value", "qualification"), [
    ("  REQUIRE_SIGNING  ", "  REQUIRE_SIGNING  ", "passed"),
    ("parse_error", "parse_error", "not_evaluated"),
    (None, "", "not_evaluated"),
    ({"state": "unknown"}, '{"state": "unknown"}', "not_evaluated"),
])
def test_ldap_csv_retains_original_fact_and_unknown_verdict(value, exported_value, qualification):
    controls = build_active_directory_controls([{
        "entity_id": 1, "entity_type": "domain", "display_name": "example.test",
        "source_section": "domain_posture", "attributes": {"ldap_signing_requirement": value},
    }])
    rows = list(csv.reader(io.StringIO(render_active_directory_report_csv({"controls": controls}).decode("utf-8-sig")), delimiter=";"))
    assert len(rows) == 2
    assert rows[1][4] == exported_value
    assert rows[1][6] == qualification
