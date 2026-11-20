"""WR01 fixture contract: synthetic rule rows, no database or live sources."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from server.sli.plugins.workstations.check_catalog import CATALOG, REASON_KEYS
from server.sli.plugins.workstations.overview_contracts import (
    CheckCounts,
    CheckResult,
    ChecksOverview,
    Count,
    Quality,
    Reason,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "workstations" / "overview.json"
ROOT = Path(__file__).parents[2]


def load_overview(payload):
    def quality(raw):
        return Quality(raw["status"], tuple(Reason(reason["code"], reason["params"]) for reason in raw["reasons"]))

    return ChecksOverview(
        state=payload["state"],
        quality=quality(payload["quality"]),
        checks=tuple(CheckResult(
            check_id=row["check_id"],
            quality=quality(row["quality"]),
            counts=CheckCounts(**{key: Count(**value) for key, value in row["counts"].items()}),
            reasons=tuple(Reason(reason["code"], reason["params"]) for reason in row["reasons"]),
        ) for row in payload["checks"]),
    )


def test_catalog_has_ten_versioned_rules_in_owner_order():
    assert [rule.check_id for rule in CATALOG] == [f"C{number:02}" for number in range(1, 11)]
    assert [rule.order for rule in CATALOG] == list(range(1, 11))
    assert [rule.rule_version for rule in CATALOG] == [1] * 10
    assert [rule.severity for rule in CATALOG] == ["high"] * 3 + ["medium"] * 5 + ["low"] * 2
    for rule in CATALOG:
        assert rule.severity_for("workstation") == rule.severity
        assert rule.severity_for("unknown") == rule.severity
        assert rule.severity_for("server") == ("medium" if rule.check_id == "C09" else rule.severity)


@pytest.mark.parametrize("state", ["data", "partial", "empty", "denied"])
def test_fixture_contract_round_trips_ten_rows_and_expected_counts(state):
    fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))
    payload = fixture["scenarios"][state]
    result = load_overview(payload).to_dict()
    assert result == {
        "contract_id": "sli.workstation-checks.v1", **payload,
        "checks": [{**definition, **row} for definition, row in zip(fixture["catalog"], payload["checks"], strict=True)],
    }
    assert len(result["checks"]) == 10
    assert [row["check_id"] for row in result["checks"]] == [rule.check_id for rule in CATALOG]


@pytest.mark.parametrize("value,relation", [(-1, "exact"), (True, "exact"), (1.5, "exact"),
                                           (None, "exact"), (0, "unknown"), (1, "estimate")])
def test_invalid_counts_cannot_be_published(value, relation):
    with pytest.raises(ValueError, match="count_invalid"):
        Count(value, relation)


@pytest.mark.parametrize("status", ["unavailable", "not_collected", "stale", "denied"])
def test_unknown_quality_cannot_claim_current_zero(status):
    with pytest.raises(ValueError, match="check_counts_quality_invalid"):
        CheckResult("C01", Quality(status), CheckCounts(Count(0, "exact"), Count(None, "unknown")))


def test_partial_counts_are_lower_bounds_and_newness_can_be_unknown():
    row = CheckResult("C01", Quality("partial"),
                      CheckCounts(Count(2, "at_least"), Count(None, "unknown")))
    assert row.to_dict()["counts"]["new_since_previous_login"] == {"value": None, "relation": "unknown"}
    with pytest.raises(ValueError, match="check_counts_quality_invalid"):
        CheckResult("C01", Quality("partial"), CheckCounts(Count(2, "exact"), Count(1, "exact")))


def test_new_count_never_exceeds_exact_station_count():
    with pytest.raises(ValueError, match="check_counts_invalid"):
        CheckCounts(Count(1, "exact"), Count(2, "exact"))


def test_denied_envelope_cannot_leak_visible_rows_or_finding_reasons():
    fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))["scenarios"]
    data = load_overview(fixture["data"])
    with pytest.raises(ValueError, match="overview_state_invalid"):
        ChecksOverview("denied", Quality("denied"), data.checks)
    with pytest.raises(ValueError, match="check_reasons_invalid"):
        CheckResult("C01", Quality("denied"),
                    CheckCounts(Count(None, "unknown"), Count(None, "unknown")),
                    (Reason("protection_disabled", {"components": "real_time_protection_enabled"}),))


def test_envelope_rejects_duplicate_rules_and_false_empty():
    fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))["scenarios"]
    data = load_overview(fixture["data"])
    with pytest.raises(ValueError, match="overview_checks_invalid"):
        ChecksOverview("data", Quality("complete"), data.checks[:-1] + (data.checks[0],))
    with pytest.raises(ValueError, match="overview_state_invalid"):
        ChecksOverview("empty", Quality("complete"), data.checks)


def test_reason_params_are_copied_and_unknown_codes_rejected():
    params = {"components": "real_time_protection_enabled"}
    reason = Reason("protection_disabled", params)
    params["components"] = "changed"
    assert reason.to_dict()["params"]["components"] == "real_time_protection_enabled"
    with pytest.raises(ValueError, match="reason_invalid"):
        Reason("unregistered_reason")


def test_all_presentation_and_reason_keys_have_server_translations():
    keys = set(REASON_KEYS.values())
    for rule in CATALOG:
        keys.update(rule.to_dict()[field] for field in ("title_key", "why_key", "action_key", "remediation_key"))
    dictionaries = [json.loads((ROOT / "config" / "i18n" / f"server.{locale}.json").read_text(encoding="utf-8"))
                    for locale in ("ru", "en")]
    for messages in dictionaries:
        assert keys <= messages.keys()
        assert all(isinstance(messages[key], str) and messages[key].strip() for key in keys)
    for key in keys:
        assert sorted(re.findall(r"\{\w+\}", dictionaries[0][key])) == sorted(
            re.findall(r"\{\w+\}", dictionaries[1][key]))
