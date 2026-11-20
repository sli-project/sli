from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from server.sli.reporting.report_intent_contract import (
    ReportIntentContractError,
    load_reporting_product_contract,
    validate_reporting_product_contract,
)


CONTRACT_PATH = Path("config/stage11a_reporting_product_v1.json")


def _contract() -> dict[str, object]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def test_approved_contract_has_six_unique_complete_selected_intents() -> None:
    result = load_reporting_product_contract(CONTRACT_PATH)

    assert result["selected_report_ids"] == (
        "security.queue",
        "ad.state",
        "ad.privileged",
        "ad.gpo.review",
        "vpn.audit",
        "operations.readiness",
    )
    assert result["selected_count"] == 6
    assert result["primary_g11a3_vertical"] == "vpn.audit"


def test_duplicate_selected_report_id_is_rejected() -> None:
    value = _contract()
    reports = value["selected_report_set"]
    assert isinstance(reports, list)
    reports.append(copy.deepcopy(reports[0]))

    with pytest.raises(ReportIntentContractError, match="selected_report_ids_unique"):
        validate_reporting_product_contract(value)


def test_missing_full_intent_section_is_rejected() -> None:
    value = _contract()
    reports = value["selected_report_set"]
    assert isinstance(reports, list)
    reports[0].pop("acceptance_lanes")

    with pytest.raises(ReportIntentContractError, match="intent_section_required"):
        validate_reporting_product_contract(value)


def test_unknown_archetype_is_rejected() -> None:
    value = _contract()
    value["selected_report_set"][0]["identity"]["primary_archetype"] = "unknown"

    with pytest.raises(ReportIntentContractError, match="primary_archetype_invalid"):
        validate_reporting_product_contract(value)


def test_multiple_primary_questions_are_rejected() -> None:
    value = _contract()
    value["selected_report_set"][0]["user_need"]["question"] = ["one", "two"]

    with pytest.raises(ReportIntentContractError, match="user_need_single_value_required"):
        validate_reporting_product_contract(value)


def test_missing_canonical_source_is_rejected_even_with_supplemental_source() -> None:
    value = _contract()
    value["selected_report_set"][0]["sources"]["canonical"] = []

    with pytest.raises(ReportIntentContractError, match="canonical_source_required"):
        validate_reporting_product_contract(value)


def test_access_requires_capability_and_server_enforced_scope() -> None:
    value = _contract()
    value["selected_report_set"][0]["access"]["server_enforced_scope"] = ""

    with pytest.raises(ReportIntentContractError, match="access_contract_invalid"):
        validate_reporting_product_contract(value)


def test_honest_states_must_keep_empty_denied_partial_stale_and_unavailable_distinct() -> None:
    value = _contract()
    value["selected_report_set"][0]["result_limits"]["honest_states"].remove("stale")

    with pytest.raises(ReportIntentContractError, match="honest_states_incomplete"):
        validate_reporting_product_contract(value)


def test_ai_authority_value_is_rejected() -> None:
    value = _contract()
    value["selected_report_set"][0]["ai_assistance"]["mode"] = "authority"

    with pytest.raises(ReportIntentContractError, match="ai_assistance_invalid"):
        validate_reporting_product_contract(value)


def test_compliance_control_requires_policy_and_control_matrix() -> None:
    value = _contract()
    report = value["selected_report_set"][0]
    report["identity"]["primary_archetype"] = "compliance-control"
    report["qualification"] = {"status": "not_applicable", "reason": "none"}

    with pytest.raises(ReportIntentContractError, match="compliance_policy_required"):
        validate_reporting_product_contract(value)


def test_non_compliance_report_keeps_risk_and_control_matrix_not_applicable() -> None:
    value = _contract()
    report = value["selected_report_set"][0]
    assert report["identity"]["primary_archetype"] != "compliance-control"
    report["risk"] = {"status": "not_applicable", "reason": "no accepted policy"}
    report["qualification"] = {"status": "not_applicable", "reason": "no accepted policy"}

    validate_reporting_product_contract(value)


def test_reconciliation_preserves_accepted_28_surface_distribution() -> None:
    value = _contract()
    value["inventory_reconciliation"]["accepted_counts"]["merge"] = 9

    with pytest.raises(ReportIntentContractError, match="inventory_counts_mismatch"):
        validate_reporting_product_contract(value)


def test_selected_set_cannot_include_deferred_ai_surface() -> None:
    value = _contract()
    value["selected_report_set"][0]["identity"]["report_id"] = "ai-analysis"

    with pytest.raises(ReportIntentContractError, match="selected_deferred_surface"):
        validate_reporting_product_contract(value)


def test_primary_vertical_must_remain_vpn_audit() -> None:
    value = _contract()
    value["primary_g11a3_vertical"] = "ad.state"

    with pytest.raises(ReportIntentContractError, match="primary_vertical_invalid"):
        validate_reporting_product_contract(value)


def test_contract_rejects_every_forbidden_architecture_expansion() -> None:
    value = _contract()
    value["change_flags"]["schema_migration"] = True

    with pytest.raises(ReportIntentContractError, match="forbidden_change_flag"):
        validate_reporting_product_contract(value)
