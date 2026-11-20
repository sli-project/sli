"""Validation for the bounded G11A-2 reporting-product package."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


CONTRACT_PATH = Path(__file__).resolve().parents[3] / "config" / "stage11a_reporting_product_v1.json"
ALLOWED_ARCHETYPES = frozenset({
    "inventory-status",
    "monitoring-operations",
    "investigation-evidence",
    "compliance-control",
    "decision-support-recommendation",
})
REQUIRED_INTENT_SECTIONS = frozenset({
    "identity", "user_need", "scope", "sources", "access", "data_quality",
    "observation", "qualification", "risk", "confidence", "result_limits",
    "views", "acceptance_lanes", "ai_assistance", "fallback_and_non_goals",
})
REQUIRED_HONEST_STATES = frozenset({"empty", "denied", "partial", "stale", "unavailable"})
REQUIRED_ACCEPTANCE_LANES = frozenset({
    "product_user", "authorization", "deterministic_interpretation",
    "api_view_model", "ui_honest_states", "evidence_audit",
})
DEFERRED_AI_SURFACES = frozenset({
    "ai-redaction-preview", "ai-prompt-preview", "ai-reports", "ai-analysis",
})
EXPECTED_DISPOSITIONS = {
    "keep": 14,
    "redesign": 0,
    "merge": 10,
    "remove": 0,
    "defer": 4,
}
FORBIDDEN_CHANGE_FLAGS = frozenset({
    "new_source", "rbac_redesign", "universal_graph", "arbitrary_report_builder",
    "mass_redesign", "schema_migration", "runtime_activation",
})


class ReportIntentContractError(ValueError):
    pass


def _object(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReportIntentContractError(code)
    return dict(value)


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require_nonempty_fields(value: Mapping[str, Any], fields: tuple[str, ...], code: str) -> None:
    if any(not _nonempty(value.get(field)) for field in fields):
        raise ReportIntentContractError(code)


def _not_applicable_or_measured(value: Any, code: str) -> None:
    item = _object(value, code)
    status = item.get("status")
    if status == "not_applicable":
        if not _nonempty(item.get("reason")):
            raise ReportIntentContractError(code)
        return
    if status != "measured" or not _nonempty(item.get("definition")):
        raise ReportIntentContractError(code)


def validate_report_intent(value: Mapping[str, Any]) -> str:
    """Validate one full passport independently of the bounded Stage 11A set."""
    intent = _object(value, "intent_section_required")
    if not REQUIRED_INTENT_SECTIONS.issubset(intent):
        raise ReportIntentContractError("intent_section_required")
    identity = _object(intent["identity"], "identity_invalid")
    _require_nonempty_fields(identity, ("report_id", "name", "primary_archetype", "version"), "identity_invalid")
    archetype = str(identity["primary_archetype"])
    if archetype not in ALLOWED_ARCHETYPES:
        raise ReportIntentContractError("primary_archetype_invalid")
    secondary = identity.get("secondary_archetype")
    if secondary is not None and secondary not in ALLOWED_ARCHETYPES:
        raise ReportIntentContractError("secondary_archetype_invalid")

    user_need = _object(intent["user_need"], "user_need_single_value_required")
    _require_nonempty_fields(user_need, ("primary_user", "question", "authorized_action"), "user_need_single_value_required")

    scope = _object(intent["scope"], "scope_invalid")
    _require_nonempty_fields(scope, ("subjects", "time_window", "domain_server_scope", "exclusions"), "scope_invalid")

    sources = _object(intent["sources"], "canonical_source_required")
    canonical = sources.get("canonical")
    if not isinstance(canonical, list) or not canonical:
        raise ReportIntentContractError("canonical_source_required")
    for item in canonical:
        source = _object(item, "canonical_source_required")
        _require_nonempty_fields(source, ("source_id", "authority", "permitted_scope", "freshness_contract"), "canonical_source_required")
    supplemental = sources.get("supplemental")
    if not isinstance(supplemental, list):
        raise ReportIntentContractError("canonical_source_required")

    access = _object(intent["access"], "access_contract_invalid")
    _require_nonempty_fields(access, ("required_capability", "dataset_or_report_grant", "server_enforced_scope"), "access_contract_invalid")
    if not isinstance(access.get("permitted_field_classes"), list) or not isinstance(access.get("allowed_actions"), list):
        raise ReportIntentContractError("access_contract_invalid")

    quality = _object(intent["data_quality"], "data_quality_invalid")
    _require_nonempty_fields(quality, ("coverage_definition", "completeness_definition", "freshness_definition", "expected_population_or_window", "denominator"), "data_quality_invalid")

    observation = _object(intent["observation"], "observation_invalid")
    _require_nonempty_fields(observation, ("server_owned_observations", "source_identity", "evidence_retention_boundary"), "observation_invalid")

    qualification = _object(intent["qualification"], "qualification_invalid")
    risk = _object(intent["risk"], "risk_invalid")
    _not_applicable_or_measured(qualification, "qualification_invalid")
    _not_applicable_or_measured(risk, "risk_invalid")
    if archetype == "compliance-control":
        if qualification.get("status") != "measured" or not _nonempty(qualification.get("policy_id")) or not _nonempty(qualification.get("control_matrix")):
            raise ReportIntentContractError("compliance_policy_required")

    _not_applicable_or_measured(intent["confidence"], "confidence_invalid")
    limits = _object(intent["result_limits"], "honest_states_incomplete")
    states = limits.get("honest_states")
    if not isinstance(states, list) or not REQUIRED_HONEST_STATES.issubset(set(states)):
        raise ReportIntentContractError("honest_states_incomplete")
    _require_nonempty_fields(limits, ("provenance", "coverage_completeness_freshness", "retention_limits", "safe_next_actions"), "honest_states_incomplete")

    views = _object(intent["views"], "views_invalid")
    _require_nonempty_fields(views, ("owner_view", "architecture_review_view", "auditor_evidence_view"), "views_invalid")
    lanes = _object(intent["acceptance_lanes"], "acceptance_lanes_invalid")
    if not REQUIRED_ACCEPTANCE_LANES.issubset(lanes) or any(not _nonempty(lanes.get(key)) for key in REQUIRED_ACCEPTANCE_LANES):
        raise ReportIntentContractError("acceptance_lanes_invalid")
    ai = _object(intent["ai_assistance"], "ai_assistance_invalid")
    if ai.get("mode") not in {"not_applicable", "draft_only"} or not _nonempty(ai.get("reason")):
        raise ReportIntentContractError("ai_assistance_invalid")
    fallback = _object(intent["fallback_and_non_goals"], "fallback_invalid")
    _require_nonempty_fields(fallback, ("deterministic_fallback", "non_goals"), "fallback_invalid")
    return str(identity["report_id"])


def validate_reporting_product_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    contract = _object(value, "contract_object_required")
    if contract.get("schema_version") != 1 or contract.get("contract_id") != "sli.stage11a.reporting-product.v1" or contract.get("stage") != "G11A-2":
        raise ReportIntentContractError("contract_identity_invalid")
    reports = contract.get("selected_report_set")
    if not isinstance(reports, list) or not reports:
        raise ReportIntentContractError("selected_report_set_required")
    report_ids = tuple(validate_report_intent(item) for item in reports)
    if len(report_ids) != len(set(report_ids)):
        raise ReportIntentContractError("selected_report_ids_unique")
    if set(report_ids) & DEFERRED_AI_SURFACES:
        raise ReportIntentContractError("selected_deferred_surface")
    if contract.get("primary_g11a3_vertical") != "vpn.audit" or "vpn.audit" not in report_ids:
        raise ReportIntentContractError("primary_vertical_invalid")

    reconciliation = _object(contract.get("inventory_reconciliation"), "inventory_counts_mismatch")
    counts = reconciliation.get("accepted_counts")
    surfaces = reconciliation.get("surfaces")
    if counts != EXPECTED_DISPOSITIONS or not isinstance(surfaces, list) or len(surfaces) != 28:
        raise ReportIntentContractError("inventory_counts_mismatch")
    actual: dict[str, int] = {key: 0 for key in EXPECTED_DISPOSITIONS}
    for surface in surfaces:
        item = _object(surface, "inventory_counts_mismatch")
        disposition = item.get("g11a0_disposition")
        if disposition not in actual or not _nonempty(item.get("surface")) or not _nonempty(item.get("stage11a_role")):
            raise ReportIntentContractError("inventory_counts_mismatch")
        actual[str(disposition)] += 1
    if actual != EXPECTED_DISPOSITIONS:
        raise ReportIntentContractError("inventory_counts_mismatch")

    deferred = contract.get("deferred_set")
    if not isinstance(deferred, list) or set(deferred) != DEFERRED_AI_SURFACES:
        raise ReportIntentContractError("deferred_set_invalid")
    merge_map = contract.get("merge_map")
    if not isinstance(merge_map, list) or len(merge_map) != 10:
        raise ReportIntentContractError("merge_map_invalid")
    flags = _object(contract.get("change_flags"), "forbidden_change_flag")
    if any(flags.get(flag) is not False for flag in FORBIDDEN_CHANGE_FLAGS):
        raise ReportIntentContractError("forbidden_change_flag")
    if contract.get("collection") != "OFF":
        raise ReportIntentContractError("collection_must_remain_off")
    return {
        "contract_id": contract["contract_id"],
        "selected_report_ids": report_ids,
        "selected_count": len(report_ids),
        "primary_g11a3_vertical": contract["primary_g11a3_vertical"],
        "inventory_counts": dict(EXPECTED_DISPOSITIONS),
    }


def load_reporting_product_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportIntentContractError("contract_unreadable") from exc
    return validate_reporting_product_contract(value)
