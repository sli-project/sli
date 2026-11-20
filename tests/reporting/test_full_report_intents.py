"""Per-product contract acceptance, using declarations and fakes without a DB."""
from copy import deepcopy
from dataclasses import replace

import pytest

from server.sli.plugins.file_audit.contracts import REPORT_KEYS, RETENTION
from server.sli.plugins.registry import call_plugin
from server.sli.reporting.report_intent_contract import (
    REQUIRED_ACCEPTANCE_LANES,
    REQUIRED_HONEST_STATES,
    REQUIRED_INTENT_SECTIONS,
    ReportIntentContractError,
    validate_report_intent,
)
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.access import resolve_access_scope
from server.sli.reporting.v2.definition import parse_params, result, source_state


# An explicit acceptance case is required when another product is registered.
V2_KEYS = (
    "ad.infrastructure", "ad.users.v2", "ad.computers.v6", "ad.computer-logons",
    "ad.new-logon-pairs", "ad.gpo.v2", "events.journal", "security.events.chains",
    "security.problems", "security.rule-quality", "vpn.accounts", "vpn.connections",
    "notifications.channels", "notifications.deliveries",
    "workstations.logons", "workstations.processes", "workstations.usb", "workstations.protection",
    "workstations.overview",
)
FILE_KEYS = tuple(f"file-audit.{key}" for key in REPORT_KEYS)


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    import psycopg
    from server.sli.core import postgres_runtime_pipeline

    def forbidden(*args, **kwargs):
        pytest.fail("Passport acceptance must not connect to a database")

    monkeypatch.setattr(psycopg, "connect", forbidden)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", forbidden)
    registry.registered_reports.cache_clear()
    yield
    registry.registered_reports.cache_clear()


@pytest.fixture(params=V2_KEYS + FILE_KEYS)
def passport(request):
    declaration = next(item for item in registry.registered_reports(validate_intents=True) if item.key == request.param)
    return declaration, declaration.intent_contract()


def test_acceptance_cases_cover_every_registered_and_reserved_product():
    definitions = registry.registered_reports(validate_intents=True)
    assert {item.key for item in definitions} == set(V2_KEYS + FILE_KEYS)
    reserved = call_plugin("sli.file-audit", "report_contracts")
    assert {item["report_key"] for item in reserved} == set(FILE_KEYS)
    assert set(FILE_KEYS) <= {item.key for item in definitions}


def test_product_user_lane_has_one_question_and_full_original_contract(passport):
    declaration, contract = passport
    key = declaration["report_key"] if isinstance(declaration, dict) else declaration.key
    assert validate_report_intent(contract) == key
    assert REQUIRED_INTENT_SECTIONS <= contract.keys()
    assert REQUIRED_ACCEPTANCE_LANES <= contract["acceptance_lanes"].keys()
    assert isinstance(contract["user_need"]["question"], str)
    assert contract["user_need"]["authorized_action"].strip()
    assert contract["acceptance_lanes"]["product_user"].strip()
    assert contract["identity"]["primary_archetype"] != "list"


def test_authorization_lane_matches_grants_fields_and_capabilities(passport):
    declaration, contract = passport
    assert contract["acceptance_lanes"]["authorization"].strip()
    access = contract["access"]
    if isinstance(declaration, dict):
        from server.sli.plugins.file_audit.access import require_access

        assert access["dataset_or_report_grant"] == declaration["report_key"]
        assert set(access["permitted_field_classes"]) == set(declaration["field_categories"])
        assert access["allowed_actions"] == list(declaration["actions"])
        assert access["required_capability"] == "file-audit.view"
        with pytest.raises(PermissionError, match="file_audit_access_denied"):
            require_access({}, action="view", agent_id="synthetic-agent",
                           source_instance_id="synthetic-source", collection_scope_id="synthetic-root")
    else:
        assert access["dataset_or_report_grant"] == declaration.access.report_key
        assert declaration.access.required_fields <= set(access["permitted_field_classes"])
        assert declaration.access.required_capabilities <= set(access["required_capability"].split(", "))
        assert (declaration.access.export_action in access["allowed_actions"]) == (declaration.export_csv is not None)
        with pytest.raises(PermissionError, match="report_access_denied"):
            resolve_access_scope({}, declaration.access)


def test_deterministic_lane_retains_explicit_policy_and_valid_interpretation(passport):
    declaration, contract = passport
    assert contract["deterministic_policy"].strip()
    assert contract["acceptance_lanes"]["deterministic_interpretation"].strip()
    assert contract["ai_assistance"]["mode"] == "not_applicable"
    broken = deepcopy(contract)
    broken["qualification"] = {"status": "measured", "definition": ""}
    with pytest.raises(ReportIntentContractError, match="qualification_invalid"):
        validate_report_intent(broken)
    if not isinstance(declaration, dict):
        with pytest.raises(ValueError, match="report_intent_invalid:deterministic_policy"):
            registry.validate_report_intents((replace(declaration, intent=replace(declaration.intent, deterministic_policy="")),))


def test_api_lane_bounds_come_from_executable_declaration_or_draft_reservation(passport):
    declaration, contract = passport
    assert contract["acceptance_lanes"]["api_view_model"].strip()
    bounds = contract["result_limits"]["execution"]
    if isinstance(declaration, dict):
        assert declaration["status"] == contract["identity"]["product_status"] == "draft"
        assert bounds["reader"] == "not_published"
        assert {key: bounds[key] for key in RETENTION} == RETENTION
        assert "max" not in bounds  # No invented executable limit for a draft.
    else:
        assert bounds["default"] == declaration.default_limit
        assert bounds["max"] == declaration.max_limit
        assert bounds["period_max_days"] == {param.key: param.max_days for param in declaration.params if param.kind == "period"}
        query = {param.key: [str(param.default or 1)] for param in declaration.params if param.required and param.kind == "domain"}
        _, paging = parse_params(declaration, query)
        assert paging["limit"] == bounds["default"]
        with pytest.raises(ValueError, match="report_limit_invalid"):
            parse_params(declaration, {**query, "limit": [str(bounds["max"] + 1)]})


def test_honest_state_lane_keeps_missing_data_distinct_from_empty(passport):
    declaration, contract = passport
    assert contract["acceptance_lanes"]["ui_honest_states"].strip()
    assert REQUIRED_HONEST_STATES <= set(contract["result_limits"]["honest_states"])
    assert contract["fallback_and_non_goals"]["deterministic_fallback"].strip()
    broken = deepcopy(contract)
    broken["result_limits"]["honest_states"].remove("partial")
    with pytest.raises(ReportIntentContractError, match="honest_states_incomplete"):
        validate_report_intent(broken)
    if not isinstance(declaration, dict):
        states = {state: result(declaration, state=source_state(state))["state"] for state in REQUIRED_HONEST_STATES}
        assert len(set(states.values())) == len(REQUIRED_HONEST_STATES)
        assert states["unavailable"] == "error"
        assert states["empty"] == "empty"


def test_evidence_lane_preserves_source_authority_and_retention_boundary(passport):
    declaration, contract = passport
    assert contract["acceptance_lanes"]["evidence_audit"].strip()
    assert contract["sources"]["canonical"]
    assert contract["observation"]["evidence_retention_boundary"] == contract["result_limits"]["retention_limits"]
    assert contract["views"]["auditor_evidence_view"] == contract["result_limits"]["provenance"]
    assert contract["fallback_and_non_goals"]["non_goals"].strip()
    broken = deepcopy(contract)
    broken["fallback_and_non_goals"]["deterministic_fallback"] = ""
    with pytest.raises(ReportIntentContractError, match="fallback_invalid"):
        validate_report_intent(broken)
    if not isinstance(declaration, dict):
        assert contract["result_limits"]["provenance"] == declaration.intent.provenance
        assert contract["observation"]["source_identity"] == "; ".join(
            source for source in declaration.intent.sources if source.startswith("Canonical:"))


@pytest.mark.parametrize("lane", sorted(REQUIRED_ACCEPTANCE_LANES))
def test_registry_rejects_each_missing_acceptance_lane(lane):
    definition = registry.get_report("ad.computers.v6")
    lanes = dict(definition.intent.acceptance_lanes)
    lanes.pop(lane)
    with pytest.raises(ValueError, match="report_intent_invalid:acceptance_lanes"):
        registry.validate_report_intents((replace(definition, intent=replace(definition.intent, acceptance_lanes=lanes)),))


@pytest.mark.parametrize("field,error", [
    ("qualification", "qualification_invalid"), ("risk", "risk_invalid"), ("confidence", "confidence_invalid"),
])
def test_registry_uses_original_interpretation_validation(field, error):
    definition = registry.get_report("ad.computers.v6")
    broken = replace(definition.intent, **{field: {"status": "invented", "reason": "synthetic"}})
    with pytest.raises(ReportIntentContractError, match=error):
        registry.validate_report_intents((replace(definition, intent=broken),))


@pytest.mark.parametrize("sources", [("Supplemental: synthetic context",), ("Canonical:",), ("untagged source",)])
def test_source_authority_cannot_be_guessed_from_an_untagged_or_supplemental_source(sources):
    definition = registry.get_report("ad.computers.v6")
    with pytest.raises(ValueError, match="report_intent_invalid:sources"):
        registry.validate_report_intents((replace(definition, intent=replace(definition.intent, sources=sources)),))


def test_full_contract_limits_follow_changed_declaration_without_changing_passport():
    definition = registry.get_report("ad.computers.v6")
    changed = replace(definition, default_limit=10, max_limit=20, export_csv=None)
    contract = changed.intent_contract()
    assert contract["result_limits"]["execution"]["default"] == 10
    assert contract["result_limits"]["execution"]["max"] == 20
    assert contract["access"]["allowed_actions"] == ["view"]
    assert changed.intent.to_json() == definition.intent.to_json()
