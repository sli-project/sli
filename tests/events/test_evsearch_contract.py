"""ES01 wire/policy/legacy contracts with server-owned synthetic fakes only."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from server.sli.events import evsearch_contract as contract
from server.sli.events.evsearch_legacy import translate_legacy


def request(conditions=None, **overrides):
    return {
        "contract_version": "evsearch.v1", "conditions": conditions or [],
        "period": {"preset": "24h", "timezone": "UTC"}, **overrides,
    }


def grant(scope=None, categories=("security", "technical"), actions=("view", "export")):
    return {
        "scope": scope or {"kind": "domain", "ids": [7]},
        "field_categories": list(categories), "allowed_actions": list(actions),
    }


def access(*grants, actions=("view", "export")):
    return {
        "policy_revision": "fixture-revision", "decision_id": "fixture-decision",
        "capabilities": ["reports.export"],
        "reports": [{"report_key": "events.explorer", "allowed": True,
                     "allowed_actions": list(actions), "grants": list(grants or [grant()])}],
    }


def publication():
    fields = [{"key": key, "category": "technical" if key in {"id", "channel", "server_id"} else "security"}
              for key in ("id", "channel", "event_id", "account", "server_id", "q", "account_kind")]
    return {
        "dataset_key": "events.v2", "fields_json": fields,
        "definition_json": {"columns": [field["key"] for field in fields],
                            "actions": ["view", "export"], "export_policy": "controlled"},
    }


def test_version_constants_and_existing_grant_identity_are_fixed():
    assert contract.CONTRACT_VERSION == "evsearch.v1"
    assert contract.API_NAMESPACE == "/api/v1/event-search"
    assert contract.ACCESS_KEY == "events.explorer"
    assert contract.LEGACY_REPORT_KEY == "events.journal"
    assert contract.FIELDS["account"].roles == {"actor", "target", "any"}


@pytest.mark.parametrize("overrides", [
    {"contract_version": "evsearch.v2"}, {"grouping_version": "future"},
    {"conditions": [{"field": "sql", "operator": "eq", "value": "opaque"}]},
    {"conditions": [{"field": "channel", "operator": "contains", "value": "opaque"}]},
    {"conditions": [{"field": "channel", "operator": "in", "value": []}]},
    {"conditions": [{"field": "account", "operator": "eq", "value": "ambiguous", "role": "any"}]},
    {"conditions": [{"field": "account", "operator": "eq", "value": 1}]},
    {"conditions": [{"field": "account", "operator": "eq", "value": True, "role": "any"}]},
    {"conditions": [{"field": "ip", "operator": "eq", "value": "invalid-ip"}]},
    {"conditions": [{"field": "channel", "operator": "missing", "value": None}]},
    {"conditions": [{"field": "legacy_journal_view", "operator": "eq", "value": "future"}]},
    {"conditions": [{"field": "channel", "operator": "eq", "value": "opaque", "scope": "all"}]},
    {"scope": {"kind": "all"}}, {"page_size": True}, {"page_size": 101},
    {"sort": []}, {"exclude_machine_system": "false"}, {"q": "x" * 257},
    {"period": {"preset": "all", "timezone": "UTC"}},
    {"period": {"preset": "custom", "timezone": "UTC", "from": "2026-01-01"}},
    {"period": {"preset": "24h", "timezone": "UTC", "from": "2026-01-01"}},
])
def test_invalid_input_never_becomes_an_unfiltered_request(overrides):
    with pytest.raises(contract.ContractError) as error:
        contract.validate_request(request(**overrides))
    assert str(error.value).startswith("evsearch.")
    assert "opaque" not in str(error.value)


@pytest.mark.parametrize("operator,value", [("eq", 4625), ("in", [4625]), ("not_in", [4625])])
def test_event_id_always_requires_positive_provider_or_channel_context(operator, value):
    condition = {"field": "event_id", "operator": operator, "value": value}
    with pytest.raises(contract.ContractError, match="event_context_required"):
        contract.validate_request(request([condition]))
    assert contract.validate_request(request([condition, {"field": "channel", "operator": "eq", "value": "Security"}]))
    with pytest.raises(contract.ContractError, match="event_context_required"):
        contract.validate_request(request([condition, {"field": "channel", "operator": "not_in", "value": ["Security"]}]))


def test_not_in_and_explicit_exists_are_retained_without_rewriting_null_semantics():
    original = request([
        {"field": "account", "role": "target", "operator": "not_in", "value": [11]},
        {"field": "account", "role": "target", "operator": "exists"},
    ])
    validated = contract.validate_request(original)
    assert validated == original
    original["conditions"][0]["value"].append(12)
    assert validated["conditions"][0]["value"] == [11]


def test_issued_scope_preserves_all_legacy_resource_assignments_without_mutation():
    server_access = access(grant(), grant({"kind": "server", "ids": [9]}), grant({"kind": "channel", "values": ["Security"]}))
    before = deepcopy(server_access)
    policy = contract.authorize_request(request(), access=server_access, publication=publication(), fields=("id",))
    assert server_access == before
    assert policy.report_key == "events.explorer"
    assert policy.scope.policy_revision == "fixture-revision"
    assert policy.scope.allows(domain_id=7)
    assert policy.scope.allows(device_id="server:9")
    assert policy.scope.allows(collection_scope_id="channel:Security")
    assert not policy.scope.allows(domain_id=8)


@pytest.mark.parametrize("server_access", [
    {"reports": []}, access(actions=()),
    access(grant(actions=("export",))),
    access(grant({"kind": "unknown", "ids": [7]})),
    access(grant(categories=("technical",))),
    # A field permission in one domain cannot be multiplied by a different
    # grant's resource scope or field categories.
    access(grant(categories=("technical",)), grant({"kind": "domain", "ids": [8]}, categories=("security", "technical"))),
    access(grant(categories=("security",)), grant(categories=("technical",))),
])
def test_denied_or_split_grants_never_authorize_hidden_predicates(server_access):
    with pytest.raises(PermissionError, match="evsearch.policy_denied"):
        contract.authorize_request(request([{"field": "account", "operator": "eq", "value": 11, "role": "any"}]),
                                   access=server_access, publication=publication(), fields=("id",))


def test_unpublished_fields_are_not_available_even_with_an_all_grant():
    with pytest.raises(PermissionError, match="evsearch.policy_denied"):
        contract.authorize_request(request([{"field": "reason", "operator": "eq", "value": "opaque"}]),
                                   access=access(grant({"kind": "all"})), publication=publication(), fields=("id",))


@pytest.mark.parametrize("change", ["dataset", "columns", "action", "export_policy", "capability", "grant_action"])
def test_export_requires_publication_fields_capability_and_independent_grant(change):
    published, server_access = publication(), access()
    if change == "dataset":
        published["dataset_key"] = "other"
    elif change == "columns":
        published["definition_json"]["columns"].remove("id")
    elif change == "action":
        published["definition_json"]["actions"] = ["view"]
    elif change == "export_policy":
        published["definition_json"]["export_policy"] = "disabled"
    elif change == "capability":
        server_access["capabilities"] = []
    else:
        server_access = access(grant(actions=("view",)))
    with pytest.raises(PermissionError):
        contract.authorize_request(request(), access=server_access, publication=published, fields=("id",), action="export")


def test_export_is_authorized_with_the_same_scope_as_view():
    view = contract.authorize_request(request(), access=access(), publication=publication(), fields=("id",))
    export = contract.authorize_request(request(), access=access(), publication=publication(), fields=("id",), action="export")
    assert export.scope == view.scope
    assert export.action == "export"


def test_q_machine_switch_and_questions_require_their_own_published_dependencies():
    published = publication()
    published["definition_json"]["evsearch_questions"] = {"failed_logons": ["account_kind"]}
    for query, dependency in ((request(q="opaque"), "q"),
                              (request(exclude_machine_system=True), "account_kind"),
                              (request(question_id="failed_logons"), "account_kind")):
        assert dependency in contract.authorize_request(query, access=access(), publication=published, fields=("id",)).fields
        narrow = deepcopy(published)
        narrow["definition_json"]["columns"].remove(dependency)
        with pytest.raises(PermissionError):
            contract.authorize_request(query, access=access(), publication=narrow, fields=("id",))
    with pytest.raises(contract.ContractError, match="unsupported_question"):
        contract.authorize_request(request(question_id="future"), access=access(), publication=published, fields=("id",))


def test_legacy_journal_keeps_exact_compatibility_predicates_and_resets_paging():
    seen = []
    def resolve(field, text, role):
        seen.append((field, role))
        return [9]
    result = translate_legacy({"q": ["opaque"], "view": ["authentication"], "server": ["synthetic-source"],
                               "cursor": ["obsolete"], "offset": ["50"], "return_to": ["/app/events"]}, resolve_identity=resolve)
    assert result.notices == ("evsearch.legacy_paging_reset",)
    assert not result.start_empty
    assert result.request["conditions"] == [
        {"field": "legacy_journal_view", "operator": "eq", "value": "authentication"},
        {"field": "legacy_journal_q", "operator": "eq", "value": "opaque"},
        {"field": "server_id", "operator": "in", "value": [9]},
    ]
    assert seen == [("server_id", None)]
    assert not set(result.request) & {"cursor", "offset"}
    assert translate_legacy({}).start_empty


def test_legacy_search_translates_roles_event_identity_period_and_explicit_view_override():
    result = translate_legacy({
        "account": ["synthetic-account"], "subject": ["synthetic-actor"], "target": ["synthetic-target"],
        "event_id": ["4625", "4624"], "provider": ["synthetic-provider"], "channel": ["Security"],
        "view": ["authentication"], "category": ["account_management"],
        "time_from": ["2026-10-01T00:00:00Z"], "time_to": ["2026-10-02T00:00:00Z"], "timezone": ["UTC"],
    }, source="search", resolve_identity=lambda field, value, role: [11])
    conditions = result.request["conditions"]
    assert {c["role"] for c in conditions if c["field"] == "account"} == {"any", "actor", "target"}
    assert [c["value"] for c in conditions if c["field"] == "category"] == ["account_management"]
    assert next(c["value"] for c in conditions if c["field"] == "event_id") == [4625, 4624]
    assert result.request["period"] == {"preset": "custom", "from": "2026-10-01T00:00:00Z", "to": "2026-10-02T00:00:00Z", "timezone": "UTC"}


@pytest.mark.parametrize("key", ["category", "risk", "tier", "account", "event_id", "provider", "channel"])
def test_search_only_parameters_are_not_invented_for_the_old_journal(key):
    with pytest.raises(contract.ContractError, match="legacy_unsupported_filter"):
        translate_legacy({key: ["opaque"]}, source="journal")


def test_search_parameters_are_not_dropped_when_search_link_translation_fails():
    with pytest.raises(contract.ContractError, match="event_context_required"):
        translate_legacy({"event_id": ["4625"]}, source="search")
    with pytest.raises(contract.ContractError, match="legacy_identity_unresolved"):
        translate_legacy({"account": ["ambiguous"]}, source="search", resolve_identity=lambda *args: [11, 12])


def test_journal_hostname_is_not_broadened_into_a_search_server_list():
    seen = []
    def resolve(field, value, role):
        seen.append(value)
        return [9]
    translate_legacy({"server": ["synthetic-one,synthetic-two"]}, resolve_identity=resolve)
    assert seen == ["synthetic-one,synthetic-two"]
    seen.clear()
    translate_legacy({"server": ["synthetic-one,synthetic-two"]}, source="search", resolve_identity=resolve)
    assert seen == ["synthetic-one", "synthetic-two"]


@pytest.mark.parametrize("query", [
    {"unknown": ["opaque"]}, {"q": ["one", "two"]}, {"q": [""]},
    {"view": ["unknown"]}, {"event_id": ["4625"]},
    {"event_id": ["invalid"], "channel": ["Security"]},
    {"account": ["opaque"], "user": ["different"]},
    {"provider": ["one"], "source": ["two"]},
    {"account": ["ambiguous"]}, {"server": ["unresolved"]},
    {"time_from": ["2026-10-01T00:00:00Z"]},
    {"time_from": ["2026-10-01"], "time_to": ["2026-10-02"], "period": ["7d"]},
    {"return_to": ["https://example.invalid/"]}, {"return_to": ["/app/../external"]},
])
def test_unsupported_legacy_link_is_an_error_instead_of_a_broader_search(query):
    with pytest.raises(contract.ContractError):
        translate_legacy(query, resolve_identity=lambda *args: [11, 12])


@pytest.mark.parametrize("value", ["//example.invalid/app/events", "/app/%2e%2e/events", "/app/events\\other", "/app/events%0a", "/app/settings", "https://[", "/app/events?x=%7f"])
def test_return_context_has_a_safe_local_allowlist(value):
    assert not contract.safe_return_to(value)


def test_all_contract_codes_have_both_server_translations():
    root = Path(__file__).resolve().parents[2]
    dictionaries = [json.loads((root / f"config/i18n/server.{language}.json").read_text(encoding="utf-8")) for language in ("ru", "en")]
    keys = {key for key in dictionaries[0] if key.startswith("evsearch.")}
    assert keys == {key for key in dictionaries[1] if key.startswith("evsearch.")}
    assert "evsearch.legacy_paging_reset" in keys
    for code in ("invalid_request", "unsupported_version", "invalid_period", "invalid_condition", "unsupported_field",
                 "unsupported_operator", "event_context_required", "unsupported_action", "policy_denied", "unsupported_question",
                 "legacy_unsupported_filter", "legacy_ambiguous_filter", "legacy_identity_unresolved"):
        assert f"evsearch.{code}" in keys
