"""Credential binding with registry/cursor fakes, never passwords or live AD."""
from copy import deepcopy

import pytest

from server.sli.agents import gpo_plan_credentials as credentials, gpo_plans as plans
from server.sli.agents.ca import AgentError
from tests.unit.test_agent_gpo_plans import ACTOR, CREDENTIAL, SELECTION, Cursor, Registry, confirmation

REGISTRY_FACTORY = credentials._registry


@pytest.fixture(autouse=True)
def registry(monkeypatch):
    monkeypatch.setattr(credentials, "_registry", lambda: Registry)


def test_bound_plan_a_cannot_be_confirmed_with_account_b_or_a_changed_revision():
    cur = Cursor()
    result = plans.preview(cur, SELECTION, actor=ACTOR)
    for change in ({"credential_id": "00000000-0000-4000-8000-000000000011"},
                   {"credential_revision": 2}, {"credential_revision": True}):
        with pytest.raises(AgentError, match="gpo_credential_changed"):
            plans.finish(cur, {**confirmation(result), **change}, actor=ACTOR)
    assert not cur.preferences
    assert cur.plans[result["plan_id"]]["status"] == "preview"


@pytest.mark.parametrize("change", ["password", "deleted", "domain", "ou", "check", "unknown_check", "checked_at", "ad_grant", "ad_ou",
    "ad_scope_change", "credential_scope_change", "gpo_scope_change", "gpo_permission_change",
    "certificate", "agent", "assignment", "disabled"])
def test_confirm_rechecks_account_grant_and_recipient_without_fallback(change):
    cur = Cursor()
    result = plans.preview(cur, SELECTION, actor=ACTOR)
    row = cur.credentials[CREDENTIAL["credential_id"]]
    if change == "password": row["credential_revision"] += 1
    elif change == "deleted": cur.credentials.clear()
    elif change == "domain": row["domain_id"] = 2
    elif change == "ou": row["ou_entity_ids"] = [9]
    elif change == "check": row["check_status"] = "unavailable"
    elif change == "unknown_check": row["check_status"] = "future-status"
    elif change == "checked_at": row["checked_at"] = "2026-01-01T00:00:00+00:00"
    elif change == "ad_grant": cur.ad_grants.clear()
    elif change == "ad_ou": cur.ad_grants[ACTOR][1] = [9]
    elif change == "ad_scope_change": cur.ad_grants[ACTOR][1].append(9)
    elif change == "credential_scope_change": row["ou_entity_ids"].append(9)
    elif change == "gpo_scope_change": cur.grants[(ACTOR, 1)]["ou_entity_ids"].append(9)
    elif change == "gpo_permission_change": cur.grants[(ACTOR, 1)]["permissions"] = ["apply"]
    elif change == "certificate": cur.recipient["certificate_sha256"] = "e" * 64
    elif change == "agent": cur.recipient["agent_id"] = "00000000-0000-4000-8000-000000000021"
    elif change == "assignment": cur.recipient["assignment_revision"] += 1
    else: cur.recipient = None
    with pytest.raises(AgentError):
        plans.finish(cur, confirmation(result), actor=ACTOR)
    assert cur.plans[result["plan_id"]]["status"] == "preview"
    assert cur.plan_audit[-1][2] == "denied" and not cur.preferences


def test_audit_and_last_choice_are_bound_and_never_contain_private_registry_fields():
    cur = Cursor()
    cur.credentials[CREDENTIAL["credential_id"]]["envelope"] = {"fixture": "private-test-marker"}
    result = plans.preview(cur, SELECTION, actor=ACTOR)
    plans.finish(cur, confirmation(result), actor=ACTOR)
    assert cur.preferences[(ACTOR, 1)] == CREDENTIAL
    assert cur.plan_audit[0][5:9] == (CREDENTIAL["credential_id"], 1,
        cur.recipient["agent_id"], cur.recipient["certificate_sha256"])
    assert cur.plan_audit[0][9] == cur.plans[result["plan_id"]]["expires_at"]
    assert "private-test-marker" not in repr((result, cur.plan_audit, cur.preferences))


def test_legacy_plans_and_replay_after_reloading_state_are_denied():
    original = Cursor()
    result = plans.preview(original, SELECTION, actor=ACTOR)
    restored = Cursor()
    restored.plans = deepcopy(original.plans)
    restored.plans[result["plan_id"]]["snapshot"].pop("credential_binding")
    with pytest.raises(AgentError, match="gpo_credential_changed"):
        plans.finish(restored, confirmation(result), actor=ACTOR)
    restored.plans = deepcopy(original.plans)
    plans.finish(restored, confirmation(result), actor=ACTOR)
    restarted = Cursor()
    restarted.plans = deepcopy(restored.plans)
    with pytest.raises(AgentError, match="gpo_plan_unavailable"):
        plans.finish(restarted, confirmation(result), actor=ACTOR)


def test_cancel_remains_possible_after_the_saved_account_is_deleted():
    cur = Cursor()
    result = plans.preview(cur, SELECTION, actor=ACTOR)
    cur.credentials.clear()
    assert plans.finish(cur, confirmation(result, cancel=True), actor=ACTOR, cancel=True)["status"] == "cancelled"
    assert not cur.preferences


def options(cur, *, actor=ACTOR, domain=1):
    selection = {key: value for key, value in SELECTION.items() if key not in CREDENTIAL}
    return credentials.options(cur, {**selection, "domain_id": domain}, actor=actor)


def test_options_use_only_last_successful_account_for_this_actor_domain_and_revision():
    cur = Cursor()
    assert options(cur)["selected_credential_id"] is None
    result = plans.preview(cur, SELECTION, actor=ACTOR)
    plans.finish(cur, confirmation(result), actor=ACTOR)
    assert options(cur)["selected_credential_id"] == CREDENTIAL["credential_id"]
    cur.credentials[CREDENTIAL["credential_id"]]["credential_revision"] += 1
    assert options(cur)["selected_credential_id"] is None
    cur.credentials[CREDENTIAL["credential_id"]]["credential_revision"] = 1
    cur.credentials[CREDENTIAL["credential_id"]]["check_status"] = "unavailable"
    value = options(cur)
    assert value["selected_credential_id"] is None and value["items"][0]["eligible"] is False
    cur.credentials.clear()
    assert options(cur)["items"] == []


def test_other_actor_never_inherits_the_last_choice_and_metadata_does_not_include_an_envelope():
    cur = Cursor()
    cur.preferences[(ACTOR, 1)] = CREDENTIAL
    other = "session:2"
    cur.grants[(other, 1)] = deepcopy(cur.grants[(ACTOR, 1)])
    cur.ad_grants[other] = {1: [2]}
    cur.credentials[CREDENTIAL["credential_id"]]["envelope"] = {"fixture": "private-test-marker"}
    result = options(cur, actor=other)
    assert result["selected_credential_id"] is None
    assert set(result["items"][0]) == {"credential_id", "credential_revision", "label", "username", "check_status", "eligible"}
    assert "private-test-marker" not in repr(result)


@pytest.mark.parametrize("change", ["key", "recipient", "scope"])
def test_missing_key_recipient_or_target_scope_disables_choices(monkeypatch, change):
    cur = Cursor()
    if change == "key":
        def missing():
            raise AgentError("ad_master_key_not_configured", 409)
        monkeypatch.setattr(Registry, "_key", missing)
    elif change == "recipient": cur.recipient = None
    else: cur.credentials[CREDENTIAL["credential_id"]]["ou_entity_ids"] = [9]
    assert options(cur)["items"][0]["eligible"] is False


def test_missing_stage3_dependency_has_no_ambient_fallback(monkeypatch):
    monkeypatch.setattr(credentials, "_registry", REGISTRY_FACTORY)
    def missing(name):
        raise ModuleNotFoundError(name=name)
    monkeypatch.setattr(credentials, "import_module", missing)
    with pytest.raises(AgentError, match="gpo_credentials_unavailable"):
        plans.preview(Cursor(), SELECTION, actor=ACTOR)


def test_plain_old_scope_does_not_authorize_new_ad_operations():
    cur = Cursor()
    cur.ad_grants.clear()
    with pytest.raises(AgentError, match="ad_operations_denied"):
        plans.preview(cur, SELECTION, actor=ACTOR)
    assert cur.plan_audit[-1][2] == "denied" and not cur.plans


@pytest.mark.parametrize("change", ["password", "deleted"])
def test_binding_uses_merged_stage3_registry_and_rechecks_its_saved_revision(monkeypatch, change):
    from server.sli.agents import ad_credentials
    from tests.unit.test_ad_operation_credentials import BODY, PASSWORD, Cursor as AccountCursor

    monkeypatch.setattr(credentials, "_registry", REGISTRY_FACTORY)
    monkeypatch.setattr(ad_credentials.secrets, "read_master_key", lambda: b"k" * 32)
    cur = AccountCursor()
    cur.scopes = {1: [2]}
    saved = ad_credentials.create(cur, BODY, actor=ACTOR)
    execute = cur.execute
    recipient = Cursor().recipient

    def query(sql, params=()):
        if sql.startswith("select public.sli_gpo_plan_recipient"):
            cur.rows = [{"recipient": recipient}]
        else:
            execute(sql, params)

    monkeypatch.setattr(cur, "execute", query)
    binding = credentials.bind(cur, ACTOR, 1, saved["credential_id"], 1, [2])
    assert binding["recipient"] == recipient
    assert binding["credential_id"] == saved["credential_id"]
    assert PASSWORD not in repr(binding) and "envelope" not in binding
    reference = {"credential_id": saved["credential_id"], "credential_revision": 1}
    if change == "password":
        ad_credentials.replace_password(cur, {**reference, "password": PASSWORD}, actor=ACTOR)
    else:
        ad_credentials.delete(cur, reference, actor=ACTOR)
    with pytest.raises(AgentError):
        credentials.bind(cur, ACTOR, 1, saved["credential_id"], 1, [2])
