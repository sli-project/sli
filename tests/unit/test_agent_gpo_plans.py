"""Stage 2 uses cursor fakes only: no AD, SYSVOL, DB or writer dispatch."""
from copy import deepcopy
from datetime import timedelta
import json

import pytest

from server.sli.agents import gpo_plans as plans
from server.sli.agents import gpo_plan_credentials as credentials
from server.sli.agents.ca import AgentError, utcnow
from tests.unit.test_agent_group_enrollment import GroupCursor

ACTOR = "session:1"
CREDENTIAL = {"credential_id": "00000000-0000-4000-8000-000000000010", "credential_revision": 1}
SELECTION = {"domain_id": 1, "computer_entity_ids": [3], **CREDENTIAL}


class Registry:
    @staticmethod
    def _scopes(cur, actor):
        return cur.ad_grants.get(actor, {})

    @staticmethod
    def _record(cur, credential, *, actor):
        if not Registry._scopes(cur, actor) or credential not in cur.credentials:
            raise AgentError("ad_operations_denied", 403)
        return deepcopy(cur.credentials[credential])

    @staticmethod
    def _key():
        return b""  # No secret is used by the planner.

    @staticmethod
    def list_credentials(cur, *, actor):
        if not Registry._scopes(cur, actor):
            raise AgentError("ad_operations_denied", 403)
        return {"items": [deepcopy(row) for row in cur.credentials.values()
                          if row["domain_id"] in Registry._scopes(cur, actor)]}


@pytest.fixture(autouse=True)
def registry(monkeypatch):
    monkeypatch.setattr(credentials, "_registry", lambda: Registry)


class Cursor(GroupCursor):
    def __init__(self):
        super().__init__()
        self.plans, self.plan_audit = {}, []
        self.ad_grants = {ACTOR: {1: [2]}}
        self.credentials = {CREDENTIAL["credential_id"]: {**CREDENTIAL, "domain_id": 1,
            "ou_entity_ids": [2], "check_status": "not_checked", "label": "fixture", "username": "EXAMPLE\\fixture"}}
        self.recipient = {"agent_id": "00000000-0000-4000-8000-000000000020",
            "certificate_sha256": "d" * 64, "assignment_revision": 1}
        self.preferences = {}
        self.grants = {(ACTOR, 1): {"ou_entity_ids": [2], "permissions": ["preview", "apply"]}}
        self.scope = {"revision": 1, "ou_entity_ids": [2], "evidence_sha256": "b" * 64, "package": {}}
        self.expire_on_finish = False
        self.directory[(3, 1)]["record"]["attributes"].update(user_account_control=4096, display_name="synthetic-host")
        self.directory[(3, 1)]["record"]["identity"].update(
            object_guid="00000000-0000-4000-8000-000000000003", object_sid="S-1-5-21-1-2-3-1003")

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        self.rows = []
        if sql.startswith("select credential_id,credential_revision,ou_entity_ids from sli_ad_operation_credentials"):
            self.rows = [deepcopy(row) for row in self.credentials.values() if row["domain_id"] == params[0]]
        elif sql.startswith("select public.sli_gpo_plan_recipient"):
            self.rows = [{"recipient": deepcopy(self.recipient)}]
        elif sql.startswith("select credential_id,credential_revision from sli_gpo_plan_last_credentials"):
            self.rows = [self.preferences[params]] if params in self.preferences else []
        elif sql.startswith("insert into sli_gpo_plan_last_credentials"):
            self.preferences[params[:2]] = {"credential_id": params[2], "credential_revision": params[3]}
        elif sql.startswith("select public.sli_agent_gpo_plan_scope"):
            grant = self.grants.get(params[:2])
            scope = {**deepcopy(self.scope), "grant_ou_entity_ids": grant["ou_entity_ids"],
                "grant_permissions": grant["permissions"]} if grant and params[2] in grant["permissions"] else None
            self.rows = [{"scope": scope}]
        elif sql.startswith("insert into sli_agent_gpo_plan_audit"):
            self.plan_audit.append(params)
        elif sql.startswith("insert into sli_agent_gpo_plans"):
            plan, actor, domain, selection, snapshot, digest, expires = params
            self.plans[plan] = dict(id=plan, actor=actor, domain_id=domain, selection=json.loads(selection),
                snapshot=json.loads(snapshot), plan_sha256=digest, expires_at=expires, status="preview")
        elif sql.startswith("select * from sli_agent_gpo_plans"):
            self.rows = [self.plans[params[0]]] if params[0] in self.plans else []
        elif sql.startswith("update sli_agent_gpo_plans"):
            row = self.plans[params[1]]
            if not self.expire_on_finish and row["status"] == "preview" and row["expires_at"] > utcnow():
                row["status"] = params[0]
                self.rows = [{"id": row["id"]}]
        elif sql.startswith("select attributes_json"):
            self.rows = [{"attributes_json": row["record"]} for row in self.directory.values() if row["version_id"] == params[0]]
        elif sql.startswith("select fqdn"):
            self.rows = [{"fqdn": "synthetic.invalid"}]
        elif sql.startswith("select e.id as entity_id,v.attributes_json"):
            self.rows = [{**deepcopy(row), "entity_id": entity} for (entity, domain), row in self.directory.items()
                         if domain == params[1] and entity in params[0]]
        elif sql.startswith("select e.id as entity_id"):
            self.rows = [{**deepcopy(row), "entity_id": entity} for (entity, domain), row in self.directory.items()
                         if domain == params[0] and row["record"]["identity"]["kind"] == "ad_computer"]
        else:
            self.calls.pop()
            super().execute(sql, params)


def confirmation(plan, *, cancel=False):
    return {"plan_id": plan["plan_id"], "plan_sha256": plan["plan_sha256"],
        **({} if cancel else {"acknowledged": True, **{key: plan["credential_binding"][key] for key in CREDENTIAL}})}


def test_preview_confirm_retry_records_one_intention_and_never_issues_credentials():
    cur = Cursor()
    before = deepcopy(cur.directory)
    plan = plans.preview(cur, SELECTION, actor=ACTOR)
    assert plan["write_enabled"] is False and plan["token_ttl_seconds"] == 604800
    assert plan["targets"] == [{"entity_id": 3, "name": "synthetic-host"}]
    assert plan["ou_entity_ids"] == [2]
    assert utcnow() + timedelta(minutes=9) < cur.plans[plan["plan_id"]]["expires_at"] <= utcnow() + timedelta(minutes=10)
    result = plans.finish(cur, confirmation(plan), actor=ACTOR)
    with pytest.raises(AgentError, match="gpo_plan_unavailable"):
        plans.finish(cur, confirmation(plan), actor=ACTOR)
    assert result == {"plan_id": plan["plan_id"], "status": "confirmed", "write_enabled": False}
    assert [event[2] for event in cur.plan_audit] == ["preview", "confirmed", "denied"]
    assert len(cur.plans) == 1 and cur.directory == before
    assert not cur.groups and not cur.tokens and not cur.agents and not cur.certificates
    assert "synthetic-host" not in repr(cur.plan_audit)
    assert not any("sli_agent_group_tokens" in sql or "command" in sql for sql, _ in cur.calls)


@pytest.mark.parametrize("actor,domain,grant", [("session:2", 1, True), (ACTOR, 2, True), (ACTOR, 1, False)])
def test_foreign_role_domain_and_unassigned_owner_are_denied(actor, domain, grant):
    cur = Cursor()
    if not grant:
        cur.grants.clear()
    with pytest.raises(AgentError, match="gpo_deployment_denied") as error:
        plans.preview(cur, {**SELECTION, "domain_id": domain}, actor=actor)
    assert error.value.status == 403 and not cur.plans
    assert cur.plan_audit[-1][2:5] == ("denied", None, "gpo_deployment_denied")


def test_ou_selection_is_finite_and_never_auto_expands_after_preview():
    cur = Cursor()
    plan = plans.preview(cur, {"domain_id": 1, "ou_entity_ids": [2], **CREDENTIAL}, actor=ACTOR)
    cur.directory[(4, 1)] = deepcopy(cur.directory[(3, 1)])
    cur.directory[(4, 1)]["version_id"] = 40
    assert plans.finish(cur, confirmation(plan), actor=ACTOR)["status"] == "confirmed"
    assert [target["entity_id"] for target in cur.plans[plan["plan_id"]]["snapshot"]["targets"]] == [3]


def test_ou_selection_includes_nested_computers_with_rdn_boundaries():
    cur = Cursor()
    attrs = cur.directory[(3, 1)]["record"]["attributes"]
    attrs["distinguished_name"] = "CN=Fixture,OU=Nested,OU=Fixture,DC=example,DC=test"
    plan = plans.preview(cur, {"domain_id": 1, "ou_entity_ids": [2], **CREDENTIAL}, actor=ACTOR)
    assert plan["targets"][0]["entity_id"] == 3
    attrs["distinguished_name"] = "CN=Fixture,OU=NotFixture,DC=example,DC=test"
    with pytest.raises(AgentError):
        plans.finish(cur, confirmation(plan), actor=ACTOR)


def test_cancel_and_expiry_do_not_change_directory_or_allow_later_confirmation():
    cur = Cursor()
    before = deepcopy(cur.directory)
    plan = plans.preview(cur, SELECTION, actor=ACTOR)
    assert plans.finish(cur, confirmation(plan, cancel=True), actor=ACTOR, cancel=True)["status"] == "cancelled"
    with pytest.raises(AgentError, match="gpo_plan_unavailable"):
        plans.finish(cur, confirmation(plan), actor=ACTOR)
    plan = plans.preview(cur, SELECTION, actor=ACTOR)
    cur.plans[plan["plan_id"]]["expires_at"] = utcnow() - timedelta(seconds=1)
    with pytest.raises(AgentError, match="gpo_plan_unavailable"):
        plans.finish(cur, confirmation(plan), actor=ACTOR)
    assert cur.directory == before and not cur.groups


@pytest.mark.parametrize("change", ["grant", "ou_grant", "writer_scope", "revision", "evidence", "package", "target_version", "identity", "ou_version", "deadline"])
def test_confirm_rechecks_permissions_snapshot_package_and_deadline(change):
    cur = Cursor()
    plan = plans.preview(cur, SELECTION, actor=ACTOR)
    if change == "grant":
        cur.grants[(ACTOR, 1)]["permissions"] = ["preview"]
    elif change == "ou_grant":
        cur.grants[(ACTOR, 1)]["ou_entity_ids"] = [9]
    elif change == "writer_scope":
        cur.scope["ou_entity_ids"] = [9]
    elif change == "revision":
        cur.scope["revision"] += 1
    elif change == "evidence":
        cur.scope["evidence_sha256"] = "c" * 64
    elif change == "package":
        cur.scope["package"] = {"version": "0.0.1"}
    elif change == "target_version":
        cur.directory[(3, 1)]["version_id"] += 1
    elif change == "identity":
        cur.directory[(3, 1)]["record"]["identity"]["object_sid"] = "S-1-5-21-1-2-3-1004"
    elif change == "ou_version":
        cur.directory[(2, 1)]["version_id"] += 1
    else:
        cur.expire_on_finish = True
    with pytest.raises(AgentError):
        plans.finish(cur, confirmation(plan), actor=ACTOR)
    assert cur.plans[plan["plan_id"]]["status"] == "preview"
    assert not any(event[2] == "confirmed" for event in cur.plan_audit)


@pytest.mark.parametrize("change", ["hash", "actor", "acknowledgment", "extra"])
def test_confirmation_cannot_be_rebound_or_modified(change):
    cur = Cursor()
    plan = plans.preview(cur, SELECTION, actor=ACTOR)
    body, actor = confirmation(plan), ACTOR
    if change == "hash": body["plan_sha256"] = "c" * 64
    elif change == "actor": actor = "session:2"
    elif change == "acknowledgment": body["acknowledged"] = 1
    else: body["computer_entity_ids"] = [4]
    with pytest.raises(AgentError):
        plans.finish(cur, body, actor=actor)
    assert cur.plans[plan["plan_id"]]["status"] == "preview"


@pytest.mark.parametrize("change", ["dc", "unknown_uac", "container", "outside", "stale", "disabled", "sid_missing"])
def test_unusable_or_outside_targets_fail_closed(change):
    cur = Cursor()
    attrs = cur.directory[(3, 1)]["record"]["attributes"]
    if change == "dc": attrs["user_account_control"] = 8192
    elif change == "unknown_uac": attrs.pop("user_account_control")
    elif change == "container": attrs["distinguished_name"] = "CN=Fixture,CN=Computers,DC=example,DC=test"
    elif change == "outside": attrs["distinguished_name"] = "CN=Fixture,OU=Other,DC=example,DC=test"
    elif change == "stale": cur.directory.pop((3, 1))
    elif change == "disabled": attrs["enabled"] = False
    else: cur.directory[(3, 1)]["record"]["identity"].pop("object_sid")
    with pytest.raises(AgentError):
        plans.preview(cur, SELECTION, actor=ACTOR)
    assert not cur.plans


@pytest.mark.parametrize("body", [{}, {"domain_id": 1}, {"domain_id": 1, "ou_entity_ids": "2"},
    {**SELECTION, "computer_entity_ids": [True]}, {**SELECTION, "script": "anything"},
    {**SELECTION, "computer_entity_ids": list(range(1, 1002))}])
def test_invalid_selection_is_rejected(body):
    with pytest.raises(AgentError):
        plans.preview(Cursor(), body, actor=ACTOR)


def test_ambiguous_identity_and_oversized_ou_expansion_are_rejected():
    cur = Cursor()
    cur.directory[(4, 1)] = deepcopy(cur.directory[(3, 1)])
    cur.directory[(4, 1)]["version_id"] = 40
    with pytest.raises(AgentError, match="gpo_identity_unavailable"):
        plans.preview(cur, {"domain_id": 1, "computer_entity_ids": [3, 4], **CREDENTIAL}, actor=ACTOR)
    assert cur.plan_audit[-1][2] == "denied" and not cur.plans
    for entity in range(4, 1004):
        cur.directory[(entity, 1)] = deepcopy(cur.directory[(3, 1)])
    with pytest.raises(AgentError, match="gpo_target_limit"):
        plans.preview(cur, {"domain_id": 1, "ou_entity_ids": [2], **CREDENTIAL}, actor=ACTOR)
    assert not cur.plans


def test_database_guards_are_transactional_and_clock_expiry_is_checked_after_reads():
    cur = Cursor()
    plan = plans.preview(cur, SELECTION, actor=ACTOR)
    plans.finish(cur, confirmation(plan), actor=ACTOR)
    assert any(sql == "select * from sli_agent_gpo_plans where id=%s for update" for sql, _ in cur.calls)
    assert any("expires_at>clock_timestamp() returning id" in sql for sql, _ in cur.calls)


def test_package_metadata_is_bounded_and_never_copies_parameters_or_secrets():
    cur = Cursor()
    cur.scope["package"] = {"version": "0.0.1", "sha256": "a" * 64, "size_bytes": 100, "signature": "valid"}
    plan = plans.preview(cur, SELECTION, actor=ACTOR)
    assert plan["package"] == cur.scope["package"]
    cur.scope["package"]["parameters"] = {"token": "synthetic-private-value"}
    with pytest.raises(AgentError, match="gpo_package_unavailable"):
        plans.preview(cur, SELECTION, actor=ACTOR)
    assert "synthetic-private-value" not in repr(cur.plan_audit)
