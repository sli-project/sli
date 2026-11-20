"""Preparation contracts with cursor fakes, no deployment or database."""
import json
from copy import deepcopy
from datetime import timedelta
from uuid import UUID

import pytest

from server.sli.agents import onboarding
from server.sli.agents.ca import AgentError, utcnow


def uid(number):
    return str(UUID(int=number))


class Cursor:
    def __init__(self, count=1):
        self.calls, self.rows, self.audits = [], [], []
        self.template = dict(id=uid(1), version=1, policy_sha256="a" * 64,
            assigned_modules=[], collection_policy={"manage_windows_audit": True})
        self.group = dict(id=uid(2), domain_id=1, ou_entity_ids=[2],
            expires_at=utcnow() + timedelta(minutes=30), revoked_at=None)
        self.requests = {uid(100 + n): dict(id=uid(100 + n), token_id=uid(2), host_id=uid(2000 + n),
            key_fingerprint=f"{n:064x}", instance_name=None, computer_entity_id=3 + n,
            computer_version_id=30 + n, status="pending") for n in range(count)}
        self.tokens, self.selections, self.copies, self.history = {}, {}, {}, {}

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        self.rows = []
        if sql.startswith("select pg_advisory"):
            return
        if sql.startswith("select * from sli_agent_policy_templates"):
            if params == (self.template["id"], self.template["version"]):
                self.rows = [self.template]
        elif sql.startswith("select distinct on(id)"):
            self.rows = [self.template]
        elif sql.startswith("select r.id,r.host_id,r.instance_name,r.key_fingerprint"):
            self.rows = [r for r in self.requests.values() if r["token_id"] == params[0]][:1000]
        elif sql.startswith("select coalesce(max(version)"):
            self.rows = [{"version": self.template["version"] if params[0] == self.template["id"] else 0}]
        elif sql.startswith("insert into sli_agent_policy_templates"):
            self.template = dict(id=params[0], version=params[1], assigned_modules=json.loads(params[2]),
                collection_policy=json.loads(params[3]), policy_sha256=params[4])
        elif sql.startswith("select * from sli_agent_group_tokens"):
            if params[0] == self.group["id"]:
                self.rows = [self.group]
        elif sql.startswith("select * from sli_agent_group_requests"):
            self.rows = [r for r in self.requests.values() if r["token_id"] == params[0]
                and (len(params) == 1 and r["status"] == "pending" or len(params) == 2 and r["id"] in params[1])]
        elif sql.startswith("select id from sli_agents"):
            self.rows = []
        elif sql.startswith("insert into sli_agent_enrollment_tokens"):
            self.tokens[params[0]] = dict(id=params[0], token_hash=params[1], host_id=params[2], key_fingerprint=params[3])
        elif sql.startswith("insert into sli_agent_onboarding_copies"):
            self.selections[params[0]] = (params[1], params[2], params[3])
        elif sql.startswith("update sli_agent_group_requests"):
            self.requests[params[1]]["status"] = params[0]
        elif sql.startswith("insert into sli_agent_audit"):
            self.audits.append(dict(action=params[0], actor=params[1], target=params[2], details=json.loads(params[3])))
        elif sql.startswith("select t.* from sli_agent_onboarding_copies"):
            if params[0] in self.selections:
                self.rows = [self.template]
        elif sql.startswith("update sli_agents set assigned_modules"):
            self.copies[params[-1]] = dict(assigned_modules=json.loads(params[0]),
                collection_policy=json.loads(params[1]), template_id=params[2], template_version=params[3],
                template_sha256=params[4], policy_revision=1)
        elif sql.startswith("insert into sli_agent_policy_history"):
            self.history[params[0]] = (json.loads(params[1]), json.loads(params[2]))
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return deepcopy(self.rows[0]) if self.rows else None

    def fetchall(self):
        return deepcopy(self.rows)


@pytest.fixture
def directory(monkeypatch):
    def resolve(cur, entity, domain, *, ou=False):
        assert domain == 1
        if ou:
            assert entity == 2
            return 20, ["ou=fixture", "dc=example", "dc=test"]
        return entity + 27, ["cn=fixture", "ou=fixture", "dc=example", "dc=test"]
    monkeypatch.setattr(onboarding, "_directory_entity", resolve)
    return resolve


def approval(cur, *, mode="selected"):
    evidence = [{k: r[k] for k in ("host_id", "key_fingerprint", "instance_name", "computer_entity_id")}
                | {"request_id": r["id"]} for r in cur.requests.values()]
    body = dict(token_id=uid(2), template_id=uid(1), template_version=1, mode=mode, evidence=evidence)
    if mode == "selected":
        body["request_ids"] = list(cur.requests)
    return body


@pytest.mark.parametrize("mode", ["selected", "rule"])
def test_thousand_approvals_are_scoped_audited_and_do_not_issue_certificates(directory, mode):
    cur = Cursor(1000)
    result = onboarding.approve(cur, approval(cur, mode=mode), actor="session:1")
    assert len(result["items"]) == len(cur.tokens) == len(cur.selections) == 1000
    assert all(item["status"] == "approved" for item in result["items"])
    assert all(r["status"] == "approved" for r in cur.requests.values())
    assert all(a["actor"] == "session:1" for a in cur.audits)
    assert cur.audits[-1]["details"]["approved"] == 1000
    assert cur.audits[-1]["details"]["domain_id"] == 1
    assert not any("insert into sli_agents" in sql or "sli_agent_certificates" in sql for sql, _ in cur.calls)
    assert not any(item["token"] in repr(cur.audits) for item in result["items"])
    replay = onboarding.approve(cur, approval(cur), actor="session:1")
    assert all(item["status"] == "already_approved" and "token" not in item for item in replay["items"])
    assert len(cur.tokens) == 1000


@pytest.mark.parametrize("change", ["missing", "key", "host", "computer", "instance", "outside", "stale"])
def test_unverified_key_or_server_scope_never_approves(directory, monkeypatch, change):
    cur = Cursor()
    body = approval(cur)
    if change == "missing":
        body["evidence"] = []
    elif change in ("key", "host", "computer", "instance"):
        field, value = {"key": ("key_fingerprint", "f" * 64), "host": ("host_id", uid(9000)),
            "computer": ("computer_entity_id", 9000), "instance": ("instance_name", "other")}[change]
        body["evidence"][0][field] = value
    elif change == "outside":
        monkeypatch.setattr(onboarding, "_directory_entity", lambda *args, ou=False:
            (20, ["ou=fixture" if ou else "cn=fixture", "dc=example", "dc=test"]))
    else:
        def stale(*args, **kwargs):
            raise AgentError("invalid_group_enrollment_scope")
        monkeypatch.setattr(onboarding, "_directory_entity", stale)
    result = onboarding.approve(cur, body, actor="session:1")
    assert result["items"][0]["status"] == "rejected"
    assert not cur.tokens and not cur.selections
    assert cur.requests[uid(100)]["status"] == "pending"
    assert cur.audits[-1]["details"]["rejected"] == 1


@pytest.mark.parametrize("field", ["expires_at", "revoked_at"])
def test_expired_or_revoked_batch_is_audited_without_approval(directory, field):
    cur = Cursor()
    cur.group[field] = utcnow() - timedelta(seconds=1)
    result = onboarding.approve(cur, approval(cur), actor="session:1")
    assert result["items"][0]["status"] == "rejected"
    assert not cur.tokens
    assert cur.audits[-1]["details"]["rejected"] == 1


def test_copy_includes_audit_toggle_and_is_independent_of_template_and_other_agent(directory):
    cur = Cursor(2)
    cur.template["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    onboarding.approve(cur, approval(cur), actor="session:1")
    tokens = list(cur.tokens)
    onboarding.copy_policy(cur, tokens[0], uid(9000))
    onboarding.copy_policy(cur, tokens[1], uid(9001))
    assert cur.copies[uid(9000)]["collection_policy"]["manage_windows_audit"] is True
    assert cur.copies[uid(9000)]["policy_revision"] == 1
    assert cur.copies[uid(9000)]["template_version"] == 1
    assert cur.history[uid(9000)][1]["manage_windows_audit"] is True
    cur.copies[uid(9000)]["assigned_modules"][0]["enabled"] = False
    cur.template["collection_policy"]["manage_windows_audit"] = False
    assert cur.copies[uid(9001)]["assigned_modules"][0]["enabled"] is True
    assert cur.copies[uid(9001)]["collection_policy"]["manage_windows_audit"] is True


def test_template_updates_are_append_only_and_require_expected_version():
    cur = Cursor()
    body = dict(template_id=uid(1), expected_version=1, assigned_modules=[],
        collection_policy={"manage_windows_audit": True})
    result = onboarding.save_template(cur, body, actor="session:1")
    assert result["version"] == 2 and len(result["policy_sha256"]) == 64
    assert cur.template["collection_policy"]["manage_windows_audit"] is True
    with pytest.raises(AgentError, match="agent_template_version_conflict"):
        onboarding.save_template(cur, body, actor="session:1")
    assert not any(sql.startswith("update sli_agent_policy_templates") for sql, _ in cur.calls)


@pytest.mark.parametrize("settings", [{"manage_windows_audit": "true"}, {"batch_size": 0}, {"unknown": True}])
def test_template_rejects_invalid_control_without_writes(settings):
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_template"):
        onboarding.save_template(cur, dict(expected_version=0, assigned_modules=[], collection_policy=settings), actor="session:1")
    assert not cur.calls


def test_template_rejects_host_bound_snapshot_modules():
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_template"):
        onboarding.save_template(cur, dict(expected_version=0, collection_policy={}, assigned_modules=[
            {"module_id": "sli.ad-snapshot", "enabled": True, "config": {}}]), actor="session:1")
    assert not cur.calls


@pytest.mark.parametrize("change", [{"request_ids": []}, {"request_ids": [uid(100)] * 2},
    {"template_version": True}, {"mode": "auto"}, {"domain_id": 1}, {"evidence": [{"request_id": uid(100)}]}])
def test_malformed_approval_never_writes(change):
    cur = Cursor()
    with pytest.raises(AgentError):
        onboarding.approve(cur, {**approval(cur), **change}, actor="session:1")
    assert not cur.calls


def test_request_from_another_batch_is_denied_without_disclosing_its_identity(directory):
    cur = Cursor()
    cur.requests[uid(100)]["token_id"] = uid(3)
    result = onboarding.approve(cur, approval(cur), actor="session:1")
    assert result["items"] == [{"request_id": uid(100), "status": "rejected", "reason": "request_not_pending"}]
    assert not cur.tokens


def test_rule_larger_than_batch_limit_requires_explicit_selection(directory):
    cur = Cursor(1001)
    body = approval(cur, mode="rule")
    body["evidence"] = []
    with pytest.raises(AgentError, match="agent_batch_size_limit"):
        onboarding.approve(cur, body, actor="session:1")
    assert not cur.tokens and not cur.audits


def test_manual_token_without_template_keeps_default_enrollment_policy():
    cur = Cursor()
    onboarding.copy_policy(cur, uid(50), uid(9000))
    assert not cur.copies and not cur.history and not cur.audits


@pytest.mark.parametrize("modules", [
    [{"module_id": "sli.workstations", "enabled": "true", "config": {}}],
    [{"module_id": "sli.workstations", "enabled": True, "config": {"batch_size": 0}}],
    [{"module_id": "sli.workstations", "enabled": True, "config": {}}] * 2,
])
def test_template_rejects_invalid_modules_without_writes(modules):
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_template"):
        onboarding.save_template(cur, dict(expected_version=0, collection_policy={}, assigned_modules=modules), actor="session:1")
    assert not cur.calls


def test_template_stamps_a_personal_initial_module_revision():
    cur = Cursor()
    result = onboarding.save_template(cur, dict(expected_version=0, collection_policy={}, assigned_modules=[
        {"module_id": "sli.workstations", "enabled": True, "config": {"policy_revision": "99"}}]), actor="session:1")
    assert result["version"] == 1
    assert cur.template["assigned_modules"][0]["config"]["policy_revision"] == "1"
    assert cur.template["collection_policy"]["manage_windows_audit"] is False


def test_owner_lists_templates_and_only_requested_batch_without_secrets():
    cur = Cursor(2)
    cur.requests[uid(101)]["token_id"] = uid(3)
    templates = onboarding.list_templates(cur, actor="session:1")
    queue = onboarding.list_requests(cur, uid(2), actor="session:1")
    assert templates["items"][0]["collection_policy"]["manage_windows_audit"] is True
    assert [item["id"] for item in queue["items"]] == [uid(100)]
    assert "token_hash" not in repr(queue) and "csr_pem" not in repr(queue)
    assert cur.audits[-1]["actor"] == "session:1"
    assert cur.audits[-1]["target"] == uid(2)


def test_host_conflict_leaves_request_pending_and_is_audited(directory, monkeypatch):
    cur = Cursor()
    execute = cur.execute
    def conflicting(sql, params=()):
        execute(sql, params)
        if sql.startswith("select id from sli_agents"):
            cur.rows = [{"id": uid(9000)}]
    monkeypatch.setattr(cur, "execute", conflicting)
    result = onboarding.approve(cur, approval(cur), actor="session:1")
    assert result["items"][0]["reason"] == "host_conflict_or_expired"
    assert cur.requests[uid(100)]["status"] == "pending"
    assert not cur.tokens
    assert cur.audits[-1]["details"]["rejected"] == 1
