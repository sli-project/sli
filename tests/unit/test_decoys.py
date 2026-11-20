"""D01 service/API contracts with retained-source and transaction fakes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
import json
from unittest.mock import Mock

import pytest

from server.api.routes import decoys as routes
from server.sli.core import decoys

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)
AGENT = "00000000-0000-4000-8000-000000000001"
SOURCE = "00000000-0000-4000-8000-000000000002"
LABEL = "00000000-0000-4000-8000-000000000003"
GUID = "00000000-0000-4000-8000-000000000004"
PRINCIPAL = {"id": 1, "type": "session", "role": "admin"}


def access(scope=None, *, actions=("view", "manage_decoy"), capability=True):
    return {"subject": {"coarse_role": "admin"}, "capabilities": ["decoys.manage"] if capability else [],
            "reports": [{"report_key": "decoys.registry", "allowed": True, "allowed_actions": list(actions),
                         "grants": [{"allowed_actions": list(actions), "field_categories": ["identity_basic", "security", "technical"],
                                     "scope": scope or {"kind": "all"}}]}]}


def body(kind="file", **changes):
    identity = ({"agent_id": AGENT, "source_instance_id": SOURCE, "collection_scope_id": "scope:one", "path": r"c:\decoys\bait.txt"}
                if kind == "file" else {"domain_id": 1, "entity_id": 12, "sid": "S-1-5-21-1-2-3-1001", "guid": GUID})
    return {"kind": kind, "identity": identity, "owner": "fixture-owner", "reason": "fixture registration", "active": True,
            "revision": 0, **changes}


def agent():
    config = {"policy_revision": "4", "roots": [{"collection_scope_id": "scope:one", "path": r"c:\decoys", "important": True,
              "sacl": {"trustee_sids": ["S-1-1-0"], "inherit_files": True, "inherit_directories": True}}], "service_account_exclusions": []}
    return {"host_id": SOURCE, "status": "active", "policy_revision": 4, "applied_policy_revision": 4,
            "last_seen": NOW, "collection_policy": {"state": "active"},
            "assigned_modules": [{"module_id": "sli.file-audit", "enabled": True, "config": deepcopy(config)}],
            "file_audit": {"reported_at": NOW, "request": {"config": config, "command": {"action": "check", "policy_revision": "4"}},
                           "scopes": {"scope:one": {"state": "verified", "reason_code": "ok"}}}}


class Cursor:
    def __init__(self, previous=None):
        self.previous, self.calls, self.rows, self.current = previous, [], [], None
        self.agent, self.present = agent(), True
        self.coverage = {"state": "complete", "read_audit_enabled": True, "lost_count": 0, "window_end": NOW}
        self.account = [{"attributes_json": {"identity": {"kind": "ad_user", "object_sid": body("account")["identity"]["sid"],
                                                        "object_guid": GUID}}, "last_observed_at_utc": NOW}]

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "from sli_agents" in sql:
            self.current = self.agent
        elif "decoy_file_present" in sql:
            self.current = {"present": self.present}
        elif "file_decoy_coverage" in sql:
            self.current = self.coverage
        elif "for update" in sql:
            self.current = self.previous

    def fetchone(self):
        return deepcopy(self.current)

    def fetchall(self):
        return deepcopy(self.account if "ad_context_entity_versions" in self.calls[-1][0] else self.rows)


def saved(**changes):
    return {**body(), "id": LABEL, "revision": 1, "active_from": NOW - timedelta(hours=1), "active_to": None,
            "actor_type": "session", "actor_id": 1, "readiness": {"state": "not_ready", "reasons": ["audit_missing"]},
            **changes}


@pytest.mark.parametrize("kind", ["account", "file"])
def test_registration_stores_exact_identity_and_safe_audit(kind):
    cur, audit = Cursor(), Mock()
    item = decoys.save_label(cur, access(), body(kind), principal=PRINCIPAL, audit=audit, now=NOW)
    insert = next(params for sql, params in cur.calls if "insert into decoy_label_versions" in sql)
    assert json.loads(insert[3]) == body(kind)["identity"]
    assert insert[4:7] == ("fixture-owner", "fixture registration", True)
    assert insert[8:10] == ("session", 1) and item["revision"] == 1
    assert set(audit.call_args.args[1]) == {"id", "revision", "active", "readiness"}
    assert item["readiness"]["state"] == ("ready" if kind == "file" else "not_ready")


def test_file_normalization_never_uses_prefix_matching():
    value = body()
    value["identity"]["path"] = "C:/Decoys/BAIT.txt"
    assert decoys.validate(value)["identity"]["path"] == r"c:\decoys\bait.txt"
    value["identity"]["path"] = r"c:\decoys-other\bait.txt"
    result = decoys.readiness(Cursor(), value, now=NOW)
    assert result["state"] == "not_ready" and "root_not_covered" in result["reasons"]


@pytest.mark.parametrize("mutate,reason", [
    (lambda a: a["file_audit"]["request"]["config"]["roots"][0].update(important=False), "read_audit_missing"),
    (lambda a: a["file_audit"]["request"]["config"].update(service_account_exclusions=["S-1-5-18"]), "exclusions_conflict"),
    (lambda a: a["file_audit"]["request"]["config"].update(source_kind="workstation"), "server_profile_required"),
    (lambda a: a["file_audit"]["scopes"]["scope:one"].update(state="partial", reason_code="sacl_missing"), "audit_missing"),
    (lambda a: a["file_audit"].update(reported_at=NOW - timedelta(days=2)), "audit_stale"),
    (lambda a: a.update(status="revoked"), "source_not_ready"),
    (lambda a: a.update(host_id=GUID), "source_not_ready"),
    (lambda a: a["collection_policy"].update(state="paused"), "source_not_ready"),
    (lambda a: a["file_audit"]["request"]["command"].update(action="restore"), "audit_missing"),
    (lambda a: a["file_audit"]["request"]["config"]["roots"][0]["sacl"].update(trustee_sids=["S-1-5-11"]), "read_audit_missing"),
])
def test_missing_or_lost_audit_is_never_ready(mutate, reason):
    cur = Cursor()
    mutate(cur.agent)
    checked = decoys.readiness(cur, body(), now=NOW)
    assert checked["state"] == "not_ready" and reason in checked["reasons"]


@pytest.mark.parametrize("coverage", [None, {"state": "gap"},
    {"state": "complete", "read_audit_enabled": True, "lost_count": 1, "window_end": NOW},
    {"state": "complete", "read_audit_enabled": True, "lost_count": 0, "window_end": NOW-timedelta(days=2)}])
def test_collection_loss_or_stale_coverage_is_visible_even_with_verified_sacl(coverage):
    cur = Cursor()
    cur.coverage = coverage
    checked = decoys.readiness(cur, body(), now=NOW)
    assert checked["state"] == "not_ready" and "collection_gap" in checked["reasons"]


def test_no_inventory_or_no_audit_remains_registerable_but_not_ready():
    cur = Cursor()
    cur.agent["file_audit"], cur.present = {}, False
    result = decoys.save_label(cur, access(), body(), principal=PRINCIPAL, audit=Mock(), now=NOW)
    assert result["readiness"]["state"] == "not_ready"
    assert {"root_not_covered", "audit_missing", "file_unverified"} <= set(result["readiness"]["reasons"])


def test_account_snapshot_proves_only_exact_identity_never_authentication_audit():
    cur = Cursor()
    assert decoys.readiness(cur, body("account"), now=NOW)["reasons"] == ["authentication_audit_unverified"]
    cur.account[0]["attributes_json"]["identity"]["object_guid"] = SOURCE
    assert "identity_unverified" in decoys.readiness(cur, body("account"), now=NOW)["reasons"]
    cur.account = []
    assert "identity_stale" in decoys.readiness(cur, body("account"), now=NOW)["reasons"]


@pytest.mark.parametrize("decision,principal", [
    ({}, PRINCIPAL), (access(actions=("view",)), PRINCIPAL), (access(capability=False), PRINCIPAL),
    (access(), {**PRINCIPAL, "role": "operator"}),
    (access({"kind": "domain", "ids": [2]}), PRINCIPAL),
    (access({"mode": "restricted", "clauses": [{"source_instance_ids": [GUID]}]}), PRINCIPAL),
])
def test_unauthorized_mutation_has_no_database_calls(decision, principal):
    cur = Cursor()
    with pytest.raises(PermissionError):
        decoys.save_label(cur, decision, body(), principal=principal, audit=Mock(), now=NOW)
    assert cur.calls == []


def test_scoped_capability_denies_win_and_scopes_are_not_cross_multiplied():
    value = body()
    scope = {"mode": "restricted", "clauses": [{"source_instance_ids": [SOURCE], "device_ids": [AGENT],
                                                "collection_scope_ids": ["scope:one"]}]}
    decision = access(scope, capability=False)
    decision["capability_policies"] = [{"capability_key": "decoys.manage", "valid": True, "effect": "allow", "scope": scope}]
    decoys.require_access(decision, value, manage=True, principal=PRINCIPAL)
    decision["capability_policies"].append({"capability_key": "decoys.manage", "valid": True, "effect": "deny", "scope": scope})
    with pytest.raises(PermissionError):
        decoys.require_access(decision, value, manage=True, principal=PRINCIPAL)
    decision = access({"mode": "restricted", "clauses": [
        {"source_instance_ids": [SOURCE], "device_ids": [GUID]},
        {"source_instance_ids": [GUID], "device_ids": [AGENT]}]})
    with pytest.raises(PermissionError):
        decoys.require_access(decision, value, manage=True, principal=PRINCIPAL)


def test_effective_grant_preserves_manage_only_with_decoy_capability():
    from server.sli.access.access_control_v4 import _bounded_report_grant

    decision = access()
    grant = decision["reports"][0]["grants"][0]
    fields = {"field.identity_basic", "field.security", "field.technical"}
    assert _bounded_report_grant(grant, fields)["allowed_actions"] == ["view"]
    assert _bounded_report_grant(grant, fields | {"decoys.manage"})["allowed_actions"] == ["manage_decoy", "view"]


def test_retarget_requires_old_scope_too_and_stale_revision_writes_nothing():
    old = saved(identity={**body()["identity"], "collection_scope_id": "scope:two"})
    cur = Cursor(old)
    decision = access({"mode": "restricted", "clauses": [{"collection_scope_ids": ["scope:one"]}]})
    with pytest.raises(PermissionError):
        decoys.save_label(cur, decision, body(revision=1), principal=PRINCIPAL, audit=Mock(), label_id=LABEL, now=NOW)
    assert not any(sql.startswith(("update", "insert")) for sql, _ in cur.calls)
    with pytest.raises(LookupError):
        decoys.save_label(Cursor(saved()), access(), body(revision=2), principal=PRINCIPAL, audit=Mock(), label_id=LABEL, now=NOW)
    with pytest.raises(LookupError):
        decoys.save_label(Cursor(), access(), body(), principal=PRINCIPAL, audit=Mock(), label_id=LABEL, now=NOW)


def test_disable_closes_old_interval_and_preserves_new_reason():
    cur = Cursor(saved())
    decoys.save_label(cur, access(), body(revision=1, active=False, reason="fixture maintenance"),
                      principal=PRINCIPAL, audit=Mock(), label_id=LABEL, now=NOW)
    close = next(params for sql, params in cur.calls if sql.startswith("update"))
    insert = next(params for sql, params in cur.calls if sql.startswith("insert"))
    assert close == (NOW, LABEL, 1) and insert[1] == 2 and insert[5:8] == ("fixture maintenance", False, NOW)
    assert "label_disabled" in json.loads(insert[10])["reasons"]


def test_registry_versions_feed_d02_and_preserve_late_authentication_after_disable():
    from server.sli.semantic import account_decoy
    from tests.unit.test_account_decoy import event, rule

    cur = Cursor()
    created = decoys.save_label(cur, access(), body("account"), principal=PRINCIPAL,
                               audit=Mock(), now=NOW - timedelta(hours=1))
    insert = next(params for sql, params in cur.calls if sql.startswith("insert"))
    original = saved(id=created["id"], kind=insert[2], identity=json.loads(insert[3]),
                     active=insert[6], active_from=insert[7], readiness=json.loads(insert[10]))
    assert original["readiness"]["state"] == "not_ready"
    row = event()
    row["occurred_at_utc"] = NOW - timedelta(seconds=1)
    row["labels"] = [original]
    key = "sid:" + original["identity"]["sid"]
    row["roles_json"]["affected_entity"] = key
    row["quality_json"]["identity_roles"]["affected_entity"]["key"] = key
    row["identities"] = [{"role": "affected_entity", "key": key, "identity": original["identity"]}]
    signals, state = account_decoy.evaluate(rule(), row, now=NOW)
    assert state == "observed" and signals[0].base_severity == "high"
    assert signals[0].decoy_context["label_id"] == created["id"]
    assert signals[0].decoy_context["label_revision"] == created["revision"]

    cur = Cursor(original)
    disabled = decoys.save_label(cur, access(), body("account", revision=1, active=False),
                                principal=PRINCIPAL, audit=Mock(), label_id=created["id"], now=NOW)
    close = next(params for sql, params in cur.calls if sql.startswith("update"))
    insert = next(params for sql, params in cur.calls if sql.startswith("insert"))
    row["labels"] = [{**original, "active_to": close[0]},
                     {**original, "revision": disabled["revision"], "active": insert[6], "active_from": insert[7]}]
    assert account_decoy.evaluate(rule(), row, now=NOW)[0] == signals
    row["occurred_at_utc"] = NOW
    assert account_decoy.evaluate(rule(), row, now=NOW) == ((), "no_match")


@pytest.mark.parametrize("bad", [None, {}, body(password="fixture-secret"), body(revision=True), body(kind=[]), body(owner=" "),
                                 body(identity={}), body("account", identity={**body("account")["identity"], "guid": None})])
def test_invalid_input_is_rejected_without_source_reads(bad):
    cur = Cursor()
    with pytest.raises(ValueError):
        decoys.save_label(cur, access(), bad, principal=PRINCIPAL, audit=Mock(), now=NOW)
    assert cur.calls == []


def test_scoped_list_predicate_precedes_paging_and_rechecks_current_coverage():
    cur = Cursor()
    cur.rows = [saved()]
    cur.agent["file_audit"] = {}
    decision = access({"mode": "restricted", "clauses": [{"source_instance_ids": [SOURCE], "device_ids": [AGENT]}]}, actions=("view",))
    result = decoys.list_labels(cur, decision, principal=PRINCIPAL)
    sql, params = cur.calls[0]
    assert "source_instance_id = ANY(%s)" in sql and "device_id = ANY(%s)" in sql
    assert params[:2] == ([SOURCE], [AGENT]) and "limit 101" in sql
    assert result["items"][0]["readiness"]["state"] == "not_ready" and not result["items"][0]["can_manage"]
    cur.rows = [saved(active_to=NOW)]
    result = decoys.list_labels(cur, access(), label_id=LABEL, after="5")
    assert result["items"][0]["readiness"] == cur.rows[0]["readiness"]
    assert "revision<%s::bigint" in cur.calls[-1][0]


class Connection(Cursor):
    def __init__(self):
        super().__init__()
        self.events = []

    def __enter__(self):
        return self

    def __exit__(self, error, *_):
        self.events.append("rollback" if error else "exit")

    def cursor(self):
        return self

    def commit(self):
        self.events.append("commit")


def test_touch_details_authorize_exact_label_version_before_native_reads():
    from tests.unit.test_file_decoy import event

    class TouchCursor(Cursor):
        def execute(self, sql, params=()):
            super().execute(sql, params)
            if "select * from decoy_label_versions" in sql:
                self.current = saved()

    cur = TouchCursor()
    obs = event()["observation"]
    cur.rows = [{"signal_id": "a"*64, "evaluation_mode": "enabled", "observation": obs,
                 "context": {"label_revision": 1, "meaning": "read", "outcome": "success"}}]
    result = decoys.list_touches(cur, access(), label_id=LABEL, revision="1")
    assert result["items"][0]["meaning"] == "read" and result["items"][0]["path"] == body()["identity"]["path"]
    assert result["items"][0]["evidence_key"] == obs["evidence_key"]
    assert cur.calls[-1][1] == (LABEL, 1, None)
    cur = TouchCursor()
    with pytest.raises(PermissionError):
        decoys.list_touches(cur, access({"mode": "restricted", "clauses": [{"device_ids": [GUID]}]}),
                            label_id=LABEL, revision="1")
    assert not any("read_file_decoy_touches" in sql for sql, _ in cur.calls)
    cur = TouchCursor()
    with pytest.raises(PermissionError):
        decoys.list_touches(cur, {}, label_id=LABEL, revision="1")
    assert not cur.calls


@pytest.mark.parametrize("revision,after", [(None, None), ("0", None), ("1", "bad"), ("9007199254740992", None)])
def test_touch_paging_and_version_are_validated_before_source_reads(revision, after):
    cur = Cursor()
    with pytest.raises(ValueError):
        decoys.list_touches(cur, access(), label_id=LABEL, revision=revision, after=after)
    assert not cur.calls


class Handler:
    _principal = PRINCIPAL

    def __init__(self, decision=None, allowed=True):
        self.decision, self.allowed, self.reads = access() if decision is None else decision, allowed, 0

    def _access_decision(self):
        return self.decision

    def _authorize_mutation(self, **kwargs):
        assert kwargs == {"required_role": "admin"}
        return self.allowed

    def _read_json_body(self):
        self.reads += 1
        return body()

    def _send_json(self, value, status=HTTPStatus.OK):
        self.response, self.status = value, status


def test_api_guards_reads_and_commits_only_after_audit(monkeypatch):
    conn = Connection()
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: conn)
    handler = Handler({}, allowed=False)
    assert routes.try_handle_post(handler, routes.PREFIX) and handler.reads == 0 and not conn.calls
    handler = Handler({})
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.FORBIDDEN and handler.reads == 0 and not conn.calls
    routes.try_handle_get(handler, routes.PREFIX, {})
    assert handler.status == HTTPStatus.FORBIDDEN and not conn.calls
    handler = Handler()
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", lambda **kwargs: conn.events.append("audit"))
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.OK and conn.events[:2] == ["audit", "commit"]
    conn.events.clear()
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", Mock(side_effect=RuntimeError("fixture-secret")))
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.SERVICE_UNAVAILABLE and conn.events and set(conn.events) == {"rollback"}
    assert "fixture-secret" not in json.dumps(handler.response)
    assert not routes.try_handle_get(handler, "/other", {}) and not routes.try_handle_post(handler, "/other")


def test_http_get_reaches_scoped_registry_instead_of_global_capability_gate(monkeypatch):
    from server.api import http_server
    from server.sli.access.access_control_v4 import route_capability

    conn = Connection()
    conn.rows = [saved()]
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: conn)
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    handler = object.__new__(http_server.RequestHandler)
    handler.path, handler.headers, handler._principal = routes.PREFIX, {}, PRINCIPAL
    handler._require_secure_api_transport = lambda path: True
    handler._require_capability = Mock(side_effect=AssertionError("scoped reader owns authorization"))
    handler._access_decision = lambda: access()
    handler._send_json = Mock()
    handler._do_GET()
    assert route_capability(routes.PREFIX) == "reports.catalog"
    handler._require_capability.assert_not_called()
    assert handler._send_json.call_args.args[0]["items"][0]["id"] == LABEL
    handler._access_decision = lambda: {}
    handler._do_GET()
    assert handler._send_json.call_args.args[1] == HTTPStatus.FORBIDDEN


@pytest.mark.parametrize("language", ["ru", "en"])
def test_api_error_envelope_is_localized_without_echoing_input(language):
    handler = Handler()
    handler.headers = {"Accept-Language": language}
    routes._error(handler, ValueError("fixture-secret"))
    from server.sli.core.messages import catalog

    assert handler.response["message"]["text"] == catalog(language)["decoys.failed"]
    assert "fixture-secret" not in json.dumps(handler.response)


@pytest.mark.parametrize("revision", ["0", "-1", "1.5", "invalid", str(2**53)])
def test_history_rejects_invalid_exact_version(revision):
    with pytest.raises(ValueError, match="decoy_invalid"):
        decoys.list_labels(Cursor(), access(), label_id=LABEL, revision=revision)


def test_exact_history_version_is_scoped_in_sql_before_pagination():
    cur = Cursor()
    assert decoys.list_labels(cur, access(), label_id=LABEL, revision="1")["items"] == []
    sql, params = cur.calls[0]
    assert "id=%s and revision=%s" in sql
    assert params[:2] == (LABEL, 1)
    with pytest.raises(ValueError, match="decoy_invalid"):
        decoys.list_labels(cur, access(), revision="1")
    with pytest.raises(ValueError, match="decoy_invalid"):
        decoys.list_labels(cur, access(), label_id=LABEL, revision="1", after="2")
