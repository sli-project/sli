"""W01 service/API tests with retained identity and transaction fakes only."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
import json
from unittest.mock import Mock

import pytest

from server.api.routes import watch_entries as routes
from server.sli.core import watch_entries as registry

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)
ENTRY = "00000000-0000-4000-8000-000000000001"
IDENTITY = {"entity_id": 12, "domain_id": 1, "sid": "S-1-5-21-1-2-3-1001",
            "guid": "00000000-0000-4000-8000-000000000002"}
PRINCIPAL = {"type": "session", "id": 1, "role": "operator"}


def access(scope=None, *, manage=True):
    actions = ["view", "manage_watch"] if manage else ["view"]
    return {"subject": {"coarse_role": "operator"}, "capabilities": ["objects.view"] + (["watch.manage"] if manage else []),
            "reports": [{"report_key": "watch.registry", "allowed": True, "allowed_actions": actions,
                         "grants": [{"allowed_actions": actions, "field_categories": ["identity_basic", "security"],
                                     "scope": scope or {"kind": "all"}}]}]}


def body(**changes):
    return {"entity_id": 12, "owner": "fixture-team", "reason": "fixture reason", "active": True,
            "expires_at": (NOW + timedelta(days=7)).isoformat(), "revision": 0, **changes}


def saved(**changes):
    value = body()
    value.pop("entity_id")
    return {**value, "id": ENTRY, "identity": deepcopy(IDENTITY), "revision": 1,
            "active_from": NOW - timedelta(hours=1), "expires_at": NOW + timedelta(days=1),
            "valid_from": NOW - timedelta(hours=1), "valid_to": None, "actor_type": "session", "actor_id": 1, **changes}


class Cursor:
    def __init__(self, previous=None):
        self.previous, self.calls, self.rows, self.current = previous, [], [], None
        self.entity = {"entity_id": 12, "domain_id": 1}
        self.account = [{"attributes_json": {"identity": {"kind": "ad_user", "object_sid": IDENTITY["sid"],
                                                        "object_guid": IDENTITY["guid"]}}}]
        self.events = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "from entities_v2_active" in sql:
            self.current = self.entity
        elif "for update" in sql:
            self.current = self.previous

    def fetchone(self):
        return deepcopy(self.current)

    def fetchall(self):
        return deepcopy(self.account if "ad_context_entity_versions" in self.calls[-1][0] else self.rows)

    def __enter__(self):
        return self

    def __exit__(self, error, *_):
        self.events.append("rollback" if error else "exit")

    def cursor(self):
        return self

    def commit(self):
        self.events.append("commit")


def test_create_resolves_exact_identity_and_audits_no_reason_or_sid():
    cur, audit = Cursor(), Mock()
    result = registry.save_entry(cur, access(), body(), principal=PRINCIPAL, audit=audit, now=NOW)
    insert = next(params for sql, params in cur.calls if sql.startswith("insert"))
    assert json.loads(insert[2]) == IDENTITY
    assert insert[3:8] == (12, "ad-domain:1", "fixture-team", "fixture reason", True)
    assert insert[8:11] == (NOW, NOW + timedelta(days=7), NOW)
    assert result["revision"] == 1
    assert audit.call_args.args[1] == {**result, "active": True}


@pytest.mark.parametrize("patch", [
    {"expires_at": NOW.isoformat()}, {"expires_at": "2026-10-19T00:00:00"}, {"expires_at": "invalid"},
    {"reason": " "}, {"owner": ""}, {"entity_id": True}, {"revision": True}, {"active": 1},
    {"password": "synthetic-value"}, {"identity": IDENTITY},
])
def test_invalid_input_reads_no_source(patch):
    cur = Cursor()
    with pytest.raises(ValueError):
        registry.save_entry(cur, access(), body(**patch), principal=PRINCIPAL, audit=Mock(), now=NOW)
    assert not cur.calls


@pytest.mark.parametrize("decision,principal", [({}, PRINCIPAL), (access(), {**PRINCIPAL, "role": "viewer"})])
def test_coarse_denial_precedes_database_reads(decision, principal):
    cur = Cursor()
    with pytest.raises(PermissionError):
        registry.save_entry(cur, decision, body(), principal=principal, audit=Mock(), now=NOW)
    assert not cur.calls


@pytest.mark.parametrize("decision", [access({"kind": "domain", "ids": [2]}), access(manage=False),
                                      {**access(), "capabilities": ["watch.manage"]}])
def test_wrong_scope_no_capability_or_no_card_access_cannot_write(decision):
    cur = Cursor()
    with pytest.raises(PermissionError):
        registry.save_entry(cur, decision, body(), principal=PRINCIPAL, audit=Mock(), now=NOW)
    assert not any(sql.startswith(("insert", "update")) for sql, _ in cur.calls)


def test_scoped_capability_requires_matching_scope_and_explicit_deny_wins():
    decision = access()
    decision["capabilities"] = ["objects.view"]
    decision["capability_policies"] = [{"capability_key": "watch.manage", "valid": True,
                                       "effect": "allow", "scope": {"kind": "domain", "ids": [1]}}]
    registry.save_entry(Cursor(), decision, body(), principal=PRINCIPAL, audit=Mock(), now=NOW)
    decision["capability_policies"].append({**decision["capability_policies"][0], "effect": "deny"})
    with pytest.raises(PermissionError):
        registry.save_entry(Cursor(), decision, body(), principal=PRINCIPAL, audit=Mock(), now=NOW)


@pytest.mark.parametrize("account", [[], [{"attributes_json": {"identity": {"kind": "ad_user", "object_sid": IDENTITY["sid"]}}}],
                                      [{"attributes_json": {"identity": {"kind": "ad_computer"}}}]])
def test_unverified_identity_cannot_be_registered(account):
    cur = Cursor()
    cur.account = account
    with pytest.raises((ValueError, TypeError)):
        registry.save_entry(cur, access(), body(), principal=PRINCIPAL, audit=Mock(), now=NOW)
    assert not any(sql.startswith(("insert", "update")) for sql, _ in cur.calls)


@pytest.mark.parametrize("previous,revision,entry_id", [
    (saved(), 0, ENTRY), (saved(), 1, None), (None, 1, ENTRY),
    (saved(identity={**IDENTITY, "guid": "00000000-0000-4000-8000-000000000009"}), 1, ENTRY),
])
def test_stale_revision_or_recreated_account_never_overwrites_history(previous, revision, entry_id):
    cur = Cursor(previous)
    with pytest.raises(LookupError):
        registry.save_entry(cur, access(), body(revision=revision), principal=PRINCIPAL, audit=Mock(), entry_id=entry_id, now=NOW)
    assert not any(sql.startswith(("insert", "update")) for sql, _ in cur.calls)


@pytest.mark.parametrize("active", [True, False])
def test_extend_or_stop_creates_revision_preserving_old_reason(active):
    original = saved()
    cur = Cursor(original)
    result = registry.save_entry(cur, access(), body(revision=1, active=active, reason="fixture change"),
                                 principal=PRINCIPAL, audit=Mock(), entry_id=ENTRY, now=NOW)
    close = next(params for sql, params in cur.calls if sql.startswith("update"))
    insert = next(params for sql, params in cur.calls if sql.startswith("insert"))
    assert close == (NOW, ENTRY, 1) and result == {"id": ENTRY, "revision": 2}
    assert insert[6:9] == ("fixture change", active, original["active_from"] if active else NOW)
    assert original["reason"] == "fixture reason"


def test_expired_entry_can_restart_or_stop_and_boundary_is_expired():
    original = saved(expires_at=NOW)
    cur = Cursor(original)
    registry.save_entry(cur, access(), body(revision=1), principal=PRINCIPAL, audit=Mock(), entry_id=ENTRY, now=NOW)
    insert = next(params for sql, params in cur.calls if sql.startswith("insert"))
    assert insert[8] == NOW
    cur.rows = [original]
    result = registry.list_entries(cur, access(), entity_id=12, principal=PRINCIPAL, now=NOW)
    assert result["items"][0]["status"] == "expired" and result["can_manage"]
    registry.save_entry(Cursor(original), access(), body(revision=1, active=False, expires_at=NOW.isoformat()),
                        principal=PRINCIPAL, audit=Mock(), entry_id=ENTRY, now=NOW)


def test_list_filters_before_paging_and_requires_source_card_access():
    cur = Cursor()
    cur.rows = [saved()]
    result = registry.list_entries(cur, access({"kind": "domain", "ids": [1]}, manage=False), now=NOW)
    sql, params = cur.calls[0]
    assert "collection_scope_id = ANY(%s)" in sql and params[0] == ["ad-domain:1"]
    assert "limit 101" in sql and not result["items"][0]["can_manage"]
    decision = access()
    decision["capabilities"] = ["watch.manage"]
    assert registry.list_entries(cur, decision, now=NOW)["items"] == []


def test_history_is_scoped_and_cursor_advances_over_filtered_rows():
    cur = Cursor()
    cur.rows = [saved(valid_to=NOW), saved(revision=2)]
    result = registry.list_entries(cur, access(), entry_id=ENTRY, after="3", now=NOW)
    assert len(result["items"]) == 2 and "revision<%s::bigint" in cur.calls[0][0]
    cur.rows = [saved(id=f"00000000-0000-4000-8000-{i:012d}") for i in range(101)]
    result = registry.list_entries(cur, {**access(), "capabilities": []}, now=NOW)
    assert result["has_more"] and result["next_cursor"] == str(cur.rows[99]["id"]) and not result["items"]


def test_effective_grants_cannot_keep_manage_without_capability():
    from server.sli.access.access_control_v4 import _bounded_report_grant
    grant = access()["reports"][0]["grants"][0]
    fields = {"field.identity_basic", "field.security"}
    assert _bounded_report_grant(grant, fields)["allowed_actions"] == ["view"]
    assert _bounded_report_grant(grant, fields | {"watch.manage"})["allowed_actions"] == ["manage_watch", "view"]


class Handler:
    _principal = PRINCIPAL

    def __init__(self, decision=None):
        self.decision, self.reads = access() if decision is None else decision, 0

    def _access_decision(self):
        return self.decision

    def _authorize_mutation(self):
        return True

    def _read_json_body(self):
        self.reads += 1
        return body(expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat())

    def _send_json(self, response, status=HTTPStatus.OK):
        self.response, self.status = response, status


def test_api_denial_and_audit_failure_roll_back_and_success_commits(monkeypatch):
    cur = Cursor()
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: cur)
    handler = Handler({})
    routes.try_handle_get(handler, routes.PREFIX, {})
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.FORBIDDEN and handler.reads == 0 and not cur.calls
    handler = Handler()
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", lambda **kwargs: cur.events.append("audit"))
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.OK and cur.events[:2] == ["audit", "commit"]
    cur.events.clear()
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", Mock(side_effect=RuntimeError("synthetic-private")))
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.SERVICE_UNAVAILABLE and cur.events and set(cur.events) == {"rollback"}
    assert "synthetic-private" not in json.dumps(handler.response)


def test_http_scoped_get_dispatches_without_global_capability_gate(monkeypatch):
    from server.api import http_server
    cur = Cursor()
    cur.rows = [saved()]
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: cur)
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    handler = object.__new__(http_server.RequestHandler)
    handler.path, handler.headers, handler._principal = routes.PREFIX, {}, PRINCIPAL
    handler._require_secure_api_transport = lambda path: True
    handler._require_capability = Mock(side_effect=AssertionError("registry owns scoped authorization"))
    handler._access_decision = access
    handler._send_json = Mock()
    handler._do_GET()
    assert handler._send_json.call_args.args[0]["items"][0]["id"] == ENTRY
    handler._require_capability.assert_not_called()


@pytest.mark.parametrize("language", ["ru", "en"])
def test_api_errors_are_localized_and_do_not_echo_input(language):
    from server.sli.core.messages import catalog
    handler = Handler()
    handler.headers = {"Accept-Language": language}
    routes._error(handler, ValueError("synthetic-private"))
    assert handler.response["message"]["text"] == catalog(language)["watch.failed"]
    assert "synthetic-private" not in json.dumps(handler.response)
