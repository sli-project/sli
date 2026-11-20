"""Coherent activation against the real migrated, disposable PostgreSQL clone."""
import json
import os

import pytest
from psycopg import connect
from psycopg.rows import dict_row

from server.sli.agents import policies
from server.sli.agents.ca import AgentError
from server.sli.plugins.file_audit import management
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_file_audit_management import AGENT, HOST, PRINCIPAL, access, body

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def activation_pg():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL not configured")
    with connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("insert into sli_agents(id,host_id,key_fingerprint,collection_policy) "
                     "values(%s,%s,%s,%s::jsonb)",
                     (AGENT, HOST, "0" * 64, json.dumps({"manage_windows_audit": True})))
        yield conn


def activation():
    return {**body("apply"), "enabled": True, "activate_collection": True}


def enqueue(conn, value=None, decision=None):
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_user")
        return management.enqueue(cur, value or activation(), principal=PRINCIPAL,
                                  access=access() if decision is None else decision)


def test_registered_assignment_history_and_sql_hashes_agree(activation_pg):
    conn = activation_pg
    assert enqueue(conn)["policy_revision"] == 2
    agent = conn.execute("select * from sli_agents where id=%s", (AGENT,)).fetchone()
    assignment = agent["assigned_modules"][0]
    request = agent["file_audit"]["request"]
    assert assignment["enabled"] is True and assignment["config"]["policy_revision"] == "2"
    assert assignment["config"] == request["config"]
    policy = conn.execute("select *,encode(sha256(convert_to(policy::text,'UTF8')),'hex') as actual "
                          "from sli_plugin_file_audit.policy_revisions where agent_id=%s", (AGENT,)).fetchone()
    assert policy["revision"] == 2 and policy["policy"] == assignment["config"]
    assert policy["policy_sha256"] == policy["actual"]
    command = conn.execute("select *,encode(sha256(convert_to(%s::jsonb::text,'UTF8')),'hex') as actual "
                           "from sli_plugin_file_audit.audit_commands where agent_id=%s",
                           (json.dumps(request["command"]), AGENT)).fetchone()
    assert command["policy_revision"] == 2 and command["action"] == "apply"
    assert command["collection_scope_ids"] == ["scope:one"]
    assert command["command_sha256"] == command["actual"]
    assert policy["actor_kind"] == command["actor_kind"] == "session"
    assert policy["actor_id"] == command["actor_id"] == 1
    history = conn.execute("select * from sli_agent_policy_history where agent_id=%s order by revision",
                           (AGENT,)).fetchall()
    assert [row["revision"] for row in history] == [1, 2]
    assert history[0]["assigned_modules"] == []
    assert history[1]["assigned_modules"] == agent["assigned_modules"]
    assert policies.check_in(agent)["file_audit"] == request


@pytest.mark.parametrize("failure", ["policy_revisions", "audit_commands", "sli_agent_policy_history",
                                   "sli_agents", "sli_agent_audit"])
@pytest.mark.parametrize("explicit_consent", [False, True])
def test_failures_roll_back_all_activation_writes_and_explicit_consent(activation_pg, failure, explicit_consent):
    """A real trigger error at each write stage must undo the whole transaction."""
    from psycopg import sql
    from psycopg.errors import RaiseException

    conn = activation_pg
    if explicit_consent:
        conn.execute("update sli_agents set collection_policy='{}'")
    before = conn.execute("select to_jsonb(a)::text as state from sli_agents a").fetchone()["state"]
    table = sql.Identifier("sli_plugin_file_audit", failure) if failure in (
        "policy_revisions", "audit_commands") else sql.Identifier("public", failure)
    conn.execute("create function public.reject_activation() returns trigger language plpgsql "
                 "as $$ begin raise exception 'synthetic_activation_failure'; end $$")
    conn.execute(sql.SQL("create trigger reject_activation after {} on {} for each row "
                        "execute function public.reject_activation()").format(
                            sql.SQL("update" if failure == "sli_agents" else "insert"), table))
    with pytest.raises(RaiseException, match="synthetic_activation_failure"):
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("set local role adlog_user")
            # Even an explicitly requested management update must roll back.
            value = activation()
            if explicit_consent:
                policies.update_control(cur, {"agent_id": AGENT, "expected_revision": 1,
                    "collection_policy": {"manage_windows_audit": True}}, actor="session:1")
                value["expected_revision"] = 2
                value["command"]["policy_revision"] = "3"
            management.enqueue(cur, value, principal=PRINCIPAL, access=access())
    assert conn.execute("select to_jsonb(a)::text as state from sli_agents a").fetchone()["state"] == before
    for name in ("sli_plugin_file_audit.policy_revisions", "sli_plugin_file_audit.audit_commands",
                 "sli_agent_policy_history", "sli_agent_audit"):
        assert conn.execute(sql.SQL("select count(*) as count from {}").format(
            sql.Identifier(*name.split(".")))).fetchone()["count"] == 0
    assert conn.execute("select 42 as recovered").fetchone()["recovered"] == 42


def test_two_owners_racing_same_revision_publish_only_one_activation(activation_pg):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from time import monotonic, sleep

    conn = activation_pg
    ready = Event()
    backend = []

    def competing():
        with connect(os.environ["ADLOG_TEST_PG_DSN"], autocommit=True, row_factory=dict_row) as other:
            other.execute("set lock_timeout='5s'")
            backend.append(other.execute("select pg_backend_pid() as pid").fetchone()["pid"])
            ready.set()
            return enqueue(other)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("set local role adlog_user")
            result = management.enqueue(cur, activation(), principal=PRINCIPAL, access=access())
            competing_result = pool.submit(competing)
            assert ready.wait(3)
            # Observe an actual blocked row lock before committing the winner.
            with connect(os.environ["ADLOG_TEST_PG_DSN"], autocommit=True, row_factory=dict_row) as observer:
                deadline = monotonic() + 3
                while monotonic() < deadline:
                    waiting = observer.execute("select wait_event_type from pg_stat_activity where pid=%s",
                                               (backend[0],)).fetchone()
                    if waiting and waiting["wait_event_type"] == "Lock":
                        break
                    sleep(0.01)
                else:
                    pytest.fail("competing activation never waited on the locked agent row")
        assert result["policy_revision"] == 2
        with pytest.raises(AgentError, match="agent_policy_revision_conflict"):
            competing_result.result(timeout=8)
    assert conn.execute("select count(*) as n from sli_plugin_file_audit.policy_revisions").fetchone()["n"] == 1
    assert conn.execute("select count(*) as n from sli_plugin_file_audit.audit_commands").fetchone()["n"] == 1
    assert conn.execute("select count(*) as n from sli_agent_policy_history").fetchone()["n"] == 2
    assert conn.execute("select count(*) as n from sli_agent_audit").fetchone()["n"] == 1


@pytest.mark.parametrize("rejection", ["scope", "extra_root", "viewer", "management", "ownership",
                                     "workstation", "channel", "limit", "invalid_config"])
def test_denied_activation_has_no_partial_registration_or_history(activation_pg, rejection):
    from copy import deepcopy

    conn = activation_pg
    value, decision, principal = activation(), access(), PRINCIPAL
    expected = "file_audit_request_denied"
    if rejection == "scope":
        decision = access(scope="scope:other")
    elif rejection == "extra_root":
        extra = deepcopy(value["config"]["roots"][0])
        extra.update(collection_scope_id="scope:other", path=r"C:\synthetic-other")
        value["config"]["roots"].append(extra)
        # The command only names the allowed root: collection must not expand its authority.
    elif rejection == "viewer":
        principal = {"type": "session", "id": 1, "role": "viewer"}
    elif rejection == "management":
        conn.execute("update sli_agents set collection_policy='{}'")
        expected = "file_audit_management_disabled"
    elif rejection == "ownership":
        prior = deepcopy(value)
        prior["config"]["roots"][0]["path"] = r"C:\prior-synthetic"
        conn.execute("update sli_agents set file_audit=%s::jsonb",
                     (json.dumps({"request": prior, "may_own_audit": True}),))
        expected = "file_audit_restore_required"
    elif rejection == "workstation":
        value["config"]["source_kind"] = "workstation"
        value["config"]["roots"][0]["share_name"] = ""
    elif rejection == "channel":
        conn.execute("update sli_agents set assigned_modules=%s::jsonb", (json.dumps([
            {"module_id": "sli.workstations", "enabled": True, "config": {}}]),))
    elif rejection == "limit":
        conn.execute("update sli_agents set assigned_modules=%s::jsonb",
                     (json.dumps(["synthetic"] * 64),))
    elif rejection == "invalid_config":
        value["config"]["roots"][0]["path"] = r"\\synthetic\denied"
    before = conn.execute("select to_jsonb(a)::text as state from sli_agents a").fetchone()["state"]
    with pytest.raises(AgentError, match=expected):
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("set local role adlog_user")
            management.enqueue(cur, value, principal=principal, access=decision)
    assert conn.execute("select to_jsonb(a)::text as state from sli_agents a").fetchone()["state"] == before
    for name in ("policy_revisions", "audit_commands"):
        assert conn.execute("select count(*) as n from sli_plugin_file_audit." + name).fetchone()["n"] == 0
    assert conn.execute("select count(*) as n from sli_agent_policy_history").fetchone()["n"] == 0


def test_runtime_role_cannot_read_or_rewrite_plugin_rows_or_history(activation_pg):
    from psycopg.errors import InsufficientPrivilege

    conn = activation_pg
    enqueue(conn)
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_user")
        assert cur.execute("select current_user as role").fetchone()["role"] == "adlog_user"
        for statement in ("select * from sli_plugin_file_audit.policy_revisions",
                          "update sli_plugin_file_audit.policy_revisions set revision=3",
                          "delete from sli_plugin_file_audit.audit_commands",
                          "update sli_agent_policy_history set revision=3",
                          "delete from sli_agent_policy_history"):
            with pytest.raises(InsufficientPrivilege), conn.transaction():
                cur.execute(statement)
        assert cur.execute("select policy_revision from sli_agents where id=%s", (AGENT,)).fetchone()["policy_revision"] == 2


def test_later_control_revision_preserves_registered_module_and_historical_bytes(activation_pg):
    conn = activation_pg
    enqueue(conn)
    history = conn.execute("select to_jsonb(h)::text as bytes from sli_agent_policy_history h "
                           "order by revision").fetchall()
    registered = conn.execute("select to_jsonb(p)::text as bytes from "
                              "sli_plugin_file_audit.policy_revisions p").fetchall()
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_user")
        policies.update_control(cur, {"agent_id": AGENT, "expected_revision": 2,
            "collection_policy": {"interval_seconds": 90}}, actor="session:1")
    agent = conn.execute("select * from sli_agents where id=%s", (AGENT,)).fetchone()
    checkin = policies.check_in(agent)
    assert checkin["policy_revision"] == 3
    assert checkin["assigned_modules"][0]["config"]["policy_revision"] == "2"
    assert checkin["file_audit"]["command"]["policy_revision"] == "2"
    assert conn.execute("select to_jsonb(h)::text as bytes from sli_agent_policy_history h "
                        "where revision<=2 order by revision").fetchall() == history
    assert conn.execute("select to_jsonb(p)::text as bytes from "
                        "sli_plugin_file_audit.policy_revisions p").fetchall() == registered


@pytest.mark.parametrize("action", ["check", "apply", "restore"])
@pytest.mark.parametrize("wire", ["component", "old_flat_action", "denied_scope"])
def test_component_server_body_crosses_real_http_dispatch_and_sql185(activation_pg, monkeypatch, action, wire):
    """Shared bytes equal the component callback in Vitest; real dispatch validates them here."""
    from contextlib import contextmanager
    from copy import deepcopy
    from http import HTTPStatus
    from pathlib import Path

    from server.api import http_server
    from server.api.routes import agents
    from sli_agent.file_audit_policy import policy

    fixture = Path(__file__).resolve().parents[2] / "frontend/src/test-fixtures/file_audit_server_ui_requests.json"
    value = json.loads(fixture.read_text("utf-8"))[action]
    conn = activation_pg
    modules = []
    if action != "apply":
        modules = [{"module_id": "sli.file-audit", "enabled": True,
                    "config": policy({**value["config"], "policy_revision": "2"})}]
    conn.execute("update sli_agents set policy_revision=2,assigned_modules=%s::jsonb", (json.dumps(modules),))
    original_agent = conn.execute("select to_jsonb(a)::text as bytes from sli_agents a").fetchone()["bytes"]
    # Only this negative regression transforms the old, rejected wire shape.
    if wire == "old_flat_action":
        value = {**value, "action": value["command"]["action"]}
        del value["command"]
    decision = {**access(scope="scope:other" if wire == "denied_scope" else "bound:scope"),
                "capabilities": ["access.manage"]}

    @contextmanager
    def runtime_connection():
        with connect(os.environ["ADLOG_TEST_PG_DSN"], row_factory=dict_row) as runtime:
            runtime.execute("set local role adlog_user")
            assert runtime.execute("select current_user as role").fetchone()["role"] == "adlog_user"
            yield runtime

    # Transport/session establishment is synthetic; dispatcher, access checks,
    # plugin resolution, _execute commit/rollback and singleton writer are real.
    monkeypatch.setattr(agents, "connect", runtime_connection)
    monkeypatch.setattr(http_server, "principal_from_headers", lambda headers: PRINCIPAL)
    handler = object.__new__(http_server.RequestHandler)
    handler.headers = {}
    handler._effective_access_cache = decision
    handler._authorize_mutation = lambda **kwargs: True
    handler._read_json_body = lambda: deepcopy(value)
    responses = []
    handler._send_json = lambda payload, status=HTTPStatus.OK, **kwargs: responses.append((payload, int(status)))
    assert agents.try_handle_post(handler, "/api/v1/admin/agents/file-audit")
    assert len(responses) == 1
    if wire != "component":
        expected = ({"error": "file_audit_request_invalid"}, 400) if wire == "old_flat_action" else (
            {"error": "file_audit_request_denied"}, 403)
        assert responses[0] == expected
        assert conn.execute("select to_jsonb(a)::text as bytes from sli_agents a").fetchone()["bytes"] == original_agent
        assert conn.execute("select count(*) as n from sli_plugin_file_audit.policy_revisions").fetchone()["n"] == 0
        assert conn.execute("select count(*) as n from sli_plugin_file_audit.audit_commands").fetchone()["n"] == 0
        assert conn.execute("select count(*) as n from sli_agent_policy_history").fetchone()["n"] == 0
        return

    command = value["command"]
    assert responses[0] == ({"policy_revision": 3, "command_id": command["command_id"], "state": "pending"}, 200)
    agent = conn.execute("select * from sli_agents where id=%s", (AGENT,)).fetchone()
    assert agent["file_audit"]["request"]["command"] == command
    selected = agent["file_audit"]["request"]["config"]
    assert selected["roots"] == value["config"]["roots"]
    assert selected["max_events"] == 17 and selected["service_account_exclusions"] == ["S-1-5-18"]
    assert selected["source_kind"] == "server" and selected["policy_revision"] == "3"
    stored = conn.execute(
        "select p.revision,p.policy,p.policy_sha256,c.command_sha256,c.action,c.collection_scope_ids,"
        "encode(sha256(convert_to(p.policy::text,'UTF8')),'hex') as policy_hash,"
        "encode(sha256(convert_to(%s::jsonb::text,'UTF8')),'hex') as command_hash "
        "from sli_plugin_file_audit.policy_revisions p join sli_plugin_file_audit.audit_commands c "
        "on c.agent_id=p.agent_id and c.source_instance_id=p.source_instance_id and c.policy_revision=p.revision",
        (json.dumps(command),)).fetchone()
    assert stored["revision"] == 3 and stored["policy"] == selected
    assert stored["policy_sha256"] == stored["policy_hash"]
    assert stored["command_sha256"] == stored["command_hash"]
    assert stored["action"] == action and stored["collection_scope_ids"] == ["bound:scope"]
    history = conn.execute("select revision,assigned_modules from sli_agent_policy_history order by revision").fetchall()
    assert [row["revision"] for row in history] == [2, 3]
    assert history[0]["assigned_modules"] == modules
    assert history[1]["assigned_modules"] == agent["assigned_modules"]
    if action == "apply":
        assert value["enabled"] is True and value["activate_collection"] is True
        assert agent["assigned_modules"] == [{"module_id": "sli.file-audit", "enabled": True, "config": selected}]
    else:
        assert "enabled" not in value and "activate_collection" not in value
        assert agent["assigned_modules"] == modules
    # Replay exact emitted bytes through the same real route: CAS rejects them.
    assert agents.try_handle_post(handler, "/api/v1/admin/agents/file-audit")
    assert responses[-1] == ({"error": "agent_policy_revision_conflict"}, 409)
    assert conn.execute("select count(*) as n from sli_plugin_file_audit.policy_revisions").fetchone()["n"] == 1
    assert conn.execute("select count(*) as n from sli_plugin_file_audit.audit_commands").fetchone()["n"] == 1



