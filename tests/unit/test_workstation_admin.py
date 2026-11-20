import json
import os
import re
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest
from test_agent_policies import AGENT, Cursor

from server.sli.agents import workstation_admin as cli
from server.sli.agents.ca import AgentError
from sli_agent.workstations import WorkstationsModule
from tests.postgres_integration_guard import assert_disposable_database


class Connection:
    def __init__(self, cur):
        self.cur = cur
        self.commit = Mock()
        self.rollback = Mock()

    def __enter__(self):
        return self

    def __exit__(self, kind, *_):
        if kind:
            self.rollback()

    @contextmanager
    def cursor(self):
        yield self.cur


def setup(monkeypatch, *, owner=True):
    cur = Cursor()
    conn = Connection(cur)
    monkeypatch.setattr(cli, "connect", lambda: conn)
    monkeypatch.setattr(cli, "owner_principal", lambda user: {"type": "session", "id": user})
    monkeypatch.setattr(cli, "effective_access", lambda p: {"platform_owner": owner})
    args = ["--agent-id", AGENT, "--owner-user-id", "1", "--actor", "fixture",
            "--expected-revision", "1"]
    return cur, conn, args


def test_enable_is_atomic_revisioned_audited_and_keeps_filters(monkeypatch, capsys):
    cur, conn, args = setup(monkeypatch)
    cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": False,
                                     "config": {"families": {"usb": False}}}]
    assert cli.main(args + ["--enable-audit"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["policy_revision"] == 3 and result["manage_windows_audit"] is True
    assert cur.agent["assigned_modules"][0]["config"]["families"]["usb"] is False
    assert [item[0] for item in cur.audits] == ["module_assign", "policy_update"]
    conn.commit.assert_called_once()


@pytest.mark.parametrize("owner,revision", [(False, 1), (True, 9)])
def test_authority_and_stale_revision_rejected_before_writes(monkeypatch, capsys, owner, revision):
    cur, conn, args = setup(monkeypatch, owner=owner)
    cur.agent["policy_revision"] = revision
    assert cli.main(args) == 1
    assert not any(sql.startswith("update") for sql, _ in cur.calls)
    conn.commit.assert_not_called()


def test_audit_management_requires_explicit_switch(monkeypatch, capsys):
    _, _, args = setup(monkeypatch)
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["manage_windows_audit"] is False


def test_policy_failure_rolls_back_assignment_and_does_not_expose_details(monkeypatch, capsys):
    _, conn, args = setup(monkeypatch)
    monkeypatch.setattr(cli.policies, "update_control", Mock(side_effect=RuntimeError("private-value")))
    assert cli.main(args) == 1
    assert capsys.readouterr().err == "workstation_admin_failed\n"
    conn.commit.assert_not_called()
    conn.rollback.assert_called_once()


@pytest.mark.parametrize("length,expected", [(122, 0), (123, 1)])
def test_actor_limit_includes_local_prefix(monkeypatch, capsys, length, expected):
    _, conn, args = setup(monkeypatch)
    args[args.index("--actor") + 1] = "a" * length
    assert cli.main(args) == expected
    assert conn.commit.call_count == (expected == 0)


def test_explicit_collection_pacing_updates_both_limits_and_keeps_filters(monkeypatch, capsys):
    cur, _, args = setup(monkeypatch)
    cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": False,
                                     "config": {"families": {"usb": False}}}]
    assert cli.main(args + ["--interval-seconds", "5", "--batch-size", "128"]) == 0
    config = cur.agent["assigned_modules"][0]["config"]
    assert config["batch_size"] == 128 and config["families"]["usb"] is False
    assert cur.agent["collection_policy"]["batch_size"] == 128
    assert cur.agent["collection_policy"]["interval_seconds"] == 5


@pytest.mark.parametrize("option,value", [("--batch-size", "129"), ("--interval-seconds", "0")])
def test_invalid_collection_pacing_rolls_back(monkeypatch, capsys, option, value):
    _, conn, args = setup(monkeypatch)
    assert cli.main(args + [option, value]) == 1
    conn.commit.assert_not_called()
    conn.rollback.assert_called_once()


@pytest.mark.parametrize('failure', [None, 'success', 'moved', 'revision', 'generation', 'short'])
def test_security_recovery_requires_three_current_stationary_read_failures(failure):
    from copy import deepcopy
    from types import SimpleNamespace

    host = '00000000-0000-4000-8000-000000000002'
    config = {'policy_revision': '2', 'deny_event_ids': [4688],
              'channel_generations': {'System': 'system-generation'}}
    progress = {'record_id': 123, 'bookmark': 'bookmark-123', 'generation': host}
    state = {'next': 1, 'channels': {'Security': progress}, 'rate': {'window': None, 'counts': {}}}
    row = {'envelope': {'generation': host, 'policy_revision': '2',
                        'cursor_after': WorkstationsModule._cursor(state)},
           'packet': {'context': {'workstations': {'read_error': 'agent_workstations_read_failed'}}}}
    rows = [deepcopy(row) for _ in range(3)]
    if failure == 'success':
        rows[1]['packet']['context']['workstations']['read_error'] = None
    if failure in ('moved', 'generation'):
        state = deepcopy(state)
        state['channels']['Security']['record_id' if failure == 'moved' else 'generation'] = (
            124 if failure == 'moved' else 'stale-generation')
        rows[1]['envelope']['cursor_after'] = WorkstationsModule._cursor(state)
    if failure == 'revision':
        rows[1]['envelope']['policy_revision'] = '1'
    if failure == 'short':
        rows.pop()
    calls = []
    cursor = SimpleNamespace(execute=lambda sql, params: calls.append((sql, params)), fetchall=lambda: rows)
    agent = {'id': AGENT, 'host_id': host}
    if failure:
        with pytest.raises(AgentError, match='workstation_security_recovery_not_blocked'):
            cli.recover_security_config(cursor, agent, config)
    else:
        changed = cli.recover_security_config(cursor, agent, config)
        assert changed['channel_generations']['Security'].startswith('security-recovery-')
        assert changed['channel_generations']['System'] == 'system-generation'
        assert changed['deny_event_ids'] == [4688] and 'Security' not in config['channel_generations']
    assert calls[0][1] == (AGENT,)


def test_recovery_of_unassigned_station_never_writes(monkeypatch, capsys):
    cur, conn, args = setup(monkeypatch)
    assert cli.main(args + ['--recover-security-read']) == 1
    assert capsys.readouterr().err == 'workstation_security_recovery_not_blocked\n'
    assert not cur.audits
    conn.commit.assert_not_called()


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("failure", [None, "stale", "audit", "recovery"])
def test_command_with_postgres_audit_contract(monkeypatch, capsys, failure):
    """Real policy writes and migration CHECK constraints; no production DSN."""
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL DSN is required")
    migrations = Path(__file__).resolve().parents[2] / "config/postgres_migrations"
    registry_sql = (migrations / "156_agent_registry.sql").read_text("utf-8")
    revision_sql = (migrations / "163_agent_policy_revisions.sql").read_text("utf-8")
    control_sql = (migrations / "169_agent_collection_control.sql").read_text("utf-8")
    database = "sli_test_workstation_admin_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute(sql.SQL("create database {}").format(sql.Identifier(database)))
        try:
            parts = conninfo_to_dict(dsn)
            parts["dbname"] = database
            with psycopg.connect(**parts, autocommit=True) as conn:
                for table in ("sli_agents", "sli_agent_audit"):
                    conn.execute(re.search(rf"create table {table} \(.*?\n\);", registry_sql, re.DOTALL)[0])
                for source in (revision_sql, control_sql):
                    conn.execute(re.search(r"alter table public.sli_agents\n.*?;", source, re.DOTALL)[0])
                conn.execute(re.search(r"alter table public.sli_agent_audit drop.*?;", revision_sql, re.DOTALL)[0])
                conn.execute(re.search(r"alter table public.sli_agent_audit add.*?;", revision_sql, re.DOTALL)[0])
                conn.execute(re.search(r"create table public.sli_agent_policy_history \(.*?\n\);", control_sql, re.DOTALL)[0])
                conn.execute(re.search(r"do \$\$\ndeclare prior_check.*?end \$\$;", control_sql, re.DOTALL)[0])
                conn.execute("insert into sli_agents(id,host_id,key_fingerprint) values(%s,%s,%s)",
                             (AGENT, str(uuid4()), "0" * 64))
                if failure == 'recovery':
                    host = str(conn.execute('select host_id from sli_agents').fetchone()[0])
                    config = {'policy_revision': '1', 'deny_event_ids': [4688]}
                    conn.execute('update sli_agents set assigned_modules=%s', (json.dumps([
                        {'module_id': 'sli.workstations', 'enabled': True, 'config': config}]),))
                    conn.execute('create table sli_agent_packet_inbox(envelope jsonb,packet jsonb)')
                    state = {'next': 1, 'channels': {'Security': {'record_id': 123,
                             'bookmark': 'bookmark-123', 'generation': host}},
                             'rate': {'window': None, 'counts': {}}}
                    for sequence in range(3):
                        conn.execute('insert into sli_agent_packet_inbox values(%s,%s)', (
                            json.dumps({'agent_id': AGENT, 'module_id': 'sli.workstations',
                                        'policy_revision': '1', 'sequence': sequence, 'generation': host,
                                        'cursor_after': WorkstationsModule._cursor(state)}),
                            json.dumps({'header': {'channel': 'Security'}, 'context': {'workstations': {
                                        'read_error': 'agent_workstations_read_failed'}}})))
            monkeypatch.setattr(cli, "connect", lambda: psycopg.connect(**parts, row_factory=dict_row))
            monkeypatch.setattr(cli, "owner_principal", lambda _: {"type": "session", "id": 1})
            monkeypatch.setattr(cli, "effective_access", lambda _: {"platform_owner": True})
            args = ["--agent-id", AGENT, "--owner-user-id", "1", "--actor", "fixture",
                    "--expected-revision", "9" if failure == "stale" else "1", "--enable-audit"]
            if failure == 'recovery':
                args += ['--recover-security-read']
            if failure == "audit":
                from server.sli.agents import registry

                audit = registry.audit
                monkeypatch.setattr(registry, "audit", lambda cur, action, *rest, **details:
                                    audit(cur, "unsupported" if action == "policy_update" else action,
                                          *rest, **details))
            rejected = failure in ('stale', 'audit')
            assert cli.main(args) == (1 if rejected else 0)
            output = capsys.readouterr()
            if failure == "audit":
                assert output.err == "workstation_admin_failed\n"
            with psycopg.connect(**parts, row_factory=dict_row) as conn:
                agent = conn.execute("select * from sli_agents").fetchone()
                audits = conn.execute("select action,actor,target from sli_agent_audit order by id").fetchall()
                history = conn.execute("select revision from sli_agent_policy_history order by revision").fetchall()
                if rejected:
                    assert agent["policy_revision"] == 1 and agent["assigned_modules"] == []
                    assert not audits and not history
                else:
                    assert agent["policy_revision"] == 3
                    assert agent["assigned_modules"][0]["enabled"] is True
                    assert agent["collection_policy"]["manage_windows_audit"] is True
                    if failure == 'recovery':
                        config = agent['assigned_modules'][0]['config']
                        assert config['channel_generations']['Security'].startswith('security-recovery-')
                        assert config['deny_event_ids'] == [4688]
                    assert audits == [{"action": action, "actor": "local:fixture", "target": AGENT}
                                      for action in ("module_assign", "policy_update")]
                    assert [row["revision"] for row in history] == [1, 2, 3]
        finally:
            admin.execute(sql.SQL("drop database {} with (force)").format(sql.Identifier(database)))
