"""Local owner command uses existing policy, scope and transaction boundaries."""
import json
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from test_file_audit_management import AGENT, HOST, Cursor, access
from test_sli_agent_file_audit import settings

from server.sli.agents import file_audit_admin as cli
from server.sli.agents.ca import AgentError
from server.sli.plugins.file_audit import management


def setup(monkeypatch, tmp_path, *, owner=True, active=True):
    cur = Cursor()
    original_execute = cur.execute
    def execute(sql, params=()):
        original_execute(sql, params)
        if sql.startswith("update sli_agents set collection_policy"):
            cur.agent["collection_policy"] = json.loads(params[0])
            cur.agent["policy_revision"] = params[1]
        elif sql.startswith("update sli_agents set assigned_modules"):
            cur.agent["assigned_modules"] = json.loads(params[0])
            cur.agent["policy_revision"] = params[1]
    cur.execute = execute
    connection = Mock()
    connection.cursor.return_value.__enter__ = Mock(return_value=cur)
    connection.cursor.return_value.__exit__ = Mock(return_value=False)

    @contextmanager
    def connect():
        try:
            yield connection
        except Exception:
            connection.rollback()
            raise

    monkeypatch.setattr(cli, "connect", connect)
    monkeypatch.setattr(cli, "owner_principal", lambda user_id: (
        {"type": "session", "id": user_id, "role": "admin"} if active else None))
    monkeypatch.setattr(cli, "effective_access", lambda p: {**access(), "platform_owner": owner})
    monkeypatch.setattr(cli, "plugin_hook", lambda *a: management.enqueue)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(settings()), encoding="utf-8")
    args = ["--agent-id", AGENT, "--owner-user-id", "1", "--actor", "fixture-operator",
            "--action", "apply", "--expected-revision", "1", "--policy", str(policy)]
    return cur, connection, args


def test_local_owner_command_authors_scoped_audited_request(monkeypatch, tmp_path, capsys):
    cur, connection, args = setup(monkeypatch, tmp_path)
    assert cli.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "pending" and result["policy_revision"] == 2
    assert result["command_id"] == cur.agent["file_audit"]["request"]["command"]["command_id"]
    call = next(params for sql, params in cur.calls if "enqueue_audit" in sql)
    assert call[:2] == (AGENT, HOST) and call[-2:] == ("session", 1)
    audits = [json.loads(params[3]) for sql, params in cur.calls if sql.startswith("insert into sli_agent_audit")]
    assert any(row.get("command_action") == "apply" for row in audits)
    assert any(row.get("owner_user_id") == 1 for row in audits)
    assert not any("path" in json.dumps(row) for row in audits)
    connection.commit.assert_called_once()


@pytest.mark.parametrize("owner,active", [(False, True), (True, False)])
def test_nonowner_or_inactive_user_cannot_mutate(monkeypatch, tmp_path, capsys, owner, active):
    cur, connection, args = setup(monkeypatch, tmp_path, owner=owner, active=active)
    assert cli.main(args) == 1
    assert capsys.readouterr().err == "file_audit_admin_owner_required\n"
    assert cur.calls == []
    connection.commit.assert_not_called()


def test_consent_and_assignment_are_explicit_and_atomic(monkeypatch, tmp_path, capsys):
    cur, connection, args = setup(monkeypatch, tmp_path)
    cur.agent["collection_policy"] = {}
    cur.agent["assigned_modules"] = [{"module_id": "sli.windows.ad-dc", "enabled": True,
                                     "config": {"source_name": "synthetic", "connect_address": "synthetic"}}]
    monkeypatch.setattr(cli.policies, "plugin_hook", lambda *a: cli.policy)
    assert cli.main(args + ["--enable-management", "--assign-module"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["policy_revision"] == 3
    updates = [sql for sql, _ in cur.calls if sql.startswith("update")]
    assert any("collection_policy" in sql for sql in updates)
    assert any("assigned_modules" in sql for sql in updates)
    assert cur.agent["file_audit"]["request"]["command"]["policy_revision"] == "3"
    assert cur.agent["assigned_modules"][-1]["config"] == cur.agent["file_audit"]["request"]["config"]
    assert [item["module_id"] for item in cur.agent["assigned_modules"]] == ["sli.windows.ad-dc", "sli.file-audit"]
    connection.commit.assert_called_once()


def test_stale_revision_rejected_before_policy_change(monkeypatch, tmp_path, capsys):
    cur, connection, args = setup(monkeypatch, tmp_path)
    cur.agent["policy_revision"] = 8
    assert cli.main(args + ["--enable-management", "--assign-module"]) == 1
    assert capsys.readouterr().err == "agent_policy_revision_conflict\n"
    assert not any(sql.startswith("update") for sql, _ in cur.calls)
    connection.commit.assert_not_called()


def test_missing_plugin_rejected_before_policy_change(monkeypatch, tmp_path, capsys):
    cur, connection, args = setup(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "plugin_hook", lambda *a: None)
    assert cli.main(args + ["--enable-management"]) == 1
    assert capsys.readouterr().err == "file_audit_plugin_unavailable\n"
    assert not any(sql.startswith("update") for sql, _ in cur.calls)
    connection.commit.assert_not_called()


def test_enqueue_failure_rolls_back_control_and_assignment(monkeypatch, tmp_path, capsys):
    _, connection, args = setup(monkeypatch, tmp_path)
    monkeypatch.setattr(cli.policies, "plugin_hook", lambda *a: cli.policy)
    def fail(*a, **kw):
        raise AgentError("file_audit_restore_required", 409)
    monkeypatch.setattr(cli, "plugin_hook", lambda *a: fail)
    assert cli.main(args + ["--enable-management", "--assign-module"]) == 1
    assert capsys.readouterr().err == "file_audit_restore_required\n"
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


def test_private_exception_is_not_printed(monkeypatch, tmp_path, capsys):
    _, connection, args = setup(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "plugin_hook", Mock(side_effect=RuntimeError("private-password-path")))
    assert cli.main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "file_audit_admin_failed\n"
    connection.commit.assert_not_called()


def test_status_uses_scoped_plugin_without_commit(monkeypatch, tmp_path, capsys):
    _, connection, args = setup(monkeypatch, tmp_path)
    status = Mock(return_value={"state": "pending"})
    monkeypatch.setattr(cli, "plugin_hook", lambda *a: status)
    assert cli.main(args[:6] + ["--actor", "fixture", "--action", "status"]) == 0
    assert json.loads(capsys.readouterr().out) == {"state": "pending"}
    assert status.call_args.kwargs["principal"]["id"] == 1
    connection.commit.assert_not_called()


@pytest.mark.parametrize("action", ["check", "restore"])
def test_consent_switches_cannot_be_used_for_read_or_restore(monkeypatch, tmp_path, capsys, action):
    cur, connection, args = setup(monkeypatch, tmp_path)
    args[args.index("apply")] = action
    assert cli.main(args + ["--enable-management"]) == 1
    assert capsys.readouterr().err == "file_audit_admin_arguments_invalid\n"
    assert cur.calls == []
    connection.commit.assert_not_called()
