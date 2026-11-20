"""Pilot retirement is audited and committed only after replacement enrollment."""
import json
from contextlib import nullcontext

import pytest

from server.sli.agents import revoke_agent

OLD = "00000000-0000-4000-8000-000000000002"
NEW = "00000000-0000-4000-8000-000000000001"
FP = "a" * 64


class Connection:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure
        self.committed = False
        self.rolled_back = False
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        self.rolled_back = exc_type is not None

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        self.rows = []
        if sql.startswith("select a.id"):
            assert params == (NEW, FP, OLD)
            assert "a.status='active'" in sql and "c.revoked_at is null" in sql
            assert "a.id<>%s" in sql
            assert "c.not_after>clock_timestamp()" in sql and "for update of a" in sql
            self.rows = [] if self.failure == "replacement" else [{"id": NEW}]
        elif sql.startswith("select id from sli_agents"):
            self.rows = [] if self.failure == "missing" else [{"id": OLD}]
        elif sql.startswith("update sli_agent_certificates"):
            self.rows = [{"serial": "aa"}, {"serial": "bb"}]
        elif "sli_agent_audit" in sql and self.failure == "audit":
            raise RuntimeError("private diagnostics")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def commit(self):
        if self.failure == "commit":
            raise RuntimeError("private diagnostics")
        self.committed = True


def arguments(**changes):
    values = {"agent-id": OLD, "replacement-host-id": NEW,
              "replacement-key-fingerprint": FP, "actor": "local-admin:test"}
    values.update(changes)
    return [arg for key, value in values.items() for arg in ("--" + key, value)]


def test_disables_pilot_and_revokes_every_certificate_with_audit(monkeypatch, capsys):
    conn = Connection()
    monkeypatch.setattr(revoke_agent, "connect", lambda: conn)
    original_print = print

    def committed_print(*args):
        assert conn.committed
        original_print(*args)

    monkeypatch.setattr(revoke_agent, "print", committed_print, raising=False)
    assert revoke_agent.main(arguments()) == 0
    assert capsys.readouterr().out == "revoked\n"
    assert ("update sli_agents set status='disabled' where id=%s", (OLD,)) in conn.calls
    audits = [params for sql, params in conn.calls if sql.startswith("insert into sli_agent_audit")]
    assert [(a[0], a[1], a[2], json.loads(a[3])) for a in audits] == [
        ("revoke", "local-admin:test", OLD, {"serial": "aa"}),
        ("revoke", "local-admin:test", OLD, {"serial": "bb"}),
        ("disable", "local-admin:test", OLD, {}),
    ]


@pytest.mark.parametrize("failure", ["replacement", "missing", "audit", "commit", "connect"])
def test_failure_has_no_success_or_private_diagnostics(monkeypatch, capsys, failure):
    conn = Connection(failure)

    def connect():
        if failure == "connect":
            raise RuntimeError("private diagnostics")
        return conn

    monkeypatch.setattr(revoke_agent, "connect", connect)
    assert revoke_agent.main(arguments()) == 1
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "revoke_agent_failed\n")
    assert not conn.committed
    if failure != "connect":
        assert conn.rolled_back
    if failure == "replacement":
        assert len(conn.calls) == 1


@pytest.mark.parametrize("changes,code", [
    ({"agent-id": "invalid"}, "invalid_agent_identity"),
    ({"replacement-host-id": "invalid"}, "invalid_agent_identity"),
    ({"replacement-key-fingerprint": "A" * 64}, "invalid_key_fingerprint"),
    ({"actor": " "}, "invalid_revoke_actor"),
    ({"actor": "a" * 129}, "invalid_revoke_actor"),
    ({"actor": "admin\ninjected"}, "invalid_revoke_actor"),
    ({"actor": "admin\x7f"}, "invalid_revoke_actor"),
])
def test_invalid_input_does_not_connect_or_echo(monkeypatch, capsys, changes, code):
    monkeypatch.setattr(revoke_agent, "connect", lambda: pytest.fail("unexpected connection"))
    with pytest.raises(SystemExit) as exc:
        revoke_agent.main(arguments(**changes))
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", code + "\n")


def test_missing_arguments_are_safe(capsys):
    with pytest.raises(SystemExit) as exc:
        revoke_agent.main([])
    assert exc.value.code == 2
    assert capsys.readouterr().err == "revoke_agent_invalid_arguments\n"
