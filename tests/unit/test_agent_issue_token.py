"""Local issuance uses the registry transaction and never exposes diagnostics."""
import json
import re
from contextlib import nullcontext

import pytest

from server.sli.agents import issue_token, registry

HOST = "00000000-0000-4000-8000-000000000001"
FP = "a" * 64


class Connection:
    def __init__(self, fail=None):
        self.calls = []
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.fail = fail

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        self.rolled_back = exc_type is not None
        self.closed = True

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params):
        self.calls.append((sql, params))
        if self.fail == "audit" and "sli_agent_audit" in sql:
            raise RuntimeError("private database diagnostics")

    def commit(self):
        if self.fail == "commit":
            raise RuntimeError("private database diagnostics")
        self.committed = True


def arguments(**changes):
    values = {"host-id": HOST, "key-fingerprint": FP, "ttl": "900", "actor": "local-admin:test"}
    values.update(changes)
    return [arg for key, value in values.items() for arg in ("--" + key, value)]


@pytest.mark.parametrize("ttl", ["60", "900"])
def test_issues_bound_token_with_audit_after_commit(monkeypatch, capsys, ttl):
    conn = Connection()
    monkeypatch.setattr(issue_token, "connect", lambda: conn)
    original_print = print

    def committed_print(*args):
        assert conn.committed and conn.closed
        original_print(*args)

    monkeypatch.setattr(issue_token, "print", committed_print, raising=False)
    assert issue_token.main(arguments(ttl=ttl)) == 0
    captured = capsys.readouterr()
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}\n", captured.out)
    assert captured.err == ""
    token = captured.out.strip()
    assert len(conn.calls) == 2
    sql, stored = conn.calls[0]
    assert sql.startswith("insert into sli_agent_enrollment_tokens")
    token_id, digest, host, fp, created, expires, instance, replacement_for = stored
    assert digest == registry.token_hash(token)
    assert (host, fp, instance) == (HOST, FP, None)
    assert replacement_for is None
    assert (expires - created).total_seconds() == int(ttl)
    sql, audit = conn.calls[1]
    assert sql.startswith("insert into sli_agent_audit")
    assert audit[:3] == ("token_create", "local-admin:test", token_id)
    assert json.loads(audit[3]) == {"ttl_seconds": int(ttl), "instance_name": None}
    assert token not in repr(conn.calls)


@pytest.mark.parametrize("changes,code", [
    ({"host-id": "invalid"}, "invalid_agent_identity"),
    ({"key-fingerprint": "A" * 64}, "invalid_key_fingerprint"),
    ({"key-fingerprint": "a" * 63}, "invalid_key_fingerprint"),
    ({"key-fingerprint": "g" * 64}, "invalid_key_fingerprint"),
    ({"ttl": "59"}, "invalid_enrollment_ttl"),
    ({"ttl": "901"}, "invalid_enrollment_ttl"),
    ({"ttl": "3600"}, "invalid_enrollment_ttl"),
    ({"ttl": "-1"}, "invalid_enrollment_ttl"),
    ({"ttl": "invalid"}, "issue_token_invalid_arguments"),
    ({"host-name": "bad\nname"}, "invalid_agent_registration_name"),
    ({"actor": " "}, "invalid_token_actor"),
    ({"actor": "admin\ninjected"}, "invalid_token_actor"),
    ({"actor": "a" * 129}, "invalid_token_actor"),
])
def test_invalid_input_never_connects_or_echoes_values(monkeypatch, capsys, changes, code):
    def forbidden():
        pytest.fail("invalid input opened a database connection")

    monkeypatch.setattr(issue_token, "connect", forbidden)
    with pytest.raises(SystemExit) as exc:
        issue_token.main(arguments(**changes))
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == code + "\n"


@pytest.mark.parametrize("failure", ["audit", "commit", "connect"])
def test_no_secret_on_transaction_failure(monkeypatch, capsys, failure):
    conn = Connection(failure)

    def connect():
        if failure == "connect":
            raise RuntimeError("private database diagnostics")
        return conn

    monkeypatch.setattr(issue_token, "connect", connect)
    assert issue_token.main(arguments()) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "issue_token_failed\n"
    assert not conn.committed
    if failure != "connect":
        assert conn.rolled_back and conn.closed


def test_missing_arguments_have_only_safe_error(capsys):
    with pytest.raises(SystemExit) as exc:
        issue_token.main([])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "issue_token_invalid_arguments\n")


def test_default_ttl_is_fifteen_minutes(monkeypatch, capsys):
    conn = Connection()
    monkeypatch.setattr(issue_token, "connect", lambda: conn)
    args = arguments()
    index = args.index("--ttl")
    del args[index:index + 2]
    assert issue_token.main(args) == 0
    _, stored = conn.calls[0]
    assert (stored[5] - stored[4]).total_seconds() == 900
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}\n", capsys.readouterr().out)


def test_replacement_name_is_approved_by_local_admin_and_recorded_before_reveal(monkeypatch, capsys):
    conn = Connection()
    monkeypatch.setattr(issue_token, "connect", lambda: conn)
    assert issue_token.main(arguments(**{"host-name": "PC.example.invalid"})) == 0
    assert conn.committed
    assert json.loads(conn.calls[1][1][3])["registration_host_name"] == "pc.example.invalid"
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}\n", capsys.readouterr().out)
