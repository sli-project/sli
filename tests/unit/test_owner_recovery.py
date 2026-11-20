"""Recovery authentication contracts, with an in-memory DB boundary only."""
from contextlib import nullcontext
from datetime import timedelta
import hashlib
from types import SimpleNamespace

import pytest

from server.sli.access import auth
from tests.unit.test_login_self_protection import Ledger


class RecoveryDatabase(Ledger):
    def __init__(self):
        super().__init__()
        self.users = {
            "owner": {"id": 1, "username": "owner", "role": "admin", "is_active": True,
                      "password_hash": auth.PASSWORD_HASHER.hash("synthetic-owner-password")},
            "other": {"id": 2, "username": "other", "role": "admin", "is_active": True,
                      "password_hash": auth.PASSWORD_HASHER.hash("synthetic-owner-password")},
        }
        self.owner_ids = {1}
        self.codes = {}
        self.audits = []

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params=()):
        normalized = " ".join(sql.lower().split())
        self.result = None
        if "from auth_users" in normalized:
            user = self.users.get(params[0].strip().lower())
            self.result = dict(user) if user else None
            if "access_platform_owners" in normalized and user and user["id"] not in self.owner_ids:
                self.result = None
            if "u.is_active=true" in normalized and user and not user["is_active"]:
                self.result = None
        elif "insert into auth_owner_recovery" in normalized:
            self.codes[params[0]] = {"code_hash": params[1], "expires_at": self.now + timedelta(minutes=10)}
        elif "from auth_owner_recovery" in normalized:
            user_id, digest = params
            code = self.codes.get(user_id)
            if code and code["code_hash"] == digest and code["expires_at"] > self.now:
                self.result = {"user_id": user_id}
                if normalized.startswith("delete"):
                    del self.codes[user_id]
        elif "insert into auth_audit" in normalized:
            self.audits.append(params)
            self.result = {"id": len(self.audits), "created_at": self.now}
        else:
            super().execute(sql, params)
            return
        self.calls.append((sql, params))


@pytest.fixture
def database(monkeypatch):
    db = RecoveryDatabase()
    monkeypatch.setattr(auth, "_connect", lambda: nullcontext(db))
    monkeypatch.setattr(auth, "ensure_auth_schema", lambda: None)
    from server.sli.sources import administrative_activity_producer
    monkeypatch.setattr(administrative_activity_producer, "mirror_auth_audit_if_enabled", lambda **_: None)
    return db


def install_code(db, *, user_id=1, seconds=600):
    code = "synthetic-recovery-secret"
    db.codes[user_id] = {"code_hash": hashlib.sha256(code.encode()).hexdigest(),
                         "expires_at": db.now + timedelta(seconds=seconds)}
    return code


def test_locked_owner_can_login_once_without_reopening_account_budget(database, caplog, capsys):
    for _ in range(5):
        auth.AccountAttempt(database, "owner").failed(database)
    blocked = dict(database.rows)
    code = install_code(database)
    principal = auth.authenticate_password(" OWNER ", "synthetic-owner-password", recovery_code=code)
    assert principal == {"type": "session", "id": 1, "username": "owner", "role": "admin"}
    assert database.rows == blocked
    assert auth.authenticate_password("owner", "synthetic-owner-password", recovery_code=code) is None
    assert [entry[3] for entry in database.audits] == ["ok", "failed"]
    assert code not in str(database.calls) + caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize("case", ["expired", "wrong", "foreign", "nonowner", "disabled", "wrong_password", "empty", "oversized", "missing"])
def test_recovery_refuses_invalid_credentials(database, case):
    code = install_code(database, seconds=0 if case == "expired" else 600)
    username, password = "owner", "synthetic-owner-password"
    if case == "wrong":
        code = "wrong-code"
    elif case == "foreign":
        username = "other"
    elif case == "nonowner":
        database.owner_ids.clear()
    elif case == "disabled":
        database.users["owner"]["is_active"] = False
    elif case == "wrong_password":
        password = "incorrect-password"
    elif case == "empty":
        code = ""
    elif case == "oversized":
        code = "x" * 129
    elif case == "missing":
        username = "missing-owner"
    assert auth.authenticate_password(username, password, recovery_code=code) is None
    assert database.audits[-1][2:4] == ("owner_recovery_login", "failed")
    assert 1 in database.codes


def test_wrong_code_never_runs_password_hash_or_account_throttle(database, monkeypatch):
    install_code(database)
    monkeypatch.setattr(auth, "AccountAttempt", lambda *_: pytest.fail("recovery must not contend with attack"))
    monkeypatch.setattr(auth, "PASSWORD_HASHER", SimpleNamespace(verify=lambda *_: pytest.fail("guess must be cheap")))
    assert auth.authenticate_password("owner", "synthetic-owner-password", recovery_code="guess") is None


def test_issue_is_owner_only_replaces_previous_and_stores_only_digest(database, monkeypatch, caplog, capsys):
    from server.sli.access import owner_recovery
    monkeypatch.setattr(owner_recovery.os, "geteuid", lambda: 0, raising=False)
    first = owner_recovery.issue_owner_recovery_code("owner")
    second = owner_recovery.issue_owner_recovery_code("OWNER")
    assert first != second
    assert len(second) >= 43
    assert database.codes[1]["code_hash"] == hashlib.sha256(second.encode()).hexdigest()
    assert database.codes[1]["expires_at"] == database.now + timedelta(minutes=10)
    with pytest.raises(ValueError, match="active_platform_owner_required"):
        owner_recovery.issue_owner_recovery_code("other")
    assert [entry[3] for entry in database.audits] == ["ok", "ok", "failed"]
    assert first not in str(database.calls) + caplog.text + str(capsys.readouterr())
    assert second not in str(database.calls)
    assert auth.authenticate_password("owner", "synthetic-owner-password", recovery_code=first) is None
    assert auth.authenticate_password("owner", "synthetic-owner-password", recovery_code=second)["id"] == 1


def test_issue_refuses_nonroot(database, monkeypatch):
    from server.sli.access import owner_recovery
    monkeypatch.setattr(owner_recovery.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(PermissionError, match="host_root_required"):
        owner_recovery.issue_owner_recovery_code("owner")
    assert not database.codes


def test_recovery_cli_requires_terminal_before_issuing(monkeypatch):
    from scripts.auth import manage_auth
    monkeypatch.setattr("sys.argv", ["manage_auth.py", "owner-recovery", "--username", "owner"])
    monkeypatch.setattr(manage_auth.sys, "stdout", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(SystemExit, match="terminal_required"):
        manage_auth.main()


def test_recovery_cli_prints_code_once_only_to_terminal(database, monkeypatch, capsys):
    from scripts.auth import manage_auth
    from server.sli.access import owner_recovery
    monkeypatch.setattr(owner_recovery.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("sys.argv", ["manage_auth.py", "owner-recovery", "--username", "owner"])
    monkeypatch.setattr(manage_auth.sys.stdout, "isatty", lambda: True)
    assert manage_auth.main() == 0
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 2 and captured.err == ""
    code = lines[-1]
    assert hashlib.sha256(code.encode()).hexdigest() == database.codes[1]["code_hash"]
    assert code not in str(database.calls)


def test_cli_database_errors_cannot_leak_code(monkeypatch):
    from scripts.auth import manage_auth
    from server.sli.access import owner_recovery
    monkeypatch.setattr("sys.argv", ["manage_auth.py", "owner-recovery", "--username", "owner"])
    monkeypatch.setattr(manage_auth.sys.stdout, "isatty", lambda: True)

    def failed_issue(_):
        raise RuntimeError("synthetic-private-driver-detail")

    monkeypatch.setattr(owner_recovery, "issue_owner_recovery_code", failed_issue)
    with pytest.raises(SystemExit, match="^owner_recovery_issue_failed$"):
        manage_auth.main()
