"""Restored credentials and a fresh HTTP session; fake DB/HTTP only."""

from contextlib import nullcontext
from email.message import Message
import io
import json
from pathlib import Path
from urllib.response import addinfourl

import pytest

from server.sli.access.auth import PASSWORD_HASHER, SESSION_COOKIE


@pytest.fixture
def restored(tmp_path, monkeypatch):
    from deploy.linux import restore_login_check as check

    password = "synthetic-restored-owner-password"
    password_file = tmp_path / "restored-owner"
    password_file.write_text(password + "\n")
    row = [7, PASSWORD_HASHER.hash(password), True]
    calls = []

    class Connection:
        def execute(self, statement, parameters=None):
            assert statement.lstrip().startswith("SELECT")
            assert parameters == ("platform-owner",)
            calls.append("database_read")
            return self

        def fetchone(self):
            return tuple(row) if row else None

    monkeypatch.setattr(check.backup, "pg_passfile", lambda: nullcontext(Path("passfile")))
    monkeypatch.setattr(check.backup, "pg_connect", lambda *a: nullcontext(Connection()))
    # A stale bootstrap secret must never override the restored secret.
    monkeypatch.setenv("SLI_PLATFORM_OWNER_PASSWORD", "synthetic-stale-bootstrap-password")
    return check, password_file, row, calls


@pytest.mark.parametrize("problem", ["mismatch", "missing", "inactive", "invalid_hash"])
def test_restored_secret_must_match_active_restored_owner_before_http(restored, monkeypatch, problem):
    check, password_file, row, calls = restored
    if problem == "mismatch":
        password_file.write_text("synthetic-different-password")
    elif problem == "missing":
        row.clear()
    elif problem == "inactive":
        row[2] = False
    else:
        row[1] = "invalid-argon2-hash"
    monkeypatch.setattr(check, "build_opener", lambda *a: pytest.fail("no HTTP with mismatched credentials"))
    with pytest.raises(RuntimeError, match="linux_restore_owner_credentials_mismatch"):
        check.check_login(password_file, "https://restore.invalid:8443", None)
    assert calls == ["database_read"]


@pytest.mark.parametrize("problem", [None, "login_401", "no_cookie", "me_401", "wrong_user", "unauthenticated", "redirect"])
def test_login_requires_new_session_cookie_and_same_restored_principal(restored, monkeypatch, problem):
    check, password_file, row, calls = restored

    def https_open(self, request):
        calls.append(request)
        headers = Message()
        status = 200
        payload = {"authenticated": True, "principal": {"type": "session", "id": 7}}
        if request.full_url.endswith("/api/auth/login"):
            assert request.get_header("Cookie") is None
            assert request.get_header("Authorization") is None
            assert request.get_header("Origin") == "https://restore.invalid:8443"
            assert json.loads(request.data) == {
                "username": "platform-owner", "password": "synthetic-restored-owner-password",
            }
            if problem == "login_401":
                status = 401
            elif problem == "redirect":
                status = 302
                headers["Location"] = "https://other.invalid/"
            elif problem != "no_cookie":
                headers["Set-Cookie"] = f"{SESSION_COOKIE}=synthetic-session; Path=/; Secure; HttpOnly"
        else:
            assert request.full_url.endswith("/api/auth/me")
            assert request.get_header("Cookie") == f"{SESSION_COOKIE}=synthetic-session"
            assert request.get_header("Authorization") is None
            if problem == "me_401":
                status = 401
            elif problem == "wrong_user":
                payload["principal"]["id"] = 8
            elif problem == "unauthenticated":
                payload["authenticated"] = False
        response = addinfourl(io.BytesIO(json.dumps(payload).encode()), headers, request.full_url, status)
        response.msg = "synthetic"
        return response

    monkeypatch.setattr(check.HTTPSHandler, "https_open", https_open)
    if problem:
        with pytest.raises(RuntimeError, match="linux_restore_fresh_login_failed"):
            check.check_login(password_file, "https://restore.invalid:8443", None)
    else:
        assert check.check_login(password_file, "https://restore.invalid:8443", None) is None
        assert len(calls) == 3


def test_cli_rejects_production_before_reading_any_secret(monkeypatch, capsys):
    from deploy.linux import restore_login_check as check

    monkeypatch.setattr(check, "check_login", lambda *a: pytest.fail("production probe forbidden"))
    assert check.main(["--project", "sli", "--password-file", "missing",
                       "--base-url", "https://restore.invalid"]) == 1
    assert capsys.readouterr().err == "linux_restore_login_check_failed\n"


def test_cli_failure_does_not_disclose_secret_or_exception(monkeypatch, capsys):
    from deploy.linux import restore_login_check as check

    def fail(*a):
        raise RuntimeError("synthetic-sensitive-exception")

    monkeypatch.setattr(check, "check_login", fail)
    assert check.main(["--project", "sli-c01-restore", "--password-file", "missing",
                       "--base-url", "https://restore.invalid"]) == 1
    assert capsys.readouterr().err == "linux_restore_login_check_failed\n"
