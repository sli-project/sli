from pathlib import Path
from types import SimpleNamespace

import pytest


def test_source_mismatch_precedes_secret(monkeypatch):
    from server.sli.sources import vpn_source_auth as auth
    monkeypatch.setattr(auth, "require_accounting_source", lambda: (Path(r"\\approved\accounting"), "tz", 420))
    monkeypatch.setattr(auth, "load_credentials", lambda **kw: pytest.fail("secret read"))
    with pytest.raises(auth.VpnSourceAuthError, match="vpn_source_endpoint_invalid"):
        with auth.accounting_source_identity(Path(r"\\other\accounting"), mode="dpapi_current_user"):
            pytest.fail("source contacted")


@pytest.mark.parametrize("failure", [None, "read", "existing", "login", "impersonate", "revert", "token_check", "load", "upn"])
def test_identity_scope_and_sanitized_failure(monkeypatch, failure):
    from server.sli.sources import vpn_source_auth as auth
    directory = Path(r"\\approved\accounting")
    events = []
    monkeypatch.setattr(auth, "require_accounting_source", lambda: (directory, "tz", 420))
    class NoToken(Exception):
        winerror = 1008
    class Token:
        def Close(self): events.append("close")
    def thread_token(*args):
        events.append("check")
        if failure == "existing": return Token()
        if failure == "token_check": raise OSError("private error")
        raise NoToken()
    def login(*args):
        events.append(("login", args))
        if failure == "login": raise OSError("private password")
        return Token()
    def impersonate(token):
        events.append("impersonate")
        if failure == "impersonate": raise OSError("private error")
    def revert():
        events.append("revert")
        if failure == "revert": raise OSError("private error")
    def stop(code):
        assert code == 74
        raise SystemExit(code)
    monkeypatch.setattr(auth.os, "_exit", stop)
    security = SimpleNamespace(OpenThreadToken=thread_token, LogonUser=login,
        ImpersonateLoggedOnUser=impersonate, RevertToSelf=revert)
    monkeypatch.setattr(auth, "_windows", lambda: (security, SimpleNamespace(GetCurrentThread=lambda: 1)))
    def load(**kwargs):
        assert kwargs == {"profile": "vpn"}
        events.append("load")
        if failure == "load": raise OSError("private error")
        return SimpleNamespace(username="vpn@example.invalid" if failure == "upn" else r"EXAMPLE\vpn", password="fixture")
    monkeypatch.setattr(auth, "load_credentials", load)
    def run():
        with auth.accounting_source_identity(directory, mode="dpapi_current_user"):
            events.append("read")
            if failure == "read": raise OSError("private password")
        events.append("local")
    if failure == "revert":
        with pytest.raises(SystemExit): run()
        assert "local" not in events
    elif failure and failure != "upn":
        with pytest.raises(auth.VpnSourceAuthError) as caught: run()
        assert "private" not in str(caught.value)
    else:
        run()
        assert events[-4:] == ["read", "revert", "close", "local"]
    if failure in ("existing", "token_check"): assert "load" not in events
    if failure in ("read", "impersonate"): assert events[-2:] == ["revert", "close"]
    if failure == "upn":
        assert ("login", ("vpn@example.invalid", None, "fixture", 9, 3)) in events
    elif failure not in ("existing", "token_check", "load"):
        assert ("login", ("vpn", "EXAMPLE", "fixture", 9, 3)) in events


def test_process_mode_does_not_load_secret(monkeypatch):
    from server.sli.sources import vpn_source_auth as auth
    monkeypatch.setattr(auth, "load_credentials", lambda **kw: pytest.fail("secret read"))
    with auth.accounting_source_identity(Path("fixture"), mode="process"):
        pass
    with pytest.raises(auth.VpnSourceAuthError, match="credential_mode_invalid"):
        with auth.accounting_source_identity(Path("fixture"), mode="unknown"):
            pytest.fail("accepted")


@pytest.mark.parametrize("component", ["radius-acquisition", "radius-session-observation"])
def test_mode_reaches_acquisition_child_only(monkeypatch, tmp_path, component):
    from scripts.runtime import remote_access_plugin_host as host
    powershell_dir = tmp_path / "System32" / "WindowsPowerShell" / "v1.0"
    powershell_dir.mkdir(parents=True)
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setenv("WINDIR", str(tmp_path))
    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL", r"EXAMPLE\owner")
    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL_SID", "S-1-5-21-1")
    monkeypatch.setenv("ADLOG_VPN_SOURCE_CREDENTIAL_MODE", "dpapi_current_user")
    monkeypatch.setattr(host, "_child_python_path", lambda: "fixture")
    environment = host._child_environment("fixture-dsn", component_id=component)
    assert environment["PATH"] == str(powershell_dir.resolve(strict=True))
    assert environment.get("ADLOG_VPN_SOURCE_CREDENTIAL_MODE") == (
        "dpapi_current_user" if component == "radius-acquisition" else None)


def test_acquisition_reverts_before_local_connection_cleanup(monkeypatch):
    from contextlib import contextmanager, nullcontext
    from server.sli.sources import radius_plugin_runtime as runtime
    from server.sli.sources import vpn_source_auth as auth
    events = []
    @contextmanager
    def identity(directory, *, mode):
        assert mode == "dpapi_current_user"
        events.append("enter")
        try: yield
        finally: events.append("revert")
    @contextmanager
    def connection():
        try: yield object()
        finally: events.append("local_cleanup")
    monkeypatch.setenv("ADLOG_VPN_SOURCE_CREDENTIAL_MODE", "dpapi_current_user")
    monkeypatch.setattr(auth, "accounting_source_identity", identity)
    monkeypatch.setattr(runtime, "verify_collection_identity", lambda: {"status": "ok"})
    monkeypatch.setattr(runtime, "connect_acquisition_worker", connection)
    monkeypatch.setattr(runtime, "component_lease_scope", lambda *a, **kw: nullcontext())
    monkeypatch.setattr(runtime, "require_accounting_source", lambda: (Path("fixture"), "tz", 420))
    monkeypatch.setattr(runtime, "acquisition_subscription_id", lambda: "fixture")
    monkeypatch.setattr(runtime, "load_runtime_state", lambda *a, **kw: SimpleNamespace(cursor=None, exact_boundary_recovery=True))
    def read(*a, **kw):
        assert events == ["enter"]
        events.append("read")
        raise OSError("fixture source failure")
    monkeypatch.setattr(runtime, "read_bounded_tail", read)
    with pytest.raises(OSError): runtime.run_acquisition_cycle()
    assert events == ["enter", "read", "revert", "local_cleanup"]


def test_mode_is_persistable():
    from server.sli.ops.worker_supervisor_secrets import WORKER_ENV_ALLOWLIST
    assert "ADLOG_VPN_SOURCE_CREDENTIAL_MODE" in WORKER_ENV_ALLOWLIST
