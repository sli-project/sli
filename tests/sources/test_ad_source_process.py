"""AD process credential boundary; no source contact in these tests."""
import os
from pathlib import Path
import subprocess
import json

import pytest


def test_eventlog_profile_does_not_change_ldap_process_login(monkeypatch):
    from types import SimpleNamespace
    from server.sli.sources import ad_source_process as source
    from server.sli.sources import ad_source_credentials as credentials
    monkeypatch.setenv("ADLOG_AD_EVENTLOG_CREDENTIAL_PROFILE", "vpn")
    monkeypatch.setattr(source, "resolve_ad_source_endpoint", lambda _: "dc.example.test")
    monkeypatch.setattr(credentials, "load_credentials", lambda profile="ad": SimpleNamespace(
        username=f"{profile}@example.test", password="synthetic-password"))
    def launch(command, *, login, cwd, timeout_seconds):
        assert login[1] == "ad@example.test"
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(source, "_run_netonly", launch)
    assert source.run_ad_source_process(["powershell.exe"], server="DC", cwd=Path.cwd(), timeout_seconds=1).returncode == 0


def test_source_environment_does_not_inherit_host_module_resolution(monkeypatch):
    from server.sli.sources import ad_source_process as source
    monkeypatch.setenv("PSModulePath", "host-powershell7-modules")
    monkeypatch.setenv("ADLOG_PG_DSN", "secret-sentinel")
    environment = source._source_environment()
    assert "PSModulePath" not in environment
    assert "ADLOG_PG_DSN" not in environment


@pytest.mark.skipif(os.environ.get("SLI_TEST_NETONLY_LOCAL") != "1", reason="explicit local Windows smoke")
@pytest.mark.windows_only
def test_native_ps5_module_resolution_survives_incompatible_parent_path(monkeypatch):
    from server.sli.sources import ad_source_process as source
    powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    # An explicit foreign module path excludes PS5 Utility on affected hosts.
    monkeypatch.setenv("PSModulePath", "C:\\sli-synthetic-missing-ps7-modules")
    script = (
        "$ErrorActionPreference='Stop'; $env:ADPS_LoadDefaultDrive='0'; "
        "$names='Get-FileHash','ConvertTo-Json','Get-Date','Import-Module',"
        "'Get-Content','Set-Content','Export-Csv'; "
        "$found=@(Get-Command $names -ErrorAction Stop); "
        "Import-Module ActiveDirectory -ErrorAction Stop; "
        "Import-Module GroupPolicy -ErrorAction Stop; "
        "[pscustomobject]@{commands=$found.Count;ad=[bool](Get-Module ActiveDirectory);"
        "gpo=[bool](Get-Module GroupPolicy);pg=[bool]$env:ADLOG_PG_DSN}|ConvertTo-Json -Compress"
    )
    result = source._run_netonly(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        login=("unused", "sli-synthetic", ".", "synthetic-not-a-real-password", 0),
        cwd=Path.cwd(), timeout_seconds=20,
    )
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    assert json.loads(result.stdout) == {"commands": 7, "ad": True, "gpo": True, "pg": False}


def test_endpoint_refusal_precedes_secret_loading(monkeypatch):
    from server.sli.sources import ad_source_process as source
    monkeypatch.setattr(source, "resolve_ad_source_endpoint", lambda _: (_ for _ in ()).throw(RuntimeError("ad_source_endpoint_invalid")))
    monkeypatch.setattr(source, "load_ad_source_login", lambda *a: pytest.fail("credential read before admission"))
    with pytest.raises(RuntimeError, match="ad_source_endpoint_invalid"):
        source.run_ad_source_process(["powershell.exe"], server="unlisted", cwd=Path.cwd(), timeout_seconds=1)


def test_login_is_not_added_to_command_environment_or_result(monkeypatch):
    from server.sli.sources import ad_source_process as source
    monkeypatch.setenv("ADLOG_PG_DSN", "pg-secret-sentinel")
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", "admin-secret-sentinel")
    monkeypatch.setattr(source, "resolve_ad_source_endpoint", lambda s: "dc.example.test")
    monkeypatch.setattr(source, "load_ad_source_login", lambda target, flags: (target, "synthetic-user", "EXAMPLE", "password-sentinel", flags))
    def launch(command, *, login, cwd, timeout_seconds):
        assert login[3] == "password-sentinel"
        assert command == ["powershell.exe", "-NoProfile"]
        assert not any("secret-sentinel" in v for v in source._source_environment().values())
        raise OSError(5, "password-sentinel synthetic-user")
    monkeypatch.setattr(source, "_run_netonly", launch)
    with pytest.raises(RuntimeError) as caught:
        source.run_ad_source_process(["powershell.exe", "-NoProfile"], server="DC", cwd=Path.cwd(), timeout_seconds=1)
    assert "sentinel" not in str(caught.value)
    assert "synthetic-user" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_coordinator_default_process_does_not_load_credentials(monkeypatch):
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker
    monkeypatch.delenv("ADLOG_AD_SOURCE_CREDENTIAL_MODE", raising=False)
    class Process:
        returncode = 0
        def communicate(self, timeout):
            return "original-output", ""
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **k: Process())
    result = worker._run_collector_process(["original"], timeout_seconds=1)
    assert result.stdout == "original-output"


def test_coordinator_netonly_dispatch_preserves_command(monkeypatch):
    from server.sli.sources import ad_source_process as source
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker
    monkeypatch.setenv("ADLOG_AD_SOURCE_CREDENTIAL_MODE", "dpapi_current_user")
    monkeypatch.setenv("ADLOG_AD_CONTEXT_DIRECTORY_SERVER", "DC")
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **k: pytest.fail("implicit process fallback"))
    def run(command, *, server, cwd, timeout_seconds):
        assert command == ["original"] and server == "DC" and timeout_seconds == 10
        return subprocess.CompletedProcess(command, 0, "netonly-output", "")
    monkeypatch.setattr(source, "run_ad_source_process", run)
    assert worker._run_collector_process(["original"], timeout_seconds=10).stdout == "netonly-output"


def test_invalid_mode_never_falls_back(monkeypatch):
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker
    monkeypatch.setenv("ADLOG_AD_SOURCE_CREDENTIAL_MODE", "typo")
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **k: pytest.fail("process fallback"))
    with pytest.raises(RuntimeError, match="ad_source_credential_mode_invalid"):
        worker._run_collector_process(["original"], timeout_seconds=1)


@pytest.mark.windows_only
def test_command_limits_fail_before_native_launch():
    from server.sli.sources import ad_source_process as source
    powershell = str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    with pytest.raises(RuntimeError, match="ad_source_process_command_too_long"):
        source._run_netonly([powershell, "x" * 1024], login=("unused", "user", ".", "sentinel", 0), cwd=Path.cwd(), timeout_seconds=1)
    with pytest.raises(RuntimeError, match="ad_source_process_command_invalid"):
        source._run_netonly(["powershell.exe"], login=(), cwd=Path.cwd(), timeout_seconds=1)


@pytest.mark.windows_only
def test_existing_v6_hour_budget_is_admitted_but_not_exceeded(monkeypatch):
    from server.sli.sources import ad_source_process as source
    powershell = str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    def no_native_call(*args, **kwargs):
        raise RuntimeError("native_boundary_reached")
    monkeypatch.setattr(source.ctypes, "WinDLL", no_native_call)
    with pytest.raises(RuntimeError, match="native_boundary_reached"):
        source._run_netonly([powershell], login=(), cwd=Path.cwd(), timeout_seconds=3600)
    with pytest.raises(RuntimeError, match="ad_source_process_command_invalid"):
        source._run_netonly([powershell], login=(), cwd=Path.cwd(), timeout_seconds=3601)


@pytest.mark.skipif(os.environ.get("SLI_TEST_NETONLY_LOCAL") != "1", reason="explicit local Windows smoke")
@pytest.mark.windows_only
def test_native_netonly_child_capture_and_local_identity(tmp_path):
    from server.sli.sources import ad_source_process as source
    import win32api
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        expected_sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        expected_session = win32security.GetTokenInformation(token, win32security.TokenSessionId)
    finally:
        token.Close()
    powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    script = "$child=[string](& $PSHOME/powershell.exe -NoProfile -NonInteractive -Command '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'); [pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;child=$child;code=$LASTEXITCODE}|ConvertTo-Json -Compress"
    script_path = tmp_path / "identity.ps1"
    script_path.write_text("$ErrorActionPreference='Stop'; " + script, encoding="utf-8")
    baseline = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-File", str(script_path)], capture_output=True, text=True, timeout=60)
    assert json.loads(baseline.stdout)["child"] == expected_sid, (baseline.stdout, baseline.stderr)
    result = source._run_netonly([powershell, "-NoProfile", "-NonInteractive", "-File", str(script_path)], login=("unused", "sli-synthetic", ".", "synthetic-not-a-real-password", 0), cwd=Path.cwd(), timeout_seconds=15)
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    assert json.loads(result.stdout) == {"sid": expected_sid, "session": expected_session, "child": expected_sid, "code": 0}


@pytest.mark.skipif(os.environ.get("SLI_TEST_NETONLY_LOCAL") != "1", reason="explicit local Windows smoke")
@pytest.mark.windows_only
def test_native_timeout_kills_descendants_and_closes_handles(tmp_path):
    from server.sli.sources import ad_source_process as source
    import win32api
    import win32event, win32job, win32pipe, win32process  # Load native DLLs before handle baseline.
    import ctypes
    count = ctypes.c_ulong()
    ctypes.windll.kernel32.GetProcessHandleCount(ctypes.c_void_p(int(win32api.GetCurrentProcess())), ctypes.byref(count))
    before = count.value
    powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    marker = tmp_path / "child-must-not-survive.txt"
    started_marker = tmp_path / "child-started.txt"
    child_script = "Set-Content -LiteralPath '" + str(started_marker) + "' -Value $PID; Start-Sleep -Seconds 20; Set-Content -LiteralPath '" + str(marker) + "' -Value survived"
    import base64
    encoded = base64.b64encode(child_script.encode("utf-16le")).decode()
    parent_script = tmp_path / "timeout-parent.ps1"
    parent_script.write_text("Start-Process -WindowStyle Hidden -FilePath $PSHOME/powershell.exe -ArgumentList '-NoProfile -EncodedCommand " + encoded + "'; Start-Sleep -Seconds 20", encoding="utf-8")
    command = [powershell, "-NoProfile", "-NonInteractive", "-File", str(parent_script)]
    with pytest.raises(RuntimeError, match="ad_source_process_timeout"):
        source._run_netonly(command, login=("unused", "sli-synthetic", ".", "synthetic-not-a-real-password", 0), cwd=Path.cwd(), timeout_seconds=5)
    assert started_marker.exists()
    child_pid = int(started_marker.read_text(encoding="utf-8-sig").strip())
    try:
        child_handle = win32api.OpenProcess(0x100000 | 0x1000, False, child_pid)
    except Exception as exc:
        assert exc.args[0] == 87  # PID no longer exists.
    else:
        try:
            assert win32event.WaitForSingleObject(child_handle, 1000) == win32event.WAIT_OBJECT_0
        finally:
            child_handle.Close()
    assert not marker.exists()
    ctypes.windll.kernel32.GetProcessHandleCount(ctypes.c_void_p(int(win32api.GetCurrentProcess())), ctypes.byref(count))
    assert count.value <= before + 2


@pytest.mark.skipif(os.environ.get("SLI_TEST_NETONLY_LOCAL") != "1", reason="explicit local Windows smoke")
@pytest.mark.windows_only
def test_native_output_limit_and_pre_resume_job_failure(monkeypatch, tmp_path):
    from server.sli.sources import ad_source_process as source
    import win32job
    powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    login = ("unused", "sli-synthetic", ".", "synthetic-not-a-real-password", 0)
    with pytest.raises(RuntimeError, match="ad_source_process_output_limit"):
        source._run_netonly([powershell, "-NoProfile", "-Command", "[Console]::Out.Write(('x'*1100000))"], login=login, cwd=Path.cwd(), timeout_seconds=15)
    marker = tmp_path / "must-not-run.txt"
    script = tmp_path / "must-not-run.ps1"
    script.write_text("Set-Content -LiteralPath '" + str(marker) + "' -Value bad", encoding="utf-8")
    monkeypatch.setattr(win32job, "AssignProcessToJobObject", lambda *a: (_ for _ in ()).throw(RuntimeError("synthetic-job-refusal")))
    with pytest.raises(RuntimeError, match="synthetic-job-refusal"):
        source._run_netonly([powershell, "-NoProfile", "-File", str(script)], login=login, cwd=Path.cwd(), timeout_seconds=15)
    assert not marker.exists()
