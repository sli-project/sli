from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "scripts/ops/Start-SLIWorkerSupervisor.ps1"
INSTALLER = ROOT / "scripts/ops/Install-SLIWorkerSupervisor.ps1"
SUPERVISOR = ROOT / "scripts/maintenance/worker_supervisor.py"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_bootstrap_job_adapter_is_kill_on_close_non_inheritable_and_verified() -> None:
    source = _source(BOOTSTRAP)

    assert "CreateJobObjectW" in source
    assert "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in source
    assert "SetInformationJobObject" in source
    assert "SetHandleInformation" in source
    assert "HANDLE_FLAG_INHERIT" in source
    assert "AssignProcessToJobObject" in source
    assert "IsProcessInJob" in source
    assert "bootstrap_job_binding_not_verified" in source


def test_bootstrap_binds_job_before_any_child_launcher_and_retains_handle() -> None:
    source = _source(BOOTSTRAP)
    bind = source.index("[BootstrapJob]::CreateAndBindCurrentProcess()")

    assert bind < source.index("& $Uv venv")
    assert bind < source.index('& $Python -c "import psycopg, win32api"')
    assert bind < source.index("& $Python $Supervisor")
    assert "[GC]::KeepAlive($LifecycleJob)" in source
    assert source.index("[GC]::KeepAlive($LifecycleJob)") > source.index("& $Python $Supervisor")
    # Closing a kill-on-close job after assigning this bootstrap would kill
    # the bootstrap itself; the OS closes the retained handle at process exit.
    assert "$LifecycleJob.Dispose()" not in source


@pytest.mark.windows_only
def test_bootstrap_job_adapter_binds_current_process_without_stopping_it() -> None:
    if os.name != "nt":
        pytest.skip("Windows Job Object adapter requires Windows")
    powershell = shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("Windows PowerShell is required")

    source = _source(BOOTSTRAP)
    match = re.search(r"\$BootstrapJobSource = @'\n(.*?)\n'@", source, re.DOTALL)
    assert match is not None
    adapter = match.group(1)
    command = f"""
$source = @'
{adapter}
'@
Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
$job = [BootstrapJob]::CreateAndBindCurrentProcess()
[ordered]@{{
  binding_verified = [bool]$job.BindingVerified
  kill_on_close = [bool]$job.KillOnClose
  handle_inheritable = [bool]$job.HandleInheritable
}} | ConvertTo-Json -Compress
[GC]::KeepAlive($job)
"""
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip())
    assert payload == {
        "binding_verified": True,
        "kill_on_close": True,
        "handle_inheritable": False,
    }


def test_task_registration_contract_remains_exact_and_limited() -> None:
    source = _source(INSTALLER)

    assert '$TaskName = "SLI Worker Supervisor"' in source
    assert '$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\.."))' in source
    assert 'Start-SLIWorkerSupervisor.ps1' in source
    assert "-MultipleInstances IgnoreNew" in source
    assert "-RunLevel Limited" in source
    assert "-LogonType Interactive" in source
    assert "Stop-Process" not in _source(BOOTSTRAP)
    assert "CREATE_BREAKAWAY_FROM_JOB" not in _source(SUPERVISOR)
