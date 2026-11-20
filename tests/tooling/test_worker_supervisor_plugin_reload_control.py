from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "scripts/ops/Restart-SLIWorkerSupervisor.ps1").read_text(encoding="utf-8")


def test_reload_is_exact_task_only_and_plan_first() -> None:
    assert '[ValidateSet("Plan", "RepairLeastPrivilege", "Restart")]' in SOURCE
    assert '"SLI Worker Supervisor"' in SOURCE
    assert "RESTART-SLI-WORKER-SUPERVISOR-FOR-PLUGIN-AUTOSTART" in SOURCE
    assert "Stop-ScheduledTask -TaskName $TaskName" in SOURCE
    assert "Start-ScheduledTask -TaskName $TaskName" in SOURCE
    assert (
        "Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue"
        in SOURCE
    )
    assert "Test-OneSupervisorTree" in SOURCE
    assert '$ExpectedPrincipal = (& whoami).Trim()' in SOURCE
    assert '$CurrentPrincipal = $ExpectedPrincipal' in SOURCE
    assert 'EXAMPLE\\operator' not in SOURCE


def test_reload_reports_unknown_children_and_requires_exact_readback() -> None:
    assert 'worker_children_stopped = $null' in SOURCE
    assert 'worker_children_observation = "not_measured"' in SOURCE
    assert 'worker_children_restart_expectation = "bootstrap_job_kill_on_close"' in SOURCE
    assert 'worker_children_preservation_guaranteed = $false' in SOURCE
    assert 'surveyed_source_contacted = $false' in SOURCE
    assert 'plugin_state_changed = $false' in SOURCE
    assert "exact_supervisor_restart_postcondition_failed" in SOURCE
    assert "after_supervisor_pids" in SOURCE
    assert "REPAIR-SLI-WORKER-SUPERVISOR-LEAST-PRIVILEGE" in SOURCE
    assert "-RunLevel Limited" in SOURCE


def test_reload_accepts_only_the_bootstrap_task_action() -> None:
    assert "Start-SLIWorkerSupervisor.ps1" in SOURCE
    assert "$ExpectedPowerShell" in SOURCE
    assert "$ExpectedBootstrap" in SOURCE


def test_reload_keeps_history_without_becoming_single_use() -> None:
    assert 'ToString("yyyyMMddTHHmmssfffZ")' in SOURCE
    assert "exact_new_reload_evidence_required" not in SOURCE
    assert "exact_new_least_privilege_evidence_required" not in SOURCE


def test_reload_plan_preserves_negative_hresult_task_results() -> None:
    hresult = -2147024891
    assert hresult & 0xFFFFFFFF == 2147942405
    assert "([int64]$info.LastTaskResult -band [int64][uint32]::MaxValue)" in SOURCE
