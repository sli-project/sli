"""Background probes must not create an interactive console on Windows."""
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("probe", ["identity", "directory", "nltest", "coordinator", "guard", "single_guard"])
def test_background_probe_requests_no_console(monkeypatch, probe):
    from server.sli.sources import dc_discovery
    from server.sli.sources import windows_runtime_identity
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
    from scripts.maintenance import worker_guard

    calls = []
    flag = 0x08000000
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", flag, raising=False)
    def run(*args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(returncode=1, stdout="", stderr="")
    monkeypatch.setattr(subprocess, "run", run)
    class Process:
        returncode = 0
        def communicate(self, timeout):
            return "", ""
    def popen(*args, **kwargs):
        calls.append(kwargs)
        return Process()
    monkeypatch.setattr(subprocess, "Popen", popen)
    if probe == "identity":
        if windows_runtime_identity.os.name != "nt":
            pytest.skip("Windows identity path")
        windows_runtime_identity.current_windows_identity()
    elif probe == "directory":
        dc_discovery._discover_with_directory_services()
    elif probe == "nltest":
        dc_discovery._discover_with_nltest("synthetic.invalid")
    elif probe in {"guard", "single_guard"}:
        if worker_guard.os.name != "nt":
            pytest.skip("Windows process inventory path")
        if probe == "guard":
            worker_guard._process_inventory()
        else:
            worker_guard._running_pids_for("synthetic.py")
    else:
        monkeypatch.setenv("ADLOG_AD_SOURCE_CREDENTIAL_MODE", "process")
        coordinator._run_collector_process(["synthetic"], timeout_seconds=1)
    assert calls and calls[0].get("creationflags", 0) & flag


@pytest.mark.parametrize("name", ["Install-SLIWorkerSupervisor.ps1", "Install-SLIWebServer-v1.ps1"])
def test_background_task_installs_hidden_powershell(name):
    script = Path("scripts/ops", name).read_text(encoding="utf-8-sig")
    assert "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File" in script


def test_event_job_keeps_process_group_without_console(monkeypatch):
    from server.jobs import collector
    if collector.os.name != "nt":
        pytest.skip("Windows job launch")
    calls = []
    def launch(*args, **kwargs):
        calls.append(kwargs)
        raise OSError("synthetic spawn failure")
    monkeypatch.setattr(collector.subprocess, "Popen", launch)
    monkeypatch.setattr(collector, "log_event", lambda *a, **kw: None)
    monkeypatch.setattr(collector, "log_internal_error", lambda *a, **kw: "synthetic")
    result = collector._run_subprocess_live(["synthetic"], 1, server="synthetic", job_id=None)
    assert result.returncode == 127
    assert calls[0]["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP
    assert calls[0]["creationflags"] & subprocess.CREATE_NO_WINDOW


def test_pilot_nested_commands_keep_process_group_without_console(monkeypatch):
    from scripts import run_dc_log_pilot as pilot
    if pilot.os.name != "nt":
        pytest.skip("Windows nested pilot launch")
    calls = []
    def launch(*args, **kwargs):
        calls.append(kwargs)
        raise OSError("synthetic spawn failure")
    monkeypatch.setattr(pilot.subprocess, "Popen", launch)
    monkeypatch.setattr(pilot, "log_event", lambda *a, **kw: None)
    assert pilot.run_command(["synthetic"], timeout_seconds=1).returncode == 127
    assert calls[0]["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP
    assert calls[0]["creationflags"] & subprocess.CREATE_NO_WINDOW


@pytest.mark.parametrize("boundary", ["collector", "pilot", "lifecycle"])
def test_windows_taskkill_hides_its_console_at_recurring_process_boundaries(
    monkeypatch, boundary,
):
    """A timeout cleanup must not open a console after a hidden child launch."""
    from server.jobs import collector
    from scripts import run_dc_log_pilot as pilot
    from scripts.runtime import storage_lifecycle_worker as lifecycle

    modules = {
        "collector": collector,
        "pilot": pilot,
        "lifecycle": lifecycle,
    }
    module = modules[boundary]
    no_window = 0x08000000
    taskkill_calls: list[tuple[list[str], dict[str, object]]] = []

    class Process:
        pid = 42
        returncode = None
        communicate_calls = 0

        def poll(self):
            return None

        def wait(self, *, timeout):
            return 0

        def kill(self):
            pass

        def communicate(self, *, timeout):
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                raise module.subprocess.TimeoutExpired(["child"], 1)
            return "", ""

    process = Process()

    def taskkill(command, **kwargs):
        taskkill_calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module.subprocess, "CREATE_NO_WINDOW", no_window, raising=False)
    monkeypatch.setattr(module.subprocess, "run", taskkill)

    if boundary in {"collector", "pilot"}:
        module._terminate_process_tree(process)
    else:
        monkeypatch.setattr(module.subprocess, "Popen", lambda *_args, **_kwargs: process)
        monkeypatch.setattr(module, "_start_job_protected", lambda _pid: None)
        monotonic = iter((0.0, 2.0, 2.0))
        monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic))
        with pytest.raises(module.subprocess.TimeoutExpired):
            module._run_command(["child"], timeout_seconds=1)

    assert taskkill_calls[0][0][0] == "taskkill"
    assert taskkill_calls[0][1]["creationflags"] & no_window


def test_shared_maintenance_command_hides_windows_child_console(monkeypatch, tmp_path):
    """A generic maintenance command must not flash a console when launched hidden."""
    from scripts.maintenance import bundle_common

    calls = []
    no_window = 0x08000000

    class Process:
        def poll(self):
            return 0

    def launch(*_args, **kwargs):
        calls.append(kwargs)
        return Process()

    monkeypatch.setattr(bundle_common, "os", SimpleNamespace(**{**vars(bundle_common.os), "name": "nt"}))
    monkeypatch.setattr(bundle_common.subprocess, "CREATE_NO_WINDOW", no_window, raising=False)
    monkeypatch.setattr(bundle_common.subprocess, "Popen", launch)
    monkeypatch.setattr(bundle_common, "TMP_DIR", tmp_path)

    result = bundle_common.run_command(["synthetic"], cwd=tmp_path)

    assert result["exit_code"] == 0
    assert calls[0]["creationflags"] & no_window


def test_supervisor_hides_long_lived_worker_console(monkeypatch, tmp_path):
    """All managed worker entrypoints share the supervisor's hidden launch boundary."""
    from scripts.maintenance import worker_supervisor

    calls = []
    no_window = 0x08000000
    process_group = 0x00000200

    class Process:
        pid = 42

    def launch(*_args, **kwargs):
        calls.append(kwargs)
        return Process()

    monkeypatch.setattr(worker_supervisor.os, "name", "nt")
    monkeypatch.setattr(
        worker_supervisor.subprocess, "CREATE_NO_WINDOW", no_window, raising=False
    )
    monkeypatch.setattr(
        worker_supervisor.subprocess,
        "CREATE_NEW_PROCESS_GROUP",
        process_group,
        raising=False,
    )
    monkeypatch.setattr(worker_supervisor.subprocess, "Popen", launch)
    monkeypatch.setattr(worker_supervisor, "ROOT", tmp_path)
    monkeypatch.setattr(worker_supervisor, "PY", tmp_path / "python.exe")
    monkeypatch.setattr(worker_supervisor, "RUNTIME", tmp_path / "runtime")
    monkeypatch.setattr(worker_supervisor, "MANAGED", {"synthetic": ("worker.py", [])})
    monkeypatch.setattr(worker_supervisor, "OWNED_CHILDREN", {})

    result = worker_supervisor._start("synthetic")

    assert result["started"] is True
    assert calls[0]["creationflags"] & process_group
    assert calls[0]["creationflags"] & no_window
