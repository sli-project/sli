from datetime import datetime, timezone
import json
from pathlib import Path

from scripts.maintenance import worker_guard, worker_supervisor
from server.sli.sources import plugin_runtime_heartbeat


def test_supervisor_registers_two_separate_plugin_hosts() -> None:
    assert worker_supervisor.MANAGED["plugin_radius_acquisition"] == (
        "remote_access_plugin_host.py",
        ["--component", "radius-acquisition"],
    )
    assert worker_supervisor.MANAGED[
        "plugin_radius_session_observation"
    ] == (
        "remote_access_plugin_host.py",
        ["--component", "radius-session-observation"],
    )
    assert worker_supervisor.START_ORDER[-2:] == (
        "plugin_radius_session_observation",
        "plugin_radius_acquisition",
    )


def test_installer_derives_task_and_runtime_identity_from_current_session() -> None:
    source = (Path(__file__).resolve().parents[2] / "scripts/ops/Install-SLIWorkerSupervisor.ps1").read_text(encoding="utf-8")

    assert "ADLOG_COLLECTION_PRINCIPAL" in source
    assert "ADLOG_COLLECTION_PRINCIPAL_SID" in source
    assert '$ExpectedPrincipal = "EXAMPLE\\operator"' not in source


def test_installer_uses_self_healing_periodic_bootstrap() -> None:
    root = Path(__file__).resolve().parents[2]
    installer = (root / "scripts/ops/Install-SLIWorkerSupervisor.ps1").read_text(encoding="utf-8")
    bootstrap_path = root / "scripts/ops/Start-SLIWorkerSupervisor.ps1"

    assert bootstrap_path.is_file()
    bootstrap = bootstrap_path.read_text(encoding="utf-8")
    assert "uv venv" in bootstrap
    assert "uv pip install" in bootstrap
    assert "requirements.txt" in bootstrap
    assert "worker_supervisor.py" in bootstrap
    assert "worker-supervisor-bootstrap.json" in bootstrap
    assert "Start-SLIWorkerSupervisor.ps1" in installer
    assert "RepetitionInterval" in installer
    assert "Minutes 5" in installer


def test_installer_can_repair_the_task_without_reprovisioning_secrets() -> None:
    source = (Path(__file__).resolve().parents[2] / "scripts/ops/Install-SLIWorkerSupervisor.ps1").read_text(encoding="utf-8")

    assert "[switch]$RepairTaskOnly" in source
    assert "if (-not $RepairTaskOnly)" in source
    assert "environment_provisioned" in source


def test_installer_accepts_task_scheduler_short_principal_readback() -> None:
    source = (Path(__file__).resolve().parents[2] / "scripts/ops/Install-SLIWorkerSupervisor.ps1").read_text(encoding="utf-8")

    assert "$ConfiguredShortPrincipal" in source
    assert "principal_matches = (" in source


def test_guard_maps_each_host_to_exact_component() -> None:
    assert worker_guard.PLUGIN_WORKERS == {
        "plugin_radius_acquisition": "radius-acquisition",
        "plugin_radius_session_observation": "radius-session-observation",
    }
    source = Path(worker_guard.__file__).read_text(encoding="utf-8")
    assert 'component_id == "radius-session-observation"' in source
    assert '"disabled", "draining", "drain_only"' in source
    assert "read_plugin_component_runtime_guard_v1" in source
    assert "from plugin_installations_v1" not in source


def test_process_inventory_can_add_component_marker(monkeypatch) -> None:
    captured = {}

    class Result:
        returncode = 0
        stdout = "123\n"
        stderr = ""

    def fake_run(argv, **_kwargs):
        captured["command"] = argv[-1]
        return Result()

    monkeypatch.setattr(worker_guard.os, "name", "nt")
    monkeypatch.setattr(worker_guard.os, "getpid", lambda: 999)
    monkeypatch.setattr(worker_guard.subprocess, "run", fake_run)
    assert worker_guard._running_pids_for(
        "remote_access_plugin_host.py",
        command_marker="--component radius-acquisition",
    ) == ([123], None)
    assert "--component radius-acquisition" in captured["command"]


def test_recent_blocked_plugin_heartbeat_enforces_backoff(monkeypatch, tmp_path) -> None:
    heartbeat_dir = tmp_path / "data" / "runtime"
    monkeypatch.setattr(plugin_runtime_heartbeat, "HEARTBEAT_DIR", heartbeat_dir)
    path = heartbeat_dir / "plugin-radius-acquisition.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "plugin_id": "sli.remote-access",
                "component_id": "radius-acquisition",
                "status": "blocked",
                "phase": "cycle_failed",
                "heartbeat_at_utc": datetime.now(timezone.utc).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    value = worker_guard._recent_plugin_block("radius-acquisition")
    assert value is not None
    assert value["retry_after_seconds"] > 0
