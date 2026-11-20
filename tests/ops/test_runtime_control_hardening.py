from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace

import pytest


def test_windows_command_matching_normalizes_slashes_and_case(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(
        module,
        "_list_processes",
        lambda: [
            {
                "pid": "4242",
                "parent_pid": "1",
                "cmd": r'C:\Python\python.exe C:\Projects\sli-platform\scripts\run_server.py',
            }
        ],
    )

    matches = module.matching_processes("SCRIPTS/run_server.py")

    assert [item["pid"] for item in matches] == ["4242"]


def test_windows_process_inventory_falls_back_to_cim_when_wmic_fails(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(module.os, "name", "nt")
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        if command[0].lower() == "wmic":
            return SimpleNamespace(returncode=1, stdout="", stderr="process - Alias not found")
        return SimpleNamespace(
            returncode=0,
            stdout='{"ProcessId":9876,"ParentProcessId":1234,"CommandLine":"python scripts\\\\run_server.py"}',
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    rows = module._list_processes()

    assert rows == [
        {
            "pid": "9876",
            "parent_pid": "1234",
            "cmd": r"python scripts\run_server.py",
            "inventory_source": "powershell_cim",
        }
    ]
    assert calls[0][0].lower() == "wmic"
    assert calls[1][0].lower() == "powershell"


def test_restart_requires_runtime_instance_and_build_identity(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    class FakeProcess:
        pid = 2222

        @staticmethod
        def poll():
            return None

    monkeypatch.setattr(module, "stop", lambda pattern, **_kwargs: {"status": "ok", "matched": [], "stopped": [], "remaining": []})
    listener_results = iter([[], [2222]])
    monkeypatch.setattr(module, "_listening_pids", lambda port, deadline=None: next(listener_results))
    monkeypatch.setattr(module, "_list_processes", lambda deadline=None: [{"pid": "2222", "parent_pid": "1", "cmd": "python scripts/run_server.py"}])
    captured: dict[str, str] = {}

    def fake_spawn(command, *, env_overrides=None):
        captured.update(env_overrides or {})
        return FakeProcess(), {"status": "started", "pid": 2222}, 0

    monkeypatch.setattr(module, "_spawn", fake_spawn)

    def fake_health(url, timeout=5, *, insecure=False, deadline=None):
        return {
            "status": "ok",
            "payload": {
                "runtime_identity": {
                    "runtime_instance_id": captured["ADLOG_RUNTIME_INSTANCE_ID"],
                    "build_id": captured["ADLOG_BUILD_ID"],
                    "process_pid": 2222,
                }
            },
        }

    monkeypatch.setattr(module, "_health_probe", fake_health)

    result = module.restart(timeout=1, total_timeout=5)

    assert result["status"] == "ok"
    assert result["identity_verified"] is True
    assert result["process_tree_verified"] is True
    assert result["port_owner_verified"] is True
    assert "payload" not in result["health"]


def _runtime_command(module, port: int) -> str:
    script = module.PROJECT_ROOT / "scripts" / "run_server.py"
    return f'"{module.sys.executable}" "{script}" --host 127.0.0.1 --port {port}'


def test_project_venv_allows_exact_project_relative_runtime_script() -> None:
    from scripts.maintenance import server_control as module

    python = module.PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    command = f'"{python}" scripts\\run_server.py --host 127.0.0.1 --port 18082'

    assert module._command_targets_project_runtime(command, 18082) is True


def test_foreign_python_cannot_authorize_project_relative_runtime_script() -> None:
    from scripts.maintenance import server_control as module

    command = (
        r'"C:\Python\python.exe" scripts\run_server.py '
        r'--host 127.0.0.1 --port 18082'
    )

    assert module._command_targets_project_runtime(command, 18082) is False


def test_stop_targets_only_verified_owner_of_requested_port(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    listener_results = iter([[101], []])
    monkeypatch.setattr(module, "_listening_pids", lambda port, deadline=None: next(listener_results))
    monkeypatch.setattr(
        module,
        "_list_processes",
        lambda deadline=None: [
            {"pid": "101", "parent_pid": "1", "cmd": _runtime_command(module, 8080)},
            {"pid": "202", "parent_pid": "1", "cmd": _runtime_command(module, 18082)},
        ],
    )
    monkeypatch.setattr(
        module,
        "_health_probe",
        lambda *args, **kwargs: {"status": "ok", "payload": {"runtime_identity": {"process_pid": 101}}},
    )
    terminated: list[int] = []
    monkeypatch.setattr(
        module,
        "_terminate_pid_tree",
        lambda pid, deadline=None: terminated.append(pid) or {"pid": pid, "exit_code": 0},
    )

    result = module.stop(target_port=8080, url="https://127.0.0.1:8080/api/health", insecure=True)

    assert result["status"] == "ok"
    assert terminated == [101]
    assert all(item.get("pid") != "202" for item in result["matched"])


def test_stop_fails_closed_when_listener_command_has_wrong_port(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(module, "_listening_pids", lambda port, deadline=None: [101])
    monkeypatch.setattr(
        module,
        "_list_processes",
        lambda deadline=None: [{"pid": "101", "parent_pid": "1", "cmd": _runtime_command(module, 18082)}],
    )
    monkeypatch.setattr(module, "_health_probe", lambda *args, **kwargs: pytest.fail("health must not authorize a wrong command"))
    monkeypatch.setattr(module, "_terminate_pid_tree", lambda *args, **kwargs: pytest.fail("wrong target must not be killed"))

    result = module.stop(target_port=8080, url="https://127.0.0.1:8080/api/health", insecure=True)

    assert result["status"] == "failed"
    assert result["failure_reason"] == "target_listener_command_mismatch"


def test_stop_fails_closed_when_listener_uses_non_project_script(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(module, "_listening_pids", lambda port, deadline=None: [101])
    monkeypatch.setattr(
        module,
        "_list_processes",
        lambda deadline=None: [
            {"pid": "101", "parent_pid": "1", "cmd": r'python C:\other\project\scripts\run_server.py --port 8080'}
        ],
    )
    monkeypatch.setattr(module, "_health_probe", lambda *args, **kwargs: pytest.fail("foreign command must fail first"))
    monkeypatch.setattr(module, "_terminate_pid_tree", lambda *args, **kwargs: pytest.fail("foreign process must not be killed"))

    result = module.stop(target_port=8080, url="https://127.0.0.1:8080/api/health", insecure=True)

    assert result["status"] == "failed"
    assert result["failure_reason"] == "target_listener_command_mismatch"


def test_stop_fails_closed_when_health_pid_differs_from_listener(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(module, "_listening_pids", lambda port, deadline=None: [101])
    monkeypatch.setattr(
        module,
        "_list_processes",
        lambda deadline=None: [{"pid": "101", "parent_pid": "1", "cmd": _runtime_command(module, 8080)}],
    )
    monkeypatch.setattr(
        module,
        "_health_probe",
        lambda *args, **kwargs: {"status": "ok", "payload": {"runtime_identity": {"process_pid": 202}}},
    )
    monkeypatch.setattr(module, "_terminate_pid_tree", lambda *args, **kwargs: pytest.fail("identity mismatch must not be killed"))

    result = module.stop(target_port=8080, url="https://127.0.0.1:8080/api/health", insecure=True)

    assert result["status"] == "failed"
    assert result["failure_reason"] == "target_health_identity_mismatch"


def test_stop_returns_deadline_failure_instead_of_starting_after_inventory_timeout(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    def timed_out(port, deadline=None):
        raise subprocess.TimeoutExpired(["netstat"], timeout=0.1)

    monkeypatch.setattr(module, "_listening_pids", timed_out)

    result = module.stop(target_port=8080, url="https://127.0.0.1:8080/api/health")

    assert result["status"] == "failed"
    assert result["failure_reason"] == "deadline_exceeded"


def test_restart_does_not_spawn_after_target_inventory_timeout(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(
        module,
        "stop",
        lambda *args, **kwargs: {"status": "failed", "remaining": [], "failure_reason": "deadline_exceeded"},
    )
    monkeypatch.setattr(module, "_listening_pids", lambda *args, **kwargs: [])
    monkeypatch.setattr(module, "_spawn", lambda *args, **kwargs: pytest.fail("spawn must not run after failed target verification"))

    result = module.restart(timeout=1, total_timeout=1)

    assert result["status"] == "failed"
    assert result["failure_reason"] == "deadline_exceeded"


def test_inventory_subprocess_receives_remaining_deadline(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(module.os, "name", "nt")
    captured: dict[str, float] = {}

    def fake_run(command, **kwargs):
        captured["timeout"] = kwargs["timeout"]
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    deadline = module.OperationDeadline(0.5)

    assert module._windows_processes_via_cim(deadline) == []
    assert 0 < captured["timeout"] <= 0.5


def test_health_output_is_compact_even_for_large_payload(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    payload = {"status": "ok", "runtime_identity": {"process_pid": 42}, "items": ["x" * 1000] * 50}
    monkeypatch.setattr(
        module,
        "_health_probe",
        lambda *args, **kwargs: {"status": "ok", "code": 200, "summary": {"status": "ok"}, "payload": payload},
    )

    result = module.health()

    assert "payload" not in result
    assert len(json.dumps(result)) < 1000


def test_health_runtime_identity_contains_process_and_release_fields() -> None:
    from server.sli.ops.runtime_identity import get_runtime_identity

    identity = get_runtime_identity()

    assert identity["runtime_instance_id"]
    assert identity["process_pid"] > 0
    assert identity["parent_pid"] >= 0
    assert identity["process_started_at_utc"].endswith("+00:00")
    assert identity["project_version"]
    assert identity["baseline_id"]
    assert identity["build_id"]


def test_windows_process_inventory_falls_back_when_wmic_returns_empty_success(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(module.os, "name", "nt")
    calls = 0

    def fake_run(command, **kwargs):
        nonlocal calls
        calls += 1
        if command[0].lower() == "wmic":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout='[{"ProcessId":10,"ParentProcessId":1,"CommandLine":"python scripts\\\\run_server.py"}]',
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    rows = module._list_processes()

    assert calls == 2
    assert rows[0]["inventory_source"] == "powershell_cim"


def test_windows_runtime_control_replaces_undecodable_native_output(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    monkeypatch.setattr(module.os, "name", "nt")
    decoding_options: list[object] = []
    powershell_calls = 0

    def fake_run(command, **kwargs):
        nonlocal powershell_calls
        decoding_options.append(kwargs.get("errors"))
        executable = str(command[0]).lower()
        if executable == "wmic":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if executable == "powershell":
            powershell_calls += 1
            if powershell_calls == 1:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if executable == "netstat":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="недекодируемый вывод", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module._list_processes() == []
    assert module._listening_pids(8080) == []
    assert module._terminate_pid_tree(101)["exit_code"] == 0
    assert decoding_options
    assert set(decoding_options) == {"replace"}


def test_main_persists_full_result_and_prints_bounded_summary(monkeypatch, tmp_path, capsys) -> None:
    from scripts.maintenance import server_control as module

    result_path = module.PROJECT_ROOT / "artifacts" / "runtime_control" / "test-result.json"
    monkeypatch.setattr(
        module,
        "health",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "payload_for_test": "x" * 50_000,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "server_control.py",
            "--json",
            "--result-file",
            str(result_path.relative_to(module.PROJECT_ROOT)),
            "status",
        ],
    )
    try:
        assert module.main() == 0
        stdout = capsys.readouterr().out
        summary = json.loads(stdout)
        persisted = json.loads(result_path.read_text(encoding="utf-8"))
        assert len(stdout) < 1000
        assert summary["status"] == "ok"
        assert summary["result_file"] == str(result_path)
        assert persisted["payload_for_test"] == "x" * 50_000
    finally:
        result_path.unlink(missing_ok=True)
