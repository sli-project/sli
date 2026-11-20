from __future__ import annotations

import importlib
import json
import os
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "scripts" / "ops" / "Start-SLIWebServer-v1.ps1"
INSTALLER = ROOT / "scripts" / "ops" / "Install-SLIWebServer-v1.ps1"
WEB_CONTROL = ROOT / "scripts" / "maintenance" / "web_server_control.py"
HEALTH_URL = "https://127.0.0.1:8080/api/health"


def _runtime_command(module, port: int = 8080) -> str:
    python = module.PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    script = module.PROJECT_ROOT / "scripts" / "run_server.py"
    return f'"{python}" "{script}" --host 127.0.0.1 --port {port}'


def test_server_control_default_start_command_is_canonical_project_venv_argv(monkeypatch) -> None:
    from scripts.maintenance import server_control

    monkeypatch.delenv("ADLOG_SERVER_START_COMMAND", raising=False)
    module = importlib.reload(server_control)

    assert module._command_argv(module.DEFAULT_START_COMMAND) == [
        str(module.PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"),
        str(module.PROJECT_ROOT / "scripts" / "run_server.py"),
        "--host",
        "127.0.0.1",
        "--port",
        "8080",
    ]


def test_ensure_running_reuses_one_verified_runtime_without_spawn(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    target = {
        "status": "verified",
        "target_port": 8080,
        "listening_pids": [4242],
        "target_pid": 4242,
        "target_process": {"pid": "4242", "cmd": _runtime_command(module)},
        "runtime_identity": {"process_pid": 4242, "runtime_instance_id": "live"},
        "health": {"status": "ok"},
    }
    monkeypatch.setattr(module, "_verified_destructive_target", lambda **_kwargs: target)
    monkeypatch.setattr(module, "_spawn", lambda *_args, **_kwargs: pytest.fail("verified runtime must not be spawned again"))
    monkeypatch.setattr(module, "stop", lambda *_args, **_kwargs: pytest.fail("ensure must not stop a verified runtime"))
    monkeypatch.setattr(module, "audit_action", lambda *_args, **_kwargs: None)

    result = module.ensure_running(
        command=_runtime_command(module),
        url=HEALTH_URL,
        target_port=8080,
        timeout=1,
        total_timeout=5,
        insecure=True,
    )

    assert result["status"] == "ok"
    assert result["already_running"] is True
    assert result["started"] is False
    assert result["listening_pids"] == [4242]
    assert result["runtime_identity"]["process_pid"] == 4242


def test_ensure_running_fails_closed_for_an_unverified_listener(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    target = {
        "status": "failed",
        "target_port": 8080,
        "listening_pids": [4242],
        "failure_reason": "target_listener_command_mismatch",
    }
    monkeypatch.setattr(module, "_verified_destructive_target", lambda **_kwargs: target)
    monkeypatch.setattr(module, "_spawn", lambda *_args, **_kwargs: pytest.fail("unverified listener must block spawn"))
    monkeypatch.setattr(module, "stop", lambda *_args, **_kwargs: pytest.fail("ensure must not stop an unverified listener"))
    monkeypatch.setattr(module, "audit_action", lambda *_args, **_kwargs: None)

    result = module.ensure_running(
        command=_runtime_command(module),
        url=HEALTH_URL,
        target_port=8080,
        timeout=1,
        total_timeout=5,
        insecure=True,
    )

    assert result["status"] == "failed"
    assert result["failure_reason"] == "target_listener_command_mismatch"
    assert result["already_running"] is False
    assert result["started"] is False


def test_ensure_running_blocks_exact_project_runtime_without_verified_listener(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    exact_runtime = {
        "pid": "4242",
        "parent_pid": "1",
        "cmd": _runtime_command(module),
    }
    monkeypatch.setattr(
        module,
        "_verified_destructive_target",
        lambda **_kwargs: {"status": "absent", "target_port": 8080, "listening_pids": []},
    )
    monkeypatch.setattr(module, "_listening_pids", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "_list_processes", lambda *_args, **_kwargs: [exact_runtime])
    monkeypatch.setattr(
        module,
        "_spawn",
        lambda *_args, **_kwargs: pytest.fail(
            "an exact project runtime without a verified listener must block spawn"
        ),
    )
    monkeypatch.setattr(module, "audit_action", lambda *_args, **_kwargs: None)

    result = module.ensure_running(
        command=_runtime_command(module),
        url=HEALTH_URL,
        target_port=8080,
        timeout=1,
        total_timeout=5,
        insecure=True,
    )

    assert result["status"] == "failed"
    assert result["failure_reason"] == "project_runtime_without_verified_listener"
    assert result["already_running"] is False
    assert result["started"] is False
    assert result["matching_runtime_pids"] == [4242]


def test_ensure_running_starts_only_after_absence_and_verifies_its_identity(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    class FakeProcess:
        pid = 5151

        @staticmethod
        def poll():
            return None

    monkeypatch.setattr(
        module,
        "_verified_destructive_target",
        lambda **_kwargs: {"status": "absent", "target_port": 8080, "listening_pids": []},
    )
    calls: list[int] = []

    def listening_pids(port: int, deadline=None) -> list[int]:
        assert port == 8080
        calls.append(port)
        return [] if len(calls) == 1 else [5151]

    monkeypatch.setattr(module, "_listening_pids", listening_pids)
    process_inventory_calls = 0

    def list_processes(deadline=None):
        nonlocal process_inventory_calls
        process_inventory_calls += 1
        if process_inventory_calls == 1:
            return []
        return [
            {
                "pid": "5151",
                "parent_pid": "1",
                "cmd": _runtime_command(module),
            }
        ]

    monkeypatch.setattr(module, "_list_processes", list_processes)
    spawned: dict[str, str] = {}

    def spawn(command: str, *, env_overrides=None):
        spawned.update(env_overrides or {})
        return FakeProcess(), {"status": "started", "pid": 5151}, 0

    monkeypatch.setattr(module, "_spawn", spawn)
    monkeypatch.setattr(module, "stop", lambda *_args, **_kwargs: pytest.fail("ensure must not delegate to restart/stop"))
    monkeypatch.setattr(module, "audit_action", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module,
        "_health_probe",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "payload": {
                "runtime_identity": {
                    "runtime_instance_id": spawned["ADLOG_RUNTIME_INSTANCE_ID"],
                    "build_id": spawned["ADLOG_BUILD_ID"],
                    "process_pid": 5151,
                }
            },
        },
    )

    result = module.ensure_running(
        command=_runtime_command(module),
        url=HEALTH_URL,
        target_port=8080,
        timeout=1,
        total_timeout=5,
        insecure=True,
    )

    assert result["status"] == "ok"
    assert result["already_running"] is False
    assert result["started"] is True
    assert result["identity_verified"] is True
    assert result["process_tree_verified"] is True
    assert result["port_owner_verified"] is True
    assert result["runtime_identity"]["process_pid"] == 5151
    assert spawned["ADLOG_RUNTIME_INSTANCE_ID"] == result["expected_runtime_instance_id"]


def test_ensure_serializes_precheck_through_spawn_without_live_runtime_access(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    state_lock = threading.Lock()
    mutex = threading.Lock()
    first_spawn_entered = threading.Event()
    second_lock_attempted = threading.Event()
    release_first_spawn = threading.Event()
    state = {
        "running": False,
        "spawns": 0,
        "lock_attempts": 0,
        "active_sections": 0,
        "max_active_sections": 0,
    }
    results: list[dict[str, object]] = []
    errors: list[BaseException] = []

    @contextmanager
    def serialized_section(target_port: int, deadline):
        assert target_port == 8080
        with state_lock:
            state["lock_attempts"] += 1
            if state["lock_attempts"] == 2:
                second_lock_attempted.set()
        assert mutex.acquire(timeout=deadline.remaining(stage="test mutex acquisition"))
        with state_lock:
            state["active_sections"] += 1
            state["max_active_sections"] = max(
                state["max_active_sections"], state["active_sections"]
            )
        try:
            yield
        finally:
            with state_lock:
                state["active_sections"] -= 1
            mutex.release()

    def verified_target(**_kwargs):
        with state_lock:
            if state["running"]:
                return {
                    "status": "verified",
                    "target_port": 8080,
                    "target_pid": 5151,
                    "listening_pids": [5151],
                    "listener_command_verified": True,
                    "runtime_identity": {"process_pid": 5151},
                    "health": {"status": "ok", "code": 200},
                }
        return {"status": "absent", "target_port": 8080, "listening_pids": []}

    def verified_start(*_args, **_kwargs):
        with state_lock:
            state["spawns"] += 1
            spawn_number = state["spawns"]
        if spawn_number == 1:
            first_spawn_entered.set()
            assert release_first_spawn.wait(2), "first controlled spawn was not released"
        with state_lock:
            state["running"] = True
        return {
            "status": "ok",
            "started": True,
            "start": {"status": "started", "pid": 5151},
            "health": {"status": "ok", "code": 200},
            "identity_verified": True,
            "process_tree_verified": True,
            "listener_command_verified": True,
            "port_owner_verified": True,
            "target_pid": 5151,
            "listening_pids": [5151],
        }

    monkeypatch.setattr(module, "_ensure_critical_section", serialized_section, raising=False)
    monkeypatch.setattr(module, "_verified_destructive_target", verified_target)
    monkeypatch.setattr(module, "_listening_pids", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "_matching_project_runtime_processes", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "_start_verified_runtime", verified_start)
    monkeypatch.setattr(module, "audit_action", lambda *_args, **_kwargs: None)

    def invoke() -> None:
        try:
            results.append(
                module.ensure_running(
                    command=_runtime_command(module),
                    url=HEALTH_URL,
                    target_port=8080,
                    timeout=2,
                    total_timeout=5,
                    insecure=True,
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first = threading.Thread(target=invoke)
    second = threading.Thread(target=invoke)
    first.start()
    assert first_spawn_entered.wait(2)
    second.start()
    try:
        assert second_lock_attempted.wait(2), "second ensure did not enter the lock contract"
        with state_lock:
            assert state["spawns"] == 1
    finally:
        release_first_spawn.set()
        first.join(2)
        second.join(2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert not errors
    assert len(results) == 2
    assert {result["status"] for result in results} == {"ok"}
    assert state["spawns"] == 1
    assert state["max_active_sections"] == 1
    assert state["active_sections"] == 0
    assert mutex.locked() is False


def test_restart_reuses_the_shared_verified_start_helper(monkeypatch) -> None:
    from scripts.maintenance import server_control as module

    stop_result = {"status": "ok", "remaining": []}
    captured: dict[str, object] = {}

    def verified_start(command: str, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return {
            "status": "ok",
            "started": True,
            "start": {"status": "started", "pid": 5151},
            "health": {"status": "ok"},
            "identity_verified": True,
            "process_tree_verified": True,
            "port_owner_verified": True,
            "listening_pids": [5151],
        }

    monkeypatch.setattr(module, "stop", lambda *_args, **_kwargs: stop_result)
    monkeypatch.setattr(module, "_listening_pids", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "_start_verified_runtime", verified_start)
    monkeypatch.setattr(module, "audit_action", lambda *_args, **_kwargs: None)

    result = module.restart(
        command=_runtime_command(module),
        url=HEALTH_URL,
        target_port=8080,
        timeout=1,
        total_timeout=5,
        insecure=True,
    )

    assert result["status"] == "ok"
    assert result["stop"] == stop_result
    assert result["start"]["pid"] == 5151
    assert captured["command"] == _runtime_command(module)
    assert captured["target_port"] == 8080
    assert captured["build_id_prefix"] == "restart"
    assert captured["require_exclusive_port_owner"] is False


def test_ensure_cli_preserves_the_bounded_verified_contract(monkeypatch, capsys) -> None:
    from scripts.maintenance import server_control as module

    captured: dict[str, object] = {}

    def ensure_running(**kwargs):
        captured.update(kwargs)
        return {"status": "ok", "already_running": True, "started": False}

    monkeypatch.setattr(module, "ensure_running", ensure_running)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "server_control.py",
            "--json",
            "ensure",
            "--command",
            _runtime_command(module),
            "--url",
            HEALTH_URL,
            "--target-port",
            "8080",
            "--timeout",
            "60",
            "--total-timeout",
            "90",
            "--insecure",
        ],
    )

    assert module.main() == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    assert captured == {
        "command": _runtime_command(module),
        "url": HEALTH_URL,
        "timeout": 60,
        "insecure": True,
        "target_port": 8080,
        "total_timeout": 90.0,
    }


def test_web_control_loads_the_dpapi_environment_with_override(monkeypatch, tmp_path) -> None:
    from scripts.maintenance import web_server_control as module

    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    cert_path.write_text("certificate", encoding="utf-8")
    key_path.write_text("key", encoding="utf-8")
    monkeypatch.delenv("ADLOG_AUTH_REQUIRED", raising=False)
    for name, value in {
        "ADLOG_TLS_CERT_PATH": str(cert_path),
        "ADLOG_TLS_KEY_PATH": str(key_path),
        "ADLOG_UI_MODE": "postgres",
    }.items():
        monkeypatch.setenv(name, value)

    captured: dict[str, object] = {}

    def load_environment(*, override_existing=False):
        captured["override_existing"] = override_existing
        for name, value in {
            "ADLOG_PG_DSN": "protected-value",
            "ADLOG_DB_BACKEND": "postgres",
            "ADLOG_DISABLE_SCHEDULER": "1",
            "ADLOG_EXTERNAL_POST_COLLECTION_WORKER": "1",
            "ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER": "1",
            "ADLOG_STORAGE_READ_MODE": "v2",
            "ADLOG_STORAGE_WRITE_MODE": "v2",
            "ADLOG_PG_ADMIN_USER": "postgres",
            "ADLOG_PG_ADMIN_PASSWORD": "synthetic-only-secret",
            "ADLOG_STORAGE_V2_WORKER_DSN": "synthetic-worker-dsn",
            "ADLOG_SEMANTIC_WORKER_DSN": "synthetic-semantic-dsn",
        }.items():
            monkeypatch.setenv(name, value)
        return {
            "status": "ok",
            "keys": [
                "ADLOG_PG_DSN",
                "ADLOG_PG_ADMIN_USER",
                "ADLOG_PG_ADMIN_PASSWORD",
                "ADLOG_STORAGE_V2_WORKER_DSN",
                "ADLOG_SEMANTIC_WORKER_DSN",
            ],
        }

    monkeypatch.setattr(module, "load_supervisor_environment", load_environment)

    result = module._load_runtime_environment()

    assert result["status"] == "ok"
    assert os.environ["ADLOG_AUTH_REQUIRED"] == "1"
    assert captured["override_existing"] is True
    assert result["checks"]["privileged_credentials_absent"] is True
    for name in (
        "ADLOG_PG_ADMIN_USER",
        "ADLOG_PG_ADMIN_PASSWORD",
        "ADLOG_STORAGE_V2_WORKER_DSN",
        "ADLOG_SEMANTIC_WORKER_DSN",
    ):
        assert name not in os.environ
        assert name not in result["protected_environment_keys_loaded"]
    assert result["credential_values_exposed"] is False


def test_web_control_does_not_persist_runtime_log_or_commands() -> None:
    from scripts.maintenance import web_server_control as module

    result = module._public_runtime_result(
        {
            "status": "failed",
            "failure_reason": "startup_health_verification_failed",
            "runtime_log_tail": "SECRET_SENTINEL",
            "command": "SECRET_SENTINEL",
        }
    )

    assert "SECRET_SENTINEL" not in json.dumps(result)


def test_web_bootstrap_uses_protected_control_without_exposing_values() -> None:
    assert BOOTSTRAP.is_file()
    source = BOOTSTRAP.read_text(encoding="utf-8")

    for required in (
        "[switch]$ValidateOnly",
        "web_server_control.py",
        "web-server-autostart.json",
        "Set-Location -LiteralPath $ResolvedProjectRoot",
        "ensure",
        "validate",
    ):
        assert required in source
    assert "ADLOG_PG_DSN" not in source
    assert "[EnvironmentVariableTarget]::User" not in source
    assert "Register-ScheduledTask" not in source
    assert "Stop-Process" not in source


def test_web_control_is_root_anchored_and_uses_server_control_ensure() -> None:
    assert WEB_CONTROL.is_file()
    source = WEB_CONTROL.read_text(encoding="utf-8")

    for required in (
        "PROJECT_ROOT = Path(__file__).resolve().parents[2]",
        "load_supervisor_environment(override_existing=True)",
        "server_control.ensure_running(",
        '"--port"',
        "https://127.0.0.1:8080/api/health",
        "web-server-autostart.json",
    ):
        assert required in source
    assert "runtime_log_tail" not in source[source.index("def _public_runtime_result"):source.index("def validate_environment")]


def test_web_installer_registers_one_least_privilege_self_healing_task() -> None:
    assert INSTALLER.is_file()
    source = INSTALLER.read_text(encoding="utf-8")

    for required in (
        "$TaskName = 'SLI Web Server'",
        "Start-SLIWebServer-v1.ps1",
        "[switch]$Apply",
        "[switch]$Start",
        "[switch]$ValidateOnly",
        "-WorkingDirectory $ResolvedProjectRoot",
        "-AtLogOn -User $ConfiguredPrincipal",
        "RepetitionInterval",
        "Minutes 5",
        "-LogonType Interactive",
        "-RunLevel Limited",
        "-MultipleInstances IgnoreNew",
        "-RestartCount 3",
        "-ExecutionTimeLimit",
        "-StartWhenAvailable",
        "Register-ScheduledTask",
        "Get-ScheduledTask",
        "Get-ScheduledTaskInfo",
        "Start-ScheduledTask",
        "web-server-autostart.json",
        "credential_values_exposed = $false",
    ):
        assert required in source
    assert "ADLOG_PG_DSN" not in source
    assert "[EnvironmentVariableTarget]::User" not in source
    assert "Stop-Process" not in source
