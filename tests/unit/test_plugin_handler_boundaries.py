"""VP11: Linux process boundaries and file-only child credentials, without a DB."""
from functools import partial
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from server.sli.core import job_executor as executor
from server.sli.core.job_registry import PROFILES, pilot_registry
from tests.unit.test_core_job_queue import Connection, job


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("purpose,identity", [("handler", "executor"), ("publisher", "publisher")])
def test_child_environment_contains_only_declared_secret_file(monkeypatch, tmp_path, profile, purpose, identity):
    secret = tmp_path / "declared-secret"
    secret.write_text("synthetic-password\n", encoding="utf-8")
    name = f"SLI_JOB_{identity.upper()}_{profile.upper()}_PASSWORD"
    monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(f"{name}_FILE", str(secret))
    monkeypatch.setenv("ADLOG_PG_PASSWORD", "synthetic-core-password")
    monkeypatch.setenv("SLI_JOB_DISPATCHER_LIGHT_PASSWORD", "synthetic-dispatcher-password")
    monkeypatch.setenv("SLI_JOB_EXECUTOR_OTHER_PASSWORD_FILE", "/run/secrets/other-plugin")
    monkeypatch.setenv("PGPASSWORD", "synthetic-libpq-password")
    process = type("Process", (), {"pid": 123, "returncode": 0, "poll": lambda _: 0})()
    seen = []

    def popen(_argv, **kwargs):
        env = kwargs["env"]
        seen.append(env)
        assert {key: value for key, value in env.items() if "PASSWORD" in key} == {f"{name}_FILE": str(secret)}
        assert "synthetic-password" not in json.dumps(env)
        assert "password" not in json.loads(env["SLI_JOB_CHILD_CONNECTION"])
        # This is the child's environment, read with the real file-secret reader.
        with monkeypatch.context() as child_env:
            child_env.setattr(os, "environ", dict(env))
            settings = executor.child_connection_settings(profile, purpose)
            assert settings["password"] == "synthetic-password"
            assert settings["user"] == f"sli_job_{identity}_{profile}"
            assert "SLI_JOB_CHILD_CONNECTION" not in os.environ
        kwargs["stdout"].write(b'{"status":"success"}')
        kwargs["stdout"].flush()
        return process

    executor.run_child({**job(), "resource_profile": profile}, purpose, deadline=1,
                       clock=lambda: 0, popen=popen, terminate=lambda _: None)
    assert len(seen) == 1


@pytest.mark.parametrize("purpose,identity", [("handler", "executor"), ("publisher", "publisher")])
def test_inline_secret_cannot_launch_child(monkeypatch, purpose, identity):
    name = f"SLI_JOB_{identity.upper()}_LIGHT_PASSWORD"
    monkeypatch.delenv(f"{name}_FILE", raising=False)
    monkeypatch.setenv(name, "synthetic-password")
    with pytest.raises(ValueError, match="executor_secret_file_required"):
        executor.run_child(job(), purpose, deadline=1,
                           popen=lambda *_args, **_kwargs: pytest.fail("child launched"))


@pytest.mark.parametrize("change,error", [
    ({"user": "sli_job_publisher_light"}, "executor_identity_invalid"),
    ({"password": "synthetic-inline"}, "executor_identity_invalid"),
    ({}, "executor_secret_file_required"),
])
def test_child_rejects_wrong_identity_or_env_secret(monkeypatch, change, error):
    monkeypatch.delenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE", raising=False)
    monkeypatch.setenv("SLI_JOB_CHILD_CONNECTION", json.dumps({"user": "sli_job_executor_light", **change}))
    with pytest.raises(ValueError, match=error):
        executor.child_connection_settings("light", "handler")


def test_child_rejects_inline_secret_even_with_declared_file(monkeypatch, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("synthetic-file-password", encoding="utf-8")
    monkeypatch.setenv("SLI_JOB_CHILD_CONNECTION", json.dumps({"user": "sli_job_executor_light"}))
    monkeypatch.setenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE", str(secret))
    monkeypatch.setenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD", "synthetic-inline-password")
    with pytest.raises(ValueError, match="executor_secret_file_required"):
        executor.child_connection_settings("light", "handler")


def test_invalid_secret_file_fails_before_launch_without_exposing_value(monkeypatch, tmp_path):
    name = "SLI_JOB_EXECUTOR_LIGHT_PASSWORD"
    monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(f"{name}_FILE", str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="secret file is unreadable or invalid") as caught:
        executor.run_child(job(), "handler", deadline=1,
                           popen=lambda *_args, **_kwargs: pytest.fail("child launched"))
    assert str(tmp_path) not in str(caught.value)


@pytest.mark.parametrize("returncode,error", [(None, "job_deadline_exceeded"), (127, "job_execution_failed")])
def test_child_cleanup_precedes_retry_without_launching_publisher(monkeypatch, tmp_path, returncode, error):
    secret = tmp_path / "secret"
    secret.write_text("synthetic-password", encoding="utf-8")
    monkeypatch.setenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE", str(secret))
    monkeypatch.delenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD", raising=False)
    monkeypatch.setattr(executor, "write_heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(executor, "STOP", type("Stop", (), {"is_set": lambda _: False})())
    process = SimpleNamespace(pid=123, returncode=returncode, poll=lambda: returncode)
    connection = Connection([True, True])
    launched = []
    stopped = []

    def popen(argv, **kwargs):
        launched.append(argv[argv.index("--child") + 1])
        assert kwargs["start_new_session"] is True
        return process

    def terminate(child):
        assert not any("fail_core_job_v1" in sql for sql, _params in connection.calls)
        stopped.append(child)

    ticks = iter([0, 1] if returncode is None else [0, 0])
    executor.execute_job(connection, pilot_registry(), {**job(), "remaining_seconds": 0.5},
                         clock=lambda: 0,
                         child=partial(executor.run_child, popen=popen, terminate=terminate,
                                       clock=lambda: next(ticks)))
    assert launched == ["handler"]
    assert stopped == [process]
    assert "fail_core_job_v1" in connection.calls[-1][0]
    assert connection.calls[-1][1][-2:] == (error, False)


@pytest.mark.host_dependent  # requires real Linux process groups and a runnable host Python
@pytest.mark.skipif(sys.platform != "linux", reason="Linux process groups required")
def test_real_hanging_handler_and_descendant_are_killed_before_retry(monkeypatch, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("synthetic-password", encoding="utf-8")
    monkeypatch.setenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE", str(secret))
    monkeypatch.delenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD", raising=False)
    monkeypatch.setattr(executor, "write_heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(executor, "STOP", type("Stop", (), {"is_set": lambda _: False})())
    ready = tmp_path / "ready"
    processes = []
    executable = os.environ.get("SLI_TEST_PYTHON", sys.executable)
    # Both processes ignore SIGTERM. The executor must use SIGKILL on the group.
    script = (
        "import pathlib,signal,subprocess,sys,time; "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
        "child=subprocess.Popen([sys.executable,'-c',"
        "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(60)"
    )

    def popen(_argv, **kwargs):
        # setup-python's shared-library interpreter may need the host loader path.
        # Only this synthetic process gets it; the executor's env stays restricted.
        if "LD_LIBRARY_PATH" in os.environ:
            kwargs["env"]["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH"]
        process = subprocess.Popen([executable, "-c", script, str(ready)], **kwargs)
        processes.append(process)
        limit = time.monotonic() + 5
        while not ready.exists() or not ready.read_text("utf-8").strip():
            if process.poll() is not None or time.monotonic() >= limit:
                raise RuntimeError("synthetic_handler_start_failed")
            time.sleep(0.01)
        return process

    connection = Connection([True, True])
    started = time.monotonic()
    try:
        executor.execute_job(connection, pilot_registry(), {**job(), "remaining_seconds": 0.5},
                             child=partial(executor.run_child, popen=popen))
        assert len(processes) == 1  # Publication never launches after timeout.
        assert processes[0].returncode == -signal.SIGKILL
        descendant = int(ready.read_text("utf-8"))
        limit = time.monotonic() + 2
        while True:
            try:
                status = Path(f"/proc/{descendant}/stat").read_text("ascii")
            except FileNotFoundError:
                break
            # An orphan zombie is stopped and awaits init's reap.
            if status.split(")", 1)[1].split()[0] == "Z":
                break
            assert time.monotonic() < limit, "descendant survived group termination"
            time.sleep(0.01)
        assert time.monotonic() - started < 8
        assert "fail_core_job_v1" in connection.calls[-1][0]
        assert connection.calls[-1][1][-2:] == ("job_deadline_exceeded", False)
    finally:
        for process in processes:
            executor.kill_group(process)
