# SPDX-License-Identifier: Apache-2.0
"""Stable SCM supervisor, outside release directories, with a startup watchdog."""
from __future__ import annotations

import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from sli_agent.config import machine_config_path, service_name
from sli_agent.updates import Updates
from sli_agent.protection import directory_lock

CHILD = "import sys; sys.path.insert(0, sys.argv[1]); from sli_agent.runtime import child_main; child_main(sys.argv[2], sys.argv[3])"


def supervise(config, config_path, stop, *, spawn=subprocess.Popen, monotonic=time.monotonic, timeout=120,
              restart_service=None):
    if any(Path(__file__).resolve().is_relative_to(root.resolve()) for root in
           (config.update_root, config.state_dir)):
        raise ValueError("agent_update_external_bootstrap_required")
    updates = Updates(config)
    with directory_lock(updates.root / "launcher-lock"):
        while not stop.is_set():
            state = updates.read()
            directory = state["current"]["directory"]
            process = None
            try:
                release = updates.verified_release(state["current"])
                # -I ignores interactive PYTHONPATH/user site; only this validated
                # release precedes the operator-installed dependency environment.
                # SCM may embed Python in PythonService.exe; that executable does
                # not implement the interpreter CLI. Use the installed Python.
                process = spawn([str(config.service_python), "-I", "-B", "-c", CHILD, str(release), str(config_path), directory],
                    cwd=release, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                started = monotonic()
                while not stop.is_set():
                    current = updates.read()
                    if current["current"]["directory"] != directory:
                        if restart_service is not None:
                            restart_service()
                            stop.set()
                        break
                    if process.poll() is not None:
                        rolled_back = updates.rollback("agent_update_self_check_failed")
                        if rolled_back and restart_service is not None:
                            restart_service()
                            stop.set()
                        break
                    if current["pending"] and monotonic() - started >= timeout:
                        # Kill and wait BEFORE rollback so the old release never
                        # collects concurrently with a failed candidate.
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        updates.rollback("agent_update_timeout")
                        if restart_service is not None:
                            restart_service()
                            stop.set()
                        break
                    stop.wait(1)
            except (OSError, ValueError):
                rolled_back = updates.rollback("agent_update_start_failed")
                if rolled_back and restart_service is not None:
                    restart_service()
                    stop.set()
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            stop.wait(1)


def request_service_restart(python_executable, instance=None):
    """Run the stable helper outside the SCM process being stopped."""
    instance_args = [] if instance is None else ["--instance", instance]
    service_name(instance)
    subprocess.Popen([str(python_executable), "-I", "-m", "sli_agent.launcher", *instance_args],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW)


@contextmanager
def windows_service_control(instance=None):
    """Open SCM with connect authority, and only this service's control rights."""
    import win32service
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    service = None
    try:
        service = win32service.OpenService(manager, service_name(instance),
            win32service.SERVICE_START | win32service.SERVICE_STOP | win32service.SERVICE_QUERY_STATUS)
        class Control:
            def StopService(self, name):
                win32service.ControlService(service, win32service.SERVICE_CONTROL_STOP)
            def WaitForServiceStatus(self, name, status, timeout):
                deadline = time.monotonic() + timeout
                while win32service.QueryServiceStatus(service)[1] != status:
                    if time.monotonic() >= deadline:
                        raise OSError("agent_service_stop_timeout")
                    time.sleep(0.2)
            def StartService(self, name):
                win32service.StartService(service, None)
        yield Control()
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        win32service.CloseServiceHandle(manager)


@contextmanager
def restart_lock(root):
    """A fast candidate failure can overlap the helper that just started it."""
    deadline = time.monotonic() + 30
    while True:
        lock = directory_lock(root / "restart-lock")
        try:
            lock.__enter__()
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError("agent_service_restart_failed") from None
            time.sleep(0.2)
    try:
        yield
    finally:
        lock.__exit__(None, None, None)


def restart_windows_service(config, *, control=None):
    """SCM owns service credentials. The helper keeps no account/password."""
    if control is None:
        try:
            with windows_service_control(config.instance_name) as native:
                return restart_windows_service(config, control=native)
        except Exception:
            Updates(config).rollback("agent_update_start_failed")
            raise RuntimeError("agent_service_restart_failed") from None
    stopped = 1  # SERVICE_STOPPED, also used by platform-independent fakes.
    updates = Updates(config)
    name = service_name(config.instance_name)
    with restart_lock(updates.root):
        try:
            try:
                control.StopService(name)
            except Exception:
                # The service may already have exited its dispatcher.
                pass
            control.WaitForServiceStatus(name, stopped, 30)
            control.StartService(name)
        except Exception:
            updates.rollback("agent_update_start_failed")
            # A start failure may be transient; retry once using the old pointer.
            try:
                control.StartService(name)
            except Exception:
                raise RuntimeError("agent_service_restart_failed") from None


def main():
    import argparse
    import os
    from sli_agent.config import AgentConfig
    if os.name != "nt":
        raise RuntimeError("agent_windows_required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance")
    args = parser.parse_args()
    config = AgentConfig.load(machine_config_path(args.instance))
    if config.instance_name != args.instance:
        raise ValueError("agent_service_instance_mismatch")
    restart_windows_service(config)


if __name__ == "__main__":
    main()
