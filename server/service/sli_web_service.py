"""Windows Service implementation for SLI Web Server.

Runs the SLI HTTPS Web Server as a native Windows Service in Session 0,
guaranteeing complete isolation from the user desktop and zero pop-up windows.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import servicemanager  # type: ignore
import win32event  # type: ignore
import win32service  # type: ignore
import win32serviceutil  # type: ignore


LOG_DIR = PROJECT_ROOT / "data" / "logs"
LOG_FILE = LOG_DIR / "sli_web_service.log"
PYTHON_EXE = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
RUN_SERVER_SCRIPT = PROJECT_ROOT / "scripts" / "run_server.py"
PYTHON_SERVICE_EXE = PROJECT_ROOT / ".venv" / "pythonservice.exe"


def _log(message: str) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


class SLIWebServerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SLIWebServer"
    _svc_display_name_ = "SLI Web Server"
    _svc_description_ = (
        "Security Log Intelligence (SLI) HTTPS Web Server - background service"
    )
    _exe_name_ = str(PYTHON_SERVICE_EXE)

    def __init__(self, args: list[str]) -> None:
        try:
            super().__init__(args)
        except Exception:
            # Allows instantiation in test or offline inspection contexts
            pass
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.process: subprocess.Popen[bytes] | None = None
        self._stopping = False

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        _log("Service stop requested by SCM.")
        self._stopping = True
        win32event.SetEvent(self.stop_event)
        self._stop_child_process()

    def _stop_child_process(self) -> None:
        if self.process is not None and self.process.poll() is None:
            _log(f"Terminating child web server process PID={self.process.pid}...")
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                    _log("Child web server process terminated cleanly.")
                except subprocess.TimeoutExpired:
                    _log("Child process did not exit in 10s, killing...")
                    self.process.kill()
                    self.process.wait(timeout=5)
            except Exception as exc:
                _log(f"Error stopping child process: {exc}")

    def SvcDoRun(self) -> None:
        _log("=== SLI Web Server Service starting ===")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

        try:
            os.chdir(str(PROJECT_ROOT))

            # Prepare environment with DPAPI secrets
            child_env = os.environ.copy()
            try:
                from server.sli.ops.worker_supervisor_secrets import (
                    load_supervisor_environment,
                    strip_http_forbidden_environment,
                )

                load_supervisor_environment(target=child_env, override_existing=True)
                strip_http_forbidden_environment(destination=child_env)
                _log("Supervisor runtime environment loaded successfully.")
            except Exception as env_exc:
                _log(f"Warning: load_supervisor_environment: {env_exc}")

            host = "127.0.0.1"
            port = "8080"
            cmd = [
                str(PYTHON_EXE),
                str(RUN_SERVER_SCRIPT),
                "--host",
                host,
                "--port",
                port,
            ]

            flags = 0
            if os.name == "nt":
                flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) | int(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                )

            LOG_DIR.mkdir(parents=True, exist_ok=True)
            runtime_out_path = LOG_DIR / "sli_web_server_runtime.log"

            restart_attempts = 0
            max_quick_restarts = 5

            while not self._stopping:
                _log(f"Spawning web server: {' '.join(cmd)}")
                with runtime_out_path.open("a", encoding="utf-8") as out_file:
                    self.process = subprocess.Popen(
                        cmd,
                        cwd=str(PROJECT_ROOT),
                        env=child_env,
                        stdout=out_file,
                        stderr=subprocess.STDOUT,
                        creationflags=flags,
                    )
                _log(f"Web server spawned with PID={self.process.pid}")

                # Monitor loop
                start_time = time.monotonic()
                while not self._stopping:
                    rc = win32event.WaitForSingleObject(self.stop_event, 1000)
                    if rc == win32event.WAIT_OBJECT_0:
                        _log("Stop event received in monitor loop.")
                        break

                    exit_code = self.process.poll()
                    if exit_code is not None:
                        _log(
                            f"Child process PID={self.process.pid} exited with code {exit_code}."
                        )
                        break

                if self._stopping:
                    break

                # If child crashed quickly, throttle restarts
                run_duration = time.monotonic() - start_time
                if run_duration < 10:
                    restart_attempts += 1
                    _log(
                        f"Quick crash detected (duration {run_duration:.1f}s, attempt {restart_attempts}/{max_quick_restarts})."
                    )
                    if restart_attempts >= max_quick_restarts:
                        _log("Exceeded maximum quick restart attempts. Service halting.")
                        break
                    time.sleep(3)
                else:
                    restart_attempts = 0

        except Exception as exc:
            _log(f"Fatal error in SvcDoRun: {exc}")
            servicemanager.LogErrorMsg(f"SLI Web Server Service fatal error: {exc}")
        finally:
            self._stop_child_process()
            _log("=== SLI Web Server Service stopped ===")
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)


def main() -> None:
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SLIWebServerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SLIWebServerService)


if __name__ == "__main__":
    main()
