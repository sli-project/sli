"""Split out of ``scripts.run_dc_log_pilot`` (plan 6.3): subprocess execution helpers.

Module-level names of ``run_dc_log_pilot`` are looked up through ``_src`` at
call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from collections import deque

import scripts.run_dc_log_pilot as _src


def _terminate_process_tree(process: subprocess.Popen[str], *, grace_seconds: float = 5.0) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(1.0, grace_seconds),
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            process.kill()
    else:
        process.terminate()
        try:
            process.wait(timeout=max(0.5, grace_seconds))
            return
        except subprocess.TimeoutExpired:
            process.kill()
    try:
        process.wait(timeout=max(0.5, grace_seconds))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=max(0.5, grace_seconds))


def run_command(command: list[str], *, timeout_seconds: int | None = None) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    command_text = " ".join(command)
    print("Running:", command_text)
    _src.log_event("runner", "command_started", "Command started.", command=command_text, timeout_seconds=timeout_seconds)
    popen_kwargs: dict[str, object] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
    try:
        process = subprocess.Popen(
            command,
            cwd=_src.ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            **popen_kwargs,
        )
    except OSError as exc:
        _src.log_event("runner", "command_failed", "Command failed to start.", command=command_text, exit_code=127, error=str(exc))
        return subprocess.CompletedProcess(command, 127, str(exc), str(exc))

    max_lines = max(100, int(os.environ.get("ADLOG_SUBPROCESS_OUTPUT_LINES", "4000")))
    lines: deque[str] = deque(maxlen=max_lines)

    def read_stdout() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line)
            print(line, end="")

    reader = threading.Thread(target=read_stdout, daemon=True)
    reader.start()
    while process.poll() is None:
        if timeout_seconds is not None and time.monotonic() - started > timeout_seconds:
            _src._terminate_process_tree(process)
            message = f"\nCommand timed out after {timeout_seconds} seconds."
            lines.append(message)
            print(message)
            reader.join(timeout=2)
            output = "".join(lines)
            duration_ms = int((time.monotonic() - started) * 1000)
            _src.log_event(
                "runner", "command_timeout", "Command timed out.",
                command=command_text, exit_code=124, duration_ms=duration_ms,
                stdout_tail=output[-2000:], error=message.strip(),
            )
            result = subprocess.CompletedProcess(command, 124, output, message)
            result.duration_ms = duration_ms
            return result
        time.sleep(0.2)
    reader.join(timeout=2)
    output = "".join(lines)
    returncode = process.returncode or 0
    duration_ms = int((time.monotonic() - started) * 1000)
    _src.log_event(
        "runner", "command_finished", "Command finished.",
        command=command_text, exit_code=returncode, duration_ms=duration_ms,
        stdout_tail=output[-2000:],
    )
    result = subprocess.CompletedProcess(command, returncode, output, "")
    result.duration_ms = duration_ms
    return result
