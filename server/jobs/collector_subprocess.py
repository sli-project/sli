"""Split out of ``server.jobs.collector`` (plan 7.2b).

Module-level names of ``collector`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.jobs.collector as _src


def _run_subprocess_live(command: list[str], timeout_seconds: int, *, server: str, job_id: int | None, env: dict[str, str] | None = None) -> _src.subprocess.CompletedProcess[str]:
    command_text = " ".join(command)
    started = _src.time.monotonic()
    _src.log_event(
        "collector", "subprocess_launching", "Collection subprocess launching.",
        job_id=job_id, server=server, command=command_text,
        timeout_seconds=timeout_seconds, collector_backend=_src.COLLECTOR_BACKEND,
    )
    popen_kwargs: dict[str, object] = {}
    if _src.os.name == "nt":
        popen_kwargs["creationflags"] = (
            getattr(_src.subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(_src.subprocess, "CREATE_NO_WINDOW", 0)
        )
    try:
        process = _src.subprocess.Popen(
            command,
            cwd=_src.ROOT,
            text=True,
            stdout=_src.subprocess.PIPE,
            stderr=_src.subprocess.STDOUT,
            bufsize=1,
            env=env,
            **popen_kwargs,
        )
    except OSError as exc:
        error_id = _src.log_internal_error(
            "collector", "subprocess_start_failed", "Collection subprocess failed to start.",
            exc=exc, job_id=job_id, server=server, command=command_text,
        )
        return _src.subprocess.CompletedProcess(command, 127, "", f"{exc} (internal_error_id={error_id})")

    _src.log_event(
        "collector", "subprocess_started", "Collection subprocess started.",
        job_id=job_id, server=server, command=command_text, subprocess_pid=process.pid,
    )
    output_lines: _src.deque[str] = _src.deque(maxlen=max(100, _src.TAIL_LIMIT))
    line_queue: _src.queue.Queue[str | None] = _src.queue.Queue()

    def reader() -> None:
        try:
            assert process.stdout is not None
            stream = process.stdout
            if hasattr(stream, "__iter__"):
                for line in stream:
                    line_queue.put(line)
            else:
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    line_queue.put(line)
        finally:
            line_queue.put(None)

    reader_thread = _src.threading.Thread(target=reader, daemon=True, name=f"collector-stdout-{process.pid}")
    reader_thread.start()
    reader_done = False
    reader_join_timeout = 2.0
    last_heartbeat = _src.time.monotonic()
    try:
        while True:
            try:
                item = line_queue.get(timeout=0.2)
            except _src.queue.Empty:
                item = ""
            if item is None:
                reader_done = True
            elif item:
                output_lines.append(item)
                clean = item.strip()
                if clean.startswith((
                    "Collection output:", "Summary:", "Starting channel:",
                    "Progress channel:", "Completed channel:", "Timed out channel:",
                    "Failed channel:", "Collection channel status:",
                )):
                    if job_id is not None:
                        _src._append_output(job_id, f"{server}: {clean}")
                        _src._update_job_progress_from_line(job_id, server, clean)
                    _src.log_event(
                        "collector", "subprocess_progress", "Collection subprocess progress.",
                        job_id=job_id, server=server, progress=clean, subprocess_pid=process.pid,
                    )

            elapsed = _src.time.monotonic() - started
            if elapsed > timeout_seconds:
                reader_join_timeout = 0.2
                _src._terminate_process_tree(process, grace_seconds=0.5)
                if process.stdout is not None:
                    try:
                        process.stdout.close()
                    except OSError:
                        pass
                output = "".join(output_lines)
                message = f"Collection process for {server} timed out after {timeout_seconds} seconds."
                _src.log_internal_error(
                    "collector", "subprocess_timeout", message,
                    job_id=job_id, server=server, command=command_text,
                    stdout_tail=_src._tail(output), subprocess_pid=process.pid,
                )
                return _src.subprocess.CompletedProcess(command, 124, output, message)
            if _src.time.monotonic() - last_heartbeat >= 30:
                last_heartbeat = _src.time.monotonic()
                _src.log_event(
                    "collector", "subprocess_heartbeat", "Collection subprocess is still running.",
                    job_id=job_id, server=server, duration_ms=int(elapsed * 1000),
                    subprocess_pid=process.pid,
                )
            if process.poll() is not None and reader_done and line_queue.empty():
                break
    except Exception as exc:
        _src._terminate_process_tree(process)
        output = "".join(output_lines)
        error_id = _src.log_internal_error(
            "collector", "subprocess_read_failed", "Collection subprocess output reader failed.",
            exc=exc, job_id=job_id, server=server, stdout_tail=_src._tail(output),
            subprocess_pid=process.pid,
        )
        return _src.subprocess.CompletedProcess(command, 125, output, f"{exc} (internal_error_id={error_id})")
    finally:
        reader_thread.join(timeout=reader_join_timeout)

    output = "".join(output_lines)
    return _src.subprocess.CompletedProcess(command, process.returncode or 0, output, "")


def _terminate_process_tree(process: _src.subprocess.Popen[str], *, grace_seconds: float = 5.0) -> None:
    """Terminate the complete collector process tree on Windows and other hosts."""
    if process.poll() is not None:
        return
    if _src.os.name == "nt":
        try:
            _src.subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=_src.subprocess.DEVNULL,
                stderr=_src.subprocess.DEVNULL,
                timeout=max(1.0, grace_seconds),
                check=False,
                creationflags=getattr(_src.subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            process.kill()
    else:
        process.terminate()
        try:
            process.wait(timeout=max(0.5, grace_seconds))
            return
        except _src.subprocess.TimeoutExpired:
            process.kill()
    try:
        process.wait(timeout=max(0.5, grace_seconds))
    except _src.subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=max(0.5, grace_seconds))


def _update_job_progress_from_line(job_id: int, server: str, line: str) -> None:
    channel = None
    events = None
    if line.startswith("Starting channel:"):
        channel = line.split(":", 1)[1].strip()
    elif line.startswith("Progress channel:"):
        rest = line.split(":", 1)[1].strip()
        channel = rest.split(" count=", 1)[0].strip()
        match = _src.re.search(r"count=(\d+)", line)
        if match:
            events = int(match.group(1))
    elif line.startswith(("Completed channel:", "Timed out channel:", "Failed channel:")):
        channel = line.split(":", 1)[1].split(" count=", 1)[0].split(" after ", 1)[0].split(" error=", 1)[0].strip()
        match = _src.re.search(r"count=(\d+)|partial_count=(\d+)", line)
        if match:
            events = int(next(value for value in match.groups() if value))
    elif line.startswith("Collection channel status:"):
        try:
            payload = _src.json.loads(line.split(":", 1)[1].strip())
            events = int(payload.get("events_collected") or 0)
        except Exception:
            pass
    with _src._lock:
        job = _src._jobs.get(job_id)
        if job is None:
            return
        job.current_server = server
        if channel:
            job.current_channel = channel
            if channel not in job.channels_in_progress and not line.startswith(("Completed channel:", "Timed out channel:", "Failed channel:")):
                job.channels_in_progress.append(channel)
        if events is not None:
            job.events_collected = max(int(job.events_collected or 0), int(events))
        job.last_progress_at = _src.utc_now()
        job.updated_at = job.last_progress_at
