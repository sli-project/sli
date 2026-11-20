from __future__ import annotations

import json
import logging
import sys
import threading
from pathlib import Path

from server.sli.ops.logging_config import JsonLineFormatter, log_exception


def test_json_formatter_keeps_internal_error_metadata() -> None:
    record = logging.LogRecord(
        name="adlog_monitor",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="boom",
        args=(),
        exc_info=None,
    )
    record.component = "collector"
    record.event = "subprocess_timeout"
    record.internal_error_id = "abc123"
    record.timeout_seconds = 120
    record.output_line = "Starting channel: Security"

    payload = json.loads(JsonLineFormatter().format(record))

    assert payload["component"] == "collector"
    assert payload["event"] == "subprocess_timeout"
    assert payload["internal_error_id"] == "abc123"
    assert payload["timeout_seconds"] == 120
    assert payload["output_line"] == "Starting channel: Security"
    assert payload["pid"]
    assert payload["thread"]


def test_internal_errors_use_environment_directory(monkeypatch, tmp_path: Path) -> None:
    from server.sli.ops import logging_config

    default = tmp_path / "default" / "internal-errors.log"
    configured = tmp_path / "configured"
    monkeypatch.setattr(logging_config, "INTERNAL_ERROR_LOG_PATH", default)
    monkeypatch.setattr(logging_config, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setenv("ADLOG_LOG_DIR", str(configured))
    error_id = logging_config.log_internal_error("tests", "failure", "Synthetic failure")
    payload = json.loads((configured / "internal-errors.log").read_text(encoding="utf-8"))
    assert payload["internal_error_id"] == error_id
    assert not default.exists()
    monkeypatch.delenv("ADLOG_LOG_DIR")
    error_id = logging_config.log_internal_error("tests", "fallback", "Synthetic failure")
    assert json.loads(default.read_text(encoding="utf-8"))["internal_error_id"] == error_id


def test_log_exception_returns_visible_error_id(monkeypatch, tmp_path: Path) -> None:
    from server.sli.ops import logging_config

    logging_config._CONFIGURED = False
    logging.getLogger("adlog_monitor").handlers.clear()
    monkeypatch.setattr(logging_config, "LOG_DIR", tmp_path)
    monkeypatch.setattr(logging_config, "LOG_PATH", tmp_path / "adlog-monitor.log")
    monkeypatch.setattr(logging_config, "INTERNAL_ERROR_LOG_PATH", tmp_path / "internal-errors.log")

    try:
        raise RuntimeError("test internal failure")
    except RuntimeError as exc:
        error_id = log_exception("collector", "unit_failure", "Unit failure.", exc, job_id=77)

    assert len(error_id) == 12
    text = (tmp_path / "internal-errors.log").read_text(encoding="utf-8")
    payload = json.loads(text.splitlines()[-1])
    assert payload["internal_error_id"] == error_id
    assert payload["error_type"] == "RuntimeError"
    assert payload["job_id"] == 77
    assert "Traceback" in payload["exception"]


def test_error_logging_fallback_never_masks_original_error(monkeypatch, tmp_path: Path) -> None:
    from server.sli.ops import logging_config

    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(logging_config, "INTERNAL_ERROR_LOG_PATH", blocked / "internal-errors.log")
    monkeypatch.setattr(logging_config, "append_jsonl_bounded", lambda *_args, **_kwargs: False)

    original = RuntimeError("original product failure")
    internal_id = logging_config.log_internal_error("tests", "fallback", "Cannot persist log", exc=original)
    exception_id = logging_config.log_exception(original, component="tests", event="fallback_exception")

    assert internal_id.startswith("INT-")
    assert len(exception_id) == 12


def test_collector_subprocess_streams_live_progress(monkeypatch) -> None:
    from server.jobs import collector

    updates: list[str] = []
    events: list[tuple[str, str, dict]] = []
    stdout_consumed = threading.Event()

    class FakeStdout:
        def __iter__(self):
            yield from [
                "Collection output: C:/tmp/DC1-1\n",
                "Starting channel: Security\n",
                "Completed channel: Security count=5\n",
            ]
            stdout_consumed.set()

    class FakeProcess:
        def __init__(self, *args, **kwargs):
            self.stdout = FakeStdout()
            self.returncode = 0
            self.pid = 12345
            self._done = False

        def poll(self):
            if self._done:
                return 0
            # Wait until the reader has processed the progress lines.
            assert stdout_consumed.wait(timeout=5)
            self._done = True
            return None

    monkeypatch.setattr(collector.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    monkeypatch.setattr(collector, "_append_output", lambda job_id, output: updates.append(output))
    monkeypatch.setattr(collector, "log_event", lambda component, event, message, **fields: events.append((component, event, fields)))

    result = collector._run_subprocess_with_internal_logging(
        [sys.executable, "dummy.py"],
        server="DC1",
        job_id=10,
        timeout_seconds=5,
    )

    assert result.returncode == 0
    assert "Collection output" in result.stdout
    assert any("Starting channel: Security" in item for item in updates)
    assert any(event == "subprocess_progress" for _, event, _ in events)


def test_powershell_collector_writes_internal_log_and_error_metadata() -> None:
    script = Path("scripts/collect/Collect-DcEventsLastHour.ps1").read_text(encoding="utf-8")

    assert "collector-internal.log" in script
    assert "function Write-InternalLog" in script
    assert 'Write-InternalLog -Event "collection_started"' in script
    assert 'Write-InternalLog -Event "channel_started"' in script
    assert 'Write-InternalLog -Event "channel_timeout"' in script
    assert 'Write-InternalLog -Event "channel_failed"' in script
    assert 'error_type = $_.Exception.GetType().FullName' in script
    assert 'script_stack_trace = $_.ScriptStackTrace' in script
