from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import pytest


def test_python_collector_xpath_and_xml_parse() -> None:
    from scripts.collect.collect_windows_events import build_event_xpath, parse_event_xml

    assert build_event_xpath(after_record_id=42) == "*[System[EventRecordID > 42]]"
    assert "TimeCreated" in build_event_xpath(start_time_utc="2026-07-08T01:02:03+00:00")
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>
        <Keywords>0x8010000000000000</Keywords><EventRecordID>123</EventRecordID>
        <TimeCreated SystemTime="2026-07-08T01:02:03.0000000Z" />
        <Computer>DC1.host13.example.invalid</Computer><Security UserID="S-1-5-18" />
      </System>
      <EventData><Data Name="TargetUserName">user1</Data><Data Name="IpAddress">192.0.2.1</Data></EventData>
    </Event>
    """
    row = parse_event_xml(xml, source_name="DC1", connect_address="192.0.2.2", channel="Security")
    assert row["computer_name"] == "DC1"
    assert row["event_id"] == 4625
    assert row["record_id"] == 123
    assert row["properties"] == ["user1", "192.0.2.1"]
    assert row["message"] is None


def test_runner_auto_backend_fails_closed_on_non_windows_instead_of_falling_back(monkeypatch) -> None:
    """The automatic PowerShell fallback was removed: "auto" on a host
    without the Python EventLog backend now fails closed rather than
    silently switching backends. PowerShell remains available, but only as
    an explicit, operator-chosen override."""
    import scripts.run_dc_log_pilot as runner

    monkeypatch.setattr(runner.os, "name", "posix", raising=False)
    with pytest.raises(runner.CollectorBackendUnavailableError):
        runner.choose_collector_backend("auto")
    assert runner.choose_collector_backend("python") == ("python", "forced_python")
    assert runner.choose_collector_backend("powershell") == ("powershell", "forced_powershell")


def test_internal_error_log_writes_jsonl(tmp_path: Path, monkeypatch) -> None:
    from server.sli.ops import logging_config

    monkeypatch.setattr(logging_config, "LOG_DIR", tmp_path)
    monkeypatch.setattr(logging_config, "INTERNAL_ERROR_LOG_PATH", tmp_path / "internal-errors.log")
    error_id = logging_config.log_internal_error(
        "tests",
        "sample_failure",
        "Sample failure.",
        exc=RuntimeError("boom"),
        level=logging.ERROR,
        job_id=7,
    )
    # This is JSONL: a rotation diagnostic may legitimately be appended by the
    # normal logger after the primary internal-error record.  Validate every
    # record independently and select the one created by this call.
    records = [
        json.loads(line)
        for line in (tmp_path / "internal-errors.log").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    payload = next(item for item in records if item.get("internal_error_id") == error_id)
    assert payload["internal_error_id"] == error_id
    assert payload["component"] == "tests"
    assert payload["event"] == "sample_failure"
    assert payload["job_id"] == 7
    assert payload["error_type"] == "RuntimeError"
    assert "boom" in payload["traceback"]


def test_collector_live_runner_emits_progress(monkeypatch) -> None:
    import server.jobs.collector as collector

    appended: list[str] = []
    monkeypatch.setattr(collector, "_append_output", lambda job_id, output: appended.append(output))

    class DummyStdout:
        def __init__(self) -> None:
            self.lines = iter(["Collection output: C:/tmp/out\n", "Starting channel: Security\n", "Completed channel: Security count=1\n"])

        def readline(self) -> str:
            try:
                return next(self.lines)
            except StopIteration:
                return ""

    class DummyProcess:
        stdout = DummyStdout()
        pid = 12345
        returncode = 0

        def poll(self):
            return 0

        def kill(self) -> None:
            pass

    monkeypatch.setattr(collector.subprocess, "Popen", lambda *args, **kwargs: DummyProcess())
    result = collector._run_subprocess_live(["cmd"], 10, server="DC1", job_id=99)
    assert result.returncode == 0
    assert any("Starting channel: Security" in item for item in appended)


def test_log_exception_backward_compatible(tmp_path: Path, monkeypatch) -> None:
    from server.sli.ops import logging_config

    monkeypatch.setattr(logging_config, "LOG_DIR", tmp_path)
    monkeypatch.setattr(logging_config, "INTERNAL_ERROR_LOG_PATH", tmp_path / "internal-errors.log")
    error_id = logging_config.log_exception(RuntimeError("compat boom"), component="tests", event="compat")
    payload = json.loads((tmp_path / "internal-errors.log").read_text(encoding="utf-8").strip())
    assert payload["internal_error_id"] == error_id
    assert payload["event"] == "compat"
    assert payload["error_type"] == "RuntimeError"


def test_winerror_timeout_and_no_more_items_are_nonfatal(monkeypatch) -> None:
    import scripts.collect.collect_windows_events as collector

    class WinError(Exception):
        pass

    class DummyEvt:
        calls = 0

        @staticmethod
        def EvtNext(query, batch_size, timeout_ms, flags):
            DummyEvt.calls += 1
            raise WinError(collector.ERROR_TIMEOUT, "EvtNext", "timeout")

    monkeypatch.setattr(collector, "win32evtlog", DummyEvt)
    assert collector.next_event_batch(object(), 64, 1000) is None

    def no_more(query, batch_size, timeout_ms, flags):
        raise WinError(collector.ERROR_NO_MORE_ITEMS, "EvtNext", "no more")

    monkeypatch.setattr(DummyEvt, "EvtNext", no_more)
    assert collector.next_event_batch(object(), 64, 1000) == []
