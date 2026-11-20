from __future__ import annotations

from dataclasses import fields
from inspect import signature
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from server.source_packs import adapters
from server.source_packs.adapters import WindowsEventLogRequest, build_windows_eventlog_command
from server.sli.sources.source_capture_continuity import AUTHENTICATION_EVENT_KEYS


def _request(**overrides: object) -> WindowsEventLogRequest:
    values: dict[str, object] = {
        "backend": "python",
        "python_executable": "python",
        "python_script": Path("collect.py"),
        "powershell_script": Path("collect.ps1"),
        "computer_name": "radius01.example.invalid",
        "source_name": "radius01.example.invalid",
        "hours": 1,
        "max_events_per_channel": 500,
        "channel_timeout_seconds": 30,
        "output_root": Path("raw"),
        "channels": ("Security",),
        "collection_mode": "current",
        "collect_message": False,
        "channel_limits": {},
        "channel_timeouts": {},
        "start_time_utc": "2026-08-01T01:00:00+00:00",
        "channel_start_times": {},
        "channel_after_record_ids": {},
        "event_ids": (6272,),
        "end_time_utc": "2026-08-01T01:20:00+00:00",
    }
    values.update(overrides)
    return WindowsEventLogRequest(**values)  # type: ignore[arg-type]


def test_python_request_forwards_bounded_selection_to_collector() -> None:
    field_names = {item.name for item in fields(WindowsEventLogRequest)}
    assert {"event_ids", "end_time_utc"} <= field_names

    command = build_windows_eventlog_command(_request())

    assert command[command.index("--event-ids-json") + 1] == "[6272]"
    assert command[command.index("--end-time-utc") + 1] == "2026-08-01T01:20:00+00:00"


def test_powershell_rejects_bounded_selection_before_process_start() -> None:
    with pytest.raises(ValueError, match="python backend"):
        build_windows_eventlog_command(_request(backend="powershell"))


def test_unbounded_powershell_command_remains_unchanged() -> None:
    command = build_windows_eventlog_command(
        _request(backend="powershell", event_ids=(), end_time_utc=None)
    )

    assert "--event-ids-json" not in command
    assert "--end-time-utc" not in command
    assert not any("EventIds" in item or "EndTime" in item for item in command)


def test_bounded_selection_requires_exact_ids_and_explicit_utc_range() -> None:
    parser = getattr(adapters, "parse_bounded_eventlog_selection", None)
    assert callable(parser), "bounded selection parser is missing"

    selection = parser(
        event_ids_json="[6272]",
        start_time_utc="2026-08-01T01:00:00Z",
        end_time_utc="2026-08-01T01:20:00+00:00",
    )

    assert selection.event_ids == (6272,)
    assert selection.start_time_utc == "2026-08-01T01:00:00+00:00"
    assert selection.end_time_utc == "2026-08-01T01:20:00+00:00"


@pytest.mark.parametrize(
    "event_ids_json",
    [
        "not-json",
        "{}",
        "[]",
        "[true]",
        '["6272"]',
        "[0]",
        "[65536]",
        "[6272,6272]",
        "[" + ",".join(str(value) for value in range(1, 66)) + "]",
    ],
)
def test_bounded_selection_rejects_invalid_event_id_allowlists(event_ids_json: str) -> None:
    with pytest.raises(ValueError, match="event ID"):
        adapters.parse_bounded_eventlog_selection(
            event_ids_json=event_ids_json,
            start_time_utc="2026-08-01T01:00:00Z",
            end_time_utc="2026-08-01T01:20:00Z",
        )


@pytest.mark.parametrize(
    ("start_time_utc", "end_time_utc"),
    [
        (None, "2026-08-01T01:20:00Z"),
        ("2026-08-01T01:00:00Z", None),
        ("2026-08-01T01:00:00", "2026-08-01T01:20:00Z"),
        ("2026-08-01T08:00:00+07:00", "2026-08-01T08:20:00+07:00"),
        ("2026-08-01T01:20:00Z", "2026-08-01T01:00:00Z"),
        ("2026-08-01T01:00:00Z", "2026-08-01T01:00:00Z"),
    ],
)
def test_bounded_selection_rejects_missing_or_invalid_utc_range(
    start_time_utc: str | None,
    end_time_utc: str | None,
) -> None:
    with pytest.raises(ValueError, match="UTC|start/end"):
        adapters.parse_bounded_eventlog_selection(
            event_ids_json="[6272]",
            start_time_utc=start_time_utc,
            end_time_utc=end_time_utc,
        )


def test_no_bounded_parameters_preserves_legacy_selection() -> None:
    assert adapters.parse_bounded_eventlog_selection(
        event_ids_json=None,
        start_time_utc=None,
        end_time_utc=None,
    ) is None


def test_legacy_lower_start_time_does_not_activate_bounded_selection() -> None:
    assert adapters.parse_bounded_eventlog_selection(
        event_ids_json=None,
        start_time_utc="2026-08-01T01:00:00Z",
        end_time_utc=None,
    ) is None


def test_python_xpath_applies_event_id_and_inclusive_utc_bounds_at_query_time() -> None:
    from scripts.collect.collect_windows_events import build_event_xpath

    parameters = signature(build_event_xpath).parameters
    assert {"event_ids", "end_time_utc"} <= set(parameters)

    assert build_event_xpath(
        start_time_utc="2026-08-01T01:00:00+00:00",
        end_time_utc="2026-08-01T01:20:00+00:00",
        event_ids=(6272,),
    ) == (
        "*[System[EventID=6272 and "
        "TimeCreated[@SystemTime >= '2026-08-01T01:00:00.000000Z' and "
        "@SystemTime <= '2026-08-01T01:20:00.000000Z']]]"
    )


def test_python_collector_opens_source_query_with_bounds_before_reading_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.collect.collect_windows_events as collector

    parameters = signature(collector.collect_channel).parameters
    assert {"event_ids", "end_time_utc"} <= set(parameters)

    observed: dict[str, str] = {}
    monkeypatch.setattr(collector, "open_remote_session", lambda computer_name: object())

    def query_events(session: object, channel: str, xpath: str) -> object:
        observed["xpath"] = xpath
        return object()

    def next_event_batch(query: object, batch_size: int, timeout_ms: int) -> list[object]:
        assert "EventID=6272" in observed["xpath"]
        assert "@SystemTime <= '2026-08-01T01:20:00.000000Z'" in observed["xpath"]
        return []

    monkeypatch.setattr(collector, "query_events", query_events)
    monkeypatch.setattr(collector, "next_event_batch", next_event_batch)

    result = collector.collect_channel(
        computer_name="radius01.example.invalid",
        source_name="radius01.example.invalid",
        channel="Security",
        out_file=tmp_path / "Security.jsonl",
        start_time_utc="2026-08-01T01:00:00+00:00",
        end_time_utc="2026-08-01T01:20:00+00:00",
        event_ids=(6272,),
        after_record_id=None,
        max_events=500,
        timeout_seconds=30,
        collect_message=False,
        progress_every=0,
    )

    assert result["status"] == "completed"
    assert result["count"] == 0


def test_python_collector_cli_validates_and_passes_bounded_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.collect.collect_windows_events as collector

    monkeypatch.setattr(collector, "os", SimpleNamespace(name="nt", environ=collector.os.environ))
    observed: dict[str, object] = {}

    def collect_channel(**kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        return {"status": "completed", "count": 0, "error": None}

    monkeypatch.setattr(collector, "win32evtlog", object())
    monkeypatch.setattr(collector, "collect_channel", collect_channel)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "collect_windows_events.py",
            "--computer-name", "radius01.example.invalid",
            "--source-name", "radius01.example.invalid",
            "--channels", "Security",
            "--start-time-utc", "2026-08-01T01:00:00Z",
            "--end-time-utc", "2026-08-01T01:20:00Z",
            "--event-ids-json", "[6272]",
            "--output-root", str(tmp_path),
        ],
    )

    try:
        exit_code = collector.main()
    except SystemExit as exc:  # argparse rejects the missing interface today.
        pytest.fail(f"bounded collector CLI rejected the request: {exc.code}")

    assert exit_code == 0
    assert observed["event_ids"] == (6272,)
    assert observed["end_time_utc"] == "2026-08-01T01:20:00+00:00"


def _registered_route() -> dict[str, object]:
    return {
        "source_name": "radius01.example.invalid",
        "source_instance_id": "radius01.example.invalid",
        "event_log_ready": True,
        "event_log_adapter": "windows-eventlog-pywin32",
    }


def _admit(**overrides: object) -> object:
    import scripts.run_dc_log_pilot as runner

    admit = getattr(runner, "validate_bounded_nps_admission", None)
    assert callable(admit), "bounded NPS admission is missing"
    assert {
        "collect_message",
        "max_events_per_channel",
        "channel_timeout_seconds",
        "command_timeout_seconds",
    } <= set(signature(admit).parameters)
    values: dict[str, object] = {
        "event_ids_json": "[6272]",
        "start_time_utc": "2026-08-01T01:00:00Z",
        "end_time_utc": "2026-08-01T01:20:00Z",
        "requested_backend": "python",
        "server": "radius01.example.invalid",
        "connect_address": "radius01.example.invalid",
        "channels": ("Security",),
        "archive": False,
        "use_record_id_cursor": False,
        "adaptive_state_mode": "observe",
        "collect_message": False,
        "max_events_per_channel": 500,
        "channel_timeout_seconds": 30,
        "command_timeout_seconds": 60,
        "route_loader": _registered_route,
    }
    values.update(overrides)
    return admit(**values)


def test_bounded_nps_admission_accepts_only_the_registered_route() -> None:
    selection = _admit()

    assert selection.event_ids == (6272,)


def _admit_source_continuity_canary(**overrides: object) -> object:
    import scripts.run_dc_log_pilot as runner

    admit = getattr(runner, "validate_bounded_source_continuity_canary_admission", None)
    assert callable(admit), "source-continuity canary admission is missing"
    values: dict[str, object] = {
        "event_ids_json": json.dumps(sorted(AUTHENTICATION_EVENT_KEYS)),
        "start_time_utc": "2026-08-01T01:00:00Z",
        "end_time_utc": "2026-08-01T01:20:00Z",
        "requested_backend": "python",
        "channels": ("Security",),
        "archive": True,
        "use_record_id_cursor": True,
        "adaptive_state_mode": "update",
        "collect_message": False,
        "max_events_per_channel": 5000,
        "channel_timeout_seconds": 120,
        "command_timeout_seconds": 180,
    }
    values.update(overrides)
    return admit(**values)


def test_source_continuity_canary_admission_accepts_exact_security_contract() -> None:
    selection = _admit_source_continuity_canary()

    assert selection.event_ids == tuple(sorted(AUTHENTICATION_EVENT_KEYS))


def test_source_continuity_canary_admission_rejects_unsorted_selector_drift() -> None:
    with pytest.raises(ValueError, match="source_continuity_canary_event_ids_mismatch"):
        _admit_source_continuity_canary(
            event_ids_json=json.dumps(list(reversed(sorted(AUTHENTICATION_EVENT_KEYS)))),
        )


def test_source_continuity_canary_command_reaches_collector_with_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.collect.collect_windows_events as collector

    monkeypatch.setattr(collector, "os", SimpleNamespace(name="nt", environ=collector.os.environ))
    observed: dict[str, object] = {}

    def collect_channel(**kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        return {"status": "completed", "count": 0, "error": None}

    command = build_windows_eventlog_command(_request(
        max_events_per_channel=5000,
        channel_timeout_seconds=120,
        channel_after_record_ids={"Security": 42},
        channel_cursor_generations={"Security": "saved-generation"},
        event_ids=tuple(sorted(AUTHENTICATION_EVENT_KEYS)),
        source_continuity_canary=True,
        output_root=tmp_path,
    ))

    assert "--source-continuity-canary" in command
    assert command[command.index("--channel-after-record-ids-json") + 1] == '{"Security": 42}'
    assert command[command.index("--channel-cursor-generations-json") + 1] == '{"Security": "saved-generation"}'
    monkeypatch.setattr(collector, "win32evtlog", object())
    monkeypatch.setattr(collector, "collect_channel", collect_channel)
    monkeypatch.setattr(sys, "argv", [command[1], *command[2:]])

    assert collector.main() == 0
    assert observed["after_record_id"] == 42
    assert observed["saved_channel_generation_identity"] == "saved-generation"


@pytest.mark.parametrize(
    "overrides",
    [
        {"server": "other.example.invalid"},
        {"connect_address": "other.example.invalid"},
        {"route_loader": lambda: (_ for _ in ()).throw(RuntimeError("unregistered"))},
        {"requested_backend": "auto"},
        {"requested_backend": "powershell"},
        {"channels": ("Security", "System")},
        {"archive": True},
        {"use_record_id_cursor": True},
        {"adaptive_state_mode": "update"},
        {"collect_message": True},
        {"max_events_per_channel": 0},
        {"max_events_per_channel": 501},
        {"channel_timeout_seconds": 0},
        {"channel_timeout_seconds": 61},
        {"command_timeout_seconds": 0},
        {"command_timeout_seconds": 76},
    ],
)
def test_bounded_nps_admission_rejects_route_or_runtime_scope_drift(
    overrides: dict[str, object],
) -> None:
    with pytest.raises((RuntimeError, ValueError)):
        _admit(**overrides)


def test_unbounded_runner_request_does_not_require_radius_registration() -> None:
    contacted = False

    def route_loader() -> dict[str, object]:
        nonlocal contacted
        contacted = True
        raise AssertionError("normal collection must not load the RADIUS route")

    assert _admit(
        event_ids_json=None,
        start_time_utc=None,
        end_time_utc=None,
        requested_backend="auto",
        channels=(),
        adaptive_state_mode="update",
        collect_message=False,
        max_events_per_channel=200,
        channel_timeout_seconds=300,
        command_timeout_seconds=600,
        use_record_id_cursor=True,
        route_loader=route_loader,
    ) is None
    assert contacted is False


def test_runner_rejects_route_mismatch_before_source_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.run_dc_log_pilot as runner

    source_command_called = False

    def run_command(*args: object, **kwargs: object) -> object:
        nonlocal source_command_called
        source_command_called = True
        raise AssertionError("source command must not run after failed admission")

    monkeypatch.setattr(runner, "load_radius_collection_routes", _registered_route)
    monkeypatch.setattr(runner, "run_command", run_command)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_dc_log_pilot.py",
            "--server", "other.example.invalid",
            "--connect-address", "other.example.invalid",
            "--channels", "Security",
            "--collector-backend", "python",
            "--start-time-utc", "2026-08-01T01:00:00Z",
            "--end-time-utc", "2026-08-01T01:20:00Z",
            "--event-ids-json", "[6272]",
            "--adaptive-state-mode", "observe",
            "--use-record-id-cursor", "false",
        ],
    )

    try:
        exit_code = runner.main()
    except SystemExit as exc:
        pytest.fail(f"runner bounded CLI rejected the request before admission: {exc.code}")

    assert exit_code == 64
    assert source_command_called is False


def test_collector_fails_before_persisting_event_outside_bounded_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.collect.collect_windows_events as collector

    batches: list[list[object]] = [[object()], []]
    monkeypatch.setattr(collector, "open_remote_session", lambda computer_name: object())
    monkeypatch.setattr(collector, "query_events", lambda session, channel, xpath: object())
    monkeypatch.setattr(collector, "next_event_batch", lambda query, batch_size, timeout_ms: batches.pop(0))
    monkeypatch.setattr(collector, "render_event_xml", lambda event: "<Event />")
    monkeypatch.setattr(
        collector,
        "parse_event_xml",
        lambda *args, **kwargs: {
            "event_id": 4624,
            "time_created": "2026-08-01T01:10:00.000000Z",
            "record_id": 1,
        },
    )
    out_file = tmp_path / "Security.jsonl"

    result = collector.collect_channel(
        computer_name="radius01.example.invalid",
        source_name="radius01.example.invalid",
        channel="Security",
        out_file=out_file,
        start_time_utc="2026-08-01T01:00:00+00:00",
        end_time_utc="2026-08-01T01:20:00+00:00",
        event_ids=(6272,),
        after_record_id=None,
        max_events=500,
        timeout_seconds=30,
        collect_message=False,
        progress_every=0,
    )

    assert result["status"] == "failed"
    assert result["count"] == 0
    assert out_file.read_text(encoding="utf-8") == ""


def test_python_collector_rejects_bounded_cursor_before_source_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.collect.collect_windows_events as collector

    source_contacted = False

    def collect_channel(**kwargs: object) -> dict[str, object]:
        nonlocal source_contacted
        source_contacted = True
        raise AssertionError("bounded cursor must fail before collection")

    monkeypatch.setattr(collector, "win32evtlog", object())
    monkeypatch.setattr(collector, "collect_channel", collect_channel)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "collect_windows_events.py",
            "--computer-name", "radius01.example.invalid",
            "--source-name", "radius01.example.invalid",
            "--channels", "Security",
            "--start-time-utc", "2026-08-01T01:00:00Z",
            "--end-time-utc", "2026-08-01T01:20:00Z",
            "--event-ids-json", "[6272]",
            "--channel-after-record-ids-json", '{"Security":42}',
            "--output-root", str(tmp_path),
        ],
    )

    assert collector.main() == 12
    assert source_contacted is False
