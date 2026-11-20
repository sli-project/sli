"""NPS-only transport wiring; no Windows source contact."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from server.source_packs.adapters import WindowsEventLogRequest, build_windows_eventlog_command


def _request(**overrides: object) -> WindowsEventLogRequest:
    values: dict[str, object] = {
        "backend": "python", "python_executable": "python", "python_script": Path("collector.py"),
        "powershell_script": Path("collector.ps1"), "computer_name": "radius01.example.test",
        "source_name": "radius01.example.test", "hours": 1, "max_events_per_channel": 50_000,
        "channel_timeout_seconds": 60, "output_root": Path("raw"), "channels": ("Security",),
        "collection_mode": "current", "collect_message": False,
        "channel_limits": {"Security": 50_000}, "channel_timeouts": {"Security": 60},
        "start_time_utc": "2026-09-09T00:00:00Z", "channel_start_times": {"Security": "2026-09-09T00:00:00Z"},
        "channel_after_record_ids": {"Security": 44}, "event_ids": (6272, 6273),
        "end_time_utc": "2026-09-09T01:00:00Z", "channel_cursor_generations": {"Security": "g1"},
        "ad_source_credential_mode": "dpapi_current_user", "nps_continuous": True,
    }
    values.update(overrides)
    return WindowsEventLogRequest(**values)  # type: ignore[arg-type]


def test_nps_request_forwards_explicit_python_mode_only() -> None:
    command = build_windows_eventlog_command(_request())

    assert "--nps-continuous" in command
    assert "--source-continuity-canary" not in command


def test_default_request_does_not_add_nps_flag() -> None:
    command = build_windows_eventlog_command(_request(nps_continuous=False))

    assert "--nps-continuous" not in command


def test_nps_session_resolves_route_before_loading_vpn_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.collect import collect_windows_events as collector

    calls: list[object] = []
    monkeypatch.setattr(collector, "win32evtlog", SimpleNamespace(EvtRpcLogin=1, EvtRpcLoginAuthDefault=0,
        EvtOpenSession=lambda login, *_: calls.append(login) or object()))
    import server.source_packs.nps_eventlog_runtime as nps
    monkeypatch.setattr(nps, "resolve_nps_eventlog_endpoint", lambda *args, **kwargs: "radius01.example.test")
    import server.sli.sources.ad_source_credentials as credentials
    monkeypatch.setattr(credentials, "load_credentials", lambda *, profile: (
        calls.append(profile) or credentials.AdSourceCredentials("vpn@example.test", "synthetic")))

    collector.open_remote_session(
        "radius01.example.test", ad_source_credential_mode="dpapi_current_user", nps_continuous=True,
    )

    assert calls[0] == "vpn"
    assert calls[1] == ("radius01.example.test", "vpn@example.test", None, "synthetic", 0)


@pytest.mark.parametrize("provider", ["Wrong-Provider", "Microsoft-Windows-Security-Auditing"])
@pytest.mark.parametrize("nps_continuous", [True, False])
def test_provider_constraint_is_enforced_before_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provider: str, nps_continuous: bool,
) -> None:
    from scripts.collect import collect_windows_events as collector

    parsed = []
    rejected = []
    xpaths = []
    parse_xml = collector.parse_event_xml
    validate_row = collector.validate_bounded_event_row

    def parse(*args, **kwargs):
        row = parse_xml(*args, **kwargs)
        parsed.append(row["provider_name"])
        return row

    def validate(*args, **kwargs):
        try:
            return validate_row(*args, **kwargs)
        except RuntimeError as exc:
            rejected.append(str(exc))
            raise

    monkeypatch.setattr(collector, "parse_event_xml", parse)
    monkeypatch.setattr(collector, "validate_bounded_event_row", validate)
    monkeypatch.setattr(collector, "open_remote_session", lambda _computer, **_: object())
    monkeypatch.setattr(collector, "probe_channel_state", lambda *_: {
        "latest_record_id": 50, "oldest_record_id": 1, "generation_identity": "g1",
    })
    monkeypatch.setattr(
        collector, "query_events",
        lambda _session, _channel, xpath: xpaths.append(xpath) or object(),
    )
    batches = [[object()], []]
    monkeypatch.setattr(collector, "next_event_batch", lambda *args: batches.pop(0))
    # Real parsing supplies packet-required xml, computer_name and channel.
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>6272</EventID>'
        '<TimeCreated SystemTime="2026-09-09T00:30:00Z"/>'
        '<EventRecordID>45</EventRecordID></System></Event>'
    )
    monkeypatch.setattr(collector, "render_event_xml", lambda _: xml)
    logged_errors = []
    monkeypatch.setattr(
        collector, "log_internal_error",
        lambda *args, **kwargs: logged_errors.append(str(kwargs["exc"])),
    )

    result = collector.collect_channel(
        computer_name="radius01.example.test", source_name="radius01.example.test", channel="Security",
        out_file=tmp_path / "Security.jsonl", start_time_utc="2026-09-09T00:00:00Z",
        end_time_utc="2026-09-09T01:00:00Z", event_ids=(6272, 6273), after_record_id=None,
        saved_channel_generation_identity="g1", max_events=50_000, timeout_seconds=60,
        collect_message=False, progress_every=0, ad_source_credential_mode="dpapi_current_user",
        nps_continuous=nps_continuous,
    )

    assert parsed == [provider]
    predicate = "Provider[@Name='Microsoft-Windows-Security-Auditing']"
    assert (predicate in xpaths[0]) is nps_continuous
    output = (tmp_path / "Security.jsonl").read_text(encoding="utf-8")
    if nps_continuous and provider == "Wrong-Provider":
        assert rejected == ["bounded_selection_provider_mismatch"]
        assert result["status"] == "failed"
        # Credential-mode failures must retain the sanitized public error.
        assert result["error"] == "ad_source_rpc_failed"
        assert logged_errors == [result["error"]]
        assert result["count"] == 0
        assert output == ""
    else:
        assert rejected == []
        assert logged_errors == []
        assert result["status"] == "completed"
        assert result["count"] == 1
        packet = json.loads(output)
        assert packet["records"][0]["payload"]["provider_name"] == provider


def test_nps_first_cycle_freezes_channel_and_persists_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cursorless bootstrap still needs a generation for cycle two."""
    from scripts.collect import collect_windows_events as collector

    xpaths: list[str] = []
    states = iter([
        {"latest_record_id": 50, "oldest_record_id": 1, "generation_identity": "nps-generation-1"},
        {"latest_record_id": 50, "oldest_record_id": 1, "generation_identity": "nps-generation-1"},
    ])
    monkeypatch.setattr(collector, "open_remote_session", lambda *args, **kwargs: object())
    monkeypatch.setattr(collector, "probe_channel_state", lambda *args, **kwargs: next(states))
    monkeypatch.setattr(
        collector, "query_events",
        lambda _session, _channel, xpath: xpaths.append(xpath) or object(),
    )
    monkeypatch.setattr(collector, "next_event_batch", lambda *args: [])

    result = collector.collect_channel(
        computer_name="radius01.example.test", source_name="radius01.example.test", channel="Security",
        out_file=tmp_path / "Security.jsonl", start_time_utc="2026-09-10T14:00:00Z",
        end_time_utc="2026-09-10T15:00:00Z", event_ids=(6272, 6273), after_record_id=None,
        max_events=50_000, timeout_seconds=60, collect_message=False, progress_every=0,
        ad_source_credential_mode="dpapi_current_user", nps_continuous=True,
    )

    assert "EventRecordID <= 50" in xpaths[0]
    assert result["channel_generation_identity"] == "nps-generation-1"
    assert result["channel_generation_identity_after_read"] == "nps-generation-1"


def test_nps_cli_second_cursor_cycle_reaches_collection_after_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.collect import collect_windows_events as collector

    monkeypatch.setattr(collector, "os", SimpleNamespace(name="nt", environ=collector.os.environ))
    observed: dict[str, object] = {}
    monkeypatch.setattr(collector, "win32evtlog", object())
    monkeypatch.setattr(collector, "collect_channel", lambda **kwargs: observed.update(kwargs) or {
        "status": "completed", "count": 0, "error": None,
    })
    monkeypatch.setattr(sys, "argv", [
        "collect_windows_events.py", "--nps-continuous", "--computer-name", "radius01.example.test",
        "--source-name", "radius01.example.test", "--ad-source-credential-mode", "dpapi_current_user",
        "--channels", "Security", "--start-time-utc", "2026-08-01T00:00:00Z",
        "--end-time-utc", "2026-09-09T00:00:00Z", "--event-ids-json", "[6272,6273]",
        "--max-events-per-channel", "50000", "--channel-timeout-seconds", "60",
        "--channel-after-record-ids-json", '{"Security":42}',
        "--channel-cursor-generations-json", '{"Security":"generation-1"}',
        "--output-root", str(tmp_path),
    ])

    assert collector.main() == 0
    assert observed["after_record_id"] == 42
    assert observed["saved_channel_generation_identity"] == "generation-1"
    assert observed["nps_continuous"] is True


@pytest.mark.parametrize("extra", [
    ["--max-events-per-channel", "50001", "--channel-limits-json", '{"Security":1}'],
    ["--max-events-per-channel", "10", "--channel-limits-json", '{"Security":50000}'],
    ["--channel-after-record-ids-json", '{"Security":0}'],
    ["--channel-cursor-generations-json", '{"Security":""}'],
])
def test_nps_cli_rejects_invalid_effective_cursor_or_ceiling_before_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: list[str],
) -> None:
    from scripts.collect import collect_windows_events as collector

    monkeypatch.setattr(collector, "win32evtlog", object())
    monkeypatch.setattr(collector, "collect_channel", lambda **_: pytest.fail("source collection must not start"))
    monkeypatch.setattr(sys, "argv", [
        "collect_windows_events.py", "--nps-continuous", "--computer-name", "radius01.example.test",
        "--source-name", "radius01.example.test", "--ad-source-credential-mode", "dpapi_current_user",
        "--channels", "Security", "--start-time-utc", "2026-08-01T00:00:00Z",
        "--end-time-utc", "2026-09-09T00:00:00Z", "--event-ids-json", "[6272,6273]",
        "--max-events-per-channel", "50000", "--channel-timeout-seconds", "60",
        "--output-root", str(tmp_path), *extra,
    ])

    assert collector.main() == 12
