"""Pure admission contract for the continuous NPS Event Log stage."""
from __future__ import annotations

import pytest


def _route() -> dict[str, object]:
    return {
        "source_name": "radius01.example.test",
        "source_instance_id": "radius01.example.test",
        "owner_confirmed_ip": "198.51.100.23",
        "event_log_ready": True,
        "event_log_adapter": "windows-eventlog-pywin32",
    }


def _admit(**overrides: object):
    from server.source_packs.nps_eventlog_runtime import validate_continuous_nps_admission

    values: dict[str, object] = {
        "event_ids_json": "[6272,6273]",
        "start_time_utc": "2026-09-09T00:00:00Z",
        "end_time_utc": "2026-09-09T01:00:00Z",
        "requested_backend": "python",
        "server": "radius01.example.test",
        "connect_address": "radius01.example.test",
        "channels": ("Security",),
        "archive": True,
        "use_record_id_cursor": True,
        "adaptive_state_mode": "observe",
        "collect_message": False,
        "max_events_per_channel": 50_000,
        "channel_timeout_seconds": 60,
        "command_timeout_seconds": 90,
        "ad_source_credential_mode": "dpapi_current_user",
        "allow_source_contact": True,
        "route_loader": _route,
    }
    values.update(overrides)
    return validate_continuous_nps_admission(**values)


def test_continuous_nps_admission_accepts_exact_fenced_contract() -> None:
    selection = _admit()

    assert selection.event_ids == (6272, 6273)
    assert selection.start_time_utc == "2026-09-09T00:00:00+00:00"


@pytest.mark.parametrize("overrides", [
    {"event_ids_json": "[6272]"},
    {"event_ids_json": "[6273,6272]"},
    {"start_time_utc": "2026-09-09T01:00:00Z"},
    {"requested_backend": "powershell"},
    {"server": "other.example.test"},
    {"connect_address": "other.example.test"},
    {"channels": ("Security", "System")},
    {"archive": False},
    {"use_record_id_cursor": False},
    {"adaptive_state_mode": "update"},
    {"collect_message": True},
    {"max_events_per_channel": 0},
    {"max_events_per_channel": 50_001},
    {"channel_timeout_seconds": 0},
    {"channel_timeout_seconds": 61},
    {"command_timeout_seconds": 0},
    {"command_timeout_seconds": 91},
    {"ad_source_credential_mode": "process"},
    {"allow_source_contact": False},
    {"route_loader": lambda: {**_route(), "event_log_ready": False}},
])
def test_continuous_nps_admission_rejects_every_contract_drift(overrides: dict[str, object]) -> None:
    with pytest.raises((RuntimeError, ValueError)):
        _admit(**overrides)


def test_continuous_nps_admission_keeps_a_long_explicit_recovery_window() -> None:
    selection = _admit(start_time_utc="2026-08-01T00:00:00Z")

    assert selection.start_time_utc == "2026-08-01T00:00:00+00:00"


@pytest.mark.parametrize("server,connect_address", [
    ("radius01.example.test", "radius01.example.test"),
    ("RADIUS01.EXAMPLE.TEST", "RADIUS01.EXAMPLE.TEST"),
])
def test_nps_endpoint_resolver_admits_only_registered_fqdn(server: str, connect_address: str) -> None:
    from server.source_packs.nps_eventlog_runtime import resolve_nps_eventlog_endpoint

    assert resolve_nps_eventlog_endpoint(
        server, connect_address=connect_address, route_loader=_route,
    ) == "radius01.example.test"


@pytest.mark.parametrize("server,connect_address", [
    ("198.51.100.23", "198.51.100.23"),
    ("radius01.example.test", "198.51.100.23"),
    ("radius01.example.test.", "radius01.example.test."),
    ("other.example.test", "other.example.test"),
])
def test_nps_endpoint_resolver_rejects_before_any_secret_load(server: str, connect_address: str) -> None:
    from server.source_packs.nps_eventlog_runtime import resolve_nps_eventlog_endpoint

    with pytest.raises(RuntimeError, match="nps_eventlog_endpoint_invalid"):
        resolve_nps_eventlog_endpoint(server, connect_address=connect_address, route_loader=_route)
