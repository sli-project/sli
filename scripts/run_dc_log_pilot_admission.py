"""Split out of ``scripts.run_dc_log_pilot`` (plan 6.3): admission gates and collector backend selection.

Module-level names of ``run_dc_log_pilot`` are looked up through ``_src`` at
call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

import scripts.run_dc_log_pilot as _src


def validate_bounded_nps_admission(
    *,
    event_ids_json: str | None,
    start_time_utc: str | None,
    end_time_utc: str | None,
    requested_backend: str,
    server: str,
    connect_address: str,
    channels: tuple[str, ...],
    archive: bool,
    use_record_id_cursor: bool,
    adaptive_state_mode: str,
    collect_message: bool,
    max_events_per_channel: int,
    channel_timeout_seconds: int,
    command_timeout_seconds: int,
    route_loader: Callable[[], Mapping[str, Any]] = _src.load_radius_collection_routes,
) -> _src.BoundedWindowsEventLogSelection | None:
    if event_ids_json is None and end_time_utc is None:
        return None
    selection = _src.parse_bounded_eventlog_selection(
        event_ids_json=event_ids_json,
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
    )
    if selection is None:  # pragma: no cover - guarded by the explicit parameters above.
        raise ValueError("bounded_nps_selection_missing")
    if selection.event_ids != (6272,):
        raise ValueError("bounded_nps_event_ids_mismatch")
    if requested_backend != "python":
        raise ValueError("bounded_nps_python_backend_required")
    if channels != ("Security",):
        raise ValueError("bounded_nps_security_channel_required")
    if archive or use_record_id_cursor or adaptive_state_mode != "observe":
        raise ValueError("bounded_nps_runtime_state_mutation_forbidden")
    if collect_message:
        raise ValueError("bounded_nps_message_collection_forbidden")
    if not 1 <= int(max_events_per_channel) <= 500:
        raise ValueError("bounded_nps_event_limit_invalid")
    if not 1 <= int(channel_timeout_seconds) <= 60:
        raise ValueError("bounded_nps_channel_timeout_invalid")
    if not 1 <= int(command_timeout_seconds) <= 75:
        raise ValueError("bounded_nps_command_timeout_invalid")

    route = route_loader()
    registered_source = str(route.get("source_name") or "").strip()
    registered_identity = str(route.get("source_instance_id") or "").strip()
    if (
        not registered_source
        or not registered_identity
        or route.get("event_log_ready") is not True
        or route.get("event_log_adapter") != _src.WINDOWS_EVENTLOG_PYTHON
    ):
        raise ValueError("bounded_nps_registered_route_required")
    if server.casefold() != registered_source.casefold():
        raise ValueError("bounded_nps_server_mismatch")
    if connect_address.casefold() != registered_source.casefold():
        raise ValueError("bounded_nps_connect_address_mismatch")
    return selection


def validate_bounded_source_continuity_canary_admission(
    *,
    event_ids_json: str | None,
    start_time_utc: str | None,
    end_time_utc: str | None,
    requested_backend: str,
    channels: tuple[str, ...],
    archive: bool,
    use_record_id_cursor: bool,
    adaptive_state_mode: str,
    collect_message: bool,
    max_events_per_channel: int,
    channel_timeout_seconds: int,
    command_timeout_seconds: int,
) -> _src.BoundedWindowsEventLogSelection:
    """Admit one explicit, bounded Security continuity declaration canary."""
    selection = _src.parse_bounded_eventlog_selection(
        event_ids_json=event_ids_json,
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
    )
    if selection is None:  # pragma: no cover - the explicit canary flag requires a selection.
        raise ValueError("source_continuity_canary_selection_missing")
    if selection.event_ids != tuple(sorted(_src.AUTHENTICATION_EVENT_KEYS)):
        raise ValueError("source_continuity_canary_event_ids_mismatch")
    if requested_backend != "python":
        raise ValueError("source_continuity_canary_python_backend_required")
    if channels != ("Security",):
        raise ValueError("source_continuity_canary_security_channel_required")
    if not archive or not use_record_id_cursor:
        raise ValueError("source_continuity_canary_record_cursor_required")
    if adaptive_state_mode != "update":
        raise ValueError("source_continuity_canary_adaptive_update_required")
    if collect_message:
        raise ValueError("source_continuity_canary_message_collection_forbidden")
    if type(max_events_per_channel) is not int or not 1 <= max_events_per_channel <= 5000:
        raise ValueError("source_continuity_canary_event_limit_invalid")
    if type(channel_timeout_seconds) is not int or not 1 <= channel_timeout_seconds <= 120:
        raise ValueError("source_continuity_canary_channel_timeout_invalid")
    if type(command_timeout_seconds) is not int or not 1 <= command_timeout_seconds <= 180:
        raise ValueError("source_continuity_canary_command_timeout_invalid")
    return selection


def apply_collection_not_before_floor(
    channel_plan: dict[str, dict[str, object]],
    floor_utc: str | None,
) -> dict[str, dict[str, object]]:
    """Keep an explicitly retired event range out of a cursor recovery cycle.

    A retained EventRecordID may legitimately point below a destructive
    retention boundary.  In that case the first post-retention read must use
    the time floor instead of replaying the retired record-id backlog.  The
    durable cursor is still advanced only by the normal successful import.
    """
    raw_floor = str(floor_utc or "").strip()
    if not raw_floor:
        return {channel: dict(item) for channel, item in channel_plan.items()}
    floor = datetime.fromisoformat(raw_floor.replace("Z", "+00:00"))
    if floor.tzinfo is None:
        raise ValueError("ADLOG_COLLECTION_NOT_BEFORE_UTC must include a timezone")
    floor = floor.astimezone(timezone.utc)
    floor_text = floor.isoformat()
    result: dict[str, dict[str, object]] = {}
    for channel, source in channel_plan.items():
        item = dict(source)
        start_raw = str(item.get("start_time_utc") or "").strip()
        start = (
            datetime.fromisoformat(start_raw.replace("Z", "+00:00"))
            if start_raw
            else None
        )
        if start is not None and start.tzinfo is None:
            raise ValueError("channel start_time_utc must include a timezone")
        cursor_time_known = "cursor_event_time_utc" in item
        cursor_time_raw = str(item.get("cursor_event_time_utc") or "").strip()
        cursor_time = (
            datetime.fromisoformat(cursor_time_raw.replace("Z", "+00:00"))
            if cursor_time_raw
            else None
        )
        if cursor_time is not None and cursor_time.tzinfo is None:
            raise ValueError("cursor_event_time_utc must include a timezone")
        cursor_before_floor = (
            cursor_time is not None
            and cursor_time.astimezone(timezone.utc) < floor
        )
        cursor_time_unproven = (
            cursor_time_known
            and cursor_time is None
            and item.get("after_record_id") is not None
        )
        if (
            start is None
            or start.astimezone(timezone.utc) < floor
            or cursor_before_floor
            or cursor_time_unproven
        ):
            if start is None or start.astimezone(timezone.utc) < floor:
                item["start_time_utc"] = floor_text
            item["after_record_id"] = None
            item["not_before_floor_applied"] = True
        result[channel] = item
    return result


class CollectorBackendUnavailableError(RuntimeError):
    """The Python Windows Event backend is unavailable and no explicit
    backend override was given, so there is no automatic fallback left to
    try. See choose_collector_backend()."""


def python_collector_available() -> tuple[bool, str]:
    """Return whether the central host can run the Python Windows Event backend."""
    if os.name != "nt":
        return False, "not_windows"
    try:
        import win32evtlog  # type: ignore  # noqa: F401
    except Exception as exc:  # pragma: no cover - depends on Windows collector host
        return False, f"pywin32_unavailable: {exc}"
    return True, "available"


def choose_collector_backend(requested: str) -> tuple[str, str]:
    """Choose collector backend.

    Production runs the Python Windows Event backend only, and `auto` (the
    default) requires it to be available -- a real production collector
    host is always Windows with pywin32 installed, so the absence of
    either is a genuine misconfiguration worth failing closed on, not a
    condition to silently paper over by switching backends. PowerShell
    remains available, but only as an explicit, operator-chosen backend
    (`--collector-backend powershell` / ADLOG_COLLECTOR_BACKEND=powershell)
    for diagnostics, rollback, or manual runs -- it is no longer an
    automatic production fallback. No Python is required on DCs; both
    backends run from the central collector host unless the optional DC
    spool client is installed separately.
    """
    clean = (requested or "auto").strip().lower()
    if clean in {"powershell", "ps"}:
        return "powershell", "forced_powershell"
    if clean in {"python", "py"}:
        return "python", "forced_python"
    available, reason = _src.python_collector_available()
    if not available:
        raise _src.CollectorBackendUnavailableError(
            f"python_collector_unavailable:{reason}"
        )
    return "python", "auto_python_available"


def append_powershell_bool_param(command: list[str], name: str, enabled: bool) -> None:
    """Append a PowerShell boolean parameter using syntax safe for -File argv.

    Passing [bool] script parameters as two argv tokens, for example
    ``-CollectMessage False``, reaches PowerShell as a plain string and can fail
    with ParameterArgumentTransformationError. The colon form keeps the command
    unambiguous in logs. ``Collect-DcEventsLastHour.ps1`` still normalizes the
    value itself because Windows PowerShell ``-File`` can deliver even colon
    boolean arguments from external callers as strings.
    """
    command.append(f"-{name}:${str(bool(enabled)).lower()}")
