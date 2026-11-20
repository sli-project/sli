from __future__ import annotations

"""Pure admission contract for the continuous NPS Security Event Log stage.

This module intentionally neither loads credentials nor contacts the source.
Callers must resolve the endpoint here before asking the DPAPI credential
boundary for the ``vpn`` profile.
"""

from datetime import datetime
import re
from typing import Any, Callable, Mapping

from server.source_packs.adapters import BoundedWindowsEventLogSelection, parse_bounded_eventlog_selection
from server.source_packs.radius.collection_routes import load_radius_collection_routes
from server.source_packs.windows_nps_radius import EVENT_IDS, PACK_ID, PROVIDER, STREAM


_FQDN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_DPAPI_CURRENT_USER = "dpapi_current_user"
_PYTHON_ADAPTER = "windows-eventlog-pywin32"


def _route_value(route: Mapping[str, Any], field: str) -> str:
    value = str(route.get(field) or "").strip()
    if not value:
        raise RuntimeError("nps_eventlog_registered_route_required")
    return value


def _registered_source(route: Mapping[str, Any]) -> str:
    source_name = _route_value(route, "source_name")
    source_instance_id = _route_value(route, "source_instance_id")
    if (
        _FQDN.fullmatch(source_name) is None
        or source_name.casefold() != source_instance_id.casefold()
        or not str(route.get("owner_confirmed_ip") or "").strip()
        or route.get("event_log_ready") is not True
        or route.get("event_log_adapter") != _PYTHON_ADAPTER
    ):
        raise RuntimeError("nps_eventlog_registered_route_required")
    return source_name


def resolve_nps_eventlog_endpoint(
    server: str,
    *,
    connect_address: str | None = None,
    route_loader: Callable[[], Mapping[str, Any]] = load_radius_collection_routes,
) -> str:
    """Return the exact registered FQDN without DNS/RPC or credential access."""
    route = route_loader()
    registered = _registered_source(route)
    requested_server = str(server or "").strip()
    requested_connect = str(connect_address if connect_address is not None else server or "").strip()
    if (
        _FQDN.fullmatch(requested_server) is None
        or _FQDN.fullmatch(requested_connect) is None
        or requested_server.casefold() != registered.casefold()
        or requested_connect.casefold() != registered.casefold()
    ):
        raise RuntimeError("nps_eventlog_endpoint_invalid")
    return registered


def validate_continuous_nps_admission(
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
    ad_source_credential_mode: str,
    allow_source_contact: bool,
    route_loader: Callable[[], Mapping[str, Any]] = load_radius_collection_routes,
) -> BoundedWindowsEventLogSelection:
    """Validate the one continuous NPS selector before any source or secret use."""
    selection = parse_bounded_eventlog_selection(
        event_ids_json=event_ids_json,
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
    )
    if selection is None or selection.event_ids != EVENT_IDS:
        raise ValueError("continuous_nps_event_ids_mismatch")
    start = datetime.fromisoformat(selection.start_time_utc)
    end = datetime.fromisoformat(selection.end_time_utc)
    if end <= start:
        raise ValueError("continuous_nps_time_window_invalid")
    if requested_backend != "python":
        raise ValueError("continuous_nps_python_backend_required")
    if channels != (STREAM,):
        raise ValueError("continuous_nps_security_channel_required")
    if not archive or not use_record_id_cursor:
        raise ValueError("continuous_nps_cursor_archive_required")
    if adaptive_state_mode != "observe":
        raise ValueError("continuous_nps_adaptive_state_required")
    if collect_message:
        raise ValueError("continuous_nps_message_collection_forbidden")
    if not 1 <= int(max_events_per_channel) <= 50_000:
        raise ValueError("continuous_nps_event_limit_invalid")
    if not 1 <= int(channel_timeout_seconds) <= 60:
        raise ValueError("continuous_nps_channel_timeout_invalid")
    if not 1 <= int(command_timeout_seconds) <= 90:
        raise ValueError("continuous_nps_command_timeout_invalid")
    if ad_source_credential_mode != _DPAPI_CURRENT_USER:
        raise ValueError("continuous_nps_dpapi_required")
    if allow_source_contact is not True:
        raise ValueError("continuous_nps_source_contact_not_allowed")

    # The route loader validates the immutable pack/provider/IDs contract.  Keep
    # these named constants here so a changed pack cannot be silently borrowed.
    if not (PACK_ID == "sli.windows.vpn-radius" and PROVIDER == "Microsoft-Windows-Security-Auditing"):
        raise RuntimeError("continuous_nps_source_pack_mismatch")
    resolve_nps_eventlog_endpoint(
        server, connect_address=connect_address, route_loader=route_loader,
    )
    return selection
