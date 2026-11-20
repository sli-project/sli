from __future__ import annotations

"""Fail-closed routing for NPS Event Log and RADIUS Accounting acquisition."""

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from server.sli.core.paths import ROOT
from server.source_packs.registry import validate_adapter_for_pack
from server.source_packs.windows_nps_radius import EVENT_IDS, PACK_ID, PROVIDER, STREAM

CONFIG_PATH = ROOT / "config" / "stage10_radius_collection_routes_v1.json"
_ADMIN_SHARES = frozenset({"c$", "admin$", "ipc$"})
_UNC_SHARE = re.compile(r"^\\\\([^\\]+)\\([^\\]+)\\?$")


class RadiusCollectionRouteError(RuntimeError):
    pass


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RadiusCollectionRouteError(f"{name}_object_required")
    return dict(value)


def _dedicated_share_path(value: Any, *, expected_host: str) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    match = _UNC_SHARE.fullmatch(text)
    if match is None:
        raise RadiusCollectionRouteError("dedicated_share_unc_required")
    host = match.group(1).casefold()
    share = match.group(2).casefold()
    if host != expected_host.casefold():
        raise RadiusCollectionRouteError("dedicated_share_host_mismatch")
    if share in _ADMIN_SHARES:
        raise RadiusCollectionRouteError("administrative_share_forbidden")
    return text


def validate_radius_collection_routes(value: Mapping[str, Any]) -> dict[str, Any]:
    config = _object(value, "route_contract")
    if int(config.get("schema_version") or 0) != 1:
        raise RadiusCollectionRouteError("unsupported_schema_version")
    if config.get("contract_id") != "sli.radius-collection-routes.v1":
        raise RadiusCollectionRouteError("contract_id_mismatch")
    source_name = str(config.get("source_name") or "").strip()
    connect_address = str(config.get("connect_address") or "").strip()
    source_instance_id = str(config.get("source_instance_id") or "").strip()
    if not source_name and not source_instance_id:
        raise RadiusCollectionRouteError("radius_source_not_configured")
    if not source_name or not source_instance_id:
        raise RadiusCollectionRouteError("source_instance_id_mismatch")
    if connect_address.casefold() != source_name.casefold():
        raise RadiusCollectionRouteError("source_identity_mismatch")
    if config.get("runtime_enabled") is not False or config.get("autostart_enabled") is not False:
        raise RadiusCollectionRouteError("runtime_must_remain_disabled")

    event = _object(config.get("event_log_route"), "event_log_route")
    if not (
        event.get("pack_id") == PACK_ID
        and event.get("channel") == STREAM
        and event.get("provider_name") == PROVIDER
        and tuple(event.get("event_ids") or ()) == EVENT_IDS
        and event.get("transport") == "windows_event_log_rpc"
        and event.get("collection_entrypoint") == "scripts/run_dc_log_pilot.py"
    ):
        raise RadiusCollectionRouteError("event_log_route_mismatch")
    validate_adapter_for_pack(str(event.get("primary_adapter") or ""), PACK_ID)
    validate_adapter_for_pack(str(event.get("fallback_adapter") or ""), PACK_ID)

    accounting = _object(config.get("accounting_route"), "accounting_route")
    timezone = _object(accounting.get("timezone_descriptor"), "timezone_descriptor")
    if not (
        accounting.get("transport") == "dedicated_read_only_smb_share"
        and set(accounting.get("administrative_shares_forbidden") or ()) == _ADMIN_SHARES
        and accounting.get("default_windows_logfiles_path_forbidden") is True
        and timezone.get("source") == "static_accepted_evidence"
        and timezone.get("timezone_id") == "N. Central Asia Standard Time"
        and int(timezone.get("utc_offset_minutes")) == 420
        and timezone.get("remote_registry_allowed") is False
        and timezone.get("drift_check_required_before_activation") is False
        and timezone.get("drift_check_accepted") is False
        and timezone.get("owner_assumption_active") is True
        and timezone.get("owner_assumption_recorded_on") == "2026-08-02"
    ):
        raise RadiusCollectionRouteError("accounting_route_mismatch")
    share_unc = _dedicated_share_path(accounting.get("share_unc"), expected_host=source_name)
    blockers = [] if share_unc else ["radius_dedicated_read_only_share_not_configured"]
    return {
        "source_name": source_name,
        "source_instance_id": source_instance_id,
        "owner_confirmed_ip": str(config.get("owner_confirmed_ip") or ""),
        "event_log_ready": True,
        "event_log_adapter": event["primary_adapter"],
        "event_log_fallback_adapter": event["fallback_adapter"],
        "accounting_ready": share_unc is not None,
        "accounting_share_unc": share_unc,
        "timezone_id": timezone["timezone_id"],
        "utc_offset_minutes": int(timezone["utc_offset_minutes"]),
        "runtime_enabled": False,
        "autostart_enabled": False,
        "blockers": blockers,
        "timezone_drift_check_accepted": False,
        "timezone_owner_assumption_active": True,
    }


def load_radius_collection_routes(path: Path | None = None) -> dict[str, Any]:
    explicit_path = path is not None
    path = path or Path(os.environ.get("ADLOG_RADIUS_COLLECTION_ROUTES_PATH") or CONFIG_PATH)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusCollectionRouteError("route_contract_unreadable") from exc
    value = _object(value, "route_contract")
    if not explicit_path:
        host = os.environ.get("ADLOG_RADIUS_SOURCE_NAME", "").strip()
        if "ADLOG_RADIUS_SOURCE_NAME" in os.environ:
            if not host:
                raise RadiusCollectionRouteError("radius_source_not_configured")
            value.update(source_name=host, connect_address=host, source_instance_id=host)
        for field, environment in (
            ("source_instance_id", "ADLOG_RADIUS_SOURCE_INSTANCE_ID"),
            ("owner_confirmed_ip", "ADLOG_RADIUS_OWNER_CONFIRMED_IP"),
        ):
            if os.environ.get(environment, "").strip():
                value[field] = os.environ[environment].strip()
        if "ADLOG_RADIUS_ACCOUNTING_SHARE_UNC" in os.environ:
            value["accounting_route"]["share_unc"] = os.environ["ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"].strip() or None
    return validate_radius_collection_routes(value)


def require_accounting_source() -> tuple[Path, str, int]:
    routes = load_radius_collection_routes()
    if not routes["accounting_ready"]:
        raise RadiusCollectionRouteError("radius_dedicated_read_only_share_not_configured")
    return (
        Path(str(routes["accounting_share_unc"])),
        str(routes["timezone_id"]),
        int(routes["utc_offset_minutes"]),
    )
