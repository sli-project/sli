from __future__ import annotations

"""Aggregate-only Operations adapter for the manual VPN/RADIUS pilot."""

from datetime import datetime, timezone
from functools import lru_cache
import json
from pathlib import Path
from typing import Any, Mapping

from server.sli.sources.plugin_resource_profiles import (
    PluginResourceProfileError,
    project_resource_profile_status,
    validate_resource_profile_registry,
)


CONTRACT_ID = "sli.radius-vpn-operations.v1"
RESOURCE_PROFILE_REGISTRY = (
    Path(__file__).resolve().parents[3]
    / "config"
    / "stage10_plugin_resource_profiles_v1.json"
)


@lru_cache(maxsize=1)
def _resource_profiles() -> dict[str, Mapping[str, Any]]:
    value = json.loads(RESOURCE_PROFILE_REGISTRY.read_text(encoding="utf-8"))
    validate_resource_profile_registry(value)
    return {str(item["profile_id"]): item for item in value["profiles"]}


def _resource_profile_view(profile_id: object) -> dict[str, Any]:
    clean_id = str(profile_id or "").strip()
    if not clean_id:
        return {
            "status": "not_configured",
            "profile_id": None,
            "ready_for_long_lived_worker": False,
        }
    try:
        profile = _resource_profiles().get(clean_id)
        if profile is None:
            return {
                "status": "not_registered",
                "profile_id": clean_id,
                "ready_for_long_lived_worker": False,
            }
        projection = project_resource_profile_status(profile)
    except (OSError, json.JSONDecodeError, PluginResourceProfileError) as exc:
        return {
            "status": "unavailable",
            "profile_id": clean_id,
            "error_type": type(exc).__name__,
            "ready_for_long_lived_worker": False,
        }
    return {
        "status": "configured_manual_inactive",
        **projection,
    }


def get_radius_vpn_operations() -> dict[str, Any]:
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select *
            from radius_vpn_operations_v1
            order by source_instance_id
            limit 20
            """
        )
        rows = [dict(row) for row in cur.fetchall()]
    return {
        "contract_id": CONTRACT_ID,
        "status": "ok",
        "items": [_public_item(row) for row in rows],
        "limits": {"source_instances": 20},
        "contains_identity_or_event_payload": False,
    }


def _public_item(row: Mapping[str, Any]) -> dict[str, Any]:
    item = {
        str(key): (
            value.astimezone(timezone.utc).isoformat()
            if isinstance(value, datetime)
            else value
        )
        for key, value in row.items()
    }
    queued = int(item.get("queued_delivery_count") or 0)
    failed = int(item.get("failed_delivery_count") or 0)
    leased = int(item.get("leased_delivery_count") or 0)
    quarantined = int(item.get("quarantined_delivery_count") or 0)
    projected = int(item.get("projected_session_count") or 0)
    unresolved = (
        int(item.get("identity_unresolved_count") or 0)
        + int(item.get("timestamp_unresolved_count") or 0)
        + quarantined
    )
    source_activation = str(item.get("source_activation") or "")
    subscription_activation = str(
        item.get("subscription_activation") or ""
    )
    if source_activation == "disabled":
        source_state = "disabled"
    elif subscription_activation == "disabled":
        source_state = "subscription_disabled"
    else:
        source_state = "manual_enabled"
    if bool(item.get("manual_worker_session_exists")):
        worker_state = "active_manual"
    elif bool(item.get("ephemeral_login_exists")):
        worker_state = "attention"
    else:
        worker_state = "manual_idle"
    if failed or leased or quarantined:
        queue_state = "attention"
    elif queued:
        queue_state = "pending_manual"
    else:
        queue_state = "drained"
    if projected == 0 and unresolved:
        dataset_state = "identity_incomplete"
    elif projected and unresolved:
        dataset_state = "partial"
    elif projected:
        dataset_state = "available"
    else:
        dataset_state = "not_collected"
    item.update({
        "plugin_id": "sli.remote-access",
        "plugin_state": "bundled_supervised_production",
        "source_state": source_state,
        "worker_state": worker_state,
        "queue_state": queue_state,
        "dataset_state": dataset_state,
        "access_state": (
            "owner_only"
            if (
                int(item.get("direct_capability_assignment_count") or 0) == 0
                and int(item.get("package_capability_mapping_count") or 0) == 0
            )
            else "assigned"
        ),
        "resource_profile": _resource_profile_view(item.get("resource_profile_id")),
    })
    return item
