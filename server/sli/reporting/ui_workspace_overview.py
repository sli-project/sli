"""Pure overview-workspace shaping helpers split out of ``ui_workspace``.

Nothing here touches storage, so no test patches these names on
``ui_workspace``; they are re-exported there unchanged.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from server.sli.sources.collector_health import summarize_collection_freshness


def _overview_alert(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(item.get("id") or 0), "title": str(item.get("title") or ""),
        "severity": str(item.get("severity") or "unknown"), "status": str(item.get("status") or "unknown"),
        "actor": item.get("actor"), "target": item.get("target"), "source": item.get("source"),
        "last_seen_utc": item.get("last_seen_utc"), "evidence_count": int(item.get("evidence_count") or 0),
        "assigned_to": item.get("assigned_to"), "updated_at": item.get("updated_at"),
        "event_db_id": item.get("last_evidence_event_id"),
    }

def _overview_source(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": str(item.get("hostname") or ""), "fqdn": item.get("fqdn"),
        "role": item.get("role"), "active": bool(item.get("is_active")) if item.get("is_active") is not None else None,
        "registered": True, "site": item.get("site_name"),
        "os_name": item.get("os_name"), "os_version": item.get("os_version"),
        "ip_addresses": list(item.get("ip_addresses") or []),
        "disk_state": str(item.get("disk_state") or "not_collected"),
        "disks": list(item.get("disks") or []),
        "inventory_observed_at_utc": item.get("inventory_observed_at_utc"),
        "inventory_source": item.get("inventory_source"),
        "collection_state": None, "collection_label": None,
        "last_successful_collection_utc": None, "last_event_time_utc": None,
        "channels_total": 0, "channels": [],
    }

def _merge_registered_source_inventory(
    cached_items: list[dict[str, Any]],
    live_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Enrich a cached source snapshot with the current bounded inventory."""
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for item in [*cached_items, *live_items]:
        hostname = str(item.get("hostname") or "").strip()
        if not hostname:
            continue
        key = hostname.casefold()
        if key not in merged:
            merged[key] = {}
            order.append(key)
        current = merged[key]
        for field, value in item.items():
            if field == "hostname" and field in current:
                continue
            if value not in (None, "", []) or field not in current:
                current[field] = value
    return [merged[key] for key in order]

def _overview_sources(registered_items: list[dict[str, Any]], health_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge registered inventory with observed collector channels.

    A source that is present only in collector health is still real and useful
    to every workspace viewer, but missing inventory attributes stay unknown.
    """
    result: dict[str, dict[str, Any]] = {}
    for item in registered_items:
        source = _overview_source(item)
        hostname = source["hostname"].strip()
        if hostname:
            result[hostname.lower()] = source
    observed: dict[str, list[dict[str, Any]]] = {}
    for item in health_items:
        hostname = str(item.get("server") or "").strip()
        if hostname:
            observed.setdefault(hostname.lower(), []).append(item)
    for key, items in observed.items():
        hostname = str(items[0].get("server") or "").strip()
        source = result.setdefault(key, {
            "hostname": hostname, "fqdn": None, "role": None, "active": None,
            "registered": False, "site": None, "os_name": None, "os_version": None,
            "ip_addresses": [],
            "disk_state": "not_collected", "disks": [],
            "inventory_observed_at_utc": None, "inventory_source": None,
            "collection_state": None, "collection_label": None,
            "last_successful_collection_utc": None, "last_event_time_utc": None,
            "channels_total": 0, "channels": [],
        })
        freshness = summarize_collection_freshness(items, selected_source=hostname)
        source.update({
            "collection_state": freshness.get("state"),
            "collection_label": freshness.get("label"),
            "last_successful_collection_utc": freshness.get("checked_at_utc"),
            "last_event_time_utc": freshness.get("latest_event_utc"),
            "channels_total": len(items),
            "channels": [{
                "server": item.get("server"), "channel": item.get("channel"),
                "collection_state": summarize_collection_freshness([item])["state"],
                "last_status": item.get("last_status"),
                "failure_reason": item.get("failure_reason") or item.get("backend_reason"),
                "last_successful_collection_utc": item.get("last_successful_collection_utc"),
                "last_event_time_utc": item.get("last_event_time_utc"),
            } for item in items],
        })
    return sorted(result.values(), key=lambda item: str(item.get("hostname") or "").lower())

def _overview_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except ValueError:
        return None

def _overview_collection_freshness(health: dict[str, Any], selected_source: str | None) -> dict[str, Any]:
    return summarize_collection_freshness(
        list(health.get("items") or []),
        health_status=health.get("status"),
        selected_source=selected_source,
    )
