"""Small read-only Operations payload for the unified UI."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any

from server.sli.agents.collection_health import get_agent_collection_health
from server.sli.sources.collector_health import get_collector_health, summarize_collection_freshness
from server.sli.core.database import get_sources
from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.events.event_catalog_quality import catalog_completeness
from server.sli.ops.postgres_operations import get_postgres_operations_status
from server.sli.plugins.registry import call_plugin
from server.sli.ops.runtime_workers import get_runtime_workers_overview
from server.sli.storage.storage_policy import get_operations_storage_summary
from server.jobs.collector import get_collection_runtime_status

get_radius_vpn_operations = partial(call_plugin, "sli.remote-access", "get_radius_vpn_operations")


def _event_catalog_completeness_view() -> dict[str, Any]:
    """Keep Operations readable when the local catalogue cannot be loaded."""
    base = {
        "basis": "distinct_catalog_entries",
        "contains_event_payload": False,
    }
    try:
        return {
            "status": "ok",
            **base,
            **catalog_completeness({"entries": all_event_catalog_entries()}),
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            **base,
            "error_type": type(exc).__name__,
        }


def _radius_vpn_operations_view() -> dict[str, Any]:
    """Keep the wider Operations page available during pilot maintenance."""
    try:
        payload = get_radius_vpn_operations()
        if payload.get("state") == "not_installed":
            return {"contract_id": "sli.radius-vpn-operations.v1", "status": "not_installed",
                    "items": [], "contains_identity_or_event_payload": False}
        return payload
    except Exception as exc:
        return {
            "contract_id": "sli.radius-vpn-operations.v1",
            "status": "unavailable",
            "items": [],
            "contains_identity_or_event_payload": False,
            "error_type": type(exc).__name__,
        }


def _collection_execution_view(
    collection: dict[str, Any], workers: dict[str, Any]
) -> dict[str, Any]:
    """Separate the HTTP process guard from the external collector state.

    The mandatory loopback HTTP verification copy is intentionally started with
    ``ADLOG_DISABLE_COLLECTION=1``.  That guard applies to the server process and
    must remain enabled, but it is not an operational outage when the separately
    owned collection worker has a fresh active heartbeat.
    """
    result = dict(collection)
    collection_worker = next(
        (
            item
            for item in (workers.get("items") or [])
            if item.get("worker_name") == "collection"
        ),
        None,
    )
    external_running = bool(
        collection_worker
        and collection_worker.get("feature_enabled", True)
        and collection_worker.get("state") in {"active", "warning"}
    )
    local_guard_only = bool(
        external_running
        and result.get("collection_block_reason")
        == "collection_disabled_by_ADLOG_DISABLE_COLLECTION"
    )
    result.update(
        {
            "operational_collection_enabled": (
                True if local_guard_only else result.get("collection_enabled")
            ),
            "operational_collection_block_reason": (
                None if local_guard_only else result.get("collection_block_reason")
            ),
            "collection_execution_owner": (
                "external_worker" if external_running else "server_process"
            ),
            "local_runtime_guard_only": local_guard_only,
        }
    )
    return result


def collection_progress_view(
    collector: dict[str, Any], workers: dict[str, Any], collection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Expose the bounded recovery state used by the external collector.

    Event freshness cannot prove a source boundary: a quiet channel may have an
    old last event even after the collector reached the current end of the
    Windows log.  The adaptive state is the durable boundary authority.
    """
    collection_worker = next(
        (
            item
            for item in (workers.get("items") or [])
            if item.get("worker_name") == "collection"
        ),
        None,
    ) or {}
    details = collection_worker.get("details") or {}
    active_job = details.get("active_job") if isinstance(details, dict) else None
    active_job = active_job if isinstance(active_job, dict) else {}

    items = []
    for channel in collector.get("items") or []:
        check_state = summarize_collection_freshness([channel])["state"]
        recovery_mode = bool(channel.get("recovery_mode"))
        adaptive_action = str(channel.get("adaptive_action") or "")
        boundary_reached = bool(
            not recovery_mode
            and (
                str(channel.get("last_status") or "") == "completed"
                or adaptive_action.startswith(
                    "exit_recovery:source_boundary_reached"
                )
            )
        )
        items.append(
            {
                "server": channel.get("server"),
                "channel": channel.get("channel"),
                "recovery_mode": recovery_mode,
                "boundary_reached": boundary_reached,
                "boundary_checked_at_utc": channel.get("last_successful_collection_utc") if boundary_reached else None,
                "check_state": check_state,
                "last_status": channel.get("last_status"),
                "failure_reason": channel.get("failure_reason") or channel.get("backend_reason"),
                "current_limit": channel.get("adaptive_limit"),
                "last_event_record_id": channel.get("last_event_record_id"),
                "last_event_time_utc": channel.get("last_event_time_utc"),
                "last_successful_collection_utc": channel.get(
                    "last_successful_collection_utc"
                ),
                "last_action": channel.get("adaptive_action"),
            }
        )

    recovery_items = [item for item in items if item["recovery_mode"]]
    boundaries_reached = sum(1 for item in items if item["boundary_reached"])
    worker_status = str(collection_worker.get("status") or "unknown")
    job_status = str(active_job.get("status") or "")
    freshness = summarize_collection_freshness(list(collector.get("items") or []))
    collection = collection or {}
    block_reason = collection.get("operational_collection_block_reason", collection.get("collection_block_reason"))
    if block_reason:
        status = "blocked"
    elif any(item["check_state"] == "error" for item in items):
        status = "failed"
    elif worker_status in {"failed", "error", "blocked"}:
        status = "blocked" if worker_status == "blocked" else "failed"
    elif worker_status == "running" or job_status == "running":
        status = "running"
    elif items and not recovery_items and boundaries_reached == len(items) and freshness["state"] == "current":
        status = "completed"
    elif recovery_items:
        status = "partial"
    elif items and freshness["state"] in {"stale", "lagging"}:
        status = freshness["state"]
    else:
        status = "unknown"
    return {
        "status": status,
        "check_state": freshness["state"],
        "block_reason": block_reason,
        "blocked_since_utc": (collection.get("collection_block") or {}).get("first_seen_at") if block_reason else None,
        "source": "postgres_adaptive_state_and_worker_heartbeat",
        "channels_total": len(items),
        "boundaries_reached": boundaries_reached,
        "channels_in_recovery": len(recovery_items),
        "worker_id": collection_worker.get("worker_id"),
        "worker_status": worker_status,
        "worker_phase": collection_worker.get("phase"),
        "heartbeat_at": collection_worker.get("heartbeat_at"),
        "job_id": active_job.get("job_id"),
        "job_status": active_job.get("status"),
        "job_phase": active_job.get("phase"),
        "items": items,
        "recovery_items": recovery_items,
    }


def _collector_health_with_collection_progress(
    collector: dict[str, Any], progress: dict[str, Any]
) -> dict[str, Any]:
    """Prefer live bounded progress over an old completed-poll timestamp.

    Collector freshness remains authoritative when the worker is not running.
    During a live collection job, however, the adaptive boundary state explains
    the channel more accurately than the age of its previous completed poll.
    """
    if not collector.get("items"):
        return collector

    worker_failed = progress.get("status") in {"failed", "blocked"} or (
        progress.get("worker_status") in {"failed", "blocked"}
    )
    if worker_failed:
        return collector

    live = (
        progress.get("status") == "running"
        or progress.get("worker_status") == "running"
        or progress.get("job_status") == "running"
    )

    progress_by_channel = {
        (str(item.get("server") or ""), str(item.get("channel") or "")): item
        for item in (progress.get("items") or [])
    }
    result = dict(collector)
    result_items: list[dict[str, Any]] = []
    for source_item in collector.get("items") or []:
        item = dict(source_item)
        bounded = progress_by_channel.get(
            (str(item.get("server") or ""), str(item.get("channel") or ""))
        )
        if bounded is None:
            result_items.append(item)
            continue
        if bounded.get("boundary_reached") and bounded.get("check_state") == "current":
            label = "граница прочитана при последней успешной проверке"
            severity = "ok"
            explanation = "Чтение границы подтверждено актуальной проверкой канала."
        elif bounded.get("boundary_reached") or bounded.get("check_state") == "error":
            result_items.append(item)
            continue
        elif bounded.get("recovery_mode"):
            label = (
                "канал догоняет границу"
                if live else "канал ожидает следующую bounded-порцию"
            )
            severity = "warn"
            explanation = (
                "Bounded recovery активен; канал догоняет известную границу."
                if live
                else "Recovery не завершён; worker продолжит его следующей bounded-порцией."
            )
        elif live:
            label = "проверяется текущая граница"
            severity = "warn"
            explanation = (
                "Живой collection worker проверяет текущую source boundary."
            )
        else:
            result_items.append(item)
            continue
        item.update(
            {
                "collection_label": label,
                "collection_severity": severity,
                "state_explanation": explanation,
            }
        )
        result_items.append(item)
    result["items"] = result_items
    return result


def get_operations_overview() -> dict[str, Any]:
    """Compose already-bounded live health data without scheduling work."""
    collector = get_collector_health()
    postgres = get_postgres_operations_status(table_limit=10)
    workers = get_runtime_workers_overview()
    collection = _collection_execution_view(
        get_collection_runtime_status(), workers
    )
    collection_progress = collection_progress_view(collector, workers, collection)
    operations_collector = _collector_health_with_collection_progress(
        collector, collection_progress
    )
    operations_collector = _legacy_source_usage(operations_collector, collection)
    return {
        "api_version": "v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "collection": collection,
        "agent_collection": get_agent_collection_health(),
        "collection_progress": collection_progress,
        "workers": workers,
        "collector_health": operations_collector,
        "storage": get_operations_storage_summary(postgres),
        "postgres": postgres,
        "catalog_completeness": _event_catalog_completeness_view(),
        "plugin_pilots": {
            "vpn_radius": _radius_vpn_operations_view(),
        },
        "read_only": True,
    }


def _legacy_source_usage(collector, collection, *, now=None):
    """Retain retired server history without treating it as a live outage."""
    now = now or datetime.now(timezone.utc)
    if collection.get("operational_collection_enabled", collection.get("collection_enabled", True)):
        return collector
    cutoff = now - timedelta(days=7)
    items = []
    for original in collector.get("items", []):
        item = dict(original)
        clocks = [datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                  for value in (item.get("last_successful_collection_utc"), item.get("last_event_time_utc")) if value]
        clocks = [value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value for value in clocks]
        if clocks and max(clocks) < cutoff and not item.get("inserted_24h"):
            item["usage_state"] = "unused"
        items.append(item)
    return {**collector, "items": items}


def get_platform_readiness() -> dict[str, Any]:
    """Agent collection and storage checks, without retired server channels."""
    postgres = get_postgres_operations_status(table_limit=10)
    workers = get_runtime_workers_overview()
    workers = {**workers, "items": [item for item in workers.get("items", []) if item.get("worker_name") != "collection"]}
    return {
        "api_version": "v1", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "agent_collection": get_agent_collection_health(),
        "workers": workers,
        "storage": get_operations_storage_summary(postgres), "postgres": postgres, "read_only": True,
    }


def get_source_detail(hostname: str) -> dict[str, Any]:
    """Return one read-only source card without inventing uncollected inventory."""
    clean_hostname = str(hostname or "").strip()
    if not clean_hostname or len(clean_hostname) > 255:
        raise ValueError("invalid_source_hostname")
    matches = [
        dict(item) for item in get_sources()
        if str(item.get("hostname") or "").strip().casefold().rstrip(".")
        == clean_hostname.casefold().rstrip(".")
    ]
    # Collection health only carries hostname identity. Do not attach those
    # channels, or choose an arbitrary registration, when domains collide.
    if len(matches) > 1:
        raise ValueError("ambiguous_source_hostname")
    inventory = matches[0] if matches else {}
    health = get_collector_health()
    channels = [
        dict(item) for item in (health.get("items") or [])
        if str(item.get("server") or "").casefold() == clean_hostname.casefold()
    ]
    if not inventory and not channels:
        raise ValueError("source_not_found")
    observed_name = str((channels[0] if channels else {}).get("server") or "")
    canonical_name = str(inventory.get("hostname") or observed_name or clean_hostname)
    return {
        "api_version": "v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "hostname": canonical_name,
            "fqdn": inventory.get("fqdn"),
            "role": inventory.get("role"),
            "active": inventory.get("is_active"),
            "domain_fqdn": inventory.get("domain_fqdn"),
            "site": inventory.get("site_name"),
            "os_name": inventory.get("os_name"),
            "os_version": inventory.get("os_version"),
            "ip_addresses": list(inventory.get("ip_addresses") or []),
            "inventory_observed_at_utc": inventory.get("inventory_observed_at_utc"),
            "inventory_source": inventory.get("inventory_source"),
            "disk_state": str(inventory.get("disk_state") or "not_collected"),
            "disks": list(inventory.get("disks") or []),
        },
        "collection_freshness": summarize_collection_freshness(
            channels, selected_source=canonical_name,
        ),
        "channels": channels,
        "limitations": [
            "IP-адрес показывается только когда он явно задан как адрес подключения источника; DNS-разрешение не подменяет инвентаризацию.",
            "Сведения о дисках показываются только после успешного ограниченного технического опроса в едином 30-минутном контуре.",
            "Время последней проверки канала и время последнего события показаны отдельно.",
        ],
        "read_only": True,
    }
