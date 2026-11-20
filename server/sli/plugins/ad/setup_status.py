"""Read-only AD/DC setup providers; the checklist and shared DTO stay in core."""
from __future__ import annotations

from typing import Any

from server.sli.core import database


def domain_controllers() -> dict[str, Any]:
    from server.sli.plugins.ad.setup import list_targets

    return list_targets()


def source_configuration(pack, controllers, domains, collection) -> list[dict[str, Any]] | None:
    """Use configured targets, never package presence or historical events."""
    if collection is not None and "agent_collection" in collection:
        return _agent_configuration(pack, controllers, domains, collection)
    if pack["pack_id"] == "sli.windows.ad-dc":
        if controllers is None:
            return None
        return [{
            "source_instance_id": item["hostname"], "configured": True,
            "enabled": False if not item["enabled"] else (
                collection["collection_enabled"] if collection is not None else None
            ),
            "activation_blocked": bool(item["enabled"] and collection is not None and not collection["collection_enabled"]),
        } for item in controllers["items"]]
    if pack["pack_id"] == "sli.windows.ad-context":
        # The coordinator's scope lives in its own environment. Domains and
        # successful imports cannot prove its current configuration/activation.
        return None if not domains else [{
            "source_instance_id": domain["fqdn"], "configured": None, "enabled": None,
        } for domain in domains]
    return None


def _agent_configuration(pack, controllers, domains, collection):
    """Exact policy bindings, never display names, target presence or old data."""
    is_dc = pack["pack_id"] == "sli.windows.ad-dc"
    modules = {"sli.windows.ad-dc"} if is_dc else {"sli.ad-snapshot"}
    binding_key = "source_name" if is_dc else "domain_dns"
    health = collection["agent_collection"]
    agents = {agent["id"]: agent for agent in health["items"]}
    grouped = {}
    labels = {}
    for binding in collection.get("_agent_source_bindings", []):
        if binding["module_id"] not in modules:
            continue
        label = binding.get(binding_key)
        if not isinstance(label, str) or not label.strip():
            continue
        label = label.strip()
        key = label.casefold()
        labels.setdefault(key, label)
        grouped.setdefault(key, []).append(binding)
    candidates = ((item["hostname"] for item in (controllers or {}).get("items", [])) if is_dc
                  else (item["fqdn"] for item in domains or []))
    for label in candidates:
        labels.setdefault(label.casefold(), label)
    if not labels:
        return None if health["state"] == "unavailable" or any(
            binding["module_id"] in modules for binding in collection.get("_agent_source_bindings", [])
        ) else []
    result = []
    for key, label in labels.items():
        bindings = grouped.get(key, [])
        checks = [check for binding in bindings for module in agents.get(binding["agent_id"], {}).get("modules", [])
                  if module["module_id"] == binding["module_id"] for check in module["channels"]]
        missing = any(binding["enabled"] and not any(
            module["module_id"] == binding["module_id"] and module["channels"]
            for module in agents.get(binding["agent_id"], {}).get("modules", [])
        ) for binding in bindings)
        active = [check for check in checks if check["state"] not in ("disabled", "paused")]
        enabled = any(binding["enabled"] for binding in bindings) if bindings else None
        state = ("unknown" if not bindings or health["state"] == "unavailable" or health.get("diagnostics")
                 else "paused" if not enabled and any(binding.get("paused") for binding in bindings)
                 else "disabled" if not enabled else "error" if any(check["state"] == "error" for check in active)
                 else "current" if not missing and active and all(check["state"] == "current" for check in active)
                 else "lagging" if any(check["state"] == "lagging" for check in active)
                 else "waiting" if any(check["state"] == "waiting" for check in active) else "unknown")
        stamps = [check["last_import_at"] for check in checks if check.get("last_import_at")]
        stamp = max(stamps, default=None)
        received = None if state == "unknown" else state == "current"
        result.append({
            "source_instance_id": label, "configured": True if bindings else None, "enabled": enabled,
            "data_received": received,
            "data_state": "fresh" if received else "unavailable" if received is None else "stale" if stamp else "never",
            "last_data_utc": stamp, "collection_state": state,
            "next_action": None if state == "current" else "check_configuration" if not bindings
                           else "enable" if enabled is False else "check_data",
        })
    return result


def source_data(pack, instances) -> dict[str, Any]:
    """Arrival time of actual data; empty successful polls are not arrivals."""
    if not instances:
        return {}
    ids = [item["source_instance_id"].casefold() for item in instances]
    if pack["source_kind"] == "context":
        rows = database.query_rows(
            """
            select lower(domain_dns) as source_instance_id, max(created_at) as last_data_utc
            from ad_snapshot_manifests m
            where lower(domain_dns) = any(?) and coverage_state in ('complete', 'partial')
              and exists (select 1 from ad_snapshot_manifest_sources s where s.manifest_id = m.manifest_id
                          and s.family = 'ad_context_base' and s.source_state in ('complete', 'partial'))
            group by lower(domain_dns)
            """, (ids,),
        )
    else:
        rows = database.query_rows(
            """
            select lower(server) as source_instance_id, max(created_at) as last_data_utc
            from collector_channel_runs
            where lower(server) = any(?) and lower(channel) = any(?) and inserted > 0
            group by lower(server)
            """, (ids, [channel.casefold() for channel in pack.get("channels", [])]),
        )
    return {str(row["source_instance_id"]).casefold(): row["last_data_utc"] for row in rows}



def context_interval():
    from server.ad_context.snapshot_manifest import SLOT_SECONDS

    return SLOT_SECONDS
