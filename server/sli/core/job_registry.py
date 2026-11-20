"""Bundled handler allowlist and manifest schedules; manifests never import code."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from server.sli.core.job_queue import digest, enqueue, idempotency_key
from server.sli.plugin_validation import (
    PROFILES as PROFILES,
    ALLOWLIST as ALLOWLIST,
    validate_shape as validate_shape,
    HandlerRegistry as HandlerRegistry,
)
from server.sli.plugins.registry import plugin_hook, plugin_installed
from server.sli.plugins.update_runtime import generation, job_manifests

ROOT = Path(__file__).resolve().parents[3]


def slot(schedule: dict, now: datetime, input_generation: str | None = None) -> str | None:
    if schedule["trigger"] == "input_available":
        return input_generation
    if schedule["trigger"] == "interval":
        return str(int(now.timestamp()) // schedule["interval_seconds"])
    local = now.astimezone(ZoneInfo(schedule["timezone"]))
    current = local.strftime("%H:%M")
    if current in schedule["calendar"]["local_times"]:
        # Both folds of a repeated local time share one key; nonexistent slots skip.
        return f"{local.date().isoformat()}:{current}"
    return None


def schedule_jobs(cur, registry: HandlerRegistry, profile: str, source: dict) -> None:
    cur.execute("select clock_timestamp()")
    now = cur.fetchone()[0]
    for manifest in registry.manifests:
        if source.get("plugin_id", "sli.remote-access") != manifest["plugin_id"]:
            continue
        for schedule in manifest["schedules"]:
            handler = next(h for h in manifest["handlers"] if h["handler_id"] == schedule["handler_id"])
            if handler["resource_profile"] != profile or handler["handler_id"] == "radius-acquisition":
                continue  # Collection remains disabled, including explicit schedules.
            generation = slot(schedule, now, source.get("manifest_id"))
            if generation is None:
                continue
            provider = plugin_hook(manifest["plugin_id"], "job_source")
            partition_key = handler["handler_id"]
            if provider is not None:
                pinned, partition_key = provider(handler, source, generation)
            else:
                pinned = {"generation": generation, "input_range": source.get("delivery_ids", []),
                          "policy_revision": source["revision"], "continuation": None,
                          "subscription_id": source["subscription_id"],
                          "delivery_ids": source.get("delivery_ids", [])}
            registered = registry.handlers[(manifest["plugin_id"], handler["handler_id"],
                handler["handler_version"], manifest["plugin_version"], digest(manifest))]
            spec = {
                "contract_id": "sli.core-job.v1", "plugin_id": manifest["plugin_id"],
                **{name: registered[name] for name in ("plugin_version", "manifest_sha256", "handler_id",
                    "handler_version", "input_contract", "result_contract", "resource_profile", "rights_profile", "budget", "max_attempts")},
                "job_type": handler["kind"], "input_ref": f"schedule:{schedule['schedule_id']}:{generation}",
                "input_sha256": digest(pinned), "pinned_input": pinned,
                "source_instance_id": source["source_instance_id"],
                "partition_key": partition_key, "access_scope": source["access_scope"],
                "priority": "normal", "continuation": None,
                "available_at_utc": now.astimezone(timezone.utc).isoformat(),
                "deadline_at_utc": (now + timedelta(seconds=300)).isoformat(),
                "max_inflight_per_source": schedule["max_inflight_per_source"],
                "schedule_key": digest([manifest["plugin_id"], schedule["schedule_id"],
                                        source["source_instance_id"], generation]),
            }
            spec["idempotency_key"] = idempotency_key(spec, pinned)
            enqueue(cur, spec)


def pilot_registry() -> HandlerRegistry:
    from server.sli.sources.ad_gpo_jobs import enabled
    from server.sli.plugins.workstations.jobs import enabled as workstations_enabled
    from server.sli.plugins.workstations import projection_jobs

    registry = HandlerRegistry()
    owners = ["sli.remote-access"]
    if enabled():
        owners.extend(("sli.ad", "sli.gpo"))
    if workstations_enabled():
        owners.append("sli.workstations")
    current = []
    for plugin_id in owners:
        if not plugin_installed(plugin_id):
            continue
        active = generation(plugin_id)
        seen = set()
        bundled = [ROOT / f"config/plugin_packages/{plugin_id}.jobs-v3.json"]
        if plugin_id == "sli.workstations" and projection_jobs.enabled():
            bundled.append(ROOT / projection_jobs.MANIFEST)
        for manifest_path in bundled:
            for path, manifest in job_manifests(plugin_id, manifest_path):
                identity = digest(manifest)
                if identity not in seen:
                    registry.register(manifest)
                    seen.add(identity)
                if path == active and not any(digest(item) == identity for item in current):
                    current.append(manifest)
    registry.manifests = current
    return registry
