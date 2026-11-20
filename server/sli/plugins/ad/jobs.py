"""Bounded AD/GPO adapters over the existing immutable snapshot projections."""
from __future__ import annotations

import json
import os
import sys

from server.ad_context.snapshot_manifest import snapshot_composition
from server.sli.core import job_queue
from server.sli.core.job_registry import HandlerRegistry, ROOT
from server.sli.plugins.registry import plugin_hook
from server.sli.plugins.update_runtime import optional_admission
from server.sli.sources.ad_snapshot_projection import (
    project_exact_manifest,
    read_projection_receipts,
    run_exact_manifest_projection_cycle,
)

FLAG = "SLI_CORE_JOB_AD_GPO_PILOT"
PROJECTIONS = {
    "ad-snapshot-manifest-coordinator": ("ad.state",),
    "ad-snapshot-projection": ("ad.computers.v6",),
    "users-report-v2-snapshot": ("ad.users.v2",),
    "gpo-snapshot": ("ad.gpo.v2",),
}
LEGACY_LOCKS = (
    "ad_log_reports_runtime_ad_snapshot_manifest_coordinator_worker",
    "ad_log_reports_runtime_ad_context_snapshot_worker",
    "ad_log_reports_runtime_computers_v6_source_worker",
    "ad_log_reports_runtime_users_v2_snapshot_worker",
)


class _ProjectionConnection:
    """Reuse the fenced session while legacy repositories request mapping rows."""
    def __init__(self, connection):
        self.connection = connection

    def cursor(self):
        from psycopg.rows import dict_row

        return self.connection.cursor(row_factory=dict_row)


def enabled() -> bool:
    return os.environ.get(FLAG, "0") == "1"


def allowed_plugins() -> frozenset[str]:
    navigation = json.loads((ROOT / "config/navigation_v3.json").read_text("utf-8"))
    return frozenset(navigation["enabled_plugins"]) & {"sli.ad", "sli.gpo"}


def gpo_snapshot_enabled() -> bool:
    """Legacy acquisition observes the same independent plugin enable axes."""
    from server.sli.sources.plugin_state import list_plugin_states

    if "sli.gpo" not in allowed_plugins():
        return False
    return all(
        state["enabled"] and state["component_runtime"] == "running"
        for state in list_plugin_states() if state["plugin_id"] == "sli.gpo"
    )


def registry() -> HandlerRegistry:
    result = HandlerRegistry()
    for plugin_id in ("sli.ad", "sli.gpo"):
        result.register(json.loads((ROOT / f"config/plugin_packages/{plugin_id}.jobs-v3.json").read_text("utf-8")))
    return result


def schedule(cur, handlers: HandlerRegistry, profile: str) -> None:
    allowed = allowed_plugins()
    for plugin_id, resource in (("sli.ad", "heavy"), ("sli.gpo", "long")):
        if resource != profile or plugin_id not in allowed:
            continue
        with optional_admission(plugin_id) as admitted:
            provider = plugin_hook(plugin_id, "schedule_jobs") if admitted else None
            if provider is not None:
                provider(cur, handlers, profile)


def schedule_ad(cur, handlers: HandlerRegistry, profile: str) -> None:
    schedule_snapshot_sources(cur, handlers, profile, "sli.ad")


def schedule_snapshot_sources(cur, handlers: HandlerRegistry, profile: str, plugin_id: str) -> None:
    from server.sli.core.job_registry import schedule_jobs

    cur.execute("select public.read_ad_snapshot_job_sources_v1(%s)", (plugin_id,))
    for row in cur.fetchall():
        schedule_jobs(cur, handlers, profile, row[0])


def job_source(handler: dict, source: dict, generation: str) -> tuple[dict, str]:
    pinned = {"generation": generation, "input_range": [source["manifest_id"]],
              "policy_revision": source["revision"], "continuation": None,
              **{key: source[key] for key in ("manifest_id", "snapshot_sha256", "domain_id")}}
    return pinned, "ad-snapshot"


def _load(conn, job: dict) -> dict:
    from server.ad_context.repository import load_projection_manifest

    pinned = job["pinned_input"]
    manifest = load_projection_manifest(_ProjectionConnection(conn), pinned["manifest_id"])
    if (str(manifest["manifest_id"]) != pinned["manifest_id"]
            or manifest["manifest_sha256"] != pinned["snapshot_sha256"]
            or int(manifest["domain_id"]) != pinned["domain_id"]
            or job["source_instance_id"] != f"ad-domain:{pinned['domain_id']}"):
        raise ValueError("snapshot_input_changed")
    return manifest


def stage(conn, job: dict) -> dict:
    if job.get("plugin_id") == "sli.gpo":
        from server.sli.plugins.gpo.jobs import stage as stage_gpo

        return stage_gpo(conn, job)
    return stage_projection(conn, job)


def stage_projection(conn, job: dict, *, projection_keys: tuple[str, ...] | None = None, required_part: str | None = None) -> dict:
    """Compute only safe identities/hashes; no receipt or permanent output DML."""
    from server.ad_context.repository import load_exact_projection_source

    if job["job_type"] == "acquire":
        return {
            "status": "blocked", "output_contract": job["result_contract"],
            "coverage_state": "not_collected", "continuation": None, "evidence_refs": [],
            "error_code": "acquisition_disabled_on_linux" if sys.platform != "win32"
                          else "acquisition_requires_agent",
        }
    if job["plugin_id"] not in allowed_plugins():
        return {
            "status": "blocked", "output_contract": job["result_contract"],
            "coverage_state": "not_collected", "continuation": None, "evidence_refs": [],
            "error_code": "snapshot_plugin_disabled",
        }
    manifest = _load(conn, job)
    composition = snapshot_composition(manifest)
    if required_part is not None and required_part not in composition["parts"]:
        return {
            "status": "blocked", "output_contract": job["result_contract"],
            "coverage_state": "not_collected", "continuation": None, "evidence_refs": [],
            "error_code": "snapshot_part_not_collected", "composition": composition,
        }

    def load_exact(family, source_id, payload_sha256):
        payload = load_exact_projection_source(
            _ProjectionConnection(conn), family=family, source_id=source_id, payload_sha256=payload_sha256)
        if not isinstance(payload, dict):
            raise ValueError("snapshot_input_invalid")
        count = sum(len(value) for value in payload.values() if isinstance(value, list))
        if count > job["budget"]["max_records"]:
            raise ValueError("snapshot_record_budget_exceeded")
        return payload

    results = project_exact_manifest(
        manifest, load_exact=load_exact,
        projection_keys=PROJECTIONS[job["handler_id"]] if projection_keys is None else projection_keys,
    )
    if any(row.get("error") for row in results.values()):
        # The old routine's diagnostic can contain source fields; never emit it.
        raise ValueError("snapshot_projection_failed")
    return {
        "status": "partial" if manifest.get("coverage_state") == "partial" else "success",
        "output_contract": job["result_contract"],
        "coverage_state": manifest.get("coverage_state", "not_proven"),
        "continuation": None, "error_code": None,
        "evidence_refs": [f"ad-snapshot:{manifest['manifest_id']}"],
        "projection_results": results,
        "composition": composition,
    }


def apply(conn, job: dict, result: dict) -> None:
    if result["status"] in {"blocked", "cancelled"}:
        return
    if job["plugin_id"] == "sli.gpo":
        from server.sli.plugins.gpo.jobs import apply as apply_gpo

        return apply_gpo(conn, job, result)
    return apply_projection(conn, job, result, stage_handler=stage)


def apply_projection(conn, job: dict, result: dict, *, stage_handler,
                     projection_keys: tuple[str, ...] | None = None) -> None:
    """Called only inside core publication; nested writes share its final fence."""
    if result["status"] in {"blocked", "cancelled"}:
        return
    if job["plugin_id"] not in allowed_plugins():
        raise RuntimeError("snapshot_plugin_disabled")
    # Cover a still-running pre-cutover loop and rollback before any snapshot DML.
    # The disposable publisher holds these session locks until its connection closes.
    with conn.cursor() as cur:
        for lock in LEGACY_LOCKS:
            cur.execute("select pg_try_advisory_lock(hashtext(%s))", (lock,))
            if not cur.fetchone()[0]:
                raise RuntimeError("legacy_snapshot_writer_busy")
        cur.execute("select set_config('sli.job_id',%s,true),set_config('sli.job_token',%s,true),"
                    "set_config('sli.job_generation',%s,true)",
                    tuple(str(value) for value in job_queue.fence(job)))
    # Compare against the exact staged computation, never against latest data.
    expected = stage_handler(conn, job)
    if (expected["projection_results"] != result.get("projection_results")
            or expected["composition"] != result.get("composition")):
        raise ValueError("snapshot_result_changed")
    manifest = _load(conn, job)
    outcome = run_exact_manifest_projection_cycle(
        _ProjectionConnection(conn), manifest_id=manifest["manifest_id"], worker_id=f"core-job:{job['job_id']}",
        load_manifest=lambda *_: manifest,
        ensure_receipts=read_projection_receipts,
        projection_keys=PROJECTIONS[job["handler_id"]] if projection_keys is None else projection_keys,
    )
    if outcome["status"] != "completed":
        # Roll back receipts as well as outputs; the queue owns retry/recovery.
        raise RuntimeError("snapshot_projection_not_completed")
