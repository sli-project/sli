"""Bounded history transfer through the core's fenced publication transaction."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from server.sli.core import job_queue
from server.sli.plugins.registry import plugin_installed
from server.sli.plugins.update_runtime import optional_admission
from server.sli.plugins.workstations import retention
from server.sli.plugins.workstations.settings import DEFAULT_DAYS, retention_days
from server.sli.storage import workstation_history

FLAG = "SLI_CORE_JOB_WORKSTATIONS_RETENTION"
PLUGIN = "sli.workstations"
SOURCE = "workstations:history"


def enabled():
    from server.sli.plugins.workstations import projection_jobs

    return (os.environ.get(FLAG, "0") == "1" or projection_jobs.enabled()) and plugin_installed(PLUGIN)


def schedule(cur, registry, profile):
    if profile != "light":
        return
    from server.sli.core.job_registry import schedule_jobs

    from server.sli.plugins.workstations import projection_jobs

    with optional_admission(PLUGIN) as admitted:
        if admitted:
            sources = []
            if os.environ.get(FLAG, "0") == "1":
                sources.append(("read_workstation_retention_job_source_v1", retention.HANDLER_ID))
            if projection_jobs.enabled():
                sources.append(("read_workstation_projection_job_source_v1", projection_jobs.HANDLER_ID))
            for reader, handler_id in sources:
                cur.execute(f"select public.{reader}()")
                source = cur.fetchone()[0]
                if source:
                    selected = SimpleNamespace(handlers=registry.handlers, manifests=[
                        manifest for manifest in registry.manifests
                        if any(item["handler_id"] == handler_id for item in manifest["handlers"])])
                    schedule_jobs(cur, selected, profile, source)
            if projection_jobs.enabled():
                cur.execute("select public.read_workstation_inventory_job_sources_v1()")
                sources = cur.fetchall()
                selected = SimpleNamespace(handlers=registry.handlers, manifests=[
                    manifest for manifest in registry.manifests
                    if any(item["handler_id"] == projection_jobs.HANDLER_ID for item in manifest["handlers"])])
                for (source,) in sources:
                    schedule_jobs(cur, selected, profile, source)


def job_source(handler, source, generation):
    from server.sli.plugins.workstations.inventory_jobs import SOURCE_PREFIX

    partition = (source["source_instance_id"] if source.get("source_instance_id", "").startswith(SOURCE_PREFIX)
                 else handler["handler_id"])
    return {"generation": generation, "input_range": [], "policy_revision": source["revision"],
            "continuation": None}, partition


class _Rows:
    def __init__(self, conn):
        self.conn = conn

    def cursor(self):
        from psycopg.rows import dict_row

        return self.conn.cursor(row_factory=dict_row)


def _now(job):
    # The first admitted schedule time is immutable across retries.
    now = datetime.fromisoformat(job["available_at_utc"].replace("Z", "+00:00"))
    if now.utcoffset() is None or job["source_instance_id"] != SOURCE:
        raise ValueError("workstation_retention_input_invalid")
    return now


def stage(conn, job):
    now = _now(job)
    with _Rows(conn).cursor() as cur:
        cur.execute("select value from public.platform_settings where key=%s", (retention.SETTING_KEY,))
        setting = cur.fetchone()
        days = retention_days(setting["value"] if setting else
                              os.environ.get("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS") or DEFAULT_DAYS)
        cur.execute("""
            select observation.* from sli_plugin_workstations.observations observation
            where family in ('processes','usb') and observed_at<%s
              and not exists (select 1 from sli_plugin_workstations.observation_holds h
                              where h.observation_id=observation.id)
            order by observed_at,id limit %s
        """, (now - timedelta(days=int(days)), retention.MAX_BATCH))
        rows = [dict(row) for row in cur.fetchall()]
    # Only immutable IDs/hashes leave the handler, never source XML or identities.
    candidates = {row["id"]: retention.digest(json.loads(json.dumps(
        row, default=lambda value: value.astimezone(timezone.utc).isoformat()))) for row in rows}
    return {"status": "partial" if len(rows) == retention.MAX_BATCH else "success",
            "retention_days": int(days), "candidates": candidates, "continuation": None,
            "coverage_state": "not_proven"}


def apply(conn, job, result, *, history=None):
    if result["status"] in {"blocked", "cancelled"}:
        return
    now = _now(job)
    candidates = result["candidates"]
    if not candidates:
        return
    adapter = history if history is not None else workstation_history.configured_history()
    if adapter is None:
        raise RuntimeError("workstation_history_unavailable")

    def preserve(row):
        if retention.digest(row) != candidates.get(row["id"]):
            raise ValueError("workstation_history_receipt_mismatch")
        return adapter.preserve(row)

    with conn.cursor() as cur:
        cur.execute("select set_config('sli.job_id',%s,true),set_config('sli.job_token',%s,true),"
                    "set_config('sli.job_generation',%s,true)",
                    tuple(str(value) for value in job_queue.fence(job)))
    outcome = retention.retain_batch(_Rows(conn), now=now,
        history=SimpleNamespace(preserve=preserve), exact_ids=list(candidates),
        expected_days=result["retention_days"])
    # Holds/settings/data can change after staging. Roll back the entire batch.
    if outcome["retention_days"] != result["retention_days"] or outcome["moved"] != len(candidates):
        raise RuntimeError("workstation_retention_plan_changed")
