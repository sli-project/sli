"""Finite core job adapter for the workstation projection queue."""
from __future__ import annotations

import os

from server.sli.core import job_queue
from server.sli.plugins.workstations import projection
from server.sli.plugins.workstations import protection
from server.sli.plugins.workstations import logon_policy
from server.sli.plugins.workstations.jobs import _Rows

FLAG = "SLI_CORE_JOB_WORKSTATIONS_PROJECTION"
HANDLER_ID = "workstations.overview-project"
SOURCE = "workstations:projection"
MANIFEST = "config/plugin_packages/sli.workstations.projection-jobs-v3.json"


def enabled():
    return os.environ.get(FLAG, "1") == "1"


def stage(conn, job):
    from server.sli.plugins.workstations import inventory_jobs

    if inventory_jobs.is_inventory(job):
        return inventory_jobs.stage(conn, job)
    if job["source_instance_id"] != SOURCE or job["handler_id"] != HANDLER_ID:
        raise ValueError("workstation_projection_job_invalid")
    evaluators = logon_policy.configured(_Rows(conn), projection.projectors())
    if not evaluators:
        return {"status": "blocked", "error_code": "workstation_projection_evaluators_unavailable",
                "coverage_state": "not_proven", "continuation": None}
    with _Rows(conn).cursor() as cur:
        limit = min(job["budget"]["max_records"], projection.MAX_BATCH)
        refresh_ids = []
        # Reserve a bounded share for age-only changes even while imports keep
        # the queue full. Neither the queue nor C09 may starve the other.
        if any(rule.key == "workstations.protection" for rule in evaluators):
            cur.execute("select clock_timestamp() as now")
            refresh_ids = protection.due(cur, now=cur.fetchone()["now"], limit=max(1, limit // 4))
        remaining = limit - len(refresh_ids)
        ids = projection.pending(cur, evaluators=evaluators, limit=remaining) if remaining else []
    return {"status": "partial" if len(ids) + len(refresh_ids) == limit else "success",
            "work_ids": ids, "protection_refresh_ids": refresh_ids,
            "continuation": None, "coverage_state": "not_proven"}


def apply(conn, job, result):
    from server.sli.plugins.workstations import inventory_jobs

    if inventory_jobs.is_inventory(job):
        return inventory_jobs.apply(conn, job, result)
    if result["status"] in {"blocked", "cancelled"}:
        return
    if job["source_instance_id"] != SOURCE or job["handler_id"] != HANDLER_ID:
        raise ValueError("workstation_projection_job_invalid")
    evaluators = logon_policy.configured(_Rows(conn), projection.projectors())
    if not evaluators:
        raise RuntimeError("workstation_projection_evaluators_unavailable")
    with _Rows(conn).cursor() as cur:
        cur.execute("select set_config('sli.job_id',%s,true),set_config('sli.job_token',%s,true),"
                    "set_config('sli.job_generation',%s,true)",
                    tuple(str(value) for value in job_queue.fence(job)))
        cur.execute("select pg_try_advisory_xact_lock(hashtext(%s)) as acquired", (projection.PROJECTOR,))
        if not cur.fetchone()["acquired"]:
            return
    limit = min(job["budget"]["max_records"], projection.MAX_BATCH)
    projection.prepare_consumers(_Rows(conn), evaluators=evaluators, limit=limit)
    projection.backfill_batch(_Rows(conn), limit=limit)
    projection.run_batch(_Rows(conn), evaluators=evaluators, work_ids=result["work_ids"], limit=limit)
    refresh_ids = result.get("protection_refresh_ids", [])
    if len(refresh_ids) + len(result["work_ids"]) > limit or len(set(refresh_ids)) != len(refresh_ids):
        raise ValueError("workstation_projection_input_invalid")
    if not refresh_ids:
        return
    with _Rows(conn).cursor() as cur:
        cur.execute("select clock_timestamp() as now")
        now = cur.fetchone()["now"]
    for station_id in refresh_ids:
        protection.refresh(_Rows(conn), station_id, now=now)
