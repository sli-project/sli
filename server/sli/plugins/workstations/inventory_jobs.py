"""Domain-partitioned inventory work in the existing finite WR05 job pool."""
from __future__ import annotations

from psycopg.types.json import Jsonb

from server.sli.core.job_queue import fence
from server.sli.plugins.workstations.jobs import _Rows

SOURCE_PREFIX = "workstations:inventory:"


def is_inventory(job):
    return str(job.get("source_instance_id") or "").startswith(SOURCE_PREFIX)


def _read(conn, job):
    with _Rows(conn).cursor() as cur:
        cur.execute("select public.read_workstation_inventory_input_v1(%s,%s,%s) as input", fence(job))
        value = cur.fetchone()["input"]
    if not isinstance(value, dict):
        raise ValueError("workstation_inventory_input_invalid")
    return value


def _page(snapshot, limit):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("workstation_inventory_budget_invalid")
    if limit != 100:
        raise ValueError("workstation_inventory_budget_invalid")
    page = snapshot["page"]
    return page["rows"], page["more"], page["next_cursor"]


def stage(conn, job):
    snapshot = _read(conn, job)
    _, more, _ = _page(snapshot, min(job["budget"]["max_records"], 100))
    return {"status": "partial" if more else "success", "coverage_state": "not_proven", "continuation": None,
            "inventory_source_sha256": snapshot["source_sha256"],
            "inventory_ids": snapshot["page"]["attempted_ids"],
            "inventory_deferred": snapshot["page"]["deferred"]}


def apply(conn, job, result):
    if result["status"] in {"blocked", "cancelled"}:
        return
    snapshot = _read(conn, job)
    if snapshot["source_sha256"] != result.get("inventory_source_sha256"):
        raise ValueError("workstation_inventory_input_changed")
    rows, _, cursor = _page(snapshot, min(job["budget"]["max_records"], 100))
    if (result.get("inventory_ids") != snapshot["page"]["attempted_ids"]
            or result.get("inventory_deferred") != snapshot["page"]["deferred"]):
        raise ValueError("workstation_inventory_page_changed")
    with _Rows(conn).cursor() as cur:
        cur.execute("select public.publish_workstation_inventory_v1(%s,%s,%s,%s,%s,%s)",
                    (*fence(job), snapshot["source_sha256"], Jsonb(rows), cursor))
