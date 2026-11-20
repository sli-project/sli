"""Bounded RADIUS stage/publish adapters registered with the core job host."""
from uuid import uuid4

from server.sli.core import job_queue as queue
from server.sli.sources.plugin_runtime_admission import CONSUMER, PluginRuntimeAdmissionError
from server.sli.sources.plugin_runtime_admission_executor import (
    acquire_component_lease,
    release_component_lease,
)


def stage_radius(conn, job: dict) -> dict:
    if job["handler_id"] == "radius-acquisition":
        return result_envelope(job, {"status": "blocked", "error_code": "acquisition_disabled", "delivery_ids": []})
    with conn.cursor() as cur:
        cur.execute("select delivery_id from public.read_radius_job_input_v1(%s,%s,%s)", queue.fence(job))
        ids = [int(row[0]) for row in cur.fetchall()]
    if set(ids) != set(job["pinned_input"]["delivery_ids"]):
        raise ValueError("radius_input_changed")
    if len(ids) > job["budget"]["max_records"]:
        raise ValueError("job_row_budget_exceeded")
    return result_envelope(job, {"status": "partial", "error_code": None, "delivery_ids": ids})


def result_envelope(job: dict, payload: dict) -> dict:
    return {
        "output_contract": job["result_contract"], "evidence_refs": [], "continuation": None,
        "coverage_state": "not_collected" if payload["status"] == "blocked" else "partial",
        **payload,
    }


def apply_radius(conn, job: dict, result: dict) -> None:
    from server.source_packs.radius.session_consumer import (
        claim_radius_deliveries, load_consumer_contract, process_radius_delivery,
    )

    if result["status"] in {"blocked", "cancelled"}:
        return
    contract = load_consumer_contract(subscription_id=job["pinned_input"]["subscription_id"])
    if contract["subscription_id"] != job["pinned_input"]["subscription_id"]:
        raise ValueError("radius_source_binding_conflict")
    ids = result["delivery_ids"]
    if not isinstance(ids, list) or len(ids) > min(50, job["budget"]["max_records"]):
        raise ValueError("job_row_budget_exceeded")
    if any(type(item) is not int or item <= 0 for item in ids) or len(set(ids)) != len(ids):
        raise ValueError("job_result_invalid")
    if set(ids) != set(job["pinned_input"]["delivery_ids"]):
        raise ValueError("radius_input_changed")
    if not ids:
        return
    # Share the legacy consumer's admission and single-writer guard. Keep the
    # lease and all effects inside the publisher transaction; never commit here.
    holder = f"core-job:{job['job_id']}:{job['lease_generation']}"
    lease = acquire_component_lease(
        conn, lease_uid=uuid4(), component_id=CONSUMER, holder_key=holder,
        activate_role=False,
    )
    # Nested consumer transactions are savepoints inside the publisher fence.
    claimed = claim_radius_deliveries(conn, limit=len(ids), contract=contract,
                                     delivery_ids=tuple(ids), activate_role=False)
    if {item.delivery_id for item in claimed} != set(ids):
        raise ValueError("radius_input_changed")
    record_budget = [job["budget"]["max_records"]]
    for item in claimed:
        process_radius_delivery(conn, delivery_id=item.delivery_id, lease_token=item.lease_token,
                                contract=contract, activate_role=False, record_budget=record_budget)
    if not release_component_lease(
        conn, lease=lease, holder_key=holder, outcome="completed", activate_role=False,
    ):
        raise PluginRuntimeAdmissionError("component_lease_release_invalid")


