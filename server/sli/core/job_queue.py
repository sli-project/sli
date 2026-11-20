"""PostgreSQL core job ledger. Callers own transactions and publication effects."""
from __future__ import annotations

import json
from typing import Any

from server.sli.plugin_validation import (
    canonical as canonical,
    digest as digest,
)


class JobConflict(ValueError):
    pass


class LeaseLost(RuntimeError):
    pass


def idempotency_key(spec: dict, pinned_input: dict) -> str:
    return digest({
        **{key: spec[key] for key in (
            "plugin_id", "handler_id", "handler_version", "manifest_sha256",
            "source_instance_id", "partition_key", "input_contract", "input_sha256",
        )},
        **{key: pinned_input[key] for key in (
            "generation", "input_range", "policy_revision", "continuation",
        )},
    })


def enqueue(cur: Any, spec: dict) -> str:
    cur.execute("select public.enqueue_core_job_v1(%s::jsonb)", (canonical(spec),))
    row = cur.fetchone()
    if not row or row[0] is None:
        raise JobConflict("job_identity_conflict")
    return str(row[0])


def claim(cur: Any, profile: str, executor_id: str, identities: list[dict]) -> dict | None:
    cur.execute("select public.claim_core_job_v1(%s,%s,%s::jsonb)",
                (profile, executor_id, canonical(identities)))
    row = cur.fetchone()
    return dict(row[0]) if row and row[0] else None


def heartbeat(cur: Any, job: dict) -> None:
    cur.execute("select public.heartbeat_core_job_v1(%s,%s,%s)", fence(job))
    if not cur.fetchone()[0]:
        raise LeaseLost("job_lease_lost")


def fence(job: dict) -> tuple:
    return job["job_id"], job["lease_token"], job["lease_generation"]


def fail(cur: Any, job: dict, code: str, *, permanent: bool = False) -> None:
    cur.execute("select public.fail_core_job_v1(%s,%s,%s,%s,%s)",
                (*fence(job), code, permanent))
    if not cur.fetchone()[0]:
        raise LeaseLost("job_lease_lost")


def publish(conn: Any, job: dict, result: dict, apply_effects: Any) -> str:
    """Lock/fence BEFORE effects; the final fence rolls back every effect on expiry."""
    envelope = {
        "contract_id": "sli.core-job-result.v1",
        **{key: job[key] for key in ("job_id", "lease_token", "lease_generation", "plugin_id",
                                    "plugin_version", "handler_id", "handler_version")},
        "status": result["status"], "output_contract": job["result_contract"],
        "output_refs": [f"core-job:{job['job_id']}"], "evidence_refs": result.get("evidence_refs", []),
        "continuation": result.get("continuation"), "coverage_state": result.get("coverage_state", "not_proven"),
        "error_code": result.get("error_code"),
    }
    result_hash = digest({"envelope": envelope, "output": result})
    envelope["result_sha256"] = result_hash
    from server.sli.core.job_registry import ROOT, validate_shape

    schema = json.loads((ROOT / "config/plugin_architecture_v3.json").read_text("utf-8"))
    validate_shape(envelope, schema["$defs"]["result"], schema)
    if len(canonical({"envelope": envelope, "output": result}).encode("utf-8")) > job["budget"]["max_result_bytes"]:
        raise ValueError("job_result_budget_exceeded")
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("select public.begin_core_job_result_v1(%s,%s,%s,%s)",
                    (*fence(job), result_hash))
        state = cur.fetchone()[0]
        if state in {"duplicate", "conflict"}:
            return state
        if state != "publish":
            raise LeaseLost("job_lease_lost")
        apply_effects(conn, job, result)
        cur.execute("select public.finish_core_job_result_v1(%s,%s,%s,%s,%s::jsonb,%s::jsonb)",
                    (*fence(job), result_hash, canonical(envelope), canonical(result)))
        if not cur.fetchone()[0]:
            raise LeaseLost("job_lease_lost")
    return "committed"
