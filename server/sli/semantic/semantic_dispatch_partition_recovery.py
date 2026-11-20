"""Fail-closed recovery for exactly three quarantined semantic dispatch jobs.

The controller deliberately has no source/archive, producer, risk, or scenario
entrypoint.  Its only mutation is a transactionally bounded replay of the
sealed dispatch-job identities.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Mapping, Sequence


RULE_ID = "investigation.account.unlock.after-lock"
RULE_VERSION = 2
RULE_SHA256 = "5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e"
EXPECTED_NORMALIZED_CONTRACT = {
    "semantic_contract_version": 1,
    "normalizer_id": "windows.named-eventdata",
    "normalizer_version": "1.4+identity-1.0",
}
ERROR_CODE = "UniqueViolation"
ERROR_CONSTRAINT = "semantic_correlation_candidate__candidate_id_evidence_order_key"
COMPLETION_ERROR_CODE = "CheckViolation"
COMPLETION_ERROR_CONSTRAINT = "semantic_correlation_dispatch_terminal"
CONFIRM_PREFIX = "REPAIR-SEMANTIC-DISPATCH-PARTITION:"
PLAN_VERSION = "semantic_dispatch_partition_recovery_v1"
EXPECTED_JOBS = {
    "10eac730-5285-5740-b605-577d3ef9f4c2": (6943209, "7291"),
    "75280b7d-4573-5bc9-9e0e-c1d3f6e897e3": (6486534, "6682"),
    "e24572a7-159d-517c-a284-a0eff96ac007": (6487797, "6295"),
}
EXPECTED_RELATIONS = (
    (6487797, (6442170, 6487797), "dispatch:2dfdf2e4219e728fcab50c8a65139153c7bd1b410ed72c0493afdec8ca7df7c4"),
    (6486534, (6436767, 6486534), "dispatch:9dd99c4a7bf00789c02b297270df71260e79096577bc4b1e6ccdba437717c037"),
    (6943209, (6923513, 6943209), "dispatch:5497fb27862a7026a64b5e77f41d8e0a3fa181d9429bffa34671b899eedebe23"),
    (6943209, (6874055, 6943209), "dispatch:b17e18e9d9fd11eb218a0b20b24175a8cf1ec427038c7700114f323a36767cfb"),
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(value: object) -> str:
    return sha256(_canonical(value).encode("utf-8")).hexdigest()


def _hex(value: object) -> str:
    text = str(value or "").casefold()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise RuntimeError("semantic dispatch recovery source hash is invalid")
    return text


def _detail_has_exact_constraint(value: object) -> bool:
    # PostgreSQL can localize everything except the quoted constraint identity.
    return f'"{ERROR_CONSTRAINT}"' in str(value or "")


def _has_expected_recovery_error(source: Mapping[str, object]) -> bool:
    code = source.get("last_error_code")
    detail = str(source.get("last_error_detail") or "")
    return (
        code == ERROR_CODE and f'"{ERROR_CONSTRAINT}"' in detail
    ) or (
        code == COMPLETION_ERROR_CODE and f'"{COMPLETION_ERROR_CONSTRAINT}"' in detail
    )


def _normalized_boundary(value: object) -> str:
    text = str(value or "")
    if not text or "+" not in text and not text.endswith("Z"):
        raise RuntimeError("semantic dispatch recovery normalized boundary is invalid")
    return text


def _expected_relation_rows() -> list[dict[str, object]]:
    return [
        {
            "trigger_source_event_id": trigger,
            "source_event_ids": list(source_ids),
            "contribution_key": contribution_key,
        }
        for trigger, source_ids, contribution_key in EXPECTED_RELATIONS
    ]


def _accepted_relations_for_trigger(trigger_source_event_id: int) -> list[dict[str, object]]:
    return [
        relation for relation in _expected_relation_rows()
        if relation["trigger_source_event_id"] == trigger_source_event_id
    ]


def _relation_rows(source: Mapping[str, object], field: str) -> list[dict[str, object]]:
    observed = source.get(field)
    if not isinstance(observed, Sequence) or isinstance(observed, (str, bytes)):
        raise RuntimeError("semantic dispatch recovery relation readback is missing")
    rows = [dict(item) for item in observed if isinstance(item, Mapping)]
    if len(rows) != len(observed):
        raise RuntimeError("semantic dispatch recovery relation readback changed")
    return sorted(rows, key=_canonical)


def _normalized_contract(source: Mapping[str, object]) -> dict[str, object]:
    try:
        version = int(source.get("semantic_contract_version") or 0)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("semantic dispatch recovery normalized contract is invalid") from exc
    normalizer_id = str(source.get("normalizer_id") or "").strip()
    normalizer_version = str(source.get("normalizer_version") or "").strip()
    if version <= 0 or not normalizer_id or not normalizer_version:
        raise RuntimeError("semantic dispatch recovery normalized contract is invalid")
    contract = {
        "semantic_contract_version": version,
        "normalizer_id": normalizer_id,
        "normalizer_version": normalizer_version,
    }
    if contract != EXPECTED_NORMALIZED_CONTRACT:
        raise RuntimeError("semantic dispatch recovery normalized contract changed")
    return contract


def _is_exact_queued_recovery_state(source: Mapping[str, object]) -> bool:
    try:
        attempt_count = int(source.get("attempt_count") or 0)
        max_attempts = int(source.get("max_attempts") or 0)
    except (TypeError, ValueError):
        return False
    accepted = source.get("accepted_relations", [])
    return (
        source.get("lease_token") is None
        and source.get("lease_until") is None
        and source.get("heartbeat_at") is None
        and attempt_count == 5
        and max_attempts == 5
        and isinstance(accepted, Sequence)
        and not isinstance(accepted, (str, bytes))
        and len(accepted) == 0
    )


def _is_exact_expired_recovery_lease(source: Mapping[str, object]) -> bool:
    try:
        attempt_count = int(source.get("attempt_count") or 0)
        max_attempts = int(source.get("max_attempts") or 0)
    except (TypeError, ValueError):
        return False
    accepted = source.get("accepted_relations", [])
    return (
        bool(source.get("lease_token"))
        and source.get("lease_until") is not None
        and source.get("heartbeat_at") is not None
        and source.get("lease_expired") is True
        and attempt_count == max_attempts == 5
        and isinstance(accepted, Sequence)
        and not isinstance(accepted, (str, bytes))
        and len(accepted) == 0
    )


def _is_exact_original_quarantine_state(source: Mapping[str, object]) -> bool:
    try:
        attempt_count = int(source.get("attempt_count") or 0)
        max_attempts = int(source.get("max_attempts") or 0)
    except (TypeError, ValueError):
        return False
    return (
        source.get("lease_token") is None
        and source.get("lease_until") is None
        and (
            source.get("heartbeat_at") is None
            if source.get("last_error_code") == ERROR_CODE
            else source.get("heartbeat_at") is not None
        )
        and attempt_count == max_attempts == 5
    )


def _valid_job_contract(source: Mapping[str, object], *, permit_completed: bool) -> tuple[str, int, str]:
    job_id = str(source.get("job_id") or "")
    expected = EXPECTED_JOBS.get(job_id)
    if expected is None:
        raise RuntimeError("semantic dispatch recovery job UUID set changed")
    trigger, suffix = expected
    status = str(source.get("dispatch_status") or "")
    legal_states = {"quarantined", "queued", "leased"}
    if permit_completed:
        legal_states.add("completed")
    if status not in legal_states:
        raise RuntimeError("semantic dispatch recovery job state changed")
    if (
        int(source.get("source_event_id") or 0) != trigger
        or source.get("rule_id") != RULE_ID
        or int(source.get("rule_version") or 0) != RULE_VERSION
        or _hex(source.get("definition_sha256")) != RULE_SHA256
        or not str(source.get("partition_key") or "").endswith(suffix)
        or str(source.get("trigger_identity") or "") != suffix
    ):
        raise RuntimeError("semantic dispatch recovery job contract changed")
    _normalized_contract(source)
    expected_relations = sorted(_accepted_relations_for_trigger(trigger), key=_canonical)
    accepted_relations = _relation_rows(source, "accepted_relations")
    repairable_relations = _relation_rows(source, "repairable_relations")
    blocking_relations = _relation_rows(source, "blocking_relations")
    if blocking_relations:
        raise RuntimeError("semantic dispatch recovery blocking relation changed")
    if status == "completed":
        if accepted_relations != expected_relations or repairable_relations:
            raise RuntimeError("semantic dispatch recovery completed relation readback changed")
    elif accepted_relations or repairable_relations != expected_relations:
        raise RuntimeError("semantic dispatch recovery repairable relation readback changed")
    if status in {"quarantined", "queued", "leased"} and not _has_expected_recovery_error(source):
        raise RuntimeError("semantic dispatch recovery job contract changed")
    if status == "queued" and not _is_exact_queued_recovery_state(source):
        raise RuntimeError("semantic dispatch recovery queued state changed")
    if status == "leased" and not _is_exact_expired_recovery_lease(source):
        raise RuntimeError("semantic dispatch recovery leased state changed")
    if status == "quarantined" and not _is_exact_original_quarantine_state(source):
        raise RuntimeError("semantic dispatch recovery quarantine state changed")
    return job_id, trigger, status


def _remaining_jobs(rows: Sequence[Mapping[str, object]]) -> list[str]:
    if len(rows) != len(EXPECTED_JOBS):
        raise RuntimeError("semantic dispatch recovery requires exactly three planned jobs")
    seen: set[str] = set()
    remaining: list[str] = []
    for source in rows:
        job_id, trigger, status = _valid_job_contract(source, permit_completed=True)
        if job_id in seen:
            raise RuntimeError("semantic dispatch recovery job UUID set changed")
        seen.add(job_id)
        if status != "completed":
            remaining.append(job_id)
    if seen != set(EXPECTED_JOBS):
        raise RuntimeError("semantic dispatch recovery job UUID set changed")
    return sorted(remaining)


def validate_recovery_rows(rows: Sequence[Mapping[str, object]]) -> list[str]:
    """Validate exact legal resume state and return remaining quarantine UUIDs."""
    return _remaining_jobs(rows)


def _observed_plan_jobs(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """Project immutable plan material from either legal resume state."""
    jobs: list[dict[str, object]] = []
    for source in rows:
        job_id, trigger, _status = _valid_job_contract(source, permit_completed=True)
        suffix = EXPECTED_JOBS[job_id][1]
        jobs.append({
            "job_id": job_id,
            "trigger_source_event_id": trigger,
            "partition_key": str(source["partition_key"]),
            "trigger_identity_suffix": suffix,
            "normalized_contract": _normalized_contract(source),
            "source_hash_sha256": _hex(source.get("source_hash")),
            "job_payload_sha256": _hex(source.get("job_payload_sha256") or _hash({
                "job_id": job_id, "trigger_source_event_id": trigger,
                "partition_key": str(source["partition_key"]),
                "source_hash_sha256": _hex(source.get("source_hash")),
            })),
        })
    return sorted(jobs, key=lambda item: str(item["job_id"]))


def build_sealed_plan(rows: Sequence[Mapping[str, object]], *, normalized_before: object) -> dict[str, object]:
    """Canonical, secret-free plan from authoritative dispatch rows only."""
    boundary = _normalized_boundary(normalized_before)
    if len(rows) != len(EXPECTED_JOBS):
        raise RuntimeError("semantic dispatch recovery requires exactly three quarantined jobs")
    jobs: list[dict[str, object]] = []
    seen: set[str] = set()
    for source in rows:
        job_id = str(source.get("job_id") or "")
        if job_id in seen:
            raise RuntimeError("semantic dispatch recovery job UUID set changed")
        seen.add(job_id)
        _job_id, trigger, _status = _valid_job_contract(source, permit_completed=False)
        suffix = EXPECTED_JOBS[job_id][1]
        jobs.append({
            "job_id": job_id,
            "trigger_source_event_id": trigger,
            "partition_key": str(source["partition_key"]),
            "trigger_identity_suffix": suffix,
            "normalized_contract": _normalized_contract(source),
            "source_hash_sha256": _hex(source.get("source_hash")),
            "job_payload_sha256": _hex(source.get("job_payload_sha256") or _hash({
                "job_id": job_id, "trigger_source_event_id": trigger,
                "partition_key": str(source["partition_key"]),
                "source_hash_sha256": _hex(source.get("source_hash")),
            })),
        })
    if seen != set(EXPECTED_JOBS):
        raise RuntimeError("semantic dispatch recovery job UUID set changed")
    material: dict[str, object] = {
        "plan_version": PLAN_VERSION,
        "rule": {"rule_id": RULE_ID, "rule_version": RULE_VERSION, "definition_sha256": RULE_SHA256},
        "error": {"code": ERROR_CODE, "constraint": ERROR_CONSTRAINT},
        "normalized_before": boundary,
        "jobs": sorted(jobs, key=lambda item: str(item["job_id"])),
        "expected_relations": _expected_relation_rows(),
        "scenario_evidence_expected": 0,
    }
    digest = _hash(material)
    return {**material, "job_count": 3, "plan_digest": digest, "confirmation": CONFIRM_PREFIX + digest}


@dataclass
class RecoveryController:
    """Dependency-injected narrow orchestration seam for controller tests/runtime."""
    snapshot: Callable[[], Sequence[Mapping[str, object]]]
    worker_is_live: Callable[[], bool]
    acquire_locks: Callable[[], bool]
    requeue: Callable[[Mapping[str, object]], None] = lambda _plan: None
    dispatch: Callable[[Mapping[str, object]], Mapping[str, object]] = lambda _plan: {"completed": 0, "failed": 0, "relations": 0}
    verify: Callable[[Mapping[str, object]], Mapping[str, object]] = lambda _plan: {}
    audit: Callable[[Mapping[str, object]], None] = lambda _result: None
    preflight: Callable[[Mapping[str, object]], bool] = lambda _plan: True

    def apply(self, *, plan_digest: str, confirmation: str, plan: Mapping[str, object]) -> dict[str, object]:
        """Apply one immutable plan; no mutation precedes full revalidation."""
        # Canonical round-trip freezes caller-owned JSON before any lock/write.
        sealed = json.loads(_canonical(plan))
        if plan_digest != sealed.get("plan_digest") or confirmation != sealed.get("confirmation"):
            raise RuntimeError("exact semantic dispatch recovery confirmation required")
        if confirmation != CONFIRM_PREFIX + str(plan_digest):
            raise RuntimeError("exact semantic dispatch recovery confirmation required")
        if self.worker_is_live():
            raise RuntimeError("semantic dispatch recovery refuses a live dispatcher")
        if not self.acquire_locks():
            raise RuntimeError("semantic dispatch recovery advisory lock is busy")
        # The current rows may be unchanged quarantines or exact completed
        # readbacks from an interrupted prior run; anything else fails closed.
        current_rows = self.snapshot()
        remaining = _remaining_jobs(current_rows)
        if remaining:
            if _canonical(_observed_plan_jobs(current_rows)) != _canonical(sealed.get("jobs")):
                raise RuntimeError("semantic dispatch recovery plan changed before any write")
            if not self.preflight(sealed):
                raise RuntimeError("semantic dispatch recovery preflight changed before any write")
        if not remaining:
            result = {"status": "already_complete", "plan_digest": plan_digest, "production_changed": False}
            self.audit(result)
            return result
        scoped = {
            "allowed_job_ids": remaining,
            "normalized_before": sealed["normalized_before"],
            "allowed_rule_identity": (RULE_ID, RULE_VERSION, RULE_SHA256),
        }
        scoped_plan = {**sealed, "jobs": [item for item in sealed["jobs"] if item["job_id"] in remaining]}
        self.requeue(scoped_plan)
        dispatch = dict(self.dispatch(scoped))
        if int(dispatch.get("failed") or 0) != 0 or int(dispatch.get("completed") or 0) != len(remaining):
            raise RuntimeError("semantic dispatch recovery processing failed or was incomplete")
        verification = dict(self.verify(sealed))
        if not (
            verification.get("completed") is True
            and verification.get("relations_exact") is True
            and verification.get("scenario_evidence_added") == 0
            and verification.get("unrelated_status_unchanged") is True
        ):
            raise RuntimeError("semantic dispatch recovery acceptance verification failed")
        result = {
            "status": "complete", "plan_digest": plan_digest, "production_changed": True,
            "dispatch": dispatch, "verification": verification,
        }
        self.audit(result)
        return result
