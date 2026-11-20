"""Execution pins and scoped operational metrics for the existing policy lifecycle.

Policies use register_risk_policy/transition_risk_policy and the separately
audited set_policy_admission. No connection, admission or activation on import.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timedelta
from hashlib import sha256
import json
import re

from server.sli.storage.evidence_ref import EvidenceRefError, EvidenceScope


def execution_pin_sha256(pin, *, rule_id: str) -> str:
    """Validate the complete immutable selector, never a UUID-only admission."""
    keys = {"version", "rule_id", "rule_sha256", "manifest_sha256", "compiler_version",
            "mapping_version", "overlay_sha256", "scope"}
    try:
        valid = (isinstance(pin, Mapping) and set(pin) == keys
                 and pin["version"] == "sli.sigma.execution.v1" and pin["rule_id"] == rule_id
                 and all(isinstance(pin[key], str) and re.fullmatch(r"[a-f0-9]{64}", pin[key])
                         for key in ("rule_sha256", "manifest_sha256", "overlay_sha256"))
                 and all(isinstance(pin[key], str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", pin[key])
                         for key in ("compiler_version", "mapping_version")))
        if not valid or asdict(EvidenceScope(**pin["scope"])) != pin["scope"]:
            raise ValueError
        return sha256(json.dumps(dict(pin), sort_keys=True, separators=(",", ":"),
                                 allow_nan=False).encode()).hexdigest()
    except (KeyError, TypeError, ValueError, EvidenceRefError):
        raise ValueError("sigma_detection_execution_pin_required") from None


def read_lifecycle_metrics(cur, *, scope: EvidenceScope, since: datetime, until: datetime,
                           limit: int = 100) -> dict:
    """SELECT-only metrics over eligible inputs, not telemetry coverage or clean events.

    The caller supplies a scope-authorized cursor. PostgreSQL evidence RLS is
    preserved. Half-open windows use input creation time, at most 31 days;
    groups never combine execution/policy versions or evaluation modes.
    """
    if (not isinstance(scope, EvidenceScope) or not isinstance(since, datetime)
            or not isinstance(until, datetime) or since.utcoffset() is None or until.utcoffset() is None
            or not timedelta(0) < until - since <= timedelta(days=31)
            or type(limit) is not int or not 1 <= limit <= 200):
        raise ValueError("sigma_lifecycle_metrics_request_invalid")
    cur.execute("""
        select detection.rule_id,detection.document_json->>'rule_sha256' as rule_sha256,
               detection.document_json->>'manifest_sha256' as manifest_sha256,
               detection.document_json->>'compiler_version' as compiler_version,
               detection.document_json->>'mapping_version' as mapping_version,
               detection.document_json->>'overlay_sha256' as overlay_sha256,
               detection.evaluation_mode,job.policy_id,job.policy_version,policy.lifecycle_status,
               semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status) as effective_mode,
               coalesce(admission.enabled,false) as admitted,
               count(distinct detection.match_id) as matches,
               count(distinct detection.match_id) filter(where job.job_id is null) as unqueued,
               count(job.job_id) as jobs,
               count(*) filter(where job.evaluation_status='queued') as queued,
               count(*) filter(where job.evaluation_status='leased') as leased,
               count(*) filter(where job.evaluation_status='completed') as completed,
               count(*) filter(where job.evaluation_status='failed') as failed,
               count(*) filter(where job.evaluation_status='quarantined') as quarantined,
               count(result.job_id) as evaluated,
               count(*) filter(where result.conclusion_state='observed') as observed,
               count(*) filter(where result.conclusion_state='not_checked') as not_checked,
               count(*) filter(where result.coverage_status<>'complete') as degraded,
               coalesce(sum(result.evaluation_ms),0) as evaluation_ms,
               coalesce(max(result.evaluation_ms),0) as max_evaluation_ms
        from semantic_detection_matches detection
        left join semantic_risk_evaluation_jobs job
          on job.detection_match_id=detection.match_id and job.source_kind='detection_match'
        left join semantic_risk_policies policy
          on policy.policy_id=job.policy_id and policy.policy_version=job.policy_version
        left join semantic_policy_admission admission
          on admission.policy_id=job.policy_id and admission.policy_version=job.policy_version
        left join semantic_risk_evaluation_results result on result.job_id=job.job_id
        where detection.document_json#>'{evidence,scope}'=%s::jsonb
          and detection.created_at >= %s and detection.created_at < %s
        group by 1,2,3,4,5,6,7,8,9,10,11,12
        order by 1,2,3,4,5,6,7,8,9 limit %s
    """, (json.dumps(asdict(scope), sort_keys=True), since, until, limit + 1))
    rows = [dict(row) for row in cur.fetchall()]
    return {"basis": "eligible_detection_inputs", "window_basis": "input_created_at",
            "since": since.isoformat(), "until": until.isoformat(),
            "rows": rows[:limit], "truncated": len(rows) > limit, "limit": limit}
