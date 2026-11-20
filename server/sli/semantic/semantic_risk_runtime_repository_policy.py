"""Split out of ``server.sli.semantic.semantic_risk_runtime_repository`` (plan 7.2b).

Module-level names of ``semantic_risk_runtime_repository`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.semantic.semantic_risk_runtime_repository as _src
from server.sli.semantic.password_policy_lock import lock_password_policy_families, lock_policy_row


def register_risk_policy(cur: _src.Any, *, policy: _src.RiskPolicyDefinition) -> None:
    compiled = _src.compile_risk_policy(policy)
    lock_password_policy_families(cur, (policy,))
    cur.execute(
        """
        insert into semantic_risk_policies(
            policy_id,policy_version,source_kind,lifecycle_status,
            definition_json,definition_sha256
        ) values (%s,%s,%s,'draft',%s::jsonb,%s)
        on conflict(policy_id,policy_version) do nothing
        """,
        (
            policy.policy_id,
            policy.policy_version,
            policy.source_kind.value,
            policy.definition_json,
            policy.definition_sha256,
        ),
    )
    cur.execute(
        """
        select source_kind,definition_json,definition_sha256
        from semantic_risk_policies where policy_id=%s and policy_version=%s
        """,
        (policy.policy_id, policy.policy_version),
    )
    row = dict(cur.fetchone() or {})
    if (
        row.get("source_kind") != policy.source_kind.value
        or _src._json_object(row.get("definition_json")) != dict(policy.definition)
        or bytes(row.get("definition_sha256") or b"") != policy.definition_sha256
    ):
        raise RuntimeError("semantic risk policy version replay conflict")
    _src.replace_risk_policy_subscription(cur, policy=compiled)


def replace_risk_policy_subscription(cur: _src.Any, *, policy: _src.CompiledRiskPolicy) -> None:
    parent = lock_policy_row(cur, policy.policy_id, policy.policy_version, expected=policy)
    if bytes(parent.get("definition_sha256") or b"") != policy.definition_sha256:
        raise RuntimeError("risk policy subscription definition hash mismatch")
    cur.execute(
        """
        select source_kind,selector_value,definition_sha256
        from semantic_risk_policy_subscriptions
        where policy_id=%s and policy_version=%s
        """,
        (policy.policy_id, policy.policy_version),
    )
    existing = dict(cur.fetchone() or {})
    expected = {
        "source_kind": policy.source_kind.value,
        "selector_value": policy.selector_value,
        "definition_sha256": policy.definition_sha256,
    }
    if existing == expected:
        return
    if parent.get("lifecycle_status") != "draft":
        raise RuntimeError("risk policy subscription is mutable only in draft")
    cur.execute(
        "delete from semantic_risk_policy_subscriptions "
        "where policy_id=%s and policy_version=%s",
        (policy.policy_id, policy.policy_version),
    )
    cur.execute(
        """
        insert into semantic_risk_policy_subscriptions(
            policy_id,policy_version,source_kind,selector_value,definition_sha256
        ) values (%s,%s,%s,%s,%s)
        """,
        (
            policy.policy_id,
            policy.policy_version,
            policy.source_kind.value,
            policy.selector_value,
            policy.definition_sha256,
        ),
    )


def transition_risk_policy(
    cur: _src.Any, *, policy_id: str, policy_version: int, target_status: str
) -> str:
    if target_status not in _src.POLICY_LIFECYCLE:
        raise ValueError("unsupported risk policy lifecycle status")
    row = lock_policy_row(cur, policy_id, int(policy_version))
    if not row:
        raise LookupError("semantic risk policy version not found")
    current = str(row["lifecycle_status"])
    if current == target_status:
        return current
    if target_status not in _src.POLICY_TRANSITIONS[current]:
        raise ValueError(f"invalid risk policy transition: {current} -> {target_status}")
    cur.execute(
        """
        update semantic_risk_policies set lifecycle_status=%s,updated_at=now()
        where policy_id=%s and policy_version=%s and lifecycle_status=%s
        returning lifecycle_status
        """,
        (target_status, policy_id, int(policy_version), current),
    )
    if cur.fetchone() is None:
        raise RuntimeError("semantic risk policy lifecycle changed concurrently")
    return target_status


def record_control_health(
    cur: _src.Any,
    *,
    partition_key: str,
    coverage: _src.ControlCoverage,
    source_reference: str,
) -> str:
    partition = str(partition_key or "").strip()
    reference = str(source_reference or "").strip()
    if not partition or len(partition) > 160:
        raise ValueError("control health partition_key must contain 1..160 characters")
    if not reference or len(reference) > 320:
        raise ValueError("control health source_reference must contain 1..320 characters")
    identity = _src.sha256(
        _src.json.dumps(
            {
                "partition_key": partition,
                "source_reference": reference,
                "assessment": coverage.assessment_sha256.hex(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).digest()
    observation_id = str(
        _src.uuid.uuid5(_src.uuid.NAMESPACE_URL, f"adlog:control-health:{identity.hex()}")
    )
    cur.execute(
        """
        insert into semantic_control_health_observations(
            observation_id,observation_key,control_id,partition_key,
            coverage_status,reason,observed_at_utc,source_reference
        ) values (%s,%s,%s,%s,%s,%s,%s,%s)
        on conflict(observation_key) do nothing
        """,
        (
            observation_id,
            identity,
            coverage.control_id,
            partition,
            coverage.status.value,
            coverage.reason,
            coverage.observed_at_utc,
            reference,
        ),
    )
    cur.execute(
        "select * from semantic_control_health_observations where observation_key=%s",
        (identity,),
    )
    row = dict(cur.fetchone() or {})
    if (
        str(row.get("observation_id")) != observation_id
        or row.get("control_id") != coverage.control_id
        or row.get("partition_key") != partition
        or row.get("coverage_status") != coverage.status.value
        or row.get("reason") != coverage.reason
        or row.get("observed_at_utc") != coverage.observed_at_utc
        or row.get("source_reference") != reference
    ):
        raise RuntimeError("control health observation replay conflict")
    return observation_id
