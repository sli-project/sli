"""Idempotent projection of enabled semantic scenarios into working findings."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from server.sli.semantic.finding_evidence import link_finding_evidence, validate_finding_evidence
from server.sli.storage.evidence_ref import EvidenceRef


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    raise RuntimeError("semantic finding identity must contain an object")


def _entity_type(role: str) -> str:
    if role in {"source_host"}:
        return "host"
    if role in {"source_ip"}:
        return "ip"
    if role in {"container_entity"}:
        return "group"
    return "account"


def publish_enabled_scenario_finding(
    cur: Any,
    *,
    job_id: str,
    scenario_id: str,
    evidence_refs: tuple[EvidenceRef, ...] = (),
) -> dict[str, object]:
    """Publish one enabled result and all of its exact evidence atomically."""
    cur.execute(
        """
        select result.evaluation_mode,result.conclusion_state,
               result.scenario_id,job.policy_id,job.policy_version,job.source_kind,job.qw_signal_id,
               admission.enabled as policy_admitted
        from semantic_risk_evaluation_results result
        join semantic_risk_evaluation_jobs job on job.job_id=result.job_id
        join semantic_risk_policies policy
          on policy.policy_id=job.policy_id and policy.policy_version=job.policy_version
        join semantic_policy_admission admission
          on admission.policy_id=policy.policy_id
         and admission.policy_version=policy.policy_version and admission.enabled is true
        where result.job_id=%s
          and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled'
        for share of policy
        """,
        (job_id,),
    )
    result = dict(cur.fetchone() or {})
    if (
        result.get("evaluation_mode") != "enabled"
        or result.get("conclusion_state") != "observed"
        or str(result.get("scenario_id") or "") != scenario_id
        or result.get("policy_admitted") is not True
    ):
        raise RuntimeError("semantic finding requires an observed enabled result")

    password_signal = None
    from server.sli.semantic.password_attack_runtime import (
        is_password_signal, lock_publication, scenario_password_signal,
    )

    # Serialize discovery with ordinary scenario writers; a concurrent managed
    # contribution cannot appear after a negative probe and bypass its proof.
    cur.execute("select identity_key from semantic_security_scenarios where scenario_id=%s", (scenario_id,))
    identity = cur.fetchone()
    if not identity or not identity.get("identity_key"):
        raise RuntimeError("semantic finding scenario is unavailable")
    cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))",
                (bytes(identity["identity_key"]).hex(),))
    if result.get("source_kind") == "qw_signal":
        from server.sli.semantic.qw_input import load_qw_signal

        if result.get("qw_signal_id"):
            signal = load_qw_signal(cur, signal_id=str(result["qw_signal_id"]))
            if is_password_signal(signal):
                password_signal = signal
    if password_signal is None:
        password_signal = scenario_password_signal(cur, scenario_id)
    if password_signal is not None:
        if result.get("source_kind") != "qw_signal":
            raise RuntimeError("password_v2_scenario_invalid")
        lock_publication(cur, password_signal)

    # A shared scenario may contain contributions from TEST/SHADOW evaluations.
    # Every contribution to its severity must come from an explicitly admitted
    # immutable policy version, including contributions from earlier jobs.
    # Admission edits take FOR UPDATE on the same policy row. Lock all contributing
    # policies first, then read admission in a fresh statement snapshot. The worker
    # only has SELECT on the admission table and must not lock/update it directly.
    cur.execute(
        """
        select policy.policy_id,policy.policy_version
        from semantic_risk_contributions contribution
        join semantic_risk_policies policy
          on policy.policy_id=contribution.policy_id
         and policy.policy_version=contribution.policy_version
        where contribution.scenario_id=%s
        order by policy.policy_id,policy.policy_version
        for share of policy
        """, (scenario_id,),
    )
    cur.execute(
        """
        select contribution.policy_sha256,policy.definition_sha256,
               policy.lifecycle_status,admission.enabled as admitted
        from semantic_risk_contributions contribution
        join semantic_risk_policies policy
          on policy.policy_id=contribution.policy_id
         and policy.policy_version=contribution.policy_version
        left join semantic_policy_admission admission
          on admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
        where contribution.scenario_id=%s
        for share of policy
        """, (scenario_id,),
    )
    contributions = list(cur.fetchall() or [])
    if not contributions or any(
        item.get("admitted") is not True
        or item.get("lifecycle_status") not in {"shadow", "enabled"}
        or not item.get("policy_sha256")
        or item.get("policy_sha256") != item.get("definition_sha256")
        for item in contributions
    ):
        raise RuntimeError("semantic finding requires admitted policy contributions")

    cur.execute(
        """
        select scenario_id,scenario_kind,scenario_key,strict_keys_json,
               title,explanation,first_seen_utc,last_seen_utc,risk_class,
               confidence_score,evidence_state
        from semantic_security_scenarios
        where scenario_id=%s
        for share
        """,
        (scenario_id,),
    )
    scenario = dict(cur.fetchone() or {})
    if not scenario:
        raise RuntimeError("semantic finding scenario is unavailable")
    if password_signal is not None and (scenario.get("scenario_kind") != password_signal.rule_id or evidence_refs):
        raise RuntimeError("password_v2_scenario_invalid")
    if scenario.get("scenario_kind") == "qw.file-acl-broad-write" and scenario.get("risk_class") != "medium":
        raise RuntimeError("file_acl_medium_publication_required")
    # All native sources must be authorized and verifiable before a finding is
    # created. A supported subset must never conceal an unsupported reference.
    if result.get("source_kind") == "detection_match":
        from server.sli.sigma.detection_input import scenario_detection_evidence

        evidence_refs = (*evidence_refs, *scenario_detection_evidence(cur, scenario_id=scenario_id))
    exact_refs = validate_finding_evidence(cur, evidence_refs)
    qw_publication = result.get("source_kind") == "qw_signal"
    if qw_publication:
        from server.sli.semantic.qw_input import scenario_qw_evidence_batches

        if scenario.get("evidence_state") != "ready":
            raise RuntimeError("qw_evidence_pending")
        # Preflight every portion before any finding write. Iterate again when
        # linking: authorization/integrity is rechecked, without a giant tuple.
        if password_signal is not None:
            from server.sli.semantic.password_attack_runtime import verify_scenario

            verify_scenario(cur, scenario_id=scenario_id)
        else:
            for _ in scenario_qw_evidence_batches(cur, scenario_id=scenario_id):
                pass
    fingerprint = f"semantic:{bytes(scenario['scenario_key']).hex()}"
    strict = _json_object(scenario["strict_keys_json"])
    actor = strict.get("actor") or strict.get("session_principal")
    target = strict.get("target_entity") or strict.get("container_entity")
    source = strict.get("source_host") or strict.get("source_ip")
    rule_code = f"semantic.{scenario['scenario_kind']}"

    cur.execute(
        "select pg_advisory_xact_lock(hashtextextended(%s,0))",
        (fingerprint,),
    )
    cur.execute(
        """
        insert into findings(
            fingerprint,rule_code,title,severity,confidence,status,
            first_seen_utc,last_seen_utc,actor,target,source,summary,
            why_it_matters,recommended_action,evidence_count,status_reason,
            repeat_count,last_evidence_event_id
        ) values(
            %s,%s,%s,%s,%s,'new',%s,%s,%s,%s,%s,%s,%s,%s,0,
            'created from enabled semantic scenario',0,null
        )
        on conflict(fingerprint) do nothing
        returning id
        """,
        (
            fingerprint,
            rule_code,
            scenario["title"],
            scenario["risk_class"],
            int(scenario["confidence_score"]) / 100.0,
            scenario["first_seen_utc"].isoformat(),
            scenario["last_seen_utc"].isoformat(),
            actor,
            target,
            source,
            scenario["explanation"],
            scenario["explanation"],
            "Review the linked evidence and validate the security impact.",
        ),
    )
    created = cur.fetchone()
    cur.execute(
        """
        select id,rule_code from findings
        where fingerprint=%s
        for update
        """,
        (fingerprint,),
    )
    finding = dict(cur.fetchone() or {})
    if not finding or finding.get("rule_code") != rule_code:
        raise RuntimeError("semantic finding fingerprint replay conflict")
    finding_id = int(finding["id"])

    password_batches = None
    if password_signal is not None:
        # A new native pass, not the preflight's retained content/verdict.
        password_batches = verify_scenario(cur, scenario_id=scenario_id)

    cur.execute(
        """
        insert into finding_evidence(finding_id,event_id,evidence_role,note)
        select %s,normalized.source_event_id,'semantic_scenario',
               'enabled semantic scenario evidence'
        from semantic_scenario_evidence evidence
        join normalized_events normalized
          on normalized.normalized_event_id=evidence.normalized_event_id
        where evidence.scenario_id=%s
        order by evidence.evidence_order
        on conflict(finding_id,event_id,evidence_role) do nothing
        returning event_id
        """,
        (finding_id, scenario_id),
    )
    added_event_ids = [int(row["event_id"]) for row in (cur.fetchall() or [])]
    typed_added = link_finding_evidence(cur, finding_id=finding_id, refs=exact_refs) if exact_refs else 0
    if password_batches is not None:
        from server.sli.semantic.password_attack_runtime import link_password_evidence

        typed_added += link_password_evidence(cur, finding_id=finding_id, batches=password_batches)
    elif qw_publication:
        for batch in scenario_qw_evidence_batches(cur, scenario_id=scenario_id):
            typed_added += link_finding_evidence(cur, finding_id=finding_id, refs=batch)

    for role, value in sorted(strict.items()):
        if qw_publication and role in {"kind", "entity", "episode"}:
            # Opaque episode keys are not display names of directory accounts.
            continue
        display = str(value or "").strip()
        if not display:
            continue
        cur.execute(
            """
            insert into finding_entities(
                finding_id,entity_type,display_name,entity_role
            )
            select %s,%s,%s,%s
            where not exists (
                select 1 from finding_entities
                where finding_id=%s
                  and coalesce(entity_type,'')=%s
                  and coalesce(display_name,'')=%s
                  and entity_role=%s
            )
            """,
            (
                finding_id,
                _entity_type(role),
                display,
                role,
                finding_id,
                _entity_type(role),
                display,
                role,
            ),
        )

    cur.execute(
        """
        select count(*)::bigint as count,max(event_id)::bigint as max_event_id
        from (
            select event_id from finding_evidence
            where finding_id=%s and evidence_role='semantic_scenario'
            union all
            select null::bigint as event_id from public.finding_evidence_refs
            where finding_id=%s and evidence_role='semantic_scenario' and storage_kind<>'core_event'
        ) exact_evidence
        """,
        (finding_id, finding_id),
    )
    evidence = dict(cur.fetchone() or {})
    evidence_count = int(evidence.get("count") or 0)
    if evidence_count <= 0:
        raise RuntimeError("semantic finding has no exact event evidence")

    cur.execute(
        """
        update findings
        set title=%s,severity=%s,confidence=%s,
            first_seen_utc=%s,last_seen_utc=%s,
            actor=coalesce(%s,actor),target=coalesce(%s,target),
            source=coalesce(%s,source),summary=%s,why_it_matters=%s,
            recommended_action=%s,evidence_count=%s,
            last_evidence_event_id=%s,updated_at=now()
        where id=%s
        """,
        (
            scenario["title"],
            scenario["risk_class"],
            int(scenario["confidence_score"]) / 100.0,
            scenario["first_seen_utc"].isoformat(),
            scenario["last_seen_utc"].isoformat(),
            actor,
            target,
            source,
            scenario["explanation"],
            scenario["explanation"],
            "Review the linked evidence and validate the security impact.",
            evidence_count,
            evidence.get("max_event_id"),
            finding_id,
        ),
    )

    cur.execute(
        """
        insert into semantic_finding_publications(
            scenario_id,finding_id,first_job_id,finding_fingerprint,
            published_evidence_count
        ) values(%s,%s,%s,%s,%s)
        on conflict(scenario_id) do nothing
        """,
        (scenario_id, finding_id, job_id, fingerprint, evidence_count),
    )
    cur.execute(
        """
        select finding_id,finding_fingerprint
        from semantic_finding_publications
        where scenario_id=%s
        """,
        (scenario_id,),
    )
    publication = dict(cur.fetchone() or {})
    if (
        int(publication.get("finding_id") or 0) != finding_id
        or publication.get("finding_fingerprint") != fingerprint
    ):
        raise RuntimeError("semantic finding publication replay conflict")

    if created is not None:
        cur.execute(
            """
            insert into finding_status_history(
                finding_id,old_status,new_status,changed_by,note
            ) values(%s,null,'new','semantic-worker',
                     'created from enabled semantic scenario')
            """,
            (finding_id,),
        )
    if qw_publication:
        # The database function admits only published observed ENABLED QW
        # objects, carries no payload and never commits or invokes a transport.
        cur.execute("select public.enqueue_qw_finding_notifications(%s) as enqueued", (scenario_id,))
    return {
        "finding_id": finding_id,
        "created": created is not None,
        "evidence_added": len(added_event_ids) + typed_added,
        "evidence_count": evidence_count,
        "fingerprint": fingerprint,
    }
