"""Read-only quality of published semantic findings; no rule activation."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from statistics import median
from typing import Any

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.reporting.read_timeout import report_read_budget
from server.sli.semantic.findings import VALID_FINDING_STATUSES
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route

MAX_FINDINGS = 10_000
DECISIONS = frozenset({"confirmed", "false_positive", "closed", "accepted_risk"})
CLASSIFICATIONS = DECISIONS - {"closed"}
# CompiledRiskPolicy.result_class / ScenarioResultClass; never arbitrary titles.
RULE_RESULT_CLASSES = frozenset({"security_incident", "security_exposure", "control_gap"})


def utc(value: Any) -> datetime:
    moment = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("report_period_invalid")
    return moment.astimezone(timezone.utc)


def compute_metrics(findings: list[dict], *, end: datetime, accepted_risk: bool) -> list[dict]:
    """One vote per finding, using lifecycle transitions strictly before end."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        groups[str(finding["rule_code"])].append(finding)
    rows = []
    for rule, cohort in sorted(groups.items()):
        counts = dict.fromkeys(("confirmed", "false_positive", "closed", "accepted_risk", "suppressed", "repeated", "complete_evidence", "missing_history"), 0)
        durations = []
        for finding in cohort:
            created = utc(finding["created_at"])
            history = sorted(
                (entry for entry in finding.get("history") or [] if created <= utc(entry["changed_at"]) < end),
                key=lambda entry: (utc(entry["changed_at"]), int(entry["id"])),
            )
            transitions = [entry for entry in history if entry["new_status"] != entry.get("old_status")]
            classifications = [entry for entry in transitions if entry["new_status"] in CLASSIFICATIONS]
            if classifications:
                counts[classifications[-1]["new_status"]] += 1
            if history and history[-1]["new_status"] == "closed":
                counts["closed"] += 1
            if not history:
                counts["missing_history"] += 1
            decisions = [entry for entry in transitions if entry["new_status"] in DECISIONS]
            if decisions:
                durations.append((utc(decisions[0]["changed_at"]) - created).total_seconds())
            counts["suppressed"] += bool(finding.get("suppressed"))
            counts["repeated"] += bool(finding.get("repeat_count", 0) or any(entry["new_status"] == "repeated" for entry in transitions))
            counts["complete_evidence"] += bool(finding.get("complete_evidence"))
        classified = counts["confirmed"] + counts["false_positive"]
        total = len(cohort)
        rows.append({
            "rule_code": rule, "findings_produced": total, **counts,
            "accepted_risk": counts["accepted_risk"] if accepted_risk else None,
            "classified": classified, "decided": len(durations),
            "false_positive_rate": round(100 * counts["false_positive"] / classified, 2) if classified else None,
            "median_decision_seconds": median(durations) if durations else None,
            "repeat_rate": round(100 * counts["repeated"] / total, 2),
            "complete_evidence_share": round(100 * counts["complete_evidence"] / total, 2),
        })
    return rows


def load_quality(start: datetime, end: datetime, *, domain_ids: list[int] | None, authorization=None) -> dict:
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.FINDINGS)
    # Every linked event must belong to the authorised domains. Missing or mixed
    # domain evidence never grants access to a restricted reader.
    scope = ""
    params: list[Any] = [start, end]
    if domain_ids is not None:
        if not domain_ids:
            raise PermissionError("report_scope_not_executable")
        scope = """and exists(select 1 from finding_evidence fe where fe.finding_id=f.id)
            and not exists(select 1 from finding_evidence fe
                left join events_v2_core e on e.id=fe.event_id
                where fe.finding_id=f.id and (e.domain_id is null or not(e.domain_id=any(%s))))"""
        params.append(domain_ids)
    params.extend([MAX_FINDINGS + 1, end])
    with report_read_budget(), connect() as conn:
        with conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute(
                f"""with cohort as (
                    select f.id,f.rule_code,f.created_at,f.repeat_count,f.evidence_count
                    from findings_active f
                    where is_semantic_finding_published_v1(f.id)
                        and f.created_at >= %s and f.created_at < %s {scope}
                    order by f.created_at,f.id limit %s
                )
                select f.*,semantic_finding_suppressed_v160(f.id,f.rule_code) as suppressed,
                    coalesce(h.history,'[]'::jsonb) as history,
                    (ev.total > 0 and ev.total=f.evidence_count and ev.resolved=ev.total) as complete_evidence
                from cohort f
                left join lateral (
                    select jsonb_agg(jsonb_build_object('id',id,'old_status',old_status,
                        'new_status',new_status,'changed_at',changed_at) order by changed_at,id) as history
                    from finding_status_history where finding_id=f.id and changed_at < %s
                ) h on true
                left join lateral (
                    select count(*) as total,
                        count(*) filter(where e.event_id is not null and e.time_created_utc is not null
                            and e.event_record_id is not null and e.channel_id is not null) as resolved
                    from finding_evidence fe left join events_v2_core e on e.id=fe.event_id
                    where fe.finding_id=f.id
                ) ev on true""", tuple(params),
            )
            findings = [dict(row) for row in cur.fetchall()]
            # Admission is current context, not attribution of a historical finding
            # to a policy version (the publication link is a protected surface).
            cur.execute("""select p.policy_id,p.policy_version,
                'semantic.' || (p.definition_json->>'scenario_kind') as rule_code,
                p.definition_json->>'result_class' as result_class,
                semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled' as enabled,
                a.policy_id is not null as managed
                from semantic_risk_policies p left join semantic_policy_admission a
                    on a.policy_id=p.policy_id and a.policy_version=p.policy_version
                order by p.policy_id,p.policy_version""")
            policies = [dict(row) for row in cur.fetchall()]
    truncated = len(findings) > MAX_FINDINGS
    accepted = "accepted_risk" in VALID_FINDING_STATUSES
    rows = compute_metrics(findings[:MAX_FINDINGS], end=end, accepted_risk=accepted)
    for row in rows:
        matched = [policy for policy in policies if policy["rule_code"] == row["rule_code"]]
        classes = {policy.get("result_class") for policy in matched}
        row["rule_result_class"] = next(iter(classes)) if len(classes) == 1 and classes <= RULE_RESULT_CLASSES else None
        row["policies"] = [f"{policy['policy_id']}:{policy['policy_version']}" for policy in matched]
        row["admitted_policies"] = [f"{policy['policy_id']}:{policy['policy_version']}" for policy in matched if policy["enabled"]]
        row["managed_policies"] = [f"{policy['policy_id']}:{policy['policy_version']}" for policy in matched if policy["managed"]]
    return {"items": rows, "truncated": truncated, "accepted_risk_supported": accepted}
