"""Shared population predicates; callers must establish report scope first."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


def problem_population_filters(*, status: str | None=None, severity: str | None=None, q: str | None=None, rule_code: str | None=None, created_from: str | None=None, created_to: str | None=None, time_from: str | None=None, time_to: str | None=None, show_suppressed: bool=False, domain_ids: list[int] | None=None, finding_id: int | None=None, attention_only: bool=False, open_only: bool=False, risk: str | None=None, entity_id: int | None=None):
    effective_status = """case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end"""
    accepted = "coalesce(risk.state='active' and risk.expires_at > statement_timestamp(),false)"
    clauses: list[str] = ["is_semantic_finding_published_v1(findings.id)",
        "(findings.rule_code<>'semantic.qw.file-acl-broad-write' or semantic_finding_in_domains_v265(findings.id,null))"]
    if risk == "accepted":
        clauses.append(accepted)
    elif risk != "all":
        clauses.append(f"not {accepted}")
    if not show_suppressed and risk != "accepted":
        clauses.append("not semantic_finding_suppressed_v160(findings.id,findings.rule_code)")
    params: list[Any] = []
    if domain_ids is not None:
        # Every core/native witness must establish membership. The definer
        # resolves plugin evidence without inventing integer core event IDs.
        clauses.append("semantic_finding_in_domains_v265(findings.id,?::bigint[])")
        params.append(domain_ids)
    if attention_only:
        clauses.append(f"({effective_status}) in ('new','confirmed','repeated')")
    elif open_only:
        clauses.append(f"({effective_status}) in ('new','confirmed','repeated','active','review')")
    if finding_id is not None:
        if int(finding_id) <= 0:
            raise ValueError("invalid_finding_id")
        clauses.append("findings.id = ?")
        params.append(int(finding_id))
    if entity_id is not None:
        if int(entity_id) <= 0:
            raise ValueError("invalid_entity_id")
        clauses.append("exists (select 1 from finding_entities linked where linked.finding_id=findings.id and linked.entity_id=?)")
        params.append(int(entity_id))
    if rule_code:
        clauses.append("findings.rule_code = ?")
        params.append(rule_code)
    for bound, operator in ((created_from, ">="), (created_to, "<")):
        if bound:
            moment = datetime.fromisoformat(bound.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                raise ValueError("report_period_invalid")
            clauses.append(f"findings.created_at {operator} ?::timestamptz")
            params.append(moment.astimezone(timezone.utc).isoformat())
    if status:
        clauses.append(f"({effective_status}) = ?")
        params.append(status)
    if severity:
        clauses.append("findings.severity = ?")
        params.append(severity)
    if time_from:
        clauses.append(
            "findings.last_seen_utc::timestamptz >= ?::timestamptz"
        )
        params.append(time_from)
    if time_to:
        clauses.append(
            "findings.last_seen_utc::timestamptz < ?::timestamptz"
        )
        params.append(time_to)
    if q:
        like = f"%{q}%"
        clauses.append(
            "(lower(coalesce(findings.title,'')) like lower(?) "
            "or lower(coalesce(findings.actor,'')) like lower(?) "
            "or lower(coalesce(findings.target,'')) like lower(?) "
            "or lower(coalesce(findings.summary,'')) like lower(?))"
        )
        params.extend([like, like, like, like])
    return effective_status, accepted, clauses, params


PROBLEM_POPULATION = "from findings_active findings\n        left join lateral (select s.*,u.username as responsible_username from semantic_suppressions s\n            join auth_users u on u.id=s.responsible_user_id\n            where s.finding_id=findings.id and s.kind='risk_acceptance'\n            order by s.id desc limit 1) risk on true"
