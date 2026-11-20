from __future__ import annotations

from server.sli.semantic.runtime_state import semantic_runtime_projection as _semantic_runtime_projection

from server.sli.semantic.problem_population import problem_population_filters, PROBLEM_POPULATION

import html
import json
import re
from datetime import datetime, timedelta, timezone
from types import EllipsisType
from typing import Any
from urllib.parse import urlencode

from server.sli.core.database import (
    is_postgres_runtime_db,
    query_rows,
    query_rows_bounded,
)
from server.sli.core.time_format import format_datetime_label, format_event_time
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.reporting.ui_labels import (
    channel_label,
    event_id_label,
    severity_label,
    status_label,
)
from server.sli.semantic.findings_pg_pipeline import (
    get_findings_refresh_status,
    refresh_findings_postgres,
)
from server.sli.semantic.semantic_identity import is_exact_domain_sid
from server.sli.storage.runtime_storage import (
    StorageRouteConsumer,
    resolve_storage_route,
)
from server.sli.storage.storage_v2_transition_controller import CutoverAuthorization
from server.source_packs.registry import resolve_source_normalizer
from server.sli.semantic.semantic_identity import is_exact_domain_sid

_FINDINGS_NORMALIZER = resolve_source_normalizer("Security")
if _FINDINGS_NORMALIZER is None:
    raise RuntimeError("Windows findings require the registered Security source normalizer")
_SOURCE_FINDING_RULES = _FINDINGS_NORMALIZER.finding_rules()
FINDING_RULES = {
    event_id: (
        rule.rule_code,
        rule.title,
        rule.severity,
        rule.why_it_matters,
    )
    for event_id, rule in _SOURCE_FINDING_RULES.items()
}
_FINDING_RECOMMENDATIONS = {
    rule.rule_code: rule.recommendation for rule in _SOURCE_FINDING_RULES.values()
}

STATUS_ORDER = {"new": 1, "active": 2, "review": 3, "confirmed": 4, "false_positive": 5, "closed": 6, "repeated": 7}

VALID_FINDING_STATUSES = frozenset(STATUS_ORDER)
ALLOWED_FINDING_TRANSITIONS: dict[str, frozenset[str]] = {
    "new": frozenset({"active", "review", "confirmed", "false_positive", "closed"}),
    "active": frozenset({"review", "confirmed", "false_positive", "closed", "repeated"}),
    "review": frozenset({"active", "confirmed", "false_positive", "closed"}),
    "confirmed": frozenset({"active", "closed"}),
    "false_positive": frozenset({"active", "closed"}),
    "closed": frozenset({"active"}),
    "repeated": frozenset({"active", "review", "confirmed", "false_positive", "closed"}),
}


_POSTGRES_ONLY_MESSAGE = "Findings are PostgreSQL-only: the SQLite runtime backend has been removed"


class FindingLifecycleError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code



def _refresh_findings_postgres(
    *,
    limit: int = 5000,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    return refresh_findings_postgres(
        rules=FINDING_RULES,
        event_label=event_id_label,
        principal=_principal,
        recommendation=_recommendation_for_rule,
        limit=limit,
        authorization=authorization,
    )


def refresh_findings_from_events(
    *,
    limit: int = 5000,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    # Storage V2 is the only route (plan 6.5); resolving it still rejects an
    # invalid or V1-rollback authorization before any read.
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.FINDINGS)
    if not is_postgres_runtime_db():
        raise RuntimeError("storage_v2_findings_requires_postgres")
    return _refresh_findings_postgres(limit=limit, authorization=authorization)


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def get_findings_dashboard_data(
    *,
    limit: int = 50,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Return the lightweight findings slice used by the main dashboard.

    Full findings endpoints include evidence, related entities and status history.
    Loading those relations per item caused up to 150 PostgreSQL round trips for
    one dashboard refresh.  The role cards only need finding identity/status
    fields, so the dashboard uses two bounded queries and leaves full evidence to
    the dedicated Findings/Investigation pages.
    """
    clean_limit = max(1, min(int(limit or 50), 200))
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.DASHBOARD)
    if not is_postgres_runtime_db():
        raise RuntimeError("storage_v2_findings_dashboard_requires_postgres")
    rows = query_rows(
        """
        select id, fingerprint, rule_code, title, severity, confidence, status,
               first_seen_utc, last_seen_utc, actor, target, source, summary,
               evidence_count, repeat_count, assigned_to, status_reason, last_repeat_detected_at, updated_at
        from findings_active
        order by case severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'low' then 4 else 5 end,
                 coalesce(last_seen_utc, updated_at::text) desc
        limit ?
        """,
        (clean_limit,),
    )
    summary_rows = query_rows(
        "select severity, status, count(*) as count from "
        + "findings_active"
        + " group by severity, status",
    )
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "backend": "postgres",
        "items": _json_safe(rows),
        "summary": _json_safe(summary_rows),
        "filters": {"limit": clean_limit},
        "details_included": False,
        "dashboard_mode": "lightweight_two_query",
        "limitations": ["evidence, related entities and status history are available on dedicated findings endpoints"],
    }


def _attach_postgres_finding_details(
    rows: list[dict[str, Any]],
    *,
    authorization: object | None = None,
    identity_labels: bool = False,
    defer_identity_labels: bool = False,
) -> None:
    finding_ids = [int(row["id"]) for row in rows]
    if not finding_ids:
        return
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.FINDINGS)
    event_source = """(
            select core.id,core.event_id,channel.value as channel,
                   core.time_created_utc,core.event_record_id,core.server_id
            from events_v2_core core
            join storage_v2_channel channel on channel.id=core.channel_id
        ) e"""
    identity_columns = identity_rank = ""
    if identity_labels:
        event_source = """(
                select core.id,core.event_id,channel.value as channel,
                       core.time_created_utc,core.event_record_id,core.server_id,core.domain_id,
                       core.subject_user_sid,core.subject_user_name,actor_domain.value as subject_domain_name,
                       core.target_user_sid,facts.membership_member_sid,provider.value as identity_provider
                from events_v2_core core
                join storage_v2_channel channel on channel.id=core.channel_id
                left join storage_v2_domain_name actor_domain on actor_domain.id=core.subject_domain_id
                left join storage_v2_provider provider on provider.id=core.provider_id
                left join event_facts_v2 facts on facts.event_id=core.id
            ) e"""
        identity_columns = """,domain_id,subject_user_sid,subject_user_name,subject_domain_name,
               target_user_sid,membership_member_sid,identity_provider,identity_domain_min,identity_domain_max,identity_event_count"""
        identity_rank = """,e.domain_id,e.subject_user_sid,e.subject_user_name,
                   e.subject_domain_name,e.target_user_sid,e.membership_member_sid,e.identity_provider,
                   min(e.domain_id) over(partition by fe.finding_id) as identity_domain_min,
                   max(e.domain_id) over(partition by fe.finding_id) as identity_domain_max,
                   count(*) over(partition by fe.finding_id) as identity_event_count"""
    evidence_rows = query_rows(
        f"""
        select finding_id, event_db_id, event_id, channel, time_created_utc,
               event_record_id, hostname, evidence_role, note{identity_columns}
        from (
            select fe.finding_id, e.id as event_db_id, e.event_id, e.channel,
                   e.time_created_utc, e.event_record_id, s.hostname,
                   fe.evidence_role, fe.note{identity_rank},
                   row_number() over (
                       partition by fe.finding_id
                       order by e.time_created_utc desc, e.id desc
                   ) as rn
            from finding_evidence fe
            join {event_source} on e.id=fe.event_id
            join servers s on s.id=e.server_id
            where fe.finding_id = any(?)
        ) ranked
        where rn <= 20
        order by finding_id, time_created_utc desc, event_db_id desc
        """,
        (finding_ids,),
    )
    entity_rows = query_rows(
        """
        with deduplicated as (
            select distinct finding_id, entity_type, display_name, entity_role
            from finding_entities
            where finding_id = any(?) and coalesce(display_name,'') <> ''
        ), ranked as (
            select finding_id, entity_type, display_name, entity_role,
                   row_number() over (
                       partition by finding_id
                       order by case entity_role when 'actor' then 1 when 'target' then 2 when 'source' then 3 else 4 end,
                                display_name
                   ) as rn
            from deduplicated
        )
        select finding_id, entity_type, display_name, entity_role
        from ranked
        where rn <= 25
        order by finding_id, rn
        """,
        (finding_ids,),
    )
    history_rows = query_rows(
        """
        select id, finding_id, old_status, new_status, changed_at, changed_by, note
        from (
            select id, finding_id, old_status, new_status, changed_at, changed_by, note,
                   row_number() over (partition by finding_id order by id desc) as rn
            from finding_status_history
            where finding_id = any(?)
        ) ranked
        where rn <= 20
        order by finding_id, id desc
        """,
        (finding_ids,),
    )
    evidence_by_id: dict[int, list[dict[str, Any]]] = {}
    entities_by_id: dict[int, list[dict[str, Any]]] = {}
    history_by_id: dict[int, list[dict[str, Any]]] = {}
    for item in evidence_rows:
        evidence_by_id.setdefault(int(item.pop("finding_id")), []).append(item)
    for item in entity_rows:
        entities_by_id.setdefault(int(item.pop("finding_id")), []).append(item)
    for item in history_rows:
        history_by_id.setdefault(int(item["finding_id"]), []).append(item)
    for row in rows:
        finding_id = int(row["id"])
        row["evidence"] = evidence_by_id.get(finding_id, [])
        row["entities"] = entities_by_id.get(finding_id, [])
        row["status_history"] = history_by_id.get(finding_id, [])
    if identity_labels and not defer_identity_labels:
        _finalize_problem_identities(rows)


def _finalize_problem_identities(rows: list[dict[str, Any]]) -> None:
    try:
        _attach_problem_identities(rows)
    except Exception:  # Optional labels must not hide proven counts or source evidence.
        for row in rows:
            row["identity_context"] = {"snapshot_state": "unavailable"}
    # These lookup inputs are not new fields on the evidence API.
    for row in rows:
        for item in row.get("evidence") or []:
            for field in ("domain_id", "subject_user_sid", "subject_user_name", "subject_domain_name",
                          "target_user_sid", "membership_member_sid", "identity_provider", "identity_domain_min",
                          "identity_domain_max", "identity_event_count"):
                item.pop(field, None)


def _principal_sid(value: Any) -> str | None:
    text = str(value or "").strip()
    # The canonical identity ladder emits sid:<domain SID>; built-ins are
    # host-qualified. Never resolve an unscoped built-in SID against AD.
    if text.lower().startswith("sid:") and text.count(":") == 1:
        sid = text[4:].upper()
        return sid if is_exact_domain_sid(sid) else None
    match = re.fullmatch(r"(?:sid:[^:]+:)?(S-1-(?:\d+-)+\d+)", text, re.IGNORECASE)
    return match.group(1).upper() if match else None


def _principal_matches_host(value: str, hostname: Any) -> bool:
    """Only host-qualified canonical keys require an exact source host."""
    text = value.strip()
    if not text.lower().startswith("sid:"):
        return True
    parts = text.split(":")
    if len(parts) == 2:
        return _principal_sid(text) is not None
    return len(parts) == 3 and parts[1].casefold() == str(hostname or "").casefold()


def _identity_time(value: Any) -> str | None:
    try:
        stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp.astimezone(timezone.utc).isoformat() if stamp.utcoffset() is not None else None
    except (TypeError, ValueError):
        return None


def _attach_problem_identities(rows: list[dict[str, Any]]) -> None:
    """Label retained identities only; never rewrite findings or call a directory.

    A missing actor is filled only from a complete, unambiguous membership-event
    sample. SID labels require the exact retained event domain and a completed
    AD observation valid at that witness time. Age is provenance, not a veto or
    a claim that an old name describes the account today.
    """
    membership_sources = {
        (identity.stream, identity.provider_name, int(identity.event_key))
        for identity in _FINDINGS_NORMALIZER.semantic_event_identities(("group.member.added",))
    }
    requests, owners = [], []
    for row in rows:
        values = dict.fromkeys([str(row.get("actor") or "").strip(), str(row.get("target") or "").strip(),
                               *(str(item.get("display_name") or "").strip() for item in row.get("entities") or []),
                               *(str(item or "").strip() for item in row.get("_identity_objects") or [])])
        context = {"actor": None, "principals": {}, "snapshot_state": "not_requested",
                   "principal_states": {value: "unverified" for value in values if _principal_sid(value)}}
        row["identity_context"] = context
        evidence = row.get("evidence") or []
        domains = {item.get("identity_domain_min") for item in evidence} | {item.get("identity_domain_max") for item in evidence}
        if len(domains) != 1 or type(next(iter(domains), None)) is not int:
            continue
        domain_id = next(iter(domains))
        if domain_id <= 0:
            continue
        actor = str(row.get("actor") or "").strip()
        sid = _principal_sid(actor)
        complete = (row.get("evidence_count") == len(evidence)
                    and all(item.get("identity_event_count") == len(evidence) for item in evidence))
        # A retained name is not evidence that an unrelated raw actor is the same account.
        candidates = [item for item in evidence
                      if (item.get("channel"), item.get("identity_provider"), item.get("event_id")) in membership_sources
                      and str(item.get("subject_user_name") or "").strip() not in {"", "-"}
                      and _principal_matches_host(actor, item.get("hostname"))
                      and (not actor or sid and _principal_sid(item.get("subject_user_sid")) == sid)]
        actors = {(str(item.get("subject_domain_name") or "").strip(),
                   str(item["subject_user_name"]).strip(), _principal_sid(item.get("subject_user_sid")))
                  for item in candidates}
        if complete and len(candidates) == len(evidence) and len(actors) == 1:
            observed_domain, name, observed_sid = next(iter(actors))
            witness = candidates[0]
            context["actor"] = {"label": f"{observed_domain}\\{name}" if observed_domain not in {"", "-"} else name,
                "source": "event", "sid": observed_sid, "domain_id": domain_id,
                "event_db_id": witness["event_db_id"], "event_id": witness["event_id"],
                "observed_at_utc": _identity_time(witness.get("time_created_utc"))}
        if row.get("evidence_count") != evidence[0].get("identity_event_count"):
            continue  # Missing/native witnesses cannot establish one complete SID/domain scope.
        for value in values:
            principal_sid = _principal_sid(value)
            if not principal_sid:
                continue
            witnesses = [item for item in evidence if principal_sid in {
                _principal_sid(item.get(field)) for field in ("subject_user_sid", "target_user_sid", "membership_member_sid")}
                and _identity_time(item.get("time_created_utc"))
                and _principal_matches_host(value, item.get("hostname"))]
            if not witnesses:
                continue
            witness = max(witnesses, key=lambda item: _identity_time(item["time_created_utc"]))
            requests.append({"request_index": len(requests), "domain_id": domain_id,
                             "sid": principal_sid.lower(), "at_utc": _identity_time(witness["time_created_utc"])})
            owners.append((context, value, {"source": "ad_snapshot", "sid": principal_sid,
                "domain_id": domain_id, "event_db_id": witness["event_db_id"],
                "event_id": witness["event_id"], "witness_at_utc": _identity_time(witness["time_created_utc"])}))
    if not requests:
        return
    # Queue pages have <=200 findings and <=25 linked entities each; no whole-AD scan.
    if len(requests) > 5400:
        return
    try:
        labels = query_rows_bounded(
            """/* problem_identity_snapshot_labels */
            select request.request_index,candidate.*
            from jsonb_to_recordset(?::jsonb) as request(request_index integer,domain_id bigint,sid text,at_utc timestamptz)
            join lateral (
                select distinct on (version.entity_id,coalesce(nullif(btrim(version.attributes_json->'attributes'->>'display_name'),''),
                    nullif(btrim(version.attributes_json->'attributes'->>'sam_account_name'),'')))
                    version.entity_id,version.source_run_id,run.observed_at_utc,
                    coalesce(nullif(btrim(version.attributes_json->'attributes'->>'display_name'),''),
                             nullif(btrim(version.attributes_json->'attributes'->>'sam_account_name'),'')) as label
                from ad_context_entity_aliases alias
                join ad_context_entity_versions version on version.entity_id=alias.entity_id
                join ad_context_runs run on run.run_id=version.source_run_id and run.status='completed'
                join ad_context_sections section on section.run_id=run.run_id
                    and section.section_name=version.source_section and section.status='complete'
                where alias.domain_id=request.domain_id and run.domain_id=request.domain_id
                  and alias.alias_type='object_sid' and alias.normalized_value=request.sid
                  and lower(version.attributes_json->'identity'->>'object_sid')=request.sid
                  and version.attributes_json->'identity'->>'kind' in ('ad_user','ad_group')
                  and version.source_section in ('directory_accounts','directory_group_graph','privileged_membership')
                  and version.valid_from_utc<=request.at_utc
                  and (version.valid_to_utc is null or version.valid_to_utc>request.at_utc)
                  and run.observed_at_utc<=request.at_utc
                order by version.entity_id,label,run.observed_at_utc desc
                limit 2
            ) candidate on true
            order by request.request_index
            """, (json.dumps(requests),), statement_timeout_ms=2000,
        )
    except Exception:  # Optional labels must not hide the unchanged problem/evidence queue.
        for context, value, _ in owners:
            context["snapshot_state"] = "unavailable"
            context["principal_states"][value] = "unavailable"
        return
    by_request: dict[int, list[dict[str, Any]]] = {}
    for label in labels:
        by_request.setdefault(label["request_index"], []).append(label)
    for index, (context, value, provenance) in enumerate(owners):
        context["snapshot_state"] = "lookup_complete"
        candidates = by_request.get(index, [])
        context["principal_states"][value] = "ambiguous" if len(candidates) > 1 else "no_match"
        if (len(candidates) == 1 and str(candidates[0].get("label") or "").strip() not in {"", "-"}
                and candidates[0].get("source_run_id") and type(candidates[0].get("entity_id")) is int
                and _identity_time(candidates[0].get("observed_at_utc"))):
            item = candidates[0]
            context["principal_states"][value] = "named"
            context["principals"][value] = {**provenance, "label": item["label"],
                "observed_at_utc": _identity_time(item.get("observed_at_utc")),
                "source_run_id": str(item.get("source_run_id") or ""), "entity_id": item.get("entity_id")}


def _home_identity_object(value: str, context: dict[str, Any], domain: str | None) -> dict[str, Any]:
    """Presentation only: retain the exact identity even when its name is unproven."""
    source = (context.get("principals") or {}).get(value)
    if source:
        # A declared retained name wins even when it resembles an identifier.
        name, state = source["label"], "named"
    elif _principal_sid(value) or re.match(r"sid:(?:[^:]+:)*S-1-", value.strip(), re.IGNORECASE):
        state = (context.get("principal_states") or {}).get(value)
        if state not in {"no_match", "ambiguous", "unverified", "unavailable"}:
            state = "unavailable" if context.get("snapshot_state") == "unavailable" else "unverified"
        name = ""
    else:
        name, state = value, "literal"
    return {"name": name, "name_state": state, "identifier": value, "source": source, "domain": domain}


def get_findings_data(
    *,
    status: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    limit: int = 200,
    refresh: bool = False,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    limit = max(1, min(int(limit or 200), 1000))
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.FINDINGS)
    if not is_postgres_runtime_db():
        raise RuntimeError("storage_v2_findings_requires_postgres")
    refresh_result = (
        (
            refresh_findings_from_events()
            if authorization is None
            else refresh_findings_from_events(authorization=authorization)
        )
        if refresh
        else None
    )
    clauses = []
    params: list[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if q:
        like = f"%{q}%"
        clauses.append("(lower(coalesce(title,'')) like lower(?) or lower(coalesce(actor,'')) like lower(?) or lower(coalesce(target,'')) like lower(?) or lower(coalesce(source,'')) like lower(?) or lower(coalesce(summary,'')) like lower(?))")
        params.extend([like, like, like, like, like])
    where = " where " + " and ".join(clauses) if clauses else ""
    rows = query_rows(
        f"""select * from findings_active {where}
        order by case severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'low' then 4 else 5 end,
                 coalesce(last_seen_utc, updated_at::text) desc limit ?""",
        (*params, limit),
    )
    summary_rows = query_rows("select severity, status, count(*) as count from findings_active group by severity, status")
    _attach_postgres_finding_details(
        rows, authorization=authorization,
    )
    rows = _json_safe(rows)
    summary_rows = _json_safe(summary_rows)
    refresh_status = (
        get_findings_refresh_status()
        if authorization is None
        else get_findings_refresh_status(authorization=authorization)
    )
    limitations = list((refresh_status or {}).get("limitations") or [])
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "backend": "postgres",
        "items": rows,
        "summary": summary_rows,
        "filters": {"status": status, "severity": severity, "q": q, "limit": limit, "refresh": bool(refresh)},
        "refresh_result": _json_safe(refresh_result),
        "refresh_status": _json_safe(refresh_status),
        "lifecycle": {
            "valid_statuses": sorted(VALID_FINDING_STATUSES, key=lambda item: STATUS_ORDER[item]),
            "allowed_transitions": {key: sorted(value, key=lambda item: STATUS_ORDER[item]) for key, value in ALLOWED_FINDING_TRANSITIONS.items()},
        },
        "limitations": limitations,
    }




def _home_groups(population, where, params, new_since, *, time_zone=None):
    """Aggregate the exact queue population before limiting the eight visible groups."""
    if time_zone is not None:
        from server.sli.semantic.problem_groups import home_cohorts
        return home_cohorts(query_rows, population, where, params, new_since, time_zone)
    return query_rows(
        f"""
        with population as materialized (
            select findings.rule_code, findings.title, findings.severity,
                   findings.created_at, findings.last_seen_utc::timestamptz as last_seen,
                   nullif(btrim(findings.assigned_to),'') as assigned_to,
                   coalesce(nullif(btrim(findings.target),''),nullif(btrim(findings.actor),'')) as object_name,
                   (select string_agg(distinct d.fqdn, ', ' order by d.fqdn)
                    from finding_evidence fe join events_v2_core e on e.id=fe.event_id
                    join domains d on d.id=e.domain_id where fe.finding_id=findings.id) as domain_name
            {population}{where}
        ), grouped as (
            select rule_code, min(title) as title,
                   min(case severity when 'critical' then 0 when 'high' then 1
                       when 'medium' then 2 when 'low' then 3 else 4 end) as importance,
                   count(*) as total,
                   case when ?::timestamptz is null then null
                       else count(*) filter(where created_at > ?::timestamptz) end as new_count,
                   max(last_seen) as last_seen_utc,
                   string_agg(distinct assigned_to, ', ' order by assigned_to) as assigned_to,
                   count(distinct (object_name,domain_name)) filter(where object_name is not null) as object_count
            from population group by rule_code
        )
        select grouped.*,
               sum(total) over() as total_problems, sum(new_count) over() as total_new,
               count(*) over() as total_groups,
               (select coalesce(jsonb_agg(to_jsonb(sample)),'[]'::jsonb) from (
                   select distinct object_name as name,domain_name as domain from population p
                   where p.rule_code=grouped.rule_code and object_name is not null
                   order by name,domain limit 3
               ) sample) as objects
        from grouped
        order by (coalesce(new_count,0)>0) desc,importance,last_seen_utc desc nulls last,rule_code
        limit 8
        """, (*params, new_since, new_since),
    )


# Sanitized report boundary; source authority, TTL and 24h aging remain in SQL.
_PASSWORD_RULES = frozenset({'qw.password-brute-force', 'qw.password-spray'})
_PASSWORD_DIAGNOSTICS = frozenset({
    'source_error', 'password_v2_native_unavailable', 'password_v2_window_truncated',
    'password_v2_xml_budget_exceeded', 'xml_invalid', 'state_bound', 'clock_regression',
    'too_late', 'coverage_gap', 'gap_native_unavailable', 'prequalification_native_unavailable',
    'episode_evidence_budget_exhausted', 'prequalification_proof_budget_exhausted',
    'missing_target', 'unclassified_failure', 'ambiguous_failure',
    'conflicting_client', 'missing_client',
})
_PASSWORD_REASONS = _PASSWORD_DIAGNOSTICS | {
    'attempt_stale', 'recent_loss', 'checkpoint_absent', 'policy_unconfirmed',
}


def _password_coverage_time(value, *, nullable=False):
    if nullable and value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value,
    ) is None:
        raise ValueError('password_coverage_shape')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _password_coverage_count(value):
    # B1 health sums at most25 positive-bigint buckets. Preserve exact digits in JS.
    if type(value) is not int or not 0 <= value <= 25 * (2**63 - 1):
        raise ValueError('password_coverage_shape')
    return str(value)


def _password_coverage_page(value, allowed_domains):
    if not isinstance(value, dict) or set(value) != {'as_of', 'rows', 'has_more'}:
        raise ValueError('password_coverage_shape')
    as_of = _password_coverage_time(value['as_of'])
    if type(value['has_more']) is not bool or not isinstance(value['rows'], list) or len(value['rows']) > 256:
        raise ValueError('password_coverage_shape')
    rows = []
    seen = set()
    row_keys = {'domain_id', 'rule_id', 'scope_ref', 'policy_state', 'status', 'reason',
                'last_attempt_at', 'last_completed_at', 'last_successful_cutoff', 'loss',
                'frozen_episode_count', 'evidence_snapshot_as_of'}
    for item in value['rows']:
        if not isinstance(item, dict) or set(item) != row_keys:
            raise ValueError('password_coverage_shape')
        domain = item['domain_id']
        if type(domain) is not int or domain not in allowed_domains or domain <= 0:
            raise ValueError('password_coverage_domain')
        if item['rule_id'] not in _PASSWORD_RULES or not isinstance(item['scope_ref'], str) or re.fullmatch('[a-f0-9]{64}', item['scope_ref']) is None:
            raise ValueError('password_coverage_shape')
        key = (domain, item['rule_id'], item['scope_ref'])
        if key in seen:
            raise ValueError('password_coverage_shape')
        seen.add(key)
        if item['policy_state'] not in {'enabled', 'disabled', 'disabled_last_known', 'unknown'} or item['status'] not in {'healthy', 'partial', 'error', 'stale', 'unknown', 'frozen'}:
            raise ValueError('password_coverage_shape')
        if item['reason'] is not None and item['reason'] not in _PASSWORD_REASONS:
            raise ValueError('password_coverage_shape')
        times = {key: _password_coverage_time(item[key], nullable=True) for key in
                 ('last_attempt_at', 'last_completed_at', 'last_successful_cutoff', 'evidence_snapshot_as_of')}
        if any(stamp is not None and stamp > as_of for stamp in times.values()):
            raise ValueError('password_coverage_shape')
        loss = item['loss']
        if not isinstance(loss, dict) or not set(loss) <= _PASSWORD_DIAGNOSTICS:
            raise ValueError('password_coverage_shape')
        projected_loss = {}
        for code, summary in loss.items():
            if not isinstance(summary, dict) or set(summary) != {'count_lower_bound', 'count_exact', 'from', 'to', 'observation_window_from', 'as_of'}:
                raise ValueError('password_coverage_shape')
            count = _password_coverage_count(summary['count_lower_bound'])
            start = _password_coverage_time(summary['from'], nullable=True)
            end = _password_coverage_time(summary['to'], nullable=True)
            observed = _password_coverage_time(summary['observation_window_from'])
            if type(summary['count_exact']) is not bool or count == '0' or (start is None) != (end is None) or (start is not None and start > end) or not as_of - timedelta(hours=24) <= observed <= as_of or _password_coverage_time(summary['as_of']) != as_of:
                raise ValueError('password_coverage_shape')
            projected_loss[code] = {**summary, 'count_lower_bound': count}
        frozen = _password_coverage_count(item['frozen_episode_count'])
        status, reason = item['status'], item['reason']
        if frozen != '0':
            status = 'frozen'
        elif status == 'healthy':
            completed = times['last_completed_at']
            if completed is None:
                status, reason = 'unknown', 'checkpoint_absent'
            elif as_of >= completed + timedelta(seconds=300):
                status, reason = 'stale', 'attempt_stale'
            elif projected_loss:
                status, reason = 'partial', 'recent_loss'
        rows.append({**item, 'domain_id': str(domain), 'loss': projected_loss,
                     'frozen_episode_count': frozen, 'status': status, 'reason': reason})
    return {'availability': 'observed', 'as_of': value['as_of'], 'rows': rows, 'has_more': value['has_more']}


def _password_coverage_unavailable():
    return {'availability': 'unavailable', 'as_of': None, 'rows': [], 'has_more': False}


def password_coverage_catalog_domains():
    """Called only after an explicit unrestricted security.queue projection."""
    rows = query_rows('select id from public.domains order by id')
    if any(type(row.get('id')) is not int or row['id'] <= 0 for row in rows):
        raise ValueError('password_coverage_domain')
    return sorted({row['id'] for row in rows})


def _read_password_detection_coverage(allowed_domains):
    if not isinstance(allowed_domains, list) or any(type(domain) is not int or domain <= 0 for domain in allowed_domains):
        raise ValueError('password_coverage_domain')
    if not allowed_domains:
        return None
    try:
        # query_rows owns a fresh connection/transaction (including timeout path).
        # On SQL failure its context rolls back/closes BEFORE this catch; no
        # shared caller transaction is committed or rolled back here.
        rows = query_rows('select public.read_password_detection_coverage(?::bigint[]) as coverage',
                          (sorted(set(allowed_domains)),))
        if len(rows) != 1 or set(rows[0]) != {'coverage'}:
            raise ValueError('password_coverage_shape')
        return _password_coverage_page(rows[0]['coverage'], set(allowed_domains))
    except Exception:
        return _password_coverage_unavailable()


def get_security_problems_data(
    *,
    status: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    rule_code: str | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    limit: int = 50,
    show_suppressed: bool = False,
    domain_ids: list[int] | None = None,
    finding_id: int | None = None,
    attention_only: bool = False,
    open_only: bool = False,
    home_order: bool = False,
    compact: bool = False,
    home_groups: bool = False,
    group_queue: bool = False,
    page_queue: bool = False,
    home_group_timezone: str | None = None,
    cohort: str | None = None,
    cohort_timezone: str = "UTC",
    after_id: int | None = None,
    new_since: str | None = None,
    risk: str | None = None,
    entity_id: int | None = None,
    authorization: CutoverAuthorization | None = None,
    password_coverage_domain_ids: list[int] | None = None,
) -> dict[str, Any]:
    """Return the bounded production-semantic problem queue.

    A semantic scenario is not a problem until the immutable production
    publication link exists.  The least-privilege membership reader is
    therefore the population boundary rather than a presentation-time filter.
    """

    clean_limit = max(1, min(int(limit or 50), 200))
    route = str(
        resolve_storage_route(
            authorization=authorization,
            consumer=StorageRouteConsumer.FINDINGS,
        ).get("route")
        or "v1"
    )
    if route != "v2" or not is_postgres_runtime_db():
        raise RuntimeError("semantic_problems_report_requires_postgres_v2")

    effective_status, accepted, clauses, params = problem_population_filters(
        status=status,
        severity=severity,
        q=q,
        domain_ids=domain_ids,
        finding_id=finding_id,
        attention_only=attention_only,
        open_only=open_only,
        time_from=time_from,
        time_to=time_to,
        show_suppressed=show_suppressed,
        risk=risk,
        entity_id=entity_id,
        rule_code=rule_code,
        created_from=created_from,
        created_to=created_to,
    )
    where = " where " + " and ".join(clauses) if clauses else ""
    ordering = f"""case ({effective_status})
                   when 'new' then 1 when 'repeated' then 2
                   when 'confirmed' then 3 when 'active' then 4
                   when 'review' then 5 when 'false_positive' then 6
                   when 'closed' then 7 else 8 end,"""
    if home_order:
        ordering = """case when findings.severity in ('critical','high') then 0 else 2 end,"""
    repeats = f"""(({effective_status})='repeated' or coalesce(findings.repeat_count,0)>0) desc,
                 coalesce(findings.repeat_count,0) desc,""" if home_order else ""
    population = PROBLEM_POPULATION
    group_prefix, group_fields = "", ""
    summary_population, summary_where, summary_params = population, where, list(params)
    if group_queue:
        if cohort is not None or home_groups or finding_id is not None:
            raise ValueError("problem_cohort_invalid")
        from server.sli.semantic.problem_groups import QUEUE_COHORT_JOIN, cohort_zone, queue_cohorts_cte
        group_prefix = queue_cohorts_cte(population, where, effective_status, accepted,
            cohort_join=QUEUE_COHORT_JOIN)
        group_fields = ",queue_groups.problem_cohort,queue_groups.occurrence_count,queue_groups.queue_cursor_id"
        params = [cohort_zone(cohort_timezone), *params]
        summary_population, summary_where, summary_params = "from queue_groups", "", list(params)
        population += " join queue_groups on queue_groups.id=findings.id"
        where = ""
        ordering, repeats = "queue_groups.queue_cursor_id desc,", ""
    elif cohort is not None:
        if home_groups:
            raise ValueError("problem_cohort_invalid")
        from server.sli.semantic.problem_groups import (
            COHORT_JOIN,
            QUEUE_COHORT_JOIN,
            cohort_value,
            cohort_zone,
        )
        value = cohort_value(cohort)
        key = json.loads(value)
        zone = cohort_zone(cohort_timezone)
        if key[0] == "finding":
            where += " and findings.id = ?"
            params = [*params, key[1]]
        else:
            population += QUEUE_COHORT_JOIN if key[0] == "queue" else COHORT_JOIN
            where += " and cohort.key = ?::jsonb"
            params = [zone, *params, value]
        ordering, repeats = "findings.id desc,", ""
    elif after_id is not None:
        ordering, repeats = "findings.id desc,", ""
    elif page_queue:
        # The ungrouped queue (including viewers without identity fields)
        # uses the same exact keyset as subsequent pages.
        ordering, repeats = "findings.id desc,", ""
    if not group_queue:
        summary_population, summary_where, summary_params = population, where, list(params)
    page_where, page_params = where, list(params)
    if after_id is not None:
        from server.sli.semantic.problem_groups import cohort_page
        if group_queue:
            if type(after_id) is not int or after_id <= 0:
                raise ValueError("invalid_cursor")
            page_where, page_params = " where queue_groups.queue_cursor_id < ?", [*params, after_id]
        else:
            page_where, page_params = cohort_page(where, params, after_id)
    groups = _home_groups(population, where, params, new_since,
        time_zone=home_group_timezone) if home_groups else None
    rows = [] if home_groups else query_rows(
        f"""
        {group_prefix}
        select findings.*,({effective_status}) as status{group_fields},
               case when risk.id is not null then to_jsonb(risk) || jsonb_build_object('state',
                   case when risk.state='active' and risk.expires_at <= statement_timestamp()
                        then 'expired' else risk.state end) else null end as risk_acceptance,
               (select coalesce(jsonb_agg(to_jsonb(a) order by a.id desc),'[]'::jsonb) from
                   (select id,action,actor,occurred_at,details from semantic_control_audit
                    where details->'rule'->>'kind'='risk_acceptance'
                      and details->'rule'->>'finding_id'=findings.id::text
                    order by id desc limit 50) a) as risk_audit,
               semantic_finding_review_v160(findings.id) as review_hint,
               semantic_finding_suppressed_v160(findings.id,findings.rule_code) as suppressed,
               case when findings.rule_code in ('semantic.qw.account-decoy','semantic.qw.file-decoy')
                    then public.finding_decoy_context(findings.id) end as decoy_label
        {population}{page_where}
        order by {ordering}
                 case findings.severity
                   when 'critical' then 1 when 'high' then 2
                   when 'medium' then 3 when 'low' then 4 else 5 end,
                 {repeats}
                 coalesce(findings.last_seen_utc,findings.updated_at::text)::timestamptz desc,
                 findings.id desc
        limit ?
        """,
        (*page_params, clean_limit + 1),
    )
    has_more = len(rows) > clean_limit
    rows = rows[:clean_limit]
    from server.sli.semantic.semantic_governance import classify_audit_change

    for row in rows:
        label = row.pop("decoy_label", None)
        if isinstance(label, dict):
            row.update(decoy_id=label.get("decoy_id"), decoy_revision=label.get("decoy_revision"))
        hint = row.get("review_hint")
        if isinstance(hint, dict):
            row["review_hint"] = {**hint, **classify_audit_change(hint)}
    if not compact:
        _attach_postgres_finding_details(rows, authorization=authorization, identity_labels=True, defer_identity_labels=True)
    summary_rows = [] if home_groups else query_rows(
        f"""
        {group_prefix}
        select {"severity,status,risk_accepted,count(*) as count,sum(occurrence_count) as occurrences"
                if group_queue else f"findings.severity,({effective_status}) as status,({accepted}) as risk_accepted,count(*) as count"}
        {summary_population}{summary_where}
        group by {"severity,status,risk_accepted" if group_queue else f"findings.severity,({effective_status}),({accepted})"}
        """,
        tuple(summary_params),
    )
    generated = datetime.now(timezone.utc)
    heartbeat_rows = query_rows(
        """
        select status,phase,heartbeat_at,expected_interval_seconds,details_json
        from runtime_worker_heartbeats
        where worker_name='semantic'
        limit 1
        """,
    )
    heartbeat = heartbeat_rows[0] if heartbeat_rows else {}
    runtime = _semantic_runtime_projection(heartbeat, generated=generated)
    limitations = list(
        (get_findings_refresh_status(authorization=authorization) or {}).get(
            "limitations"
        )
        or []
    )
    if runtime["findings_state"] == "stale":
        limitations.append(
            "Нет свежего подтверждения работы проверки; проблемы показаны по сохранённым данным, "
            "а полнота текущего состояния не подтверждена."
        )
    elif (
        runtime["facts_state"] == "active"
        and runtime["relations_state"] == "active"
        and runtime["findings_state"] == "inactive"
    ):
        limitations.append(
            "Факты и связи обрабатываются, но оценка риска и публикация новых "
            "проблем в этом режиме не включены."
        )
    elif runtime["findings_state"] in {"inactive", "unknown"}:
        limitations.append(
            "Работа проверки сейчас не подтверждена; отсутствие новых "
            "результатов нельзя считать отсутствием проблем."
        )
    report_state = (
        "stale"
        if runtime["findings_state"] == "stale"
        else "partial"
        if runtime["findings_state"] in {"inactive", "unknown"}
        else "available"
        if rows or groups
        else "empty"
    )
    # Optional identity work runs last: its shared-deadline exhaustion must not
    # prevent mandatory counts/runtime/coverage reads that were already proven.
    password_coverage = (_read_password_detection_coverage(password_coverage_domain_ids)
                         if password_coverage_domain_ids is not None else None)
    if not compact:
        _finalize_problem_identities(rows)
    if home_group_timezone is not None and groups:
        representatives = []
        for group in groups:
            sample = group.get("representative")
            if isinstance(sample, dict):
                sample["_identity_objects"] = group.get("object_names") or []
                representatives.append(sample)
        try:
            _attach_postgres_finding_details(representatives, authorization=authorization, identity_labels=True)
        except Exception:  # Optional home names must not replace proven counts with an error.
            for sample in representatives:
                sample["identity_context"] = {"snapshot_state": "unavailable"}
        for group in groups:
            sample = group.pop("representative", None) or {}
            context = sample.get("identity_context") or {}
            group["identity_state"] = context.get("snapshot_state")
            names = list(dict.fromkeys(value for value in group.pop("object_names", []) if value))
            group["objects"] = [_home_identity_object(value, context, group.get("domain_name")) for value in names]
            group["object_count"] = len(names)
    return {
        **({"decision_groups": _json_safe(groups)} if home_groups else {}),
        "generated_at_utc": generated.isoformat(),
        "status": "ok",
        "state": report_state,
        "source": "semantic_production_findings",
        **({"password_detection_coverage": password_coverage}
           if password_coverage_domain_ids is not None else {}),
        "items": _json_safe(rows),
        "summary": _json_safe(summary_rows),
        "has_more": has_more,
        "limits": {"limit": clean_limit, "details_per_finding": 20},
        "lifecycle": {
            "valid_statuses": sorted(
                VALID_FINDING_STATUSES,
                key=lambda item: STATUS_ORDER[item],
            ),
            "allowed_transitions": {
                key: sorted(value, key=lambda item: STATUS_ORDER[item])
                for key, value in ALLOWED_FINDING_TRANSITIONS.items()
            },
        },
        "semantic_runtime": runtime,
        "limitations": limitations,
    }


PROBLEM_EVIDENCE_COUNT_LIMIT = 10_000


def get_problem_evidence_page(
    finding_id: int, *, after_id: int = 0, limit: int = 20,
    native_access=None, native_fields_allowed=False, action="view", domain_ids=None,
    position=None, watermark=None, legacy_cursor=False,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Read every retained evidence link, including unavailable source events.

    The caller must check membership in the published problem population first.
    Source retention must not silently shorten the list of evidence links.
    """
    route = resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.FINDINGS)
    if route.get("route") != "v2" or not is_postgres_runtime_db():
        raise RuntimeError("semantic_problems_report_requires_postgres_v2")
    if native_access is not None:
        from server.sli.semantic.file_acl_evidence import page

        return page(finding_id, after_id=after_id, limit=limit, access=native_access,
                    fields_allowed=native_fields_allowed, action=action, domain_ids=domain_ids,
                    position=position, watermark=watermark, legacy_cursor=legacy_cursor)
    clean_limit = max(1, min(int(limit), 200))
    if finding_id <= 0 or after_id < 0:
        raise ValueError("invalid_evidence_page")
    # Count a bounded population independently of the page position. A capped
    # count is a lower bound, never an exact total or an invented zero.
    totals = query_rows(
        """select count(*) as total from (
            select id from finding_evidence where finding_id=? limit ?
        ) counted""",
        (finding_id, PROBLEM_EVIDENCE_COUNT_LIMIT + 1),
    )
    rows = query_rows(
        """
        select fe.id as evidence_id, e.id as event_db_id, e.event_id, channel.value as channel,
               e.time_created_utc, e.event_record_id, s.hostname, fe.evidence_role, fe.note
        from finding_evidence fe
        left join events_v2_core e on e.id=fe.event_id
        left join storage_v2_channel channel on channel.id=e.channel_id
        left join servers s on s.id=e.server_id
        where fe.finding_id=? and fe.id>?
        order by fe.id
        limit ?
        """,
        (finding_id, after_id, clean_limit + 1),
    )
    count = int(totals[0]["total"]) if totals else None
    page = {"items": rows[:clean_limit], "has_more": len(rows) > clean_limit,
            "total": count if count is not None and count <= PROBLEM_EVIDENCE_COUNT_LIMIT else None}
    if page["total"] is None:
        page["total_lower_bound"] = max(count or 0, len(rows))
    return page


def get_finding_status_history(
    finding_id: int,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    clean_limit = max(1, min(int(limit or 50), 200))
    rows = query_rows(
        """
        select id, finding_id, old_status, new_status, changed_at, changed_by, note
        from finding_status_history
        where finding_id = ?
        order by id desc
        limit ?
        """,
        (int(finding_id), clean_limit),
    )
    return _json_safe(rows)


def update_finding_lifecycle(
    finding_id: int,
    *,
    new_status: str,
    changed_by: str = "",
    note: str | None = None,
    assigned_to: str | None | EllipsisType = ...,
    status_reason: str | None = None,
) -> dict[str, Any]:
    """Update a decision; omitted assignment preserves it, explicit None clears it."""
    finding_id = int(finding_id)
    target_status = str(new_status or "").strip().lower()
    actor = str(changed_by or "").strip()
    if not actor or len(actor) > 200:
        raise FindingLifecycleError("actor_required", "Finding decisions require an actor")
    clean_note = str(note or "").strip()[:2000] or None
    assignee_supplied = assigned_to is not ...
    reason_supplied = status_reason is not None or clean_note is not None
    requested_assignee = str(assigned_to or "").strip()[:300] or None
    requested_reason = str(status_reason if status_reason is not None else (clean_note or "")).strip()[:2000] or None
    if target_status not in VALID_FINDING_STATUSES:
        raise FindingLifecycleError("invalid_status", f"Unsupported finding status: {target_status or '<empty>'}")

    if not is_postgres_runtime_db():
        raise RuntimeError(_POSTGRES_ONLY_MESSAGE)
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from findings where id=%s for update", (finding_id,))
            current = cur.fetchone()
            if not current:
                raise FindingLifecycleError("not_found", f"Finding {finding_id} was not found")
            old_status = str(current.get("status") or "new")
            _validate_finding_transition(old_status, target_status)
            changed = old_status != target_status
            if changed and not (clean_note or requested_reason):
                raise FindingLifecycleError("reason_required", "Finding transitions require a reason")
            effective_assignee = requested_assignee if assignee_supplied else current.get("assigned_to")
            effective_reason = requested_reason if reason_supplied else current.get("status_reason")
            reason_changed = effective_reason != current.get("status_reason")
            if (assignee_supplied or reason_changed or clean_note) and not (clean_note or requested_reason):
                raise FindingLifecycleError("reason_required", "Finding decisions require a reason")
            closed_at = (current.get("closed_at") or datetime.now(timezone.utc).isoformat()) if target_status == "closed" else None
            cur.execute(
                """
                update findings
                set status=%s,
                    assigned_to=%s,
                    status_reason=%s,
                    closed_at=%s,
                    updated_at=now()
                where id=%s
                returning *
                """,
                (target_status, effective_assignee, effective_reason, closed_at, finding_id),
            )
            updated = dict(cur.fetchone())
            if changed or clean_note or assignee_supplied or reason_changed:
                cur.execute(
                    """
                    insert into finding_status_history(finding_id, old_status, new_status, changed_by, note)
                    values (%s, %s, %s, %s, %s)
                    """,
                    (finding_id, old_status, target_status, actor, clean_note or effective_reason),
                )

    updated = _json_safe(updated)
    updated["status_history"] = get_finding_status_history(finding_id, limit=50)
    return {
        "status": "ok",
        "backend": "postgres",
        "changed": changed,
        "finding": updated,
    }


def _validate_finding_transition(old_status: str, new_status: str) -> None:
    if old_status == new_status:
        return
    allowed = ALLOWED_FINDING_TRANSITIONS.get(old_status, frozenset())
    if new_status not in allowed:
        raise FindingLifecycleError(
            "invalid_transition",
            f"Finding status transition {old_status!r} -> {new_status!r} is not allowed",
        )

def render_findings_report(data: dict[str, Any]) -> str:
    cards = "".join(_finding_card(item) for item in data.get("items") or []) or '<div class="empty">Findings пока не обнаружены.</div>'
    summary = data.get("summary") or []
    summary_rows = "".join(f"<tr><td>{severity_label(row['severity'])}</td><td>{status_label(row['status'])}</td><td>{row['count']}</td></tr>" for row in summary) or '<tr><td colspan="3">Нет данных</td></tr>'
    return f"""<!doctype html>
<html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Findings</title>{report_style()}</head>
<body>{report_controls()}<main class=\"wrap\">
<header class=\"hero\"><div class=\"eyebrow\">ИБ-слой</div><h1>Findings: объекты проверки</h1><p class=\"subtitle\">Повторяемые выводы с evidence-событиями, статусом, важностью и рекомендацией. Это не автоматическое доказательство инцидента, а список направлений для проверки.</p><div class=\"pillrow\"><span class=\"pill\">{html.escape(format_datetime_label(data.get('generated_at_utc')))}</span><span class=\"pill\">Найдено: {len(data.get('items') or [])}</span></div></header>
<section><h2>Сводка</h2><table><thead><tr><th>Важность</th><th>Статус</th><th>Количество</th></tr></thead><tbody>{summary_rows}</tbody></table></section>
<section><h2>Активные findings</h2><div class=\"grid\">{cards}</div></section>
</main></body></html>"""


def _finding_card(item: dict[str, Any]) -> str:
    ev_links = "".join(_evidence_link(ev) for ev in item.get("evidence") or []) or '<span class="muted">Нет evidence</span>'
    entities = _format_related_entities(item.get("entities") or [])
    repeat_count = int(item.get("repeat_count") or 0)
    evidence_count = int(item.get("evidence_count") or len(item.get("evidence") or []) or 0)
    counters = f'<span class="pill">evidence: {evidence_count}</span>'
    if repeat_count:
        counters += f'<span class="pill">повторов: {repeat_count}</span>'
        if item.get("last_repeat_detected_at"):
            counters += f'<span class="pill">последний повтор: {html.escape(format_event_time(item.get("last_repeat_detected_at")))}</span>'
    return f"""<article class="card">
<div class="pillrow"><span class="badge {html.escape(str(item.get('severity')))}">{severity_label(item.get('severity'))}</span><span class="pill">{status_label(item.get('status'))}</span><span class="pill">confidence: {html.escape(str(item.get('confidence')))}</span>{counters}</div>
<h3>{html.escape(str(item.get('title')))}</h3>
<p>{html.escape(str(item.get('summary') or ''))}</p>
<div class="entity-grid"><div><span>Кто</span><strong>{html.escape(str(item.get('actor') or '—'))}</strong></div><div><span>Цель</span><strong>{html.escape(str(item.get('target') or '—'))}</strong></div><div><span>Источник</span><strong>{html.escape(str(item.get('source') or '—'))}</strong></div></div>
<p><b>Почему важно:</b> {html.escape(str(item.get('why_it_matters') or '—'))}</p>
<p><b>Что сделать:</b> {html.escape(str(item.get('recommended_action') or '—'))}</p>
<p><b>Назначено:</b> {html.escape(str(item.get('assigned_to') or '—'))} · <b>Причина статуса:</b> {html.escape(str(item.get('status_reason') or '—'))}</p>
<p class="muted">Связанные сущности: {entities}</p>
{_status_history_html(item.get('status_history') or [])}
<div class="evidence-actions">{ev_links}</div>
</article>"""


def _status_history_html(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="muted">История статуса отсутствует.</p>'
    rows = []
    for item in items[:8]:
        old_status = status_label(item.get("old_status")) if item.get("old_status") else "создан"
        new_status = status_label(item.get("new_status"))
        rows.append(
            f"<li>{html.escape(old_status)} → {html.escape(new_status)} · "
            f"{html.escape(str(item.get('changed_by') or 'system'))} · "
            f"{html.escape(format_event_time(item.get('changed_at')))}"
            f"{': ' + html.escape(str(item.get('note'))) if item.get('note') else ''}</li>"
        )
    return '<details><summary>История статуса</summary><ul>' + ''.join(rows) + '</ul></details>'


def _format_related_entities(entities: list[dict[str, Any]], *, limit: int = 8) -> str:
    seen: set[tuple[str, str, str]] = set()
    labels: list[str] = []
    for ent in entities:
        display = str(ent.get("display_name") or "").strip()
        if not display:
            continue
        key = (str(ent.get("entity_role") or ""), str(ent.get("entity_type") or ""), display.casefold())
        if key in seen:
            continue
        seen.add(key)
        role = ""
        entity_role = str(ent.get("entity_role") or "").strip()
        if entity_role == "actor":
            role = "инициатор: "
        elif entity_role == "target":
            role = "цель: "
        elif entity_role == "source":
            role = "источник: "
        labels.append(f"{role}{html.escape(display)}")
    if not labels:
        return "—"
    visible = labels[:limit]
    hidden = len(labels) - len(visible)
    suffix = f"; еще {hidden}" if hidden > 0 else ""
    return "; ".join(visible) + suffix


def _evidence_link(ev: dict[str, Any]) -> str:
    params = {"event_db_id": ev.get("event_db_id"), "limit": 1}
    return f'<a class="button" href="/reports/event-details.html?{urlencode(params)}">{html.escape(event_id_label(ev.get("event_id")))} · {html.escape(str(ev.get("hostname")))}</a>'


def _principal(domain: Any, user: Any) -> str | None:
    u = str(user or "").strip()
    d = str(domain or "").strip()
    if not u:
        return None
    return f"{d}\\{u}" if d else u


def _recommendation_for_rule(rule_code: str) -> str:
    return _FINDING_RECOMMENDATIONS.get(
        rule_code,
        "Проверить evidence-события и подтвердить легитимность действия.",
    )

