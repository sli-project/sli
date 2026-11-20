"""Security problem queue (security.queue) on the v2 report framework (plan 5.7).

Rows are published production-semantic findings. Lifecycle changes and the
hand-off to an investigation stay on the findings/investigations APIs; the
declaration only names the UI component that calls them (``Detail.actions``).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import replace
from hashlib import sha256
from typing import Any

from server.sli.access.access_control_v4 import (
    capability_decision_for_resource_groups,
    report_action_decision,
)
from server.sli.core.keyset_cursor import decode_cursor, encode_cursor
from server.sli.core.messages import FINDING_SEVERITIES, FINDING_STATUSES, message
from server.sli.reporting.v2.access import ReportAccess, report_grant
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    HomeContribution,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    resolve_period,
    result,
    source_state,
)
from server.sli.semantic.findings import (
    get_problem_evidence_page,
    get_security_problems_data,
    password_coverage_catalog_domains,
)
from server.sli.semantic.investigation_cases import case_resource_groups_batch
from server.sli.semantic.investigation_finding_links import linked_cases_for_findings
from server.sli.semantic.problem_groups import COHORT_MAX_LENGTH

REPORT_KEY = "security.problems"
ACCESS_KEY = "security.queue"
STATUSES = tuple((status, message(f"security.problems.status.{status}")["text"]) for status in FINDING_STATUSES)
SEVERITIES = tuple((severity, message(f"reports.v2.security.problems.columns.severity.labels.{severity}")["text"]) for severity in FINDING_SEVERITIES)
ATTENTION = {"new", "confirmed", "repeated"}
IN_PROGRESS = {"active", "review"}
CLOSED = {"false_positive", "closed"}
_SYSTEM = re.compile(r"^sid:([^:]+):S-1-5-18$", re.IGNORECASE)
_AUDIT_POLICY = "Audit policy was changed"
# Built-in L1 policy titles (semantic_risk_policies.definition_json.title) with
# registered plain-language wording; the key is the message prefix.
_L1_WORDING = {
    "Member was added to a privileged group": "privileged_group",
    "Scheduled task was registered": "scheduled_task",
    "Security event log was cleared": "eventlog_cleared",
}
_REVIEW_BUCKETS = frozenset({"machine_account", "system_account", "known_gpo_refresh", "interactive_admin", "unknown"})
_EXACT = frozenset({"raw_evidence"})
_IDENTITY = frozenset({"identity_basic"})
_TECHNICAL = frozenset({"technical"})
_RISK_FIELDS = (
    "id", "finding_id", "state", "reason", "responsible_user_id", "responsible_username",
    "expires_at", "created_at", "created_by", "changed_by",
)
_FINDING_FIELDS = (
    "id", "rule_code", "title", "severity", "confidence", "status", "summary",
    "why_it_matters", "recommended_action", "first_seen_utc", "last_seen_utc",
    "evidence_count", "repeat_count", "updated_at", "published_at_utc", "suppressed", "actor", "target",
    "source", "assigned_to", "status_reason", "decoy_id", "decoy_revision",
    "occurrence_count", "problem_cohort",
)
_NESTED_FIELDS = {
    "evidence": ("event_db_id", "event_record_id", "event_id", "hostname", "channel", "time_created_utc", "evidence_role", "note"),
    "entities": ("entity_type", "display_name", "entity_role"),
    "status_history": ("id", "old_status", "new_status", "changed_at", "changed_by", "note"),
}


def _principal(value: Any, *, source_host: bool = False, hide_sid: bool = False) -> str | dict[str, Any] | None:
    text = str(value or "").strip()
    system = _SYSTEM.match(text)
    if system:
        return message("security.problems.entity.system", {"name": system.group(1).upper()})
    # Presentation only: unresolved SID-shaped actors stay unknown, not named.
    if hide_sid and re.match(r"(?:sid:(?:[^:]+:)*)?S-1-", text, re.IGNORECASE):
        return message("security.problems.actor.unknown")
    if source_host and text.isdigit():
        return message("security.problems.entity.source_host")
    return text or None


def presentation(finding: dict[str, Any]) -> dict[str, Any]:
    """Registered wording for findings with an explicit presentation contract."""
    audit = finding.get("title") == _AUDIT_POLICY
    identity = finding.get("identity_context") or {}
    actor = identity.get("actor") or (identity.get("principals") or {}).get(str(finding.get("actor") or "").strip())
    fields = {
        "title_text": message("security.problems.presentation.audit_title") if audit else finding.get("title") or message("security.problems.presentation.default_title", {"id": finding.get("id") or "?"}),
        "what_happened": message("security.problems.presentation.audit_what") if audit else finding.get("summary") or message("security.problems.presentation.default_what"),
        "why_text": message("security.problems.presentation.audit_why") if audit else finding.get("why_it_matters") or message("security.problems.presentation.default_why"),
        "next_text": message("security.problems.presentation.audit_next") if audit else finding.get("recommended_action") or message("security.problems.presentation.default_next"),
        "actor_text": message("security.problems.identity.name", {"name": actor["label"]}) if actor
            else _principal(finding.get("actor"), hide_sid=True) or message("security.problems.actor.undefined"),
        "wording_limitation": None if audit else message("security.problems.presentation.wording_limitation"),
    }
    l1 = _L1_WORDING.get(finding.get("title") or "")
    if l1:
        for field, suffix in (("title_text", "title"), ("what_happened", "what"), ("why_text", "why"),
                              ("next_text", "next")):
            fields[field] = message(f"security.problems.presentation.{l1}_{suffix}")
        fields["wording_limitation"] = None
    decoy = finding.get("rule_code") == "semantic.qw.account-decoy"
    file_decoy = finding.get("rule_code") == "semantic.qw.file-decoy"
    watch = finding.get("rule_code") == "semantic.qw.account-watch"
    password = {"semantic.qw.password-spray": "spray", "semantic.qw.password-brute-force": "brute",
                "semantic.qw.disabled-account-logon": "disabled"}.get(finding.get("rule_code"))
    if password:
        for field, suffix in (("title_text", "title"), ("what_happened", "what"), ("why_text", "why"),
                              ("next_text", "next"), ("wording_limitation", "limitation")):
            prefix = password if suffix in {"title", "what"} else "password"
            fields[field] = message(f"security.problems.presentation.{prefix}_{suffix}")
    if decoy or file_decoy or watch:
        for field, suffix in (("title_text", "title"), ("what_happened", "what"), ("why_text", "why"),
                              ("next_text", "next"), ("wording_limitation", "limitation")):
            prefix = "watch" if watch else "file_decoy" if file_decoy else "decoy"
            fields[field] = message(f"security.problems.presentation.{prefix}_{suffix}")
    acl = finding.get("rule_code") == "semantic.qw.file-acl-broad-write"
    if acl:
        for field, suffix in (("title_text", "title"), ("what_happened", "what"), ("why_text", "what"), ("next_text", "next")):
            fields[field] = message(f"security.problems.presentation.file_acl_broad_{suffix}")
        fields["wording_limitation"] = message("security.problems.presentation.file_acl_broad_what")
    return {
        "presentation_code": "file_acl_broad_write" if acl else f"password_{password}" if password else "account_watch_activity" if watch else "file_decoy_touched" if file_decoy else "account_decoy_used" if decoy else "audit_policy_changed" if audit else l1 or None,
        "title_code": fields["title_text"].get("code") if isinstance(fields["title_text"], dict) else None,
        "what_code": fields["what_happened"].get("code") if isinstance(fields["what_happened"], dict) else None,
        "why_code": fields["why_text"].get("code") if isinstance(fields["why_text"], dict) else None,
        "next_step_code": fields["next_text"].get("code") if isinstance(fields["next_text"], dict) else None,
        **{field: value["text"] if isinstance(value, dict) else value for field, value in fields.items()},
        "presentation_messages": {field: value for field, value in fields.items() if isinstance(value, dict)},
    }


def _row(finding: dict[str, Any], transitions: dict[str, list[str]]) -> dict[str, Any]:
    status = str(finding.get("status") or "new")
    evidence = list(finding.get("evidence") or [])
    view = presentation(finding)
    bucket = (finding.get("review_hint") or {}).get("bucket")
    review_message = message(f"reports.v2.security.problems.presentation.{bucket}") if bucket in _REVIEW_BUCKETS and (finding.get("review_hint") or {}).get("has_audit_change") is not False else None
    if review_message:
        view["presentation_messages"]["review_hint_text"] = review_message
    identity = finding.get("identity_context") or {}
    principals = identity.get("principals") or {}
    entities = [principals.get(str(entity.get("display_name") or "").strip(), {}).get("label")
                or _principal(entity.get("display_name"), source_host=entity.get("entity_role") == "source_host") or message("security.problems.entity.unknown")
                for entity in finding.get("entities") or []]
    observations = [*principals.values(), *([identity["actor"]] if identity.get("actor") else [])]
    sources = list(dict.fromkeys(
        f"{item['label']} [{item.get('sid') or '—'}] · "
        f"{('AD / ' + str(item.get('source_run_id'))) if item['source'] == 'ad_snapshot' else str(item['event_id']) + ' / #' + str(item['event_db_id'])}"
        f" · {item.get('observed_at_utc') or '—'}" for item in observations))
    if sources:
        view["presentation_messages"]["identity_sources_text"] = message("security.problems.identity.sources_partial" if identity.get("snapshot_state") == "unavailable"
            else "security.problems.identity.sources", {"details": "; ".join(sources)})
    elif identity.get("snapshot_state") == "unavailable":
        view["presentation_messages"]["identity_sources_text"] = message("security.problems.identity.unavailable")
    assigned = str(finding.get("assigned_to") or "").strip()
    if not assigned:
        view["presentation_messages"]["assigned_to_text"] = message("security.problems.assignee.unassigned")
    return {
        **{key: finding[key] for key in _FINDING_FIELDS if key in finding},
        **{key: [{field: item[field] for field in fields if field in item} for item in finding.get(key) or []]
           for key, fields in _NESTED_FIELDS.items()},
        "risk_acceptance": {key: finding["risk_acceptance"][key] for key in _RISK_FIELDS
                            if key in finding["risk_acceptance"]} if finding.get("risk_acceptance") else None,
        "risk_audit": [
            {**{key: item[key] for key in ("id", "action", "actor", "occurred_at") if key in item},
             "details": {"rule": {key: item.get("details", {}).get("rule", {})[key] for key in _RISK_FIELDS
                                  if key in item.get("details", {}).get("rule", {})}}}
            for item in finding.get("risk_audit") or []
        ],
        "review_hint": {"bucket": (finding.get("review_hint") or {}).get("bucket")
                        if (finding.get("review_hint") or {}).get("bucket") in _REVIEW_BUCKETS else None},
        **view,
        "identity_context": identity,
        "identity_sources_text": view["presentation_messages"].get("identity_sources_text", {}).get("text"),
        "entity_identifiers": ", ".join(str(entity.get("display_name") or "") for entity in finding.get("entities") or []) or None,
        "assigned_to_text": assigned or view["presentation_messages"]["assigned_to_text"]["text"],
        "review_hint_text": review_message["text"] if review_message else None,
        "status": status,
        "status_message": message(f"security.problems.status.{status}") if status in FINDING_STATUSES else None,
        "severity_message": message(f"reports.v2.security.problems.columns.severity.labels.{finding['severity']}") if finding.get("severity") in FINDING_SEVERITIES else None,
        "allowed_statuses": list(dict.fromkeys([status, *transitions.get(status, [])])),
        "evidence_total": finding.get("evidence_count") if finding.get("evidence_count") is not None else len(evidence),
        "entity_messages": entities,
        "entity_text": ", ".join(entity["text"] if isinstance(entity, dict) else entity for entity in entities) or None,
        # Native counts belong to the separately authorised evidence page;
        # queue-only viewers must not learn file-scope witness counts.
        **({"evidence_count": None, "evidence_total": None, "evidence": []}
           if finding.get("rule_code") == "semantic.qw.file-acl-broad-write" else {}),
    }


def _linked_cases(rows: list[dict[str, Any]], context: QueryContext) -> list[dict[str, Any] | None]:
    """Case each row's finding is linked to (None when not linked or not readable)."""
    access = context.access
    report_key = next((key for key in ("investigations.workspace", "cases.workspace")
                       if report_grant(access, key) and "view" in report_grant(access, key).get("allowed_actions", [])), None)
    if report_key is None:
        return [None] * len(rows)
    try:
        by_finding = linked_cases_for_findings([int(row["id"]) for row in rows if row.get("id") is not None])
        resources = case_resource_groups_batch(
            sorted({int(case["id"]) for case in by_finding.values()}),
            authorization=context.runtime.get("storage_route_authorization"),
        ) if by_finding else {}
        by_finding = {
            finding_id: {key: case.get(key) for key in ("id", "public_id", "status")}
            for finding_id, case in by_finding.items()
            if int(case["id"]) in resources
            and capability_decision_for_resource_groups(access, "investigations.view", resource_groups=resources[int(case["id"])])["allowed"]
            and report_action_decision(access, report_key, "view", resource_groups=resources[int(case["id"])])["allowed"]
        }
    except Exception:  # the queue must stay readable if the link table is unavailable
        logging.getLogger(__name__).warning("finding-case links are unavailable")
        by_finding = {}
    return [by_finding.get(int(row["id"])) if row.get("id") is not None else None for row in rows]


def _count(summary: list[dict[str, Any]], statuses: set[str]) -> int:
    return sum(int(row.get("count") or 0) for row in summary
               if row.get("status") in statuses and not row.get("risk_accepted"))


def _open_queue(params: dict[str, Any]) -> bool:
    return (params.get("population", "open") == "open" and not params.get("status")
            and not params.get("risk") and params.get("id") is None)


def _query(context: QueryContext) -> dict[str, Any]:
    projection = queue_access(context.access, context.action)
    if not projection.fields_allowed(frozenset({'security'})):
        raise PermissionError('report_field_categories_not_allowed')
    # Authorization/category projection precedes the catalog and coverage API.
    allowed = projection.domain_ids
    selected = context.domain_ids
    coverage_domains = (sorted(set(selected) & set(allowed)) if allowed is not None and selected is not None
                        else selected if selected is not None else allowed)
    if coverage_domains is None:
        try:
            coverage_domains = password_coverage_catalog_domains()
        except Exception:
            # The catalog read owns/cleans its connection, just like coverage reads.
            coverage_domains = None
    params = context.params
    group_queue = (not context.runtime.get("home_summary", False)
                   and params.get("cohort") is None and params.get("id") is None
                   and projection.fields_allowed(_IDENTITY))
    cohort_binding = {"report": REPORT_KEY, "cohort": params, "domains": context.domain_ids,
                      "timezone": context.timezone, "action": context.action, "group_queue": group_queue}
    after_id = None
    if params.get("cohort") is not None and not projection.fields_allowed(_IDENTITY):
        raise PermissionError("report_field_categories_not_allowed")
    if context.cursor:
        position = decode_cursor(context.cursor, cohort_binding)
        after_id = position.get("after_id")
        if set(position) != {"after_id"} or type(after_id) is not int or after_id <= 0:
            raise ValueError("invalid_cursor")
    if params.get("time_from") or params.get("time_to"):
        resolve_period({"period": "custom", "from": params.get("time_from"), "to": params.get("time_to")},
                       timezone_name=context.timezone, max_days=90)
    raw = get_security_problems_data(
        status=params.get("status"), severity=params.get("severity"), q=params.get("q"),
        limit=context.limit, authorization=context.runtime.get("storage_route_authorization"),
        domain_ids=context.domain_ids, finding_id=params.get("id"),
        password_coverage_domain_ids=coverage_domains,
        attention_only=params.get("population") == "attention" or context.runtime.get("home_summary", False),
        open_only=_open_queue(params) and not context.runtime.get("home_summary", False),
        group_queue=group_queue,
        page_queue=not context.runtime.get("home_summary", False),
        after_id=after_id,
        home_order=context.runtime.get("home_summary", False), compact=context.runtime.get("home_summary", False),
        time_from=params.get("time_from"), time_to=params.get("time_to"),
        show_suppressed=params.get("show_suppressed") == "true",
        risk=params.get("risk"),
        rule_code=params.get("rule_code"), created_from=params.get("created_from"), created_to=params.get("created_to"),
        cohort_timezone=context.timezone,
        **({"cohort": params["cohort"]} if params.get("cohort") is not None else {}),
        **({"entity_id": int(params["entity_id"])} if params.get("entity_id") is not None else {}),
    )
    rows = projected_rows(raw, context, projection)
    summary = list(raw.get("summary") or [])
    state = source_state(raw.get("state"))
    if state == "ok" and not rows:
        state = "empty"
    runtime = raw.get("semantic_runtime") or {}
    limitations = [{"code": f"problems_{index}", "text": str(text)} for index, text in enumerate(raw.get("limitations") or [])]
    if runtime.get("findings_state") != "active":
        limitation = message("reports.v2.security.problems.limitations.zero_is_not_safe")
        limitations.append({"code": "zero_is_not_safe", "text": limitation["text"], "presentation_messages": {"text": limitation}})
        if state in {"ok", "empty"}:
            state = "partial"
    coverage_requested = coverage_domains != [] and state != 'denied'
    password_coverage = raw.get('password_detection_coverage') if coverage_requested else None
    if coverage_requested and password_coverage is None:
        password_coverage = {'availability': 'unavailable', 'as_of': None, 'rows': [], 'has_more': False}
    incomplete = password_coverage is not None and (
        password_coverage['availability'] != 'observed' or password_coverage['has_more']
        or not password_coverage['rows']
        or any(row['policy_state'] in {'unknown', 'disabled_last_known'}
               or row['frozen_episode_count'] != '0'
               or row['policy_state'] == 'enabled' and row['status'] != 'healthy'
               for row in password_coverage['rows']))
    if incomplete:
        limitation = message('reports.v2.security.problems.limitations.password_coverage_incomplete')
        limitations.append({'code': 'password_coverage_incomplete', 'text': limitation['text'],
                            'presentation_messages': {'text': limitation}})
        if state in {'ok', 'empty'}:
            state = 'partial'
    attention, in_progress = _count(summary, ATTENTION), _count(summary, IN_PROGRESS)
    return result(
        REPORT, state=state, items=rows, has_more=bool(raw.get("has_more")),
        next_cursor=(encode_cursor(cohort_binding, {"after_id": raw["items"][-1].get("queue_cursor_id", rows[-1]["id"])})
                     if rows and raw.get("has_more") else None),
        filtered_count=sum(int(item.get("count") or 0) for item in summary),
        metrics=[
            {"key": "open", "label": message("reports.v2.security.problems.metrics.open.label")["text"], "value": attention + in_progress, "tone": "warning" if attention + in_progress else "neutral"},
            {"key": "attention", "label": message("reports.v2.security.problems.metrics.attention.label")["text"], "value": attention, "tone": "danger" if attention else "neutral", "filter": {"population": "attention"}},
            {"key": "progress", "label": message("reports.v2.security.problems.metrics.progress.label")["text"], "value": in_progress, "tone": "accent", "filter": {"status": "active"}},
            {"key": "closed", "label": message("reports.v2.security.problems.metrics.closed.label")["text"], "value": _count(summary, CLOSED), "tone": "success", "filter": {"status": "closed"}},
        ],
        coverage={"state": runtime.get("findings_state"),
                  **({"password_detection": password_coverage} if password_coverage is not None else {}),
                  "event_at_utc": max((str(row["last_seen_utc"]) for row in rows if row.get("last_seen_utc")), default=None),
                  "published_at_utc": max((str(row["published_at_utc"]) for row in rows if row.get("published_at_utc")), default=None),
                  "worker_checked_at_utc": runtime.get("heartbeat_at")},
        limitations=limitations,
    )


def queue_access(access, action: str = "view") -> ReportAccess:
    # The domain adapter rejects scopes the population reader cannot enforce.
    return ReportAccess(REPORT, access, action)


def projected_rows(raw: dict[str, Any], context: QueryContext, projection: ReportAccess) -> list[dict[str, Any]]:
    """Shared allowlist and field policy for the v2 and legacy queue aliases."""
    transitions = (raw.get("lifecycle") or {}).get("allowed_transitions") or {}
    rows = [_row(item, transitions) for item in raw.get("items") or []]
    if not context.runtime.get("home_summary"):
        for row, linked in zip(rows, _linked_cases(rows, context)):
            row["linked_case"] = linked
    return projection.result(result(REPORT, state="ok", items=rows))["items"]


def _detail(context: QueryContext, row_id: str) -> dict[str, Any]:
    """Recheck queue membership on every evidence page before reading links."""
    projection = queue_access(context.access, context.action)
    finding_id = int(row_id)
    params = context.params
    if params.get("cohort") is not None and not projection.fields_allowed(_IDENTITY):
        raise PermissionError("report_field_categories_not_allowed")
    authorization = context.runtime.get("storage_route_authorization")
    population = get_security_problems_data(
        finding_id=finding_id, status=params.get("status"), severity=params.get("severity"), q=params.get("q"),
        entity_id=params.get("entity_id"), rule_code=params.get("rule_code"),
        **({"cohort": params["cohort"], "cohort_timezone": context.timezone}
           if params.get("cohort") is not None else {}),
        created_from=params.get("created_from"), created_to=params.get("created_to"),
        show_suppressed=params.get("show_suppressed") == "true", risk=params.get("risk"),
        domain_ids=context.domain_ids, time_from=params.get("time_from"), time_to=params.get("time_to"),
        attention_only=params.get("population") == "attention",
        open_only=_open_queue(params),
        # This is only an ID-membership recheck. Optional labels must not spend
        # the shared read budget before the separately authorized evidence page.
        limit=1, compact=True, authorization=authorization,
    )
    if not any(row.get("id") == finding_id for row in population.get("items") or []):
        raise LookupError("report_row_not_found")
    binding = {"report": REPORT_KEY, "row": row_id, "params": params,
               "domains": context.domain_ids, "action": context.action,
               "native_access": sha256(json.dumps(context.access, sort_keys=True, default=str).encode()).hexdigest(),
               "scope": context.scope.fingerprint if context.scope else context.access}
    cursor = decode_cursor(context.cursor, binding) if context.cursor else {"after_id": 0}
    typed = cursor.get("version") == 2
    after_id = 0 if typed else cursor.get("after_id")
    if type(after_id) is not int or after_id < 0 or typed and set(cursor) != {"version", "position", "watermark"}:
        raise ValueError("invalid_cursor")
    page = get_problem_evidence_page(finding_id, after_id=after_id, limit=context.limit, authorization=authorization,
        native_access=context.access, native_fields_allowed=projection.fields_allowed(frozenset({"security", "raw_evidence", "identity_basic", "technical"})),
        action=context.action, domain_ids=context.domain_ids, position=cursor.get("position") if typed else None,
        watermark=cursor.get("watermark") if typed else None, legacy_cursor=bool(context.cursor) and not typed)
    rows = page["items"]
    native = [row for row in rows if row.get("storage_kind") == "file_audit_snapshot"]
    missing_sources = sum(row.get("availability") == "unavailable" if row.get("storage_kind") == "file_audit_snapshot"
                          else row.get("event_db_id") is None for row in rows)
    partial = missing_sources or any(row.get("grants_has_more") or row.get("coverage", {}).get("state") != "complete" for row in native)
    next_position = page.get("next_position")
    next_cursor = None
    if page["has_more"]:
        next_cursor = encode_cursor(binding, {"version": 2, "position": next_position, "watermark": page["watermark"]}) if next_position else encode_cursor(binding, {"after_id": rows[-1]["evidence_id"]})
    return result(
        REPORT, state="partial" if partial else "ok" if rows else "empty",
        items=rows, filtered_count=page["total"],
        coverage={"evidence_total_lower_bound": page.get("total_lower_bound"),
                  "evidence_missing_sources": missing_sources, "evidence_native_snapshots": len(native),
                  **({"evidence_historical": True} if native else {})},
        has_more=page["has_more"], next_cursor=next_cursor,
    )


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Security analyst",
        question=message("reports.v2.security.problems.intent.question")["text"],
        action="Inspect finding evidence and record an authorized human lifecycle decision.",
        scope="Server-granted published findings; selected status, severity, family and subject filters.",
        exclusions="Not a complete security assessment; no findings does not prove a safe environment or complete rule execution.",
        sources=(
            "Canonical: published findings from accepted deterministic server policies.",
            "Supplemental: exact retained evidence events and rule-runtime diagnostics.",
        ),
        freshness_expectation=message("reports.v2.security.problems.intent.freshness_expectation")["text"],
        rights="security.queue view grant; engine-enforced finding and evidence scope; lifecycle actions and exports require independent grants.",
        field_classes=(
            "security",
            "identity_basic",
            "technical",
            "raw_evidence",
        ),
        coverage="Applicable accepted policies and their authorized source windows; rule runtime and source coverage are distinct.",
        completeness="Successfully evaluated eligible policy/subject/window combinations divided by expected combinations in the authorized scope; findings and passed controls are not the numerator. Unknown without evaluation coverage.",
        denominator=message("reports.v2.security.problems.intent.denominator")["text"],
        retention="Published findings and derived facts follow their lifecycle/hold policy; exact source evidence has separate bounded retention.",
        provenance="Finding ID, accepted deterministic rule/policy identity, evidence event IDs and analyst decision history.",
        primary_archetype="queue",
        product_archetype="decision-support-recommendation",
        deterministic_policy="Display published findings and their existing severity, suppression and lifecycle; decisions require separate human authorization.",
        result_limits="Finding pages and evidence pages are bounded independently; finding count is not policy evaluation coverage.",
        fallback="Preserve missing-source and evidence-expired limitations; no findings is not a clean security assessment.",
        acceptance_lanes={
            "product_user": "Published findings support a human triage and lifecycle decision.",
            "authorization": "security.queue scope, evidence access, export and lifecycle permissions remain independent.",
            "deterministic_interpretation": "Finding severity and policy identity come from published records; no new scoring is computed.",
            "api_view_model": "Finding filters, lifecycle fields and evidence cursors preserve the existing reader contract.",
            "ui_honest_states": "Empty queue, denied grant, partial evaluation, stale and unavailable sources stay distinct.",
            "evidence_audit": "Finding ID, policy identity, retained evidence and human decision history remain attributable.",
        },
    ),
    key=REPORT_KEY,
    section="investigation",
    title=message("reports.v2.security.problems.title")["text"],
    description=message("reports.v2.security.problems.description")["text"],
    archetype="queue",
    access=AccessRule(ACCESS_KEY, frozenset({"security"}), scope="domain"),
    row_categories={
        "evidence": _EXACT, "evidence.hostname": _EXACT | _TECHNICAL, "evidence.channel": _EXACT | _TECHNICAL,
        "status_history": _EXACT | _IDENTITY, "status_reason": _EXACT,
        "actor": _IDENTITY, "actor_text": _IDENTITY, "presentation_messages.actor_text": _IDENTITY, "target": _IDENTITY,
        "problem_cohort": _IDENTITY,
        "entities": _IDENTITY, "entity_text": _IDENTITY, "entity_messages": _IDENTITY,
        "assigned_to": _IDENTITY, "assigned_to_text": _IDENTITY,
        "presentation_messages.assigned_to_text": _IDENTITY, "source": _TECHNICAL,
        "entity_identifiers": _IDENTITY, "identity_context": _IDENTITY | _EXACT,
        "identity_sources_text": _IDENTITY | _EXACT,
        "presentation_messages.identity_sources_text": _IDENTITY | _EXACT,
        "decoy_id": _TECHNICAL, "decoy_revision": _TECHNICAL,
        "risk_acceptance.reason": _EXACT,
        **{f"risk_acceptance.{key}": _IDENTITY for key in
           ("responsible_user_id", "responsible_username", "created_by", "changed_by")},
        "risk_audit": _EXACT | _IDENTITY,
    },
    params=(
        Param.integer("id", message("reports.v2.security.problems.params.id.label")["text"], hidden=True),
        Param("domain", message("reports.v2.security.problems.params.domain.label")["text"], "domain", hidden=True),
        Param("time_from", message("reports.v2.security.problems.params.time_from.label")["text"], "text", hidden=True),
        Param("time_to", message("reports.v2.security.problems.params.time_to.label")["text"], "text", hidden=True),
        replace(Param.choice("population", message("reports.v2.security.problems.params.population.label")["text"], tuple(
            (key, message(f"reports.v2.security.problems.params.population.options.{key}")["text"])
            for key in ("open", "attention", "all"))), default="open"),
        Param.choice("status", message("reports.v2.security.problems.columns.status.label")["text"], STATUSES),
        Param.choice("severity", message("reports.v2.security.problems.columns.severity.label")["text"], SEVERITIES),
        replace(Param.text("q", message("reports.v2.security.problems.params.q.label")["text"]), field_categories=_IDENTITY),
        replace(Param.integer("entity_id", message("reports.v2.security.problems.params.entity_id.label")["text"], hidden=True), field_categories=_IDENTITY),
        Param.choice("show_suppressed", message("reports.v2.security.problems.params.show_suppressed.label")["text"], (("true", message("reports.v2.security.problems.params.show_suppressed.options.true")["text"]),)),
        Param.choice("risk", message("reports.v2.security.problems.params.risk.label")["text"], (
            ("accepted", message("reports.v2.security.problems.params.risk.options.accepted")["text"]),
            ("all", message("reports.v2.security.problems.params.risk.options.all")["text"]),
        )),
        replace(Param.text("cohort", message("reports.v2.security.problems.params.cohort.label")["text"],
                           max_length=COHORT_MAX_LENGTH), hidden=True, field_categories=_IDENTITY),
        Param("rule_code", message("reports.v2.security.problems.params.rule_code.label")["text"], "text", hidden=True),
        Param("created_from", message("reports.v2.security.problems.params.created_from.label")["text"], "text", hidden=True),
        Param("created_to", message("reports.v2.security.problems.params.created_to.label")["text"], "text", hidden=True),
    ),
    columns=(
        Column("title", message("reports.v2.security.problems.columns.title.label")["text"], path="title_text"),
        Column("occurrence_count", message("reports.v2.security.problems.columns.occurrence_count.label")["text"],
               component="problems.occurrences"),
        Column("id", message("reports.v2.security.problems.columns.id.label")["text"], "number"),
        Column("severity", message("reports.v2.security.problems.columns.severity.label")["text"], "state", labels=dict(SEVERITIES)),
        Column("status", message("reports.v2.security.problems.columns.status.label")["text"], "state", labels=dict(STATUSES)),
        Column("risk_acceptance", message("reports.v2.security.problems.columns.risk_acceptance.label")["text"], component="problems.risk-badge"),
        Column("actor", message("reports.v2.security.problems.columns.actor.label")["text"], path="actor_text", field_categories=_IDENTITY),
        Column("review_hint", message("reports.v2.security.problems.columns.review_hint.label")["text"], path="review_hint_text"),
        Column("suppressed", message("reports.v2.security.problems.columns.suppressed.label")["text"], "state", labels={"true": message("reports.v2.security.problems.params.show_suppressed.options.true")["text"], "false": message("reports.v2.security.problems.columns.suppressed.labels.false")["text"]}),
        Column("assigned_to", message("reports.v2.security.problems.columns.assigned_to.label")["text"], path="assigned_to_text", field_categories=_IDENTITY),
        Column("last_seen_utc", message("reports.v2.security.problems.columns.last_seen_utc.label")["text"], "datetime"),
        Column("evidence", message("reports.v2.security.problems.columns.evidence.label")["text"], "number", path="evidence_total"),
        Column("what", message("reports.v2.security.problems.columns.what.label")["text"], path="what_happened", optional=True),
        Column("why", message("reports.v2.security.problems.columns.why.label")["text"], path="why_text", optional=True),
        Column("next", message("reports.v2.security.problems.columns.next.label")["text"], path="next_text", optional=True),
        Column("entities", message("reports.v2.security.problems.columns.entities.label")["text"], path="entity_text", optional=True, field_categories=_IDENTITY),
        Column("actor_identifier", message("reports.v2.security.problems.columns.actor_identifier.label")["text"], path="actor", optional=True, field_categories=_IDENTITY),
        Column("entity_identifiers", message("reports.v2.security.problems.columns.entity_identifiers.label")["text"], optional=True, field_categories=_IDENTITY),
        Column("identity_sources", message("reports.v2.security.problems.columns.identity_sources.label")["text"], path="identity_sources_text", optional=True, field_categories=_IDENTITY | _EXACT),
        Column("first_seen_utc", message("reports.v2.security.problems.columns.first_seen_utc.label")["text"], "datetime", optional=True),
        Column("repeat_count", message("reports.v2.security.problems.columns.repeat_count.label")["text"], "number", optional=True),
        Column("decoy_id", message("reports.v2.security.problems.columns.decoy_id.label")["text"], "code", optional=True, field_categories=_TECHNICAL),
        Column("decoy_revision", message("reports.v2.security.problems.columns.decoy_revision.label")["text"], component="decoys.version", optional=True, field_categories=_TECHNICAL),
    ),
    query=_query,
    row_key="id",
    detail=Detail(
        title=message("reports.v2.security.problems.detail.title")["text"],
        key="id",
        query=_detail,
        default_limit=20,
        access=AccessRule(ACCESS_KEY, frozenset({"security", "raw_evidence"})),
        columns=(
            Column("event_id", message("reports.v2.security.problems.detail.columns.event_id.label")["text"], "code", link="/app/events/{event_db_id}", field_categories=_EXACT),
            Column("hostname", message("reports.v2.security.problems.detail.columns.hostname.label")["text"], field_categories=_EXACT | _TECHNICAL),
            Column("channel", message("reports.v2.security.problems.detail.columns.channel.label")["text"], field_categories=_EXACT | _TECHNICAL),
            Column("time_created_utc", message("reports.v2.security.problems.detail.columns.time_created_utc.label")["text"], "datetime", field_categories=_EXACT),
        ),
        row_links=((message("reports.v2.security.problems.detail.row_links./app/events/{event_db_id}")["text"], "/app/events/{event_db_id}"),),
        actions="problems.lifecycle",
        row_component="problems.acl-evidence",
    ),
    presets=(
        (message('reports.v2.security.problems.presets.{"population":"attention"}')["text"], {"population": "attention"}),
        (message('reports.v2.security.problems.presets.{"severity":"high"}')["text"], {"severity": "high"}),
        (message('reports.v2.security.problems.presets.{"status":"active"}')["text"], {"status": "active"}),
        (message('reports.v2.security.problems.presets.{"risk":"accepted"}')["text"], {"risk": "accepted"}),
    ),
    default_limit=50,
    max_limit=200,
    home_order=10,
    home_contributions=(HomeContribution(key="attention", metric_key="attention", label_code="home.kpi.attention",
                                         unit_code="home.unit.problems", meaning="lower_is_better", order=10,
                                         filters={"population": "attention"}),),
)
