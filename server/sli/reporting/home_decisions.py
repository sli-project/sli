"""The home decision queue uses the same publication, scope and field gates as its report."""
from __future__ import annotations

import logging
import json

from server.sli.access.auth import previous_login
from server.sli.access.domain_scope import resolve_report_domain_selection
from server.sli.core.database import QueryTimeoutError
from server.sli.reporting.home_summary import _context_filters, _href
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.reports.security_problems import REPORT, presentation
from server.sli.semantic.findings import get_security_problems_data
from server.sli.semantic.problem_groups import cohort_value

_LOG = logging.getLogger(__name__)


def decision_summary(access, *, authorization, context):
    filters = {**_context_filters(context, REPORT.key), "population": "attention"}
    payload = {"contract_id": "sli.home-summary.v3", "time_zone": context["time_zone"],
               "state": "denied", "groups": [], "total": None, "new_count": None,
               "previous_login_at": None, "updated_at_utc": None,
               "remaining_groups": None, "remaining_problems": None,
               "href": _href(REPORT.key, filters), "warnings": []}
    try:
        projection = ReportAccess(REPORT, access)
        # The existing report route gates parameters/declaration on the full
        # issued scope. Do not emit a cohort link that that gate would reject.
        cohorts_allowed = ReportAccess(REPORT, access).fields_allowed(frozenset({"identity_basic"}))
        selection = resolve_report_domain_selection(access, REPORT.access,
            {} if context["domain_id"] is None else {"domain_id": [str(context["domain_id"])]})
        if not selection.domains:
            return payload
        # Field checks cover the full queried scope, including the global selection.
        projection.scope = projection.restrict_request({"domain": context["domain_id"]})
        identity = projection.fields_allowed(frozenset({"identity_basic"}))
        exact = projection.fields_allowed(frozenset({"identity_basic", "raw_evidence"}))
        since = previous_login(access.get("subject") or {})
        raw = get_security_problems_data(
            authorization=authorization, domain_ids=selection.domain_ids,
            attention_only=True, compact=True, home_groups=True, new_since=since, limit=1,
            time_from=filters.get("time_from"), time_to=filters.get("time_to"),
            home_group_timezone=context["time_zone"] if identity and cohorts_allowed else None,
        )
    except PermissionError as exc:
        if str(exc) == "domain_scope_denied":
            raise
        return payload
    except QueryTimeoutError:
        return {**payload, "state": "error"}
    except Exception:  # noqa: BLE001 - never expose reader errors containing source identities
        _LOG.warning("Home decision queue unavailable")
        return {**payload, "state": "error"}
    state = {"available": "ok"}.get(raw.get("state"), raw.get("state", "error"))
    if state not in {"ok", "empty", "partial", "stale"}:
        return {**payload, "state": state}
    if not isinstance(raw.get("decision_groups"), list):
        return {**payload, "state": "error"}
    groups = []
    for row in raw.get("decision_groups") or []:
        view = presentation(row)
        cohort = row.get("cohort") if identity and cohorts_allowed else None
        if cohort is not None:
            cohort = cohort_value(json.dumps(cohort, ensure_ascii=False, separators=(",", ":")))
        groups.append({"key": cohort or row["rule_code"], "title": view["title_text"],
                       "title_message": view["presentation_messages"].get("title_text"),
                       "severity": ("critical", "high", "medium", "low", "unknown")[int(row["importance"])],
                       "total": int(row["total"]), "new_count": int(row["new_count"]) if row["new_count"] is not None else None,
                       "last_seen_utc": row.get("last_seen_utc"),
                       "assigned_to": row.get("assigned_to") if identity else None,
                       "assignee_state": ("mixed" if row.get("assigned_to") and row.get("unassigned_count")
                                          else "assigned" if row.get("assigned_to") else "unassigned") if identity else "unknown",
                       "unassigned_count": int(row.get("unassigned_count") or 0) if identity else None,
                       "day": row.get("day") if identity else None,
                       "identity_state": row.get("identity_state") if identity else None,
                       "objects": [{**{key: obj[key] for key in ("name", "name_state", "domain", "identifier") if key in obj},
                                    **({"snapshot_name": True} if obj.get("source") else {}),
                                    **({"source": obj["source"]} if exact and obj.get("source") else {})}
                                   for obj in row.get("objects", [])] if identity else [],
                       "object_count": int(row["object_count"]) if identity else None,
                       "href": _href(REPORT.key, {**filters, "rule_code": row["rule_code"],
                                                **({"cohort": cohort} if cohort is not None else {})})})
    first = (raw.get("decision_groups") or [{}])[0]
    total = int(first.get("total_problems", 0))
    new_count = int(first.get("total_new") or 0) if since else None
    warnings, observed = [], []
    for domain in selection.domains:
        freshness = domain["freshness"]
        if freshness.get("observed_at_utc"):
            observed.append(freshness["observed_at_utc"])
        reason = None
        if freshness.get("snapshot_state") not in {"ok", "complete", "available"} or not freshness.get("observed_at_utc"):
            reason = "home.queue.warning.source_incomplete"
        elif state in {"partial", "stale"}:
            reason = "home.queue.warning.analysis_unconfirmed"
        if reason:
            warnings.append({"domain": domain["display_name"], "reason_code": reason,
                             "href": "/app/operations?domain=" + str(domain["id"])})
    uncertain_empty = not groups and (state in {"partial", "stale"} or bool(warnings))
    if uncertain_empty:
        state = "partial"
    elif state in {"ok", "empty"}:
        state = "ok" if groups else "empty"
    return {**payload, "state": state,
            "groups": groups, "total": None if uncertain_empty else total,
            "new_count": None if uncertain_empty else new_count, "previous_login_at": since,
            "updated_at_utc": min(observed) if len(observed) == len(selection.domains) else None,
            "remaining_groups": None if uncertain_empty else int(first.get("total_groups", 0)) - len(groups),
            "remaining_problems": None if uncertain_empty else total - sum(row["total"] for row in groups), "warnings": warnings}

