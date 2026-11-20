"""Compact home projection over the existing, access-filtered report readers."""
from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timezone
from functools import cmp_to_key
from urllib.parse import urlencode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from server.sli.core.database import QueryTimeoutError
from server.sli.access.domain_scope import parse_domain_id, resolve_domain_selection
from server.sli.access.scope import AccessScope, ScopeClause, legacy_domain_ids
from server.sli.reporting.read_timeout import remaining_read_ms, report_read_budget
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext, Param, parse_params, resolve_period
from server.sli.reporting.v2.registry import catalog, get_report

_LOG = logging.getLogger(__name__)
SUMMARY_REPORTS = ("security.problems", "ad.infrastructure", "ad.computers.v6")
_READABLE = {"ok", "partial", "stale"}
_ACTIVE = {"new", "repeated", "confirmed", "active", "review"}


def _href(key, filters=None):
    query = urlencode(filters or {})
    return f"/app/report/{key}" + (f"?{query}" if query else "")


def _read(definition, access, authorization, *, context=None, contribution=None, windows=None):
    projection = ReportAccess(definition, access)
    if contribution and not projection.fields_allowed(contribution.required_fields):
        raise PermissionError("report_field_categories_not_allowed")
    if contribution and contribution.availability:
        availability = contribution.availability()
        if availability.get("state") != "enabled":
            disabled = availability.get("state") == "disabled"
            return {"state": "not_collected" if disabled else "error",
                    "reason": "plugin_disabled" if disabled else "plugin_state_unknown"}
    visible = replace(definition, params=tuple(p for p in definition.params if projection.fields_allowed(p.field_categories)))
    v2 = context and context.get("home_contract", "v2") == "v2"
    query = {"limit": ["5" if v2 and definition.key == "security.problems" else "20"]}
    runtime = {"storage_route_authorization": authorization}
    if contribution:
        runtime["home_windows"] = windows
        if windows:
            if not any(p.key == "period" for p in visible.params):
                visible = replace(visible, params=(*visible.params, Param.period()))
            query.update(period=["custom"], **{"from": [windows[0]["from_utc"]], "to": [windows[0]["to_utc"]]})
    if context:
        query["tz"] = [context["time_zone"]]
        if context["domain_id"] is not None:
            if definition.access.scope == "delegated" and contribution is None:
                return {"state": "denied", "reason": "report_scope_not_executable"}
            # Domain intersection also applies to reports without a domain control.
            if not any(p.key == "domain" for p in visible.params):
                visible = replace(visible, params=(*visible.params, Param("domain", "Domain", "domain")))
            query["domain"] = [str(context["domain_id"])]
        if v2 and definition.key == "security.problems":
            runtime["home_summary"] = True
            if context["period"]["preset"] != "current":
                query["time_from"] = [context["period"]["from_utc"]]
                query["time_to"] = [context["period"]["to_utc"]]
    required = [p for p in visible.params if p.kind == "domain" and p.required and p.default is None]
    if required:
        for param in required:
            if param.key not in query:
                return {"state": "not_collected", "reason": "domain_required"}
    params, paging = parse_params(visible, query)
    projection.validate_request(query, paging)
    scope = projection.restrict_request(params)
    if definition.access.scope == "domain" and context and "domain_ids" in context:
        ids = context["domain_ids"]
        selected = AccessScope("restricted", (ScopeClause(
            collection_scope_ids=tuple(f"ad-domain:{domain_id}" for domain_id in ids),
        ),)) if ids else AccessScope()
        scope = scope.intersect(selected)
        if scope.mode == "none":
            raise PermissionError("report_scope_not_executable")
    context = QueryContext(
        access=access, params=params, domain_ids=legacy_domain_ids(scope) if definition.access.scope == "domain" else None, action="view",
        cursor=None, limit=paging["limit"], timezone=paging["timezone"],
        runtime=runtime, field_access=projection.fields_allowed,
        scope=scope, principal=access.get("subject") or {},
    )
    reader = contribution.reader if contribution else None
    data = projection.result((reader or definition.query)(context))
    data["scope"] = {"mode": scope.mode, "domain_ids": context.domain_ids}
    if contribution and definition.access.scope == "delegated" and params.get("domain") is not None:
        data["scope"] = {"mode": "delegated", "domain_ids": [params["domain"]]}
    return data


def home_summary(access, *, authorization=None, version="v1", query=None):
    if "workspace.view" not in access.get("capabilities", []):
        raise PermissionError("workspace_view_required")
    if version not in {"v1", "v2", "v3"}:
        raise ValueError("home_contract_invalid")
    generated = datetime.now(timezone.utc)
    query = dict(query or {})
    if "domain_id" in query:
        domain = parse_domain_id(query)
        if "domain" in query or "scope" in query:
            raise ValueError("domain_scope_invalid")
        query.pop("domain_id")
        query.update(scope=["domain"], domain=[str(domain)])
    context = _context(query, generated)
    if version == "v3":
        from server.sli.reporting.home_decisions import decision_summary

        with report_read_budget():
            return decision_summary(access, authorization=authorization, context=context)
    selection_query = {} if context["domain_id"] is None else {"domain_id": [str(context["domain_id"])]}
    with report_read_budget():
        selection = resolve_domain_selection(access, selection_query)
        context.update(domain_ids=selection.domain_ids, home_contract=version)
        payload = _build_summary(access, authorization, version, context, generated)
        domains = []
        for domain in selection.domains:
            if len(selection.domains) == 1:
                summary = payload
            else:
                domain_context = {**context, "scope": "domain", "domain_id": domain["id"], "domain_ids": [domain["id"]]}
                summary = _build_summary(access, authorization, version, domain_context, generated)
            domains.append({**domain, "summary": {key: summary[key] for key in (
                "metrics", "kpis", "freshness", "readers", "problems_found", "observation_health",
            ) if key in summary}})
        payload.update(domain_scope=selection.to_json(), domains=domains)
    return payload


def _build_summary(access, authorization, version, context, generated):
    # V1 keeps its presentation and limits while sharing the domain boundary.
    link_context = context if version == "v2" or context["domain_id"] is not None else None
    catalog_items = catalog(access)["items"]
    public_by_access = {get_report(item["key"]).access.report_key: item for item in catalog_items}
    items = sorted(
        (item for item in catalog_items if item["home_order"] is not None),
        key=lambda item: (item["home_order"], item["key"]),
    )
    reports, freshness, deviations, queue = [], [], [], []
    queue_state, queue_has_more = "denied", False
    candidates, readers, decision_count = [], [], None
    measured, kpis = {}, []
    with report_read_budget():
        for item in items:
            report = {"key": item["key"], "title": item["title"], "href": _href(item["key"])}
            reports.append(report)
            if item["key"] not in SUMMARY_REPORTS:
                continue
            data = {"state": "denied"}
            if item["executable"]:
                try:
                    remaining_read_ms()
                    data = _read(get_report(item["key"]), access, authorization, context=context)
                except PermissionError:
                    data = {"state": "denied"}
                except QueryTimeoutError:
                    data = {"state": "error", "reason": "read_timeout"}
                except Exception:  # noqa: BLE001 - degrade one optional reader without exposing source identifiers
                    # No exception text: readers may include source identifiers.
                    _LOG.warning("Home summary report reader unavailable")
                    data = {"state": "error", "reason": "reader_failed"}
            state = "error" if data["state"] == "unavailable" else data["state"]
            measured[item["key"]] = data
            filters = _context_filters(link_context, item["key"])
            report["href"] = _href(item["key"], filters)
            coverage = data.get("coverage") or {}
            freshness.append({**report, "state": state, "reason": data.get("reason") or (data.get("state_details") or {}).get("reason"),
                              "last_successful_check_utc": coverage.get("last_successful_check_utc") or coverage.get("last_successful_collection_utc"),
                              "observed_at_utc": coverage.get("observed_at_utc"),
                              "event_at_utc": coverage.get("event_at_utc"),
                              "snapshot_at_utc": coverage.get("snapshot_at_utc"),
                              "published_at_utc": coverage.get("published_at_utc"),
                              "state_details": data.get("state_details"),
                              "limitation": next((entry["text"] for entry in data.get("limitations", []) if entry.get("text")), None)})
            if version == "v2":
                readers.append({**freshness[-1], "period_kind": "observations" if item["key"] == "security.problems" and context["period"]["preset"] != "current" else "snapshot",
                                "scope": data.get("scope"),
                                "message_code": f"home.state.{state}"})
                candidates.extend(_attention_items(item, data, state, filters))
            if state in _READABLE | {"processing"}:
                for metric in data.get("metrics", []):
                    value = metric.get("value")
                    if metric.get("tone") in {"danger", "warning"} and isinstance(value, (int, float)) and value > 0:
                        deviations.append({"report_key": item["key"], "key": metric["key"], "report_title": item["title"],
                                           "label": metric["label"], "value": value, "tone": metric["tone"],
                                           "href": _href(item["key"], {**filters, **(metric.get("filter") or {})})})
            if item["key"] == "security.problems":
                queue_state = state
                if state in _READABLE | {"empty", "processing"}:
                    decision_count = next((m["value"] for m in data.get("metrics", []) if m["key"] == "attention"), None)
                rows = [row for row in data.get("items", []) if row.get("status") in _ACTIVE] if state in _READABLE else []
                queue_has_more = bool(data.get("has_more")) or len(rows) > 5
                queue = [{"id": row["id"], "title": row.get("title_text") or row.get("title"),
                          "severity": row.get("severity"), "assigned_to": row.get("assigned_to"),
                          "href": _href(item["key"], {**filters, "status": row["status"], "severity": row.get("severity") or ""})} for row in rows[:5]]
        if version == "v2":
            from server.sli.reporting.home_pool import read_pool

            kpis, contributed_readers, contributed_attention = read_pool(
                catalog_items, measured, access, authorization, context, generated,
            )
            readers.extend(contributed_readers)
            candidates.extend(contributed_attention)
            for reader in contributed_readers:
                if not any(link["key"] == reader["key"] for link in reports):
                    reports.append({key: reader[key] for key in ("key", "title", "href")})
    deviations.sort(key=lambda item: (item["tone"] != "danger", -item["value"], item["report_key"], item["key"]))
    pinned = sorted((item for item in access.get("reports", []) if item.get("allowed") and item.get("pinned")),
                    key=lambda item: str(item.get("preference_updated_at") or ""), reverse=True)
    pinned_links = []
    for item in pinned[:8]:
        public = public_by_access.get(item["report_key"])
        key = public["key"] if public else item["report_key"]
        href = _href(key) if public else item.get("target_path") or "/app/reports"
        if href.startswith(("/report/", "/reports")) and not href.endswith(".html"):
            href = "/app" + href
        pinned_links.append({"key": key, "title": public["title"] if public else item["name"], "href": href})
    payload = {"contract_id": "sli.home-summary.v1", "freshness": freshness, "deviations": deviations[:5],
            "metrics": [{"report_key": key, "state": data["state"], "items": data.get("metrics", [])} for key, data in measured.items()],
            "action_queue": {"state": queue_state, "items": queue, "has_more": queue_has_more},
            "reports": reports, "pinned": pinned_links}
    if version == "v2":
        candidates.sort(key=cmp_to_key(_compare_attention))
        health = _observation_state(readers)
        attention_state = queue_state
        if candidates and queue_state in {"empty", "denied"}:
            attention_state = "ok" if queue_state == "empty" and health == "ok" else "partial"
        public_context = {key: value for key, value in context.items() if key != "home_contract"}
        payload.update(contract_id="sli.home-summary.v2", context=public_context, generated_at_utc=generated.isoformat(),
                       readers=readers, kpis=kpis,
                       observation_health={"state": health, "message_code": f"home.observation.{health}"},
                       problems_found={"state": queue_state, "count": decision_count, "message_code": "home.problems.known" if decision_count is not None else "home.problems.unknown",
                                       "href": _href("security.problems", {**_context_filters(context, "security.problems"), "population": "attention"})},
                       action_queue={"state": attention_state, "items": candidates[:5], "has_more": len(candidates) > 5 or queue_has_more})
    return payload


def _context(query, now):
    if set(query) - {"contract", "scope", "domain", "period", "from", "to", "tz"}:
        raise ValueError("home_parameter_unknown")
    if any(len(values) != 1 or not isinstance(values[0], str) for values in query.values()):
        raise ValueError("home_parameter_invalid")
    first = lambda key, default=None: (query.get(key) or [default])[0]
    scope = first("scope", "accessible")
    if scope not in {"accessible", "domain"} or (scope == "domain") != bool(first("domain")):
        raise ValueError("home_scope_invalid")
    domain = None
    if scope == "domain":
        try:
            domain = int(first("domain"))
        except (ValueError, TypeError) as exc:
            raise ValueError("home_scope_invalid") from exc
        if domain <= 0:
            raise ValueError("home_scope_invalid")
    zone = first("tz", "UTC")
    try:
        ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
        raise ValueError("home_timezone_invalid") from exc
    preset = first("period", "current")
    if preset == "current":
        if query.get("from") or query.get("to"):
            raise ValueError("home_period_invalid")
        period = {"preset": "current", "kind": "snapshot", "as_of_utc": now.isoformat()}
    else:
        period = {**resolve_period({"period": preset, "from": first("from"), "to": first("to")}, timezone_name=zone, max_days=90, now=now), "kind": "observations"}
    return {"scope": scope, "domain_id": domain, "period": period, "time_zone": zone}


def _context_filters(context, key):
    if not context:
        return {}
    filters = {"tz": context["time_zone"]}
    if context["domain_id"] is not None:
        filters["domain"] = context["domain_id"]
    if key == "security.problems" and context["period"]["preset"] != "current":
        filters.update(time_from=context["period"]["from_utc"], time_to=context["period"]["to_utc"])
    return filters


def _attention_items(report, data, state, filters):
    key = report["key"]
    items = []
    if state in _READABLE | {"processing"} and key == "security.problems":
        from server.sli.reporting.v2.reports.security_problems import ATTENTION

        for row in data.get("items", []):
            if row.get("status") not in ATTENTION:
                continue
            items.append({"id": f"problem:{row['id']}", "problem_id": row["id"], "kind": "problem",
                          "priority_group": 0 if row.get("severity") in {"critical", "high"} else 2,
                          "severity": row.get("severity"), "needs_decision": True, "repeat_count": row.get("repeat_count") or 0,
                          "repeated": row.get("status") == "repeated" or bool(row.get("repeat_count")),
                          "observed_at_utc": row.get("last_seen_utc"), "title": row.get("title_text"),
                          "what": row.get("what_happened"), "object": row.get("entity_text") or row.get("target"),
                          "why": row.get("why_text"), "next_step": row.get("next_text"),
                          "presentation_code": row.get("presentation_code"), "message_code": "home.attention.problem",
                          "title_code": row.get("title_code"), "what_code": row.get("what_code"),
                          "why_code": row.get("why_code"), "next_step_code": row.get("next_step_code"),
                          "object_code": None if row.get("entity_text") or row.get("target") else "home.attention.object_unknown",
                          "href": _href(key, {**filters, "id": row["id"]})})
    coverage = data.get("coverage") or {}
    analysis_unconfirmed = key == "security.problems" and coverage.get("state") in {"inactive", "unknown"}
    broken_coverage = state == "partial" and (analysis_unconfirmed or any(coverage.get(key) for key in ("missing_sources", "missing_domains", "failed", "partial")))
    if (state in {"not_collected", "processing", "stale"} or broken_coverage) and data.get("reason") != "domain_required":
        code = "home.attention.analysis_unconfirmed" if analysis_unconfirmed else f"home.attention.{state}"
        items.append({"id": f"observation:{key}", "kind": "observation", "priority_group": 1,
                      "severity": None, "needs_decision": False, "repeat_count": 0,
                      "observed_at_utc": (data.get("coverage") or {}).get("observed_at_utc"),
                      "message_code": code, "object": {"report_key": key},
                      "what_code": code, "why_code": "home.attention.observation_why",
                      "next_step_code": "home.attention.observation_next",
                      "href": _href(key, filters)})
    if state in _READABLE and key == "ad.infrastructure":
        for row in data.get("items", []):
            if row.get("qualification") != "failed":
                continue
            items.append({"id": f"ad-check:{row['row_id']}", "kind": "ad_check", "priority_group": 3,
                          "severity": row.get("severity"), "needs_decision": False, "repeat_count": 0,
                          "observed_at_utc": row.get("observed_at_utc"), "title": row.get("label"),
                          "object": row.get("entity_name"), "what": row.get("actual_text"),
                          "why": row.get("basis"), "next_step": row.get("expected_condition"),
                          "title_code": f"reports.v2.ad.infrastructure.controls.{row.get('control_id')}.label" if row.get("control_id") else None,
                          "next_step_code": "home.attention.ad_next",
                          "message_code": "home.attention.ad_check", "href": _href(key, {**filters, "row_id": row["row_id"]})})
    return items


def _compare_attention(left, right):
    severities = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for a, b in ((left["priority_group"], right["priority_group"]),
                 (severities.get(left["severity"], 4), severities.get(right["severity"], 4)),
                 (not left["needs_decision"], not right["needs_decision"]),
                 (not left.get("repeated", False), not right.get("repeated", False)),
                 (-left["repeat_count"], -right["repeat_count"])):
        if a != b:
            return -1 if a < b else 1
    def observed(item):
        try:
            value = datetime.fromisoformat(str(item["observed_at_utc"]).replace("Z", "+00:00"))
            return value.timestamp() if value.tzinfo else float("-inf")
        except (ValueError, TypeError):
            return float("-inf")
    a, b = observed(left), observed(right)
    if a != b:
        return -1 if a > b else 1
    # Numeric finding identity follows the reader's final SQL tie breaker.
    a, b = left.get("problem_id", left["id"]), right.get("problem_id", right["id"])
    if type(a) is type(b):
        return (a < b) - (a > b)
    return (left["id"] > right["id"]) - (left["id"] < right["id"])


def _observation_state(readers):
    relevant = [item for item in readers if item["state"] != "denied" and item.get("health", True)]
    states = {item["state"] for item in relevant}
    for state in ("error", "not_collected", "processing", "stale", "partial"):
        if state in states:
            return state
    return "ok" if states and all(item["observed_at_utc"] for item in relevant) else "unknown"
