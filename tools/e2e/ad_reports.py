"""Payload-free checks of the four AD/DC report surfaces on a disposable copy."""
import json
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen


def zero_reason(report, category, source_count, state, coverage):
    if source_count:
        return "report_empty_with_source_rows", True
    if report == "security.events.chains":
        return ("no_authentication_events_in_window" if category else "no_significant_security_events_in_window"), False
    if report == "security.problems":
        return "no_published_findings_in_domain_window:" + str(coverage or "unknown"), False
    if report == "ad.users.v2":
        return "no_current_directory_user_population:" + str(state), False
    return "no_core_events_in_domain_window", False


def check_reports(conn, *, base_url, domain):
    from server.sli.plugins.ad.windows_ad_dc.catalog import (
        SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS,
        security_event_ids_for_family,
    )

    checks = []
    for report, category in (("events.journal", None), ("security.events.chains", None),
                             ("security.events.chains", "authentication"), ("ad.users.v2", "active"),
                             ("ad.users.v2", "disabled"),
                             ("security.problems", None)):
        query = {"period": "24h", "limit": 50, "tz": "UTC"}
        if report == "security.events.chains":
            query["domain"] = domain
            if category:
                query["category"] = category
        if report == "ad.users.v2":
            query.pop("period")
            query.update(tab="all", account_state="enabled" if category == "active" else "disabled")
        if report == "security.problems":
            query.pop("period")
            from datetime import datetime, timedelta, timezone
            now = datetime.now(timezone.utc)
            query.update(domain=domain, time_from=(now - timedelta(hours=24)).isoformat(), time_to=now.isoformat())
        item = {"report": report, "category": category, "failed": False, "reason": None}
        try:
            with urlopen(base_url + f"/api/v2/reports/{report}/data?" + urlencode(query), timeout=60) as response:
                payload = json.load(response)
            item.update(http=200, rows=len(payload.get("items") or []), state=payload.get("state"),
                        has_more=payload.get("has_more"), filtered_count=payload.get("filtered_count"),
                        coverage_state=(payload.get("coverage") or {}).get("state"))
            if item["state"] in {"error", "denied", "not_installed"}:
                item.update(failed=True, reason="report_" + str(item["state"]))
            if report == "ad.users.v2":
                source = conn.execute("select count(*) as n from entities_v2_active e "
                    "join storage_v2_entity_type t on t.id=e.entity_type_id "
                    "join ad_context_entity_versions v on v.entity_id=e.id and v.valid_to_utc is null "
                    "and v.source_section='directory_accounts' where e.domain_id=%s and t.value='ad_user' "
                    "and v.attributes_json->'attributes'->>'enabled'=%s",
                    (domain, "true" if category == "active" else "false")).fetchone()["n"]
            elif report == "security.problems":
                source = conn.execute("select count(*) as n from findings_active f "
                    "where f.last_seen_utc::timestamptz>=now()-interval '24 hours' "
                    "and exists(select 1 from finding_evidence fe join events_v2_core e on e.id=fe.event_id "
                    "where fe.finding_id=f.id and e.domain_id=%s) "
                    "and not exists(select 1 from finding_evidence fe left join events_v2_core e on e.id=fe.event_id "
                    "where fe.finding_id=f.id and (e.domain_id is null or e.domain_id<>%s))",
                    (domain, domain)).fetchone()["n"]
                item["audit_policy_change_events"] = conn.execute("select count(*) as n from events_v2_core "
                    "where domain_id=%s and event_id=4719 and time_created_utc>=now()-interval '24 hours'",
                    (domain,)).fetchone()["n"]
            else:
                ids = list(security_event_ids_for_family(category)) if category else list(SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS)
                source = conn.execute("select count(*) as n from events_v2_core "
                    "where domain_id=%s and time_created_utc>=now()-interval '24 hours' "
                    "and (%s or event_id=any(%s))", (domain, report == "events.journal", ids)).fetchone()["n"]
            item["source_rows"] = source
            if not item["rows"] and not item["failed"]:
                item["reason"], item["failed"] = zero_reason(report, category, source, item["state"], item["coverage_state"])
                if report == "security.problems" and not item["audit_policy_change_events"]:
                    item["reason"] += ";no_audit_policy_change_events"
        except HTTPError as exc:
            item.update(http=exc.code, failed=True, reason="report_http_error")
        except Exception as exc:  # noqa: BLE001 -- never expose private diagnostics
            conn.rollback()
            item.update(failed=True, reason="report_check_failed:" + type(exc).__name__)
        checks.append(item)
    return checks
