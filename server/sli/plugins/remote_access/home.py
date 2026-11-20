"""Compact Home aggregates from the installed VPN package's retained read views."""
from __future__ import annotations

from server.sli.core.database import query_rows_bounded
from server.sli.reporting.reporting_common import format_iso, parse_utc
from server.sli.reporting.v2.definition import HomeContribution
from server.sli.reports.vpn_report_composition import vpn_report_composition_decision
from server.sli.reports.vpn_connections_reporting import _coverage_state
from server.sli.sources.plugin_state import report_plugin_state


def availability():
    return report_plugin_state("vpn.connections") or {"state": "unknown"}


def read(ctx):
    domain = ctx.params.get("domain")
    if not domain:
        return {"state": "not_collected", "reason": "domain_required"}
    if not vpn_report_composition_decision(ctx.access, source_domain_id=domain).sessions.allowed:
        return {"state": "denied"}
    current, previous = ctx.runtime["home_windows"]
    coverage_rows = query_rows_bounded("select * from radius_vpn_session_coverage_v1 where domain_id=?", (domain,), statement_timeout_ms=3000)
    if not coverage_rows:
        return {"state": "not_collected"}
    coverage = coverage_rows[0]
    state = _coverage_state(coverage)
    if state == "not_collected":
        return {"state": "not_collected"}
    rows = query_rows_bounded(
        """select count(*) filter(where started_at_utc<? and stopped_at_utc>?) as current_count,
                  count(*) filter(where started_at_utc<? and stopped_at_utc>?) as previous_count
           from radius_vpn_session_rows_v1 where domain_id=? and entity_id is not null
             and stopped_at_utc is not null and started_at_utc is not null
             and stopped_at_utc>started_at_utc and started_at_utc<? and stopped_at_utc>?""",
        (current["to_utc"], current["from_utc"], previous["to_utc"], previous["from_utc"],
         domain, current["to_utc"], previous["from_utc"]), statement_timeout_ms=3000,
    )
    aggregate = rows[0] if rows else {}
    first = parse_utc(coverage.get("history_available_from_utc"))
    last = parse_utc(coverage.get("history_available_to_utc"))
    def fingerprint(window):
        return {"domains": [domain], "state": state,
                "complete": bool(state == "available" and first and last and first <= parse_utc(window["from_utc"])
                                 and last >= parse_utc(window["to_utc"]))}
    return {"state": "ok" if state == "available" else "processing" if state == "processing" else "partial",
            "metrics": [{"key": "closed", "value": aggregate.get("current_count"),
                         "previous_value": aggregate.get("previous_count") if first and first <= parse_utc(previous["from_utc"]) else None}],
            "coverage": {"observed_at_utc": format_iso(last) if last else None},
            "comparison_coverage": fingerprint(current), "previous_coverage": fingerprint(previous)}


CLOSED_SESSIONS = HomeContribution(
    key="vpn_closed", metric_key="closed", label_code="home.kpi.vpn_closed", unit_code="home.unit.sessions",
    period_kind="observations", reader=read, availability=availability, order=40, filters={"status": "closed"},
)
