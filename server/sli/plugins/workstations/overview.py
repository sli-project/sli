"""Scoped projected inventory and finding reader for the registered WS report.

No raw history scan or collection is performed. Existing projected findings are
observations, not proof that missing checks evaluated successfully.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace

from server.sli.core.messages import message
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.plugins.workstations import devices
from server.sli.plugins.workstations.access import REPORT_KEY, station_predicate
from server.sli.plugins.workstations.check_catalog import BY_ID, CATALOG
from server.sli.plugins.workstations.importer import digest
from server.sli.plugins.workstations.overview_contracts import (
    CheckCounts,
    CheckResult,
    Count,
    Quality,
)
from server.sli.plugins.workstations.reports import FIELDS
from server.sli.plugins.workstations.reports import make_report as legacy_report
from server.sli.plugins.workstations.scope import RESOURCES
from server.sli.reporting.v2.access import report_grant
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    Param,
    ReportDefinition,
    View,
    result,
)
from server.sli.sources.process_identity_contract import (
    bounded_process_text,
    windows_process_id,
)

PAGE_SIZE = 50

# Agent-bound stations retain the exact WR03 resources. AD-only stations use
# current directory identity/membership, not inventory's historical OU caption.
STATION_RESOURCES = RESOURCES + """, station_resources as (
    select i.station_id,r.agent_key,r.plugin_id,r.source_instance_id,r.entity_id,r.device_id,
           case when i.ad_computer_id is not null then 'ad-domain:'||i.domain_id::text
                else r.collection_scope_id end as collection_scope_id,
           r.ou_path,r.ad_computer_id
    from sli_plugin_workstations.station_inventory i
      join resources r on r.agent_key=i.agent_key
    where (i.entity_id is null or exists(select 1 from devices d
               where d.agent_key=i.agent_key and d.entity_id=i.entity_id))
      and ((i.ad_computer_id is null and i.domain_id is null
            and not exists(select 1 from resources current_binding
                where current_binding.agent_key=i.agent_key and current_binding.ad_computer_id is not null))
        or exists(select 1 from resources current_binding
            where current_binding.agent_key=i.agent_key
              and current_binding.ad_computer_id=i.ad_computer_id
              and current_binding.collection_scope_id='ad-domain:'||i.domain_id::text))
    union all
    select i.station_id,null::text as agent_key,'sli.workstations'::text as plugin_id,
           null::text as source_instance_id,e.id as entity_id,e.natural_key as device_id,
           'ad-domain:' || e.domain_id::text as collection_scope_id,
           v.attributes_json->'attributes'->>'organizational_unit' as ou_path,e.id as ad_computer_id
    from sli_plugin_workstations.station_inventory i
    join entities_v2_active e on e.id=i.ad_computer_id
    join storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'
    left join ad_context_entity_versions v on v.entity_id=e.id
      and v.source_section='directory_accounts' and v.valid_to_utc is null
    where i.agent_key is null and i.domain_id=e.domain_id
)
"""


def admission(access):
    """A legacy family grant alone cannot widen the new overview's field set."""
    grant = report_grant(access, REPORT_KEY)
    if not grant:
        raise PermissionError("workstation_access_denied")
    return station_predicate({**access, "reports": [grant]}, inventory=True)


def check_rows(observed):
    counts = {row["check_id"]: row["stations"] for row in observed}
    return [CheckResult(rule.check_id, Quality("partial"), CheckCounts(
        Count(counts[rule.check_id], "at_least") if counts.get(rule.check_id) else Count(None, "unknown"),
        Count(None, "unknown"))).to_dict() for rule in CATALOG]


def select_reference(references, index, agent_key):
    if type(index) is not int or not isinstance(references, list) or not 0 <= index < min(len(references), 100):
        raise ValueError("workstation_evidence_invalid")
    reference = references[index]
    if not isinstance(reference, dict) or reference.get("kind") not in {"workstation_observation", "protection_snapshot"}:
        raise ValueError("workstation_evidence_invalid")
    if not agent_key or reference.get("agent_key") != agent_key:
        raise PermissionError("workstation_access_denied")
    return reference


def observation_evidence(row, reference):
    body = row.get("observation")
    xml = row.get("source_xml")
    if (not isinstance(body, dict) or not isinstance(xml, str)
            or row.get("id") != reference.get("observation_id")
            or row.get("agent_key") != reference.get("agent_key")
            or body.get("agent_key") != row.get("agent_key")
            or digest(body) != row.get("observation_sha256")
            or hashlib.sha256(xml.encode("utf-8")).hexdigest() != reference.get("source_sha256")
            or body.get("source_sha256") != reference.get("source_sha256")):
        raise ValueError("workstation_evidence_mismatch")
    return {key: row.get(key) for key in ("id", "family", "observed_at", "source_xml", "observation_sha256")} | {
        "storage_kind": "workstation_observation", "source_sha256": reference["source_sha256"]}


def _evidence(cur, base, params, context, definition):
    finding_id = context.params.get("finding_id")
    index = context.params.get("evidence_index")
    if (type(finding_id) is not str or not re.fullmatch("[a-f0-9]{64}", finding_id)
            or type(index) is not int or not 1 <= index <= 100):
        raise ValueError("workstation_evidence_invalid")
    cur.execute(base + "select f.evidence_refs,v.agent_key from observed f join visible v using(station_id) where f.id=%s",
                (*params, finding_id))
    finding = cur.fetchone()
    if not finding:
        raise PermissionError("workstation_access_denied")
    reference = select_reference(finding["evidence_refs"], index - 1, finding["agent_key"])
    rows = []
    if reference["kind"] == "workstation_observation":
        cur.execute("select id,agent_key,family,observed_at,observation,observation_sha256,source_xml "
                    "from sli_plugin_workstations.observations where agent_key=%s and id=%s limit 2",
                    (finding["agent_key"], reference.get("observation_id")))
        records = cur.fetchall()
        if len(records) == 1:
            rows = [observation_evidence(dict(records[0]), reference)]
    else:
        cur.execute("select observed_at,state,state_sha256 from sli_plugin_workstations.protection_state "
                    "where agent_key=%s and state_sha256=%s and observed_at=%s limit 1",
                    (finding["agent_key"], reference.get("sha256"), reference.get("observed_at")))
        record = cur.fetchone()
        if record:
            if digest(record["state"]) != reference.get("sha256"):
                raise ValueError("workstation_evidence_mismatch")
            rows = [{"storage_kind": "protection_snapshot", "state": record["state"],
                     "observed_at": record["observed_at"], "source_sha256": record["state_sha256"]}]
    return result(definition, state="ok" if rows else "not_collected", items=rows,
                  coverage={"state": "available" if rows else "not_collected", "source": "postgres_exact"})


def _selection(context):
    if type(context.limit) is not int or not 1 <= context.limit <= PAGE_SIZE:
        raise ValueError("workstation_request_invalid")
    predicate, params = admission(context.access)
    # Search only the already authorized inventory + latest-login projection.
    # Never use an event's source address as the workstation's address, or
    # substitute a SID/actor for its target account. One bound pattern keeps
    # wildcard escaping identical across all fields and cannot widen scope.
    search_expression = """exists(select 1 from (
        select s.metadata->>'display_name' as value
        union all select m.last_interactive_login#>>'{account,name}'
        union all select concat_ws(chr(92),m.last_interactive_login#>>'{account,domain}',
                                   m.last_interactive_login#>>'{account,name}')
            where m.last_interactive_login#>>'{account,name}' is not null
        union all select value from jsonb_array_elements_text(
            case when jsonb_typeof(s.metadata->'ip_addresses')='array'
                 then s.metadata->'ip_addresses' else '[]'::jsonb end)
        ) search_values where search_values.value ilike %s)"""
    for name, expression in (("search", search_expression),
                             ("ou", "s.metadata->>'ou_path'=%s")):
        value = context.params.get(name)
        if value:
            if type(value) is not str or len(value) > 256:
                raise ValueError("workstation_request_invalid")
            predicate += " and " + expression
            params.append("%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                          if name == "search" else value)
    domain = context.params.get("domain", context.params.get("domain_id"))
    if domain is not None:
        if type(domain) is not int or domain <= 0:
            raise ValueError("workstation_request_invalid")
        predicate += " and s.domain_id=%s"
        params.append(domain)
    check = context.params.get("check_id")
    if check and check not in BY_ID:
        raise ValueError("workstation_request_invalid")
    if context.cursor is not None and (type(context.cursor) is not str or not 1 <= len(context.cursor) <= 256):
        raise ValueError("workstation_request_invalid")
    return predicate, params


def _paging(cur, base, params, check, cursor, limit):
    if not cursor:
        return {"start": 1, "has_previous": False, "previous_cursor": None}
    restriction = " and v.station_id<=%s"
    values = [*params, cursor]
    if check:
        restriction += " and exists(select 1 from observed f where f.station_id=v.station_id and f.check_id=%s)"
        values.append(check)
    cur.execute(base + "select count(*) as preceding from visible v where true" + restriction, values)
    preceding = cur.fetchone()["preceding"]
    cur.execute(base + "select v.station_id from visible v where true" + restriction
                + " order by v.station_id desc limit %s", (*values, limit + 1))
    backwards = cur.fetchall()
    return {"start": preceding + 1, "has_previous": preceding > 0,
            "previous_cursor": backwards[-1]["station_id"] if len(backwards) > limit else None}



def finding_card(row, station_id):
    """Expose only supported observed C04 facts, never arbitrary subject JSON.

    Native Subject account is not necessarily the process owner. Keep it, raw
    commands/XML and unvalidated signature/active claims out of this card DTO.
    """
    item = dict(row)
    subject = item.pop("subject_ref", None)
    if (item.get("check_id") == "C04" and isinstance(subject, dict)
            and subject.get("kind") == "workstation_process_observation"
            and subject.get("station_id") == station_id):
        path = subject.get("path")
        item["process_details"] = {
            "path": bounded_process_text(path, "process_name") if isinstance(path, str) else None,
            "process_id": windows_process_id(subject.get("process_id")),
            "signature_status": "not_received" if subject.get("signature_status") == "not_received" else "unknown",
            "current_state": "unknown",
        }
        measurement = subject.get('file_measurement')
        if measurement is not None:
            from sli_agent.signature_contract import validate_measurement
            try:
                item['process_details']['file_measurement'] = validate_measurement(measurement)
            except ValueError:
                pass  # Unsupported stored evidence is not upgraded to a trust claim.
    return item


def read_overview(context, definition, station_id=None):
    predicate, params = _selection(context)
    if station_id is not None:
        if type(station_id) is not str or not 1 <= len(station_id) <= 256:
            raise ValueError("workstation_request_invalid")
        predicate += " and s.station_id=%s"
        params.append(station_id)
    base = STATION_RESOURCES + """, visible as materialized (
        select s.*,m.protection,m.health,m.last_interactive_login,m.as_of_utc
        from sli_plugin_workstations.station_inventory s
        left join sli_plugin_workstations.station_summary m using(station_id)
        where """ + predicate + """
    ), observed as materialized (
        select f.* from sli_plugin_workstations.check_findings f join visible v using(station_id)
        where f.status='active'
    ) """
    with connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read read only")
        cur.execute("set local statement_timeout='5000ms'")
        if station_id is not None and context.params.get("finding_id"):
            return _evidence(cur, base, params, context, definition)
        cur.execute(base + "select count(*) as total,count(agent_key) as agent_stations,"
                    "(select count(distinct station_id) from observed) as observed_stations,"
                    "exists(select 1 from sli_plugin_workstations.station_inventory) as inventory_built,"
                    "transaction_timestamp() as as_of from visible", params)
        summary = cur.fetchone()
        inventory_built = summary["inventory_built"]
        if station_id is not None and not summary["total"]:
            raise PermissionError("workstation_access_denied")
        cur.execute(base + "select check_id,count(distinct station_id) as stations from observed group by check_id", params)
        checks = check_rows(cur.fetchall())
        selected = context.params.get("check_id")
        paging = _paging(cur, base, params, selected, context.cursor if station_id is None else None, context.limit)
        restriction, page_params = "", list(params)
        if selected:
            restriction += " and exists(select 1 from observed f where f.station_id=v.station_id and f.check_id=%s)"
            page_params.append(selected)
        if context.cursor and station_id is None:
            restriction += " and v.station_id>%s"
            page_params.append(context.cursor)
        cur.execute(base + """select v.*,
            (select count(distinct check_id) from observed f where f.station_id=v.station_id) as observed_checks
            from visible v where true """ + restriction + " order by v.station_id limit %s",
                    (*page_params, context.limit + 1))
        rows = [dict(row) for row in cur.fetchall()]
        device_counts = devices.summaries(cur, [row["station_id"] for row in rows[:context.limit]], now=summary["as_of"])
        for row in rows[:context.limit]:
            row["devices"] = device_counts[row["station_id"]]
        if selected:
            cur.execute(base + "select count(distinct station_id) as total from observed where check_id=%s", (*params, selected))
            filtered_count = cur.fetchone()["total"]
        else:
            filtered_count = summary["total"]
        if not inventory_built:
            filtered_count = None
        findings = []
        if station_id is not None:
            cur.execute(base + "select id,station_id,check_id,rule_version,revision,reason_code,reason_params,"
                        "quality,evidence_refs,last_observed_at,subject_ref from observed order by check_id,id limit 101", params)
            findings = [finding_card(row, station_id) for row in cur.fetchall()]
        cur.execute(base + "select distinct metadata->>'ou_path' as value from visible "
                    "where nullif(metadata->>'ou_path','') is not null order by value limit 101", params)
        ous = [{"value": row["value"], "label": row["value"]} for row in cur.fetchall()]
    items = rows[:context.limit]
    # All diagnostics use the same authorized, filtered population as the rows.
    # Published inventory establishes observed counts, including a scoped/filter
    # zero. The existence flag exposes no foreign station metadata or counts.
    # A wholly empty projection still cannot establish that inventory ran.
    population_status = ("inventory_pending" if not inventory_built else
                         "no_agents" if not summary["agent_stations"] else
                         "awaiting_observations" if not summary["observed_stations"] else "partial")
    return result(definition, state="partial", items=items, has_more=len(rows) > context.limit,
                  next_cursor=items[-1]["station_id"] if len(rows) > context.limit else None,
                  filtered_count=filtered_count, collections={"checks": checks, "findings": findings[:100], "paging": [paging]},
                  metrics=[{"key": "stations", "label": "workstations.overview.stations",
                            "value": summary["total"] if inventory_built else None,
                            "quality": "observed" if inventory_built else "unknown"},
                           {"key": "observed", "label": "workstations.overview.observed",
                            "value": summary["observed_stations"] if inventory_built else None,
                            "quality": "observed" if inventory_built else "unknown"}],
                  filter_options={"ou": ous[:100]},
                  coverage={"state": "partial", "completeness": "not_proven", "population_status": population_status,
                            "card_findings_has_more": len(findings) > 100},
                  window={**context.params.get("period", {}), "generated_at_utc": summary["as_of"]})


def make_report():
    intent = replace(legacy_report("protection").intent,
                     question="Which authorized workstations have observed findings, and what evidence should be reviewed?",
                     action="Open the scoped station and inspect its observed findings and source evidence.",
                     scope="Current projected inventory within the atomic overview grant and current workstation read scope.",
                     sources=("Canonical: workstation inventory, summary and active finding projections.",
                              "Supplemental: exact retained PostgreSQL observations and protection snapshots referenced by findings."),
                     freshness_expectation="Projection and source timestamps describe observed freshness; evaluator completeness is unproven.",
                     rights="workstations.overview atomic field grant and workstation read capability, including scoped denies.",
                     coverage="Authorized projected station identities; distinct observed findings do not establish evaluated coverage.",
                     completeness="Not proven: missing or zero observed findings never establish a passed check.",
                     denominator="Distinct authorized projected stations after search, domain and OU filters.",
                     retention="This view reads retained PostgreSQL evidence only; missing evidence is unavailable, with no history substitution.",
                     provenance="Station and finding IDs, rule revision and exact server-owned source references and hashes.",
                     primary_archetype="list",
                     deterministic_policy="Read projected station identities and active findings; missing evaluations remain unknown.",
                     result_limits="50 stations per page, 100 findings per card and 100 source references per finding; five-second reads.",
                     fallback="Source read errors fail visibly; missing exact retained evidence is not collected. No decisions or source collection.",
                     acceptance_lanes={
                         "product_user": "Open an authorized projected station, its observed findings and retained source, then return to the list.",
                         "authorization": "Atomic overview grant and current scoped read admission precede counts, pages, cards and evidence.",
                         "deterministic_interpretation": "Distinct observed findings are lower bounds; missing evaluations remain unknown.",
                         "api_view_model": "Registered report data/detail routes use bounded keyset pages and exact source references.",
                         "ui_honest_states": "Denied, partial, unknown and unavailable source states never become safe zero.",
                         "evidence_audit": "Exact PostgreSQL source hashes are checked; no mutation or audit guarantee is asserted.",
                     })
    definition = ReportDefinition(
        key=REPORT_KEY, section="reports/workstations", title=message("workstations.overview.title")["text"], description="",
        archetype="journal", intent=intent, row_key="station_id",
        access=AccessRule(REPORT_KEY, FIELDS, scope="delegated", accepts_generic_scope=True),
        params=(Param.period(max_days=90), replace(Param.domain(), required=False), Param.text("search", "workstations.overview.search"),
                Param.choice("ou", "workstations.overview.ou", options_from="ou"),
                Param.integer("domain_id", "workstations.overview.domain", hidden=True),
                Param.choice("check_id", "workstations.overview.check", [(r.check_id, r.check_id) for r in CATALOG]),
                replace(Param.text("finding_id", "Finding"), hidden=True),
                Param.integer("evidence_index", "Evidence", hidden=True)),
        columns=(Column("station_id", "workstations.overview.station"),),
        views=(View("table", key="checks", source="checks"), View("table", key="stations"),
               View("table", key="findings", source="findings"), View("table", key="paging", source="paging")),
        detail=Detail("workstations.overview.station", "station_id", (),
                      query=lambda context, row_id: read_overview(context, definition, row_id)),
        query=lambda context: read_overview(context, definition), default_limit=PAGE_SIZE, max_limit=PAGE_SIZE,
    )
    return definition
