"""Home measurement over retained privileged-membership observations, not source events."""
from __future__ import annotations

from server.sli.core.database import query_rows_bounded
from server.sli.reporting.v2.definition import HomeContribution


def _bounds(ctx):
    windows = ctx.runtime.get("home_windows")
    return windows or (ctx.params["period"],)


def _changes_sql(ctx):
    scope, params = _domain_scope(ctx, "relation")
    return f"""from ad_context_relation_versions relation
        cross join lateral (values (relation.valid_from_utc,'added'),(relation.valid_to_utc,'removed')) change(at,kind)
        where {scope} and relation.source_section='privileged_membership'
          and relation.relation_kind='member_of' and change.at>=? and change.at<?
          and not exists (select 1 from ad_context_relation_versions adjacent
              where adjacent.domain_id=relation.domain_id and adjacent.relation_key=relation.relation_key
                and adjacent.source_section=relation.source_section and adjacent.id<>relation.id
                and ((change.kind='added' and adjacent.valid_to_utc=change.at)
                     or (change.kind='removed' and adjacent.valid_from_utc=change.at)))
          and (change.kind='removed' or exists (select 1 from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id
              where run.domain_id=relation.domain_id and run.status='completed'
                and section.section_name='privileged_membership' and section.status='complete'
                and run.observed_at_utc<relation.valid_from_utc))""", params


def _domain_scope(ctx, alias):
    if ctx.domain_ids is not None:
        return f"{alias}.domain_id=any(?)", [ctx.domain_ids]
    if ctx.scope.mode != "all":
        raise PermissionError("report_scope_not_executable")
    return "true", []


def read(ctx, *, details=False):
    windows = _bounds(ctx)
    sql, scope_params = _changes_sql(ctx)
    start, end = windows[-1]["from_utc"], windows[0]["to_utc"]
    rows = query_rows_bounded(
        f"""select count(*) filter(where change.at>=?) as current_count,
                   count(*) filter(where change.at<?) as previous_count {sql}""",
        tuple([windows[0]["from_utc"], windows[0]["from_utc"], *scope_params, start, end]), statement_timeout_ms=3000,
    )
    aggregate = rows[0] if rows else {}
    run_scope, run_params = _domain_scope(ctx, "run")
    history = query_rows_bounded(
        f"""select run.domain_id,min(run.observed_at_utc) as history_from,
                   max(run.observed_at_utc) as observed_at_utc
            from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id
            where {run_scope} and run.status='completed' and section.section_name='privileged_membership'
              and section.status='complete' and run.observed_at_utc<=?
            group by run.domain_id order by run.domain_id""",
        tuple([*run_params, end]), statement_timeout_ms=3000,
    )
    from server.sli.reporting.reporting_common import format_iso, parse_utc

    domains = [row["domain_id"] for row in history]
    scoped = ctx.domain_ids is not None and domains == sorted(ctx.domain_ids)
    baseline = bool(history) and scoped and all(parse_utc(row["history_from"]) < parse_utc(start) for row in history)
    # Snapshot import history cannot prove continuous event-stream coverage.
    fingerprint = {"complete": False, "domains": domains, "kind": "snapshot_observations"}
    data = {"state": "partial" if history else "not_collected",
            "metrics": [{"key": "privileged_changes", "value": aggregate.get("current_count") if history else None,
                         "previous_value": aggregate.get("previous_count") if baseline and len(windows) == 2 else None}],
            "coverage": {"observed_at_utc": min((format_iso(row["observed_at_utc"]) for row in history), default=None),
                         "domain_ids": domains, "missing_domains": sorted(set(ctx.domain_ids or []) - set(domains))},
            "comparison_coverage": fingerprint, "previous_coverage": fingerprint,
            "limitations": [{"code": "snapshot_observations", "text": "Изменения — наблюдения импортированной истории членства; время изменения в AD и непрерывное покрытие событий не подтверждены. Первоначальный состав не считается изменением."}]}
    if details:
        rows = query_rows_bounded(
            f"""select relation.id,relation.source_entity_id as entity_id,relation.target_entity_id as group_id,
                       change.kind,change.at as observed_at_utc {sql}
                order by change.at desc,relation.id desc,change.kind limit ? offset ?""",
            tuple([*scope_params, windows[0]["from_utc"], end, ctx.limit + 1, int(ctx.cursor or 0)]), statement_timeout_ms=3000,
        )
        data.update(items=[{**row, "observed_at_utc": format_iso(row["observed_at_utc"]),
                                 "row_id": f"{row['id']}:{row['kind']}"} for row in rows[:ctx.limit]], has_more=len(rows) > ctx.limit)
    return data


PRIVILEGED_CHANGES = HomeContribution(
    key="privileged_changes", metric_key="privileged_changes", label_code="home.kpi.privileged_changes",
    unit_code="home.unit.events", period_kind="observations", required_fields=frozenset({"privilege", "technical"}),
    reader=read, order=30, filters={"tab": "privileged_changes"},
)
