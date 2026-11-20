"""VPN account dataset and aggregates over the shared directory projection."""

from __future__ import annotations

import server.sli.reporting.reporting_v4 as _src
from server.sli.reports.ad_hygiene_policy import REPLICATION_CAVEAT, thresholds


def read_accounts(*, where_sql, scope_params, effective_filter_clauses,
                  effective_filter_params, category_caps, vpn_cursor_id,
                  order_sql, clean_limit):
    dataset_key = "ad.accounts.vpn"
    summary_where = where_sql.replace("{alias}", "source_entity")
    scoped_where = _src._append_predicates(summary_where, effective_filter_clauses)
    connector = " and " if scoped_where else " where "
    summary = _vpn_account_summary(summary_where, scope_params, category_caps)
    from_sql = f"""from ad_context_relation_versions relation
            join entities_v2 source_entity on source_entity.id=relation.source_entity_id
            join storage_v2_entity_type entity_type on entity_type.id=source_entity.entity_type_id
            {_src.VPN_ACCOUNT_ATTRIBUTES_LATERAL}
            {scoped_where}{connector}relation.valid_to_utc is null
              and relation.relation_kind='member_of'
              and relation.source_section='vpn_membership'
              and entity_type.value='ad_user'
              and {_src._active_entity_predicate('source_entity')}"""
    totals = _src.query_rows_bounded(
        f"select count(distinct source_entity.id) as filtered_count {from_sql}",
        tuple(scope_params + effective_filter_params), statement_timeout_ms=5000,
    )
    filtered_count = int(totals[0]["filtered_count"]) if totals else 0
    page_params = scope_params + effective_filter_params
    if vpn_cursor_id is not None:
        from_sql += " and source_entity.id>?"
        page_params = page_params + [vpn_cursor_id]
    rows = _src.query_rows_bounded(
        f"""select distinct source_entity.id as _cursor_id,source_entity.id::text as object_id,source_entity.display_name,source_entity.natural_key,
                   (account.attributes_json->'attributes'->>'enabled')::boolean as enabled,
                   account.attributes_json->'attributes'->>'last_logon_utc' as last_logon_utc,
                   {_src.runtime_filter_expression(dataset_key, 'activity_state')} as activity_state,
                   (account.attributes_json->'attributes'->>'password_never_expires')::boolean as password_never_expires,
                   (account.attributes_json->'attributes'->>'admin_count')::integer as admin_count,
                   account.attributes_json->'attributes'->>'department' as department,
                   account.attributes_json->'attributes'->>'title' as title,
                   account.attributes_json->'attributes'->>'email' as email,
                   exists(
                       select 1 from ad_context_relation_versions privileged
                       where privileged.source_entity_id=source_entity.id
                         and privileged.valid_to_utc is null
                         and privileged.relation_kind='member_of'
                         and privileged.source_section='privileged_membership'
                   ) as privileged_overlap,
                   greatest(account.last_observed_at_utc,source_entity.last_seen_utc) as observed_at
            {from_sql}
            order by {order_sql}
            limit ?""",
        tuple(page_params + [clean_limit + 1]), statement_timeout_ms=5000,
    )
    return summary, rows, filtered_count


def _vpn_account_summary(
    scoped_where: str,
    scope_params: _src.Sequence[_src.Any],
    field_categories: set[str],
) -> dict[str, _src.Any]:
    """Aggregate users reached by the bounded VPN-group collection slice."""
    connector = " and " if scoped_where else " where "
    rows = _src.query_rows_bounded(
        f"""with vpn_users as (
                select distinct source_entity.id,source_entity.last_seen_utc,
                       {_src.runtime_filter_expression('ad.accounts.vpn', 'activity_state')} as activity_state,
                       account.attributes_json->'attributes' as attributes,
                       account.last_observed_at_utc,
                       exists(
                           select 1 from ad_context_relation_versions privileged
                           where privileged.source_entity_id=source_entity.id
                             and privileged.valid_to_utc is null
                             and privileged.relation_kind='member_of'
                             and privileged.source_section='privileged_membership'
                       ) as privileged_overlap
                from ad_context_relation_versions relation
                join entities_v2 source_entity on source_entity.id=relation.source_entity_id
                join storage_v2_entity_type entity_type on entity_type.id=source_entity.entity_type_id
                {_src.VPN_ACCOUNT_ATTRIBUTES_LATERAL}
                {scoped_where}{connector}relation.valid_to_utc is null
                  and relation.relation_kind='member_of'
                  and relation.source_section='vpn_membership'
                  and entity_type.value='ad_user'
                  and {_src._active_entity_predicate('source_entity')}
            )
            select count(*) as total_users,
                   count(*) filter(where (attributes->>'enabled')::boolean is true) as enabled_users,
                   count(*) filter(where activity_state='active') as active_users,
                   count(*) filter(where (attributes->>'enabled')::boolean is false) as disabled_users,
                   count(*) filter(where attributes is null or attributes->>'enabled' is null) as unknown_account_state_users,
                   count(*) filter(where (attributes->>'enabled')::boolean is true
                       and activity_state='inactive') as inactive_users,
                   count(*) filter(where (attributes->>'password_never_expires')::boolean is true) as password_never_expires_users,
                   count(*) filter(where privileged_overlap) as privileged_overlap_users,
                   count(*) filter(where activity_state='unknown') as unknown_activity_users,
                   max(greatest(last_observed_at_utc,last_seen_utc)) as latest_observed_at_utc
            from vpn_users""",
        tuple(scope_params), statement_timeout_ms=5000,
    )
    aggregate = rows[0] if rows else {}
    summary: dict[str, _src.Any] = {
        "kind": "ad_vpn_membership",
        "aggregate_scope": "effective_report_scope",
        "inactive_threshold_days": thresholds()["inactivity"],
        "limitations": [
            "Состав VPN определяется только членством в явно заданных группах AD.",
            "Неактивность — признак гигиены по последнему входу, а не подтверждённый инцидент.",
            REPLICATION_CAVEAT,
            "Неизвестно: дата входа или наблюдения отсутствует, некорректна либо дата входа позже наблюдения. Такие записи не классифицируются по политике.",
            "Состояние учётной записи берётся из отдельного directory_accounts, а до его появления — из ограниченного снимка участника VPN-группы.",
            "Отсутствующий снимок учётной записи показывается как неопределённое состояние, а не как отключение.",
            "События подключения VPN-шлюза этим срезом не собираются.",
        ],
        "collection": _src._context_section_coverage(
            ("vpn_membership", "directory_accounts", "privileged_membership"),
            _src._coverage_scope(scoped_where, "source_entity"),
            scope_params,
        ),
    }
    if "identity_basic" in field_categories:
        summary["total_users"] = int(aggregate.get("total_users") or 0)
    if "security" in field_categories:
        summary["enabled_users"] = int(aggregate.get("enabled_users") or 0)
        summary["active_users"] = int(aggregate.get("active_users") or 0)
        summary["disabled_users"] = int(aggregate.get("disabled_users") or 0)
        summary["unknown_account_state_users"] = int(aggregate.get("unknown_account_state_users") or 0)
        summary["inactive_users"] = int(aggregate.get("inactive_users") or 0)
        summary["unknown_activity_users"] = int(aggregate.get("unknown_activity_users") or 0)
        summary["password_never_expires_users"] = int(aggregate.get("password_never_expires_users") or 0)
        summary["latest_observed_at_utc"] = aggregate.get("latest_observed_at_utc")
    if "privilege" in field_categories:
        summary["privileged_overlap_users"] = int(aggregate.get("privileged_overlap_users") or 0)
    return summary


