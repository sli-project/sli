"""Split out of ``server.sli.reporting.reporting_v4`` (plan 7.2b).

Module-level names of ``reporting_v4`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reporting.reporting_v4 as _src
from server.sli.plugins.registry import require_plugin
from server.sli.reports.ad_hygiene_policy import REPLICATION_CAVEAT, inactivity_sql, thresholds


def _ad_snapshot_summary(
    scoped_where: str,
    scope_params: _src.Sequence[_src.Any],
    field_categories: set[str],
) -> dict[str, _src.Any]:
    """Return scope-aware AD aggregates without inventing risk classifications."""
    connector = " and " if scoped_where else " where "
    current_context = """exists(
        select 1 from ad_context_entity_versions version
        where version.entity_id=entity.id
          and version.valid_to_utc is null
          and version.source_section='directory_accounts'
    )"""
    summary: dict[str, _src.Any] = {
        "kind": "ad_snapshot",
        "aggregate_scope": "effective_report_scope",
        "collection": _src._context_section_coverage(
            ("directory_accounts", "privileged_membership", "vpn_membership", "gpo_governance"),
            _src._coverage_scope(scoped_where, "entity"),
            scope_params,
        ),
        "limitations": [
            "Агрегаты описывают только объекты с текущей версией контекста AD.",
            REPLICATION_CAVEAT,
            "Неактивность пользователей: неизвестно при отсутствии корректной даты входа или наблюдения; неизвестные записи не считаются прошедшими проверку.",
            "DCSync, Kerberos, ACL и иные категории вне опубликованных полей этим набором данных не вычисляются.",
        ],
    }
    if "identity_basic" in field_categories:
        totals = _src.query_rows_bounded(
            f"""select count(*) as total_objects
                from entities_v2_active entity
                join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
                {scoped_where}{connector}{current_context}""",
            tuple(scope_params), statement_timeout_ms=_src.REPORT_DATA_TIMEOUT_MS,
        )
        types = _src.query_rows_bounded(
            f"""select entity_type.value as entity_type,count(*) as object_count
                from entities_v2_active entity
                join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
                {scoped_where}{connector}{current_context}
                group by entity_type.value
                order by object_count desc,entity_type.value
                limit 100""",
            tuple(scope_params), statement_timeout_ms=_src.REPORT_DATA_TIMEOUT_MS,
        )
        summary["total_objects"] = int((totals[0] if totals else {}).get("total_objects") or 0)
        summary["by_entity_type"] = [
            {"entity_type": str(row.get("entity_type") or "unknown"), "count": int(row.get("object_count") or 0)}
            for row in types
        ]
    if "security" in field_categories:
        observations = _src.query_rows_bounded(
            f"""select count(*) filter(where entity.last_seen_utc is null) as without_observation_count,
                       max(entity.last_seen_utc) as latest_observed_at_utc
                from entities_v2_active entity
                join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
                {scoped_where}{connector}{current_context}""",
            tuple(scope_params), statement_timeout_ms=_src.REPORT_DATA_TIMEOUT_MS,
        )
        observation = observations[0] if observations else {}
        summary["without_observation_count"] = int(observation.get("without_observation_count") or 0)
        summary["latest_observed_at_utc"] = observation.get("latest_observed_at_utc")
        account_controls = _src.query_rows_bounded(
            f"""with scoped_accounts as (
                    select entity_type.value as entity_type,
                           version.attributes_json->'attributes' as attributes, version.last_observed_at_utc
                    from ad_context_entity_versions version
                    join entities_v2_active entity on entity.id=version.entity_id
                    join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
                    {scoped_where}{connector}version.valid_to_utc is null
                      and version.source_section='directory_accounts'
                ),
                operating_system_groups as (
                    select nullif(attributes->>'operating_system','') as operating_system,
                           nullif(attributes->>'operating_system_version','') as operating_system_version,
                           count(*) as object_count
                    from scoped_accounts
                    where entity_type='ad_computer'
                      and nullif(attributes->>'operating_system','') is not null
                    group by 1,2
                ),
                controls as (
                    select
                       count(*) filter(where entity_type='ad_user') as observed_users,
                       count(*) filter(where entity_type='ad_user'
                         and (attributes->>'enabled')::boolean is false) as disabled_users,
                       count(*) filter(where entity_type='ad_user'
                         and {inactivity_sql('attributes', 'last_observed_at_utc')} is true) as inactive_users,
                       count(*) filter(where entity_type='ad_user'
                         and (attributes->>'password_never_expires')::boolean is true) as password_never_expires_users,
                       count(*) filter(where entity_type='ad_user'
                         and coalesce((attributes->>'locked_out')::boolean,false) is true) as locked_users,
                       count(*) filter(where entity_type='ad_computer') as observed_computers,
                       count(*) filter(where entity_type='ad_computer'
                         and (attributes->>'enabled')::boolean is false) as disabled_computers,
                       count(*) filter(where entity_type='ad_computer'
                         and (attributes->>'is_inactive')::boolean is true) as inactive_computers,
                       count(*) filter(where entity_type='ad_computer'
                         and nullif(attributes->>'operating_system','') is not null) as computers_with_operating_system,
                       0 as reserved
                    from scoped_accounts
                )
                select controls.*,
                       coalesce((
                           select jsonb_agg(jsonb_build_object(
                               'operating_system',operating_system,
                               'operating_system_version',operating_system_version,
                               'count',object_count
                           ) order by object_count desc,operating_system,operating_system_version)
                           from operating_system_groups
                       ),'[]'::jsonb) as operating_system_distribution
                from controls""",
            tuple(scope_params), statement_timeout_ms=_src.REPORT_DATA_TIMEOUT_MS,
        )
        controls = account_controls[0] if account_controls else {}
        summary["account_controls"] = {
            "observed_users": int(controls.get("observed_users") or 0),
            "disabled_users": int(controls.get("disabled_users") or 0),
            "inactive_users": int(controls.get("inactive_users") or 0),
            "password_never_expires_users": int(controls.get("password_never_expires_users") or 0),
            "locked_users": int(controls.get("locked_users") or 0),
        }
        raw_distribution = controls.get("operating_system_distribution") or []
        summary["computer_controls"] = {
            "observed_computers": int(controls.get("observed_computers") or 0),
            "disabled_computers": int(controls.get("disabled_computers") or 0),
            "inactive_computers": int(controls.get("inactive_computers") or 0),
            "computers_with_operating_system": int(
                controls.get("computers_with_operating_system") or 0
            ),
            "operating_system_distribution": [
                {
                    "operating_system": row.get("operating_system"),
                    "operating_system_version": row.get("operating_system_version"),
                    "count": int(row.get("count") or 0),
                }
                for row in raw_distribution
                if isinstance(row, _src.Mapping)
            ],
        }
    return summary


def _privileged_account_summary(
    scoped_where: str,
    scope_params: _src.Sequence[_src.Any],
    field_categories: set[str],
) -> dict[str, _src.Any]:
    """Aggregate current privileged membership links inside the effective scope."""
    connector = " and " if scoped_where else " where "
    rows = _src.query_rows_bounded(
        f"""select count(*) as total_relations,
                   count(distinct relation.source_entity_id) as unique_subjects,
                   count(distinct relation.target_entity_id) as unique_target_groups,
                   count(distinct relation.source_entity_id) filter(
                       where (account.attributes_json->'attributes'->>'enabled')::boolean is false
                   ) as disabled_subjects,
                   count(distinct relation.source_entity_id) filter(
                       where (account.attributes_json->'attributes'->>'enabled')::boolean is true
                         and {inactivity_sql("account.attributes_json->'attributes'", 'account.last_observed_at_utc')} is true
                   ) as inactive_subjects,
                   max(greatest(relation.last_observed_at_utc,source_entity.last_seen_utc)) as latest_observed_at_utc
            from ad_context_relation_versions relation
            join entities_v2 source_entity on source_entity.id=relation.source_entity_id
            join entities_v2 target_entity on target_entity.id=relation.target_entity_id
            {_src.VPN_ACCOUNT_ATTRIBUTES_LATERAL}
            {scoped_where}{connector}relation.valid_to_utc is null
              and relation.relation_kind='member_of'
              and relation.source_section='privileged_membership'
              and {_src._active_entity_predicate('source_entity', 'target_entity')}""",
        tuple(scope_params), statement_timeout_ms=5000,
    )
    aggregate = rows[0] if rows else {}
    summary: dict[str, _src.Any] = {
        "kind": "ad_privileged_membership",
        "aggregate_scope": "effective_report_scope",
        "collection": _src._context_section_coverage(
            ("privileged_membership", "directory_accounts"),
            _src._coverage_scope(scoped_where, "source_entity"),
            scope_params,
        ),
        "limitations": [
            "Сводка учитывает только текущие наблюдаемые связи member_of с распознанными привилегированными группами.",
            REPLICATION_CAVEAT,
            "Неактивность: неизвестно при отсутствии корректной даты входа или наблюдения; неизвестные записи не считаются прошедшими проверку.",
            "Состояние учётной записи берётся из текущего directory_accounts; отсутствующий снимок остаётся неопределённым.",
            "Владельцы и полные вложенные пути отсутствуют в текущем контракте и не подставляются.",
        ],
    }
    if "privilege" in field_categories:
        summary["total_relations"] = int(aggregate.get("total_relations") or 0)
        summary["unique_target_groups"] = int(aggregate.get("unique_target_groups") or 0)
    if "identity_basic" in field_categories:
        summary["unique_subjects"] = int(aggregate.get("unique_subjects") or 0)
    if "security" in field_categories:
        summary["latest_observed_at_utc"] = aggregate.get("latest_observed_at_utc")
        summary["disabled_subjects"] = int(aggregate.get("disabled_subjects") or 0)
        summary["inactive_subjects"] = int(aggregate.get("inactive_subjects") or 0)
    return summary


def _vpn_account_summary(
    scoped_where: str,
    scope_params: _src.Sequence[_src.Any],
    field_categories: set[str],
) -> dict[str, _src.Any]:
    """Compatibility entry point; VPN aggregation belongs to its plugin."""
    return require_plugin(
        "sli.remote-access", "accounts_summary", scoped_where, scope_params, field_categories,
    )


def _context_section_coverage(
    section_names: _src.Sequence[str],
    scoped_where: str,
    scope_params: _src.Sequence[_src.Any],
) -> dict[str, dict[str, _src.Any]]:
    """Describe the latest imported status per section and visible domain."""
    names = tuple(dict.fromkeys(str(item) for item in section_names if str(item)))
    if not names:
        return {}
    if "run.server_id" in scoped_where:
        return {
            name: {
                "state": "scope_not_applicable",
                "domain_count": 0,
                "complete_domain_count": 0,
                "partial_domain_count": 0,
                "failed_domain_count": 0,
                "skipped_domain_count": 0,
                "latest_observed_at_utc": None,
            }
            for name in names
        }
    scope_predicate = f" and {scoped_where.removeprefix(' where ')}" if scoped_where else ""
    rows = _src.query_rows_bounded(
        f"""with ranked as (
                select run.domain_id,section.section_name,section.status,run.observed_at_utc,
                       row_number() over(
                           partition by run.domain_id,section.section_name
                           order by run.observed_at_utc desc,run.created_at desc,run.run_id desc
                       ) as position
                from ad_context_runs run
                join ad_context_sections section on section.run_id=run.run_id
                where section.section_name=any(?) and run.status='completed'
                {scope_predicate}
            )
            select section_name,count(*) as domain_count,
                   count(*) filter(where status='complete') as complete_domain_count,
                   count(*) filter(where status='partial') as partial_domain_count,
                   count(*) filter(where status='failed') as failed_domain_count,
                   count(*) filter(where status='skipped') as skipped_domain_count,
                   max(observed_at_utc) as latest_observed_at_utc
            from ranked where position=1 group by section_name order by section_name""",
        tuple([list(names), *scope_params]), statement_timeout_ms=3000,
    )
    by_name = {str(row["section_name"]): row for row in rows}
    result: dict[str, dict[str, _src.Any]] = {}
    for name in names:
        row = by_name.get(name, {})
        domains = int(row.get("domain_count") or 0)
        complete = int(row.get("complete_domain_count") or 0)
        partial = int(row.get("partial_domain_count") or 0)
        failed = int(row.get("failed_domain_count") or 0)
        skipped = int(row.get("skipped_domain_count") or 0)
        if domains == 0:
            state = "not_collected"
        elif failed == domains:
            state = "failed"
        elif skipped == domains:
            state = "skipped"
        elif complete == domains:
            state = "complete"
        else:
            state = "partial"
        result[name] = {
            "state": state,
            "domain_count": domains,
            "complete_domain_count": complete,
            "partial_domain_count": partial,
            "failed_domain_count": failed,
            "skipped_domain_count": skipped,
            "latest_observed_at_utc": row.get("latest_observed_at_utc"),
        }
    return result


def _coverage_scope(scoped_where: str, source_alias: str) -> str:
    """Map an already-authorized entity scope to the AD Context run alias."""
    return scoped_where.replace(f"{source_alias}.", "run.")


def _gpo_governance_summary(
    scoped_where: str,
    scope_params: _src.Sequence[_src.Any],
    field_categories: set[str],
) -> dict[str, _src.Any]:
    """Summarize observed GPO entities without overstating configured ACL."""
    connector = " and " if scoped_where else " where "
    rows = _src.query_rows_bounded(
        f"""select count(*) as total_gpo,
                   count(*) filter(where nullif(trim(coalesce(
                       version.attributes_json->'attributes'->>'owner',''
                   )), '') is null) as missing_owner_count,
                   count(*) filter(
                       where ({_src.GPO_LINK_COUNT_SQL})=0
                   ) as unlinked_policy_count,
                   count(*) filter(
                       where ({_src.GPO_APPLICATION_STATE_SQL})='disabled'
                   ) as disabled_policy_count,
                   count(*) filter(
                       where ({_src.GPO_APPLICATION_STATE_SQL})
                             in ('computer_only','user_only')
                   ) as partially_enabled_policy_count,
                   count(*) filter(
                       where ({_src.GPO_EXECUTABLE_COUNT_SQL})>0
                   ) as executable_component_policy_count,
                   coalesce(sum({_src.GPO_EXECUTABLE_COUNT_SQL}),0)
                       as executable_component_total_count,
                   count(*) filter(
                       where jsonb_array_length({_src.GPO_SETTINGS_SQL})>0
                   ) as setting_policy_count,
                   coalesce(sum(jsonb_array_length({_src.GPO_SETTINGS_SQL})),0)
                       as setting_total_count,
                   count(*) filter(where exists (
                       select 1 from jsonb_array_elements({_src.GPO_SETTINGS_SQL}) setting
                       where lower(coalesce(setting->>'sensitive_value_present','false'))='true'
                   )) as sensitive_value_policy_count,
                   count(*) filter(
                       where ({_src.GPO_LINK_COUNT_SQL})=0
                          or ({_src.GPO_APPLICATION_STATE_SQL})='disabled'
                   ) as manual_review_count,
                   max(greatest(version.last_observed_at_utc,entity.last_seen_utc)) as latest_observed_at_utc
             from ad_context_entity_versions version
             join entities_v2 entity on entity.id=version.entity_id
             join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
             {scoped_where}{connector}version.valid_to_utc is null
               and version.source_section='gpo_governance'
               and (entity_type.value='gpo' or lower(entity_type.value) like '%gpo%')
               and {_src._active_entity_predicate('entity')}""",
        tuple(scope_params), statement_timeout_ms=5000,
    )
    aggregate = rows[0] if rows else {}
    summary: dict[str, _src.Any] = {
        "kind": "ad_gpo_governance",
        "aggregate_scope": "effective_report_scope",
        "collection": _src._context_section_coverage(
            ("gpo_governance",),
            _src._coverage_scope(scoped_where, "entity"),
            scope_params,
        ),
        "limitations": [
            "Сводка описывает только объекты GPO, наблюдаемые в текущем контексте AD.",
            "Отсутствующее значение owner является полнотой наблюдения, а не доказательством бесхозной политики.",
            "Наличие script, scheduled task или service является инвентарным фактом и без контекста не считается риском.",
            "GPMC XML и configured ACL читаются ограниченно; эффективный доступ через членство в группах не вычисляется.",
            "Содержимое SYSVOL, состояние резервной копии и план отката без отдельных источников не вычисляются.",
        ],
    }
    if "identity_basic" in field_categories:
        total = int(aggregate.get("total_gpo") or 0)
        missing_owner = int(aggregate.get("missing_owner_count") or 0)
        summary["total_gpo"] = total
        summary["missing_owner_count"] = missing_owner
        summary["owner_observation_state"] = (
            "not_collected"
            if total > 0 and missing_owner == total
            else "partial"
            if missing_owner > 0
            else "observed"
        )
    if "security" in field_categories:
        summary["unlinked_policy_count"] = int(
            aggregate.get("unlinked_policy_count") or 0
        )
        summary["disabled_policy_count"] = int(
            aggregate.get("disabled_policy_count") or 0
        )
        summary["partially_enabled_policy_count"] = int(
            aggregate.get("partially_enabled_policy_count") or 0
        )
        summary["executable_component_policy_count"] = int(
            aggregate.get("executable_component_policy_count") or 0
        )
        summary["executable_component_total_count"] = int(
            aggregate.get("executable_component_total_count") or 0
        )
        summary["executable_component_risk_qualified"] = False
        summary["setting_policy_count"] = int(
            aggregate.get("setting_policy_count") or 0
        )
        summary["setting_total_count"] = int(
            aggregate.get("setting_total_count") or 0
        )
        summary["sensitive_value_policy_count"] = int(
            aggregate.get("sensitive_value_policy_count") or 0
        )
        summary["manual_review_count"] = int(
            aggregate.get("manual_review_count") or 0
        )
        summary["manual_review_basis"] = [
            "link_count_zero",
            "application_state_disabled",
        ]
        summary["latest_observed_at_utc"] = aggregate.get("latest_observed_at_utc")
    return summary
