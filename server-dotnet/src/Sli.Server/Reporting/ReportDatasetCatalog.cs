using System.Text.Json.Nodes;
namespace Sli.Server.Reporting;

// Server-owned allowlists and SQL from the frozen reporting_v4 reference.
internal static class ReportDatasetCatalog
{
    internal static readonly JsonObject Data = JsonNode.Parse("""
{
  "RUNTIME_FILTER_FIELDS": {
    "entities.v2": {
      "entity_type": "entity_type.value",
      "display_name": "entity.display_name"
    },
    "ad.audit.snapshot": {
      "entity_type": "entity_type.value"
    },
    "events.v2": {
      "event_id": "event.event_id",
      "channel": "channel.value",
      "time_created_utc": "event.time_created_utc"
    },
    "security.problems": {
      "severity": "findings.severity",
      "status": "findings.status"
    },
    "ad.accounts.privileged": {
      "privilege": "target_entity.display_name"
    },
    "ad.accounts.vpn": {
      "enabled": "(account.attributes_json->'attributes'->>'enabled')::boolean",
      "activity_state": "case when account.attributes_json->'attributes'->>'enabled' is null then 'unknown' when (account.attributes_json->'attributes'->>'enabled')::boolean is false then 'disabled' when {inactive_account} is null then 'unknown' when {inactive_account} then 'inactive' else 'active' end",
      "privileged_overlap": "exists(select 1 from ad_context_relation_versions filter_privileged where filter_privileged.source_entity_id=source_entity.id and filter_privileged.valid_to_utc is null and filter_privileged.relation_kind='member_of' and filter_privileged.source_section='privileged_membership')",
      "department": "account.attributes_json->'attributes'->>'department'"
    },
    "ad.gpo.governance": {
      "application_state": "coalesce(nullif(version.attributes_json->'attributes'->>'application_state',''),nullif(version.attributes_json->'attributes'->>'status',''))",
      "link_count": "case when coalesce(version.attributes_json->'attributes'->>'link_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'link_count')::integer end"
    }
  },
  "RUNTIME_SORT_FIELDS": {
    "entities.v2": {
      "id": "entity.id",
      "entity_type": "entity_type.value",
      "display_name": "entity.display_name",
      "natural_key": "entity.natural_key",
      "last_seen_utc": "entity.last_seen_utc",
      "context_source": "context_source"
    },
    "ad.audit.snapshot": {
      "object_id": "entity.id",
      "display_name": "entity.display_name",
      "entity_type": "entity_type.value",
      "last_seen_utc": "entity.last_seen_utc",
      "context_source": "context_source",
      "enabled": "enabled",
      "is_inactive": "is_inactive",
      "password_never_expires": "password_never_expires",
      "locked_out": "locked_out"
    },
    "events.v2": {
      "id": "event.id",
      "time_created_utc": "event.time_created_utc",
      "event_id": "event.event_id",
      "channel": "channel.value",
      "subject_user_name": "event.subject_user_name",
      "target_user_name": "event.target_user_name"
    },
    "security.problems": {
      "title": "findings.title",
      "severity": "findings.severity",
      "status": "findings.status",
      "evidence_event_id": "findings.last_evidence_event_id"
    },
    "ad.accounts.privileged": {
      "object_id": "source_entity.id",
      "display_name": "source_entity.display_name",
      "natural_key": "source_entity.natural_key",
      "privilege_path": "privilege_path",
      "last_seen_utc": "last_seen_utc",
      "enabled": "enabled",
      "is_inactive": "is_inactive",
      "password_never_expires": "password_never_expires",
      "locked_out": "locked_out",
      "last_logon_utc": "last_logon_utc"
    },
    "ad.accounts.vpn": {
      "object_id": "source_entity.id",
      "display_name": "source_entity.display_name",
      "natural_key": "source_entity.natural_key",
      "enabled": "enabled",
      "last_logon_utc": "last_logon_utc",
      "activity_state": "activity_state",
      "password_never_expires": "password_never_expires",
      "admin_count": "admin_count",
      "department": "department",
      "title": "title",
      "email": "email",
      "privileged_overlap": "privileged_overlap",
      "observed_at": "observed_at"
    },
    "ad.gpo.governance": {
      "object_id": "entity.id",
      "display_name": "entity.display_name",
      "natural_key": "entity.natural_key",
      "observed_at": "observed_at",
      "modified_utc": "modified_utc",
      "application_state": "application_state",
      "link_count": "link_count",
      "link_enabled_count": "link_enabled_count",
      "link_enforced_count": "link_enforced_count",
      "permission_count": "permission_count",
      "scheduled_task_count": "scheduled_task_count",
      "service_count": "service_count",
      "scope": "scope",
      "purpose": "purpose",
      "review_reason": "review_reason",
      "settings": "settings",
      "signals": "signals",
      "next_steps": "next_steps"
    }
  },
  "DEFAULT_ORDERS": {
    "entities.v2": "entity.last_seen_utc desc nulls last,entity.id desc",
    "ad.audit.snapshot": "entity.last_seen_utc desc nulls last,entity.id desc",
    "events.v2": "event.time_created_utc desc,event.id desc",
    "security.problems": "findings.id desc",
    "ad.accounts.privileged": "relation.last_observed_at_utc desc,relation.id desc",
    "ad.accounts.vpn": "privileged_overlap desc,enabled asc,last_logon_utc asc nulls first,source_entity.display_name",
    "ad.gpo.governance": "observed_at desc nulls last,entity.id desc"
  },
  "GPO_EXECUTABLE_COUNT_SQL": "case when coalesce(version.attributes_json->'attributes'->>'gpo_startup_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_startup_script_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_logon_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_logon_script_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_scheduled_task_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_scheduled_task_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_service_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_service_count')::integer else 0 end",
  "queries": {
    "_execute_definition_0": "select entity.id,entity_type.value as entity_type,entity.display_name,entity.natural_key,entity.last_seen_utc,\n                      case when exists(select 1 from ad_context_entity_versions v where v.entity_id=entity.id) then 'AD Context' else 'Storage V2' end as context_source\n               from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id\n               {scoped_where} order by {order_sql} limit ?",
    "_execute_definition_1": "select entity.id::text as object_id,entity.display_name,entity_type.value as entity_type,entity.last_seen_utc,\n                       'AD Context' as context_source,\n                       (version.attributes_json->'attributes'->>'enabled')::boolean as enabled,\n                       case when entity_type.value='ad_user' then (case when (version.attributes_json->'attributes'->>'last_logon_utc') ~ 'T.*(Z|[+-][0-9]{2}:[0-9]{2})$' and pg_input_is_valid((version.attributes_json->'attributes'->>'last_logon_utc'),'timestamp with time zone') then case when version.last_observed_at_utc is not null and (version.attributes_json->'attributes'->>'last_logon_utc')::timestamptz <= version.last_observed_at_utc then (version.attributes_json->'attributes'->>'last_logon_utc')::timestamptz < version.last_observed_at_utc - interval '{inactivity_days} days' end end) else (version.attributes_json->'attributes'->>'is_inactive')::boolean end as is_inactive,\n                       (version.attributes_json->'attributes'->>'password_never_expires')::boolean as password_never_expires,\n                       (version.attributes_json->'attributes'->>'locked_out')::boolean as locked_out\n                from entities_v2_active entity\n                join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id\n                join ad_context_entity_versions version\n                  on version.entity_id=entity.id\n                 and version.valid_to_utc is null\n                 and version.source_section='directory_accounts'\n                {scoped_where}\n                order by {order_sql} limit ?",
    "_execute_definition_3": "select title,severity,status,last_evidence_event_id as evidence_event_id\n               from findings_active findings {filtered_where} order by {order_sql} limit ?",
    "_execute_definition_4": "select count(*) as total_items,max(updated_at) as latest_observed_at_utc\n                from findings_active findings {filtered_where}",
    "_execute_definition_5": "select source_entity.id::text as object_id,source_entity.display_name,source_entity.natural_key,\n                       concat('member_of → ',target_entity.display_name) as privilege_path,\n                       greatest(relation.last_observed_at_utc,source_entity.last_seen_utc) as last_seen_utc,\n                       (account.attributes_json->'attributes'->>'enabled')::boolean as enabled,\n                       (case when (account.attributes_json->'attributes'->>'last_logon_utc') ~ 'T.*(Z|[+-][0-9]{2}:[0-9]{2})$' and pg_input_is_valid((account.attributes_json->'attributes'->>'last_logon_utc'),'timestamp with time zone') then case when account.last_observed_at_utc is not null and (account.attributes_json->'attributes'->>'last_logon_utc')::timestamptz <= account.last_observed_at_utc then (account.attributes_json->'attributes'->>'last_logon_utc')::timestamptz < account.last_observed_at_utc - interval '{inactivity_days} days' end end) as is_inactive,\n                       (account.attributes_json->'attributes'->>'password_never_expires')::boolean as password_never_expires,\n                       (account.attributes_json->'attributes'->>'locked_out')::boolean as locked_out,\n                       account.attributes_json->'attributes'->>'last_logon_utc' as last_logon_utc\n                from ad_context_relation_versions relation\n                join entities_v2 source_entity on source_entity.id=relation.source_entity_id\n                join entities_v2 target_entity on target_entity.id=relation.target_entity_id\n                left join lateral (\n                    select current.attributes_json,current.last_observed_at_utc\n                    from ad_context_entity_versions current\n                    where current.entity_id=source_entity.id\n                      and current.source_section in ('directory_accounts','vpn_membership')\n                      and current.valid_to_utc is null\n                    order by case current.source_section\n                                 when 'directory_accounts' then 0 else 1\n                             end,\n                             current.last_observed_at_utc desc,current.id desc\n                    limit 1\n                ) account on true\n                {scoped_where}{connector}relation.valid_to_utc is null\n                  and relation.relation_kind='member_of'\n                  and relation.source_section='privileged_membership'\n                  and entity_v2_is_active(source_entity.id) and entity_v2_is_active(target_entity.id)\n                order by {order_sql} limit ?",
    "_execute_definition_6": "select entity.id::text as object_id,\n                       entity.display_name,entity.natural_key,\n                       coalesce(nullif(version.attributes_json->'attributes'->>'application_state',''),nullif(version.attributes_json->'attributes'->>'status','')) as application_state,\n                       case when lower(coalesce(version.attributes_json->'attributes'->>'gpo_computer_enabled','')) in ('true','false') then (version.attributes_json->'attributes'->>'gpo_computer_enabled')::boolean end as computer_enabled,\n                       case when lower(coalesce(version.attributes_json->'attributes'->>'gpo_user_enabled','')) in ('true','false') then (version.attributes_json->'attributes'->>'gpo_user_enabled')::boolean end as user_enabled,\n                       case when coalesce(version.attributes_json->'attributes'->>'link_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'link_count')::integer end as link_count,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_link_enabled_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_link_enabled_count')::integer end as link_enabled_count,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_link_enforced_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_link_enforced_count')::integer end as link_enforced_count,\n                       coalesce(version.attributes_json->'attributes'->'links','[]'::jsonb) as links,\n                       case when lower(coalesce(version.attributes_json->'attributes'->>'gpo_wmi_filter_present','')) in ('true','false') then (version.attributes_json->'attributes'->>'gpo_wmi_filter_present')::boolean end as wmi_filter_present,\n                       nullif(version.attributes_json->'attributes'->>'gpo_wmi_filter_id','') as wmi_filter_id,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_permission_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_permission_count')::integer end as permission_count,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_permission_custom_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_permission_custom_count')::integer end as permission_custom_count,\n                       coalesce(version.attributes_json->'attributes'->'gpo_security_filtering_sids','[]'::jsonb) as security_filtering_sids,\n                       coalesce(version.attributes_json->'attributes'->'gpo_security_filtering_deny_sids','[]'::jsonb) as security_filtering_deny_sids,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_startup_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_startup_script_count')::integer end as startup_script_count,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_logon_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_logon_script_count')::integer end as logon_script_count,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_scheduled_task_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_scheduled_task_count')::integer end as scheduled_task_count,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_service_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_service_count')::integer end as service_count,\n                       case when coalesce(version.attributes_json->'attributes'->>'gpo_local_group_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_local_group_count')::integer end as local_group_count,\n                       case when jsonb_typeof(version.attributes_json->'attributes'->'gpo_settings')='array' then version.attributes_json->'attributes'->'gpo_settings' else '[]'::jsonb end as settings,\n                       case when coalesce(version.attributes_json->'attributes'->>'modified_utc','') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' then (version.attributes_json->'attributes'->>'modified_utc')::timestamptz end as modified_utc,\n                       greatest(version.last_observed_at_utc,entity.last_seen_utc) as observed_at\n                 from ad_context_entity_versions version\n                 join entities_v2 entity on entity.id=version.entity_id\n                 join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id\n                 {scoped_where}{connector}version.valid_to_utc is null\n                   and version.source_section='gpo_governance'\n                   and (entity_type.value='gpo' or lower(entity_type.value) like '%gpo%')\n                   and entity_v2_is_active(entity.id)\n                 order by {order_sql} limit ?",
    "_ad_snapshot_summary_0": "select count(*) as total_objects\n                from entities_v2_active entity\n                join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id\n                {scoped_where}{connector}{current_context}",
    "_ad_snapshot_summary_1": "select entity_type.value as entity_type,count(*) as object_count\n                from entities_v2_active entity\n                join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id\n                {scoped_where}{connector}{current_context}\n                group by entity_type.value\n                order by object_count desc,entity_type.value\n                limit 100",
    "_ad_snapshot_summary_2": "select count(*) filter(where entity.last_seen_utc is null) as without_observation_count,\n                       max(entity.last_seen_utc) as latest_observed_at_utc\n                from entities_v2_active entity\n                join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id\n                {scoped_where}{connector}{current_context}",
    "_ad_snapshot_summary_3": "with scoped_accounts as (\n                    select entity_type.value as entity_type,\n                           version.attributes_json->'attributes' as attributes, version.last_observed_at_utc\n                    from ad_context_entity_versions version\n                    join entities_v2_active entity on entity.id=version.entity_id\n                    join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id\n                    {scoped_where}{connector}version.valid_to_utc is null\n                      and version.source_section='directory_accounts'\n                ),\n                operating_system_groups as (\n                    select nullif(attributes->>'operating_system','') as operating_system,\n                           nullif(attributes->>'operating_system_version','') as operating_system_version,\n                           count(*) as object_count\n                    from scoped_accounts\n                    where entity_type='ad_computer'\n                      and nullif(attributes->>'operating_system','') is not null\n                    group by 1,2\n                ),\n                controls as (\n                    select\n                       count(*) filter(where entity_type='ad_user') as observed_users,\n                       count(*) filter(where entity_type='ad_user'\n                         and (attributes->>'enabled')::boolean is false) as disabled_users,\n                       count(*) filter(where entity_type='ad_user'\n                         and (case when (attributes->>'last_logon_utc') ~ 'T.*(Z|[+-][0-9]{2}:[0-9]{2})$' and pg_input_is_valid((attributes->>'last_logon_utc'),'timestamp with time zone') then case when last_observed_at_utc is not null and (attributes->>'last_logon_utc')::timestamptz <= last_observed_at_utc then (attributes->>'last_logon_utc')::timestamptz < last_observed_at_utc - interval '{inactivity_days} days' end end) is true) as inactive_users,\n                       count(*) filter(where entity_type='ad_user'\n                         and (attributes->>'password_never_expires')::boolean is true) as password_never_expires_users,\n                       count(*) filter(where entity_type='ad_user'\n                         and coalesce((attributes->>'locked_out')::boolean,false) is true) as locked_users,\n                       count(*) filter(where entity_type='ad_computer') as observed_computers,\n                       count(*) filter(where entity_type='ad_computer'\n                         and (attributes->>'enabled')::boolean is false) as disabled_computers,\n                       count(*) filter(where entity_type='ad_computer'\n                         and (attributes->>'is_inactive')::boolean is true) as inactive_computers,\n                       count(*) filter(where entity_type='ad_computer'\n                         and nullif(attributes->>'operating_system','') is not null) as computers_with_operating_system,\n                       0 as reserved\n                    from scoped_accounts\n                )\n                select controls.*,\n                       coalesce((\n                           select jsonb_agg(jsonb_build_object(\n                               'operating_system',operating_system,\n                               'operating_system_version',operating_system_version,\n                               'count',object_count\n                           ) order by object_count desc,operating_system,operating_system_version)\n                           from operating_system_groups\n                       ),'[]'::jsonb) as operating_system_distribution\n                from controls",
    "_privileged_account_summary_0": "select count(*) as total_relations,\n                   count(distinct relation.source_entity_id) as unique_subjects,\n                   count(distinct relation.target_entity_id) as unique_target_groups,\n                   count(distinct relation.source_entity_id) filter(\n                       where (account.attributes_json->'attributes'->>'enabled')::boolean is false\n                   ) as disabled_subjects,\n                   count(distinct relation.source_entity_id) filter(\n                       where (account.attributes_json->'attributes'->>'enabled')::boolean is true\n                         and (case when (account.attributes_json->'attributes'->>'last_logon_utc') ~ 'T.*(Z|[+-][0-9]{2}:[0-9]{2})$' and pg_input_is_valid((account.attributes_json->'attributes'->>'last_logon_utc'),'timestamp with time zone') then case when account.last_observed_at_utc is not null and (account.attributes_json->'attributes'->>'last_logon_utc')::timestamptz <= account.last_observed_at_utc then (account.attributes_json->'attributes'->>'last_logon_utc')::timestamptz < account.last_observed_at_utc - interval '{inactivity_days} days' end end) is true\n                   ) as inactive_subjects,\n                   max(greatest(relation.last_observed_at_utc,source_entity.last_seen_utc)) as latest_observed_at_utc\n            from ad_context_relation_versions relation\n            join entities_v2 source_entity on source_entity.id=relation.source_entity_id\n            join entities_v2 target_entity on target_entity.id=relation.target_entity_id\n            left join lateral (\n                    select current.attributes_json,current.last_observed_at_utc\n                    from ad_context_entity_versions current\n                    where current.entity_id=source_entity.id\n                      and current.source_section in ('directory_accounts','vpn_membership')\n                      and current.valid_to_utc is null\n                    order by case current.source_section\n                                 when 'directory_accounts' then 0 else 1\n                             end,\n                             current.last_observed_at_utc desc,current.id desc\n                    limit 1\n                ) account on true\n            {scoped_where}{connector}relation.valid_to_utc is null\n              and relation.relation_kind='member_of'\n              and relation.source_section='privileged_membership'\n              and entity_v2_is_active(source_entity.id) and entity_v2_is_active(target_entity.id)",
    "_context_section_coverage_0": "with ranked as (\n                select run.domain_id,section.section_name,section.status,run.observed_at_utc,\n                       row_number() over(\n                           partition by run.domain_id,section.section_name\n                           order by run.observed_at_utc desc,run.created_at desc,run.run_id desc\n                       ) as position\n                from ad_context_runs run\n                join ad_context_sections section on section.run_id=run.run_id\n                where section.section_name=any(?) and run.status='completed'\n                {scope_predicate}\n            )\n            select section_name,count(*) as domain_count,\n                   count(*) filter(where status='complete') as complete_domain_count,\n                   count(*) filter(where status='partial') as partial_domain_count,\n                   count(*) filter(where status='failed') as failed_domain_count,\n                   count(*) filter(where status='skipped') as skipped_domain_count,\n                   max(observed_at_utc) as latest_observed_at_utc\n            from ranked where position=1 group by section_name order by section_name",
    "_gpo_governance_summary_0": "select count(*) as total_gpo,\n                   count(*) filter(where nullif(trim(coalesce(\n                       version.attributes_json->'attributes'->>'owner',''\n                   )), '') is null) as missing_owner_count,\n                   count(*) filter(\n                       where (case when coalesce(version.attributes_json->'attributes'->>'link_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'link_count')::integer end)=0\n                   ) as unlinked_policy_count,\n                   count(*) filter(\n                       where (coalesce(nullif(version.attributes_json->'attributes'->>'application_state',''),nullif(version.attributes_json->'attributes'->>'status','')))='disabled'\n                   ) as disabled_policy_count,\n                   count(*) filter(\n                       where (coalesce(nullif(version.attributes_json->'attributes'->>'application_state',''),nullif(version.attributes_json->'attributes'->>'status','')))\n                             in ('computer_only','user_only')\n                   ) as partially_enabled_policy_count,\n                   count(*) filter(\n                       where (case when coalesce(version.attributes_json->'attributes'->>'gpo_startup_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_startup_script_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_logon_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_logon_script_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_scheduled_task_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_scheduled_task_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_service_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_service_count')::integer else 0 end)>0\n                   ) as executable_component_policy_count,\n                   coalesce(sum(case when coalesce(version.attributes_json->'attributes'->>'gpo_startup_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_startup_script_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_logon_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_logon_script_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_scheduled_task_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_scheduled_task_count')::integer else 0 end + case when coalesce(version.attributes_json->'attributes'->>'gpo_service_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_service_count')::integer else 0 end),0)\n                       as executable_component_total_count,\n                   count(*) filter(\n                       where jsonb_array_length(case when jsonb_typeof(version.attributes_json->'attributes'->'gpo_settings')='array' then version.attributes_json->'attributes'->'gpo_settings' else '[]'::jsonb end)>0\n                   ) as setting_policy_count,\n                   coalesce(sum(jsonb_array_length(case when jsonb_typeof(version.attributes_json->'attributes'->'gpo_settings')='array' then version.attributes_json->'attributes'->'gpo_settings' else '[]'::jsonb end)),0)\n                       as setting_total_count,\n                   count(*) filter(where exists (\n                       select 1 from jsonb_array_elements(case when jsonb_typeof(version.attributes_json->'attributes'->'gpo_settings')='array' then version.attributes_json->'attributes'->'gpo_settings' else '[]'::jsonb end) setting\n                       where lower(coalesce(setting->>'sensitive_value_present','false'))='true'\n                   )) as sensitive_value_policy_count,\n                   count(*) filter(\n                       where (case when coalesce(version.attributes_json->'attributes'->>'link_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'link_count')::integer end)=0\n                          or (coalesce(nullif(version.attributes_json->'attributes'->>'application_state',''),nullif(version.attributes_json->'attributes'->>'status','')))='disabled'\n                   ) as manual_review_count,\n                   max(greatest(version.last_observed_at_utc,entity.last_seen_utc)) as latest_observed_at_utc\n             from ad_context_entity_versions version\n             join entities_v2 entity on entity.id=version.entity_id\n             join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id\n             {scoped_where}{connector}version.valid_to_utc is null\n               and version.source_section='gpo_governance'\n               and (entity_type.value='gpo' or lower(entity_type.value) like '%gpo%')\n               and entity_v2_is_active(entity.id)",
    "read_accounts_0": "select count(distinct source_entity.id) as filtered_count {from_sql}",
    "read_accounts_1": "select distinct source_entity.id as _cursor_id,source_entity.id::text as object_id,source_entity.display_name,source_entity.natural_key,\n                   (account.attributes_json->'attributes'->>'enabled')::boolean as enabled,\n                   account.attributes_json->'attributes'->>'last_logon_utc' as last_logon_utc,\n                   case when account.attributes_json->'attributes'->>'enabled' is null then 'unknown' when (account.attributes_json->'attributes'->>'enabled')::boolean is false then 'disabled' when {inactive_account} is null then 'unknown' when {inactive_account} then 'inactive' else 'active' end as activity_state,\n                   (account.attributes_json->'attributes'->>'password_never_expires')::boolean as password_never_expires,\n                   (account.attributes_json->'attributes'->>'admin_count')::integer as admin_count,\n                   account.attributes_json->'attributes'->>'department' as department,\n                   account.attributes_json->'attributes'->>'title' as title,\n                   account.attributes_json->'attributes'->>'email' as email,\n                   exists(\n                       select 1 from ad_context_relation_versions privileged\n                       where privileged.source_entity_id=source_entity.id\n                         and privileged.valid_to_utc is null\n                         and privileged.relation_kind='member_of'\n                         and privileged.source_section='privileged_membership'\n                   ) as privileged_overlap,\n                   greatest(account.last_observed_at_utc,source_entity.last_seen_utc) as observed_at\n            {from_sql}\n            order by {order_sql}\n            limit ?",
    "vpn_from": "from ad_context_relation_versions relation\n            join entities_v2 source_entity on source_entity.id=relation.source_entity_id\n            join storage_v2_entity_type entity_type on entity_type.id=source_entity.entity_type_id\n            left join lateral (\n                    select current.attributes_json,current.last_observed_at_utc\n                    from ad_context_entity_versions current\n                    where current.entity_id=source_entity.id\n                      and current.source_section in ('directory_accounts','vpn_membership')\n                      and current.valid_to_utc is null\n                    order by case current.source_section\n                                 when 'directory_accounts' then 0 else 1\n                             end,\n                             current.last_observed_at_utc desc,current.id desc\n                    limit 1\n                ) account on true\n            {scoped_where}{connector}relation.valid_to_utc is null\n              and relation.relation_kind='member_of'\n              and relation.source_section='vpn_membership'\n              and entity_type.value='ad_user'\n              and entity_v2_is_active(source_entity.id)",
    "_vpn_account_summary_0": "with vpn_users as (\n                select distinct source_entity.id,source_entity.last_seen_utc,\n                       case when account.attributes_json->'attributes'->>'enabled' is null then 'unknown' when (account.attributes_json->'attributes'->>'enabled')::boolean is false then 'disabled' when {inactive_account} is null then 'unknown' when {inactive_account} then 'inactive' else 'active' end as activity_state,\n                       account.attributes_json->'attributes' as attributes,\n                       account.last_observed_at_utc,\n                       exists(\n                           select 1 from ad_context_relation_versions privileged\n                           where privileged.source_entity_id=source_entity.id\n                             and privileged.valid_to_utc is null\n                             and privileged.relation_kind='member_of'\n                             and privileged.source_section='privileged_membership'\n                       ) as privileged_overlap\n                from ad_context_relation_versions relation\n                join entities_v2 source_entity on source_entity.id=relation.source_entity_id\n                join storage_v2_entity_type entity_type on entity_type.id=source_entity.entity_type_id\n                left join lateral (\n                    select current.attributes_json,current.last_observed_at_utc\n                    from ad_context_entity_versions current\n                    where current.entity_id=source_entity.id\n                      and current.source_section in ('directory_accounts','vpn_membership')\n                      and current.valid_to_utc is null\n                    order by case current.source_section\n                                 when 'directory_accounts' then 0 else 1\n                             end,\n                             current.last_observed_at_utc desc,current.id desc\n                    limit 1\n                ) account on true\n                {scoped_where}{connector}relation.valid_to_utc is null\n                  and relation.relation_kind='member_of'\n                  and relation.source_section='vpn_membership'\n                  and entity_type.value='ad_user'\n                  and entity_v2_is_active(source_entity.id)\n            )\n            select count(*) as total_users,\n                   count(*) filter(where (attributes->>'enabled')::boolean is true) as enabled_users,\n                   count(*) filter(where activity_state='active') as active_users,\n                   count(*) filter(where (attributes->>'enabled')::boolean is false) as disabled_users,\n                   count(*) filter(where attributes is null or attributes->>'enabled' is null) as unknown_account_state_users,\n                   count(*) filter(where (attributes->>'enabled')::boolean is true\n                       and activity_state='inactive') as inactive_users,\n                   count(*) filter(where (attributes->>'password_never_expires')::boolean is true) as password_never_expires_users,\n                   count(*) filter(where privileged_overlap) as privileged_overlap_users,\n                   count(*) filter(where activity_state='unknown') as unknown_activity_users,\n                   max(greatest(last_observed_at_utc,last_seen_utc)) as latest_observed_at_utc\n            from vpn_users"
  },
  "event_views": {
    "attention": [
      1102,
      2887,
      4719,
      4724,
      4726,
      4728,
      4732
    ],
    "authentication": [
      4624,
      4625,
      4634,
      4648,
      4768,
      4769,
      4771,
      4776
    ],
    "accounts": [
      4720,
      4722,
      4723,
      4724,
      4725,
      4726,
      4728,
      4729,
      4732,
      4733,
      4738,
      4740,
      4756,
      4757,
      4767,
      4781
    ],
    "tasks": [
      7036,
      7040,
      7045
    ]
  },
  "summary_bases": {
    "_ad_snapshot_summary": {
      "kind": "ad_snapshot",
      "aggregate_scope": "effective_report_scope",
      "limitations": [
        "Агрегаты описывают только объекты с текущей версией контекста AD.",
        "lastLogonTimestamp — приблизительный реплицируемый атрибут; возможна задержка репликации. Это не доказательство отсутствия входов.",
        "Неактивность пользователей: неизвестно при отсутствии корректной даты входа или наблюдения; неизвестные записи не считаются прошедшими проверку.",
        "DCSync, Kerberos, ACL и иные категории вне опубликованных полей этим набором данных не вычисляются."
      ]
    },
    "_privileged_account_summary": {
      "kind": "ad_privileged_membership",
      "aggregate_scope": "effective_report_scope",
      "limitations": [
        "Сводка учитывает только текущие наблюдаемые связи member_of с распознанными привилегированными группами.",
        "lastLogonTimestamp — приблизительный реплицируемый атрибут; возможна задержка репликации. Это не доказательство отсутствия входов.",
        "Неактивность: неизвестно при отсутствии корректной даты входа или наблюдения; неизвестные записи не считаются прошедшими проверку.",
        "Состояние учётной записи берётся из текущего directory_accounts; отсутствующий снимок остаётся неопределённым.",
        "Владельцы и полные вложенные пути отсутствуют в текущем контракте и не подставляются."
      ]
    },
    "_gpo_governance_summary": {
      "kind": "ad_gpo_governance",
      "aggregate_scope": "effective_report_scope",
      "limitations": [
        "Сводка описывает только объекты GPO, наблюдаемые в текущем контексте AD.",
        "Отсутствующее значение owner является полнотой наблюдения, а не доказательством бесхозной политики.",
        "Наличие script, scheduled task или service является инвентарным фактом и без контекста не считается риском.",
        "GPMC XML и configured ACL читаются ограниченно; эффективный доступ через членство в группах не вычисляется.",
        "Содержимое SYSVOL, состояние резервной копии и план отката без отдельных источников не вычисляются."
      ]
    },
    "_vpn_account_summary": {
      "kind": "ad_vpn_membership",
      "aggregate_scope": "effective_report_scope",
      "limitations": [
        "Состав VPN определяется только членством в явно заданных группах AD.",
        "Неактивность — признак гигиены по последнему входу, а не подтверждённый инцидент.",
        "lastLogonTimestamp — приблизительный реплицируемый атрибут; возможна задержка репликации. Это не доказательство отсутствия входов.",
        "Неизвестно: дата входа или наблюдения отсутствует, некорректна либо дата входа позже наблюдения. Такие записи не классифицируются по политике.",
        "Состояние учётной записи берётся из отдельного directory_accounts, а до его появления — из ограниченного снимка участника VPN-группы.",
        "Отсутствующий снимок учётной записи показывается как неопределённое состояние, а не как отключение.",
        "События подключения VPN-шлюза этим срезом не собираются."
      ]
    }
  },
  "legacy_dynamic": [
    "collector-health.html",
    "autocollection.html",
    "system-health.html",
    "storage-health.html",
    "db-status.html",
    "diagnostics.html",
    "findings.html",
    "investigation.html",
    "role-overview.html",
    "ui-navigation.html",
    "security-events-monitor.html",
    "ai-redaction-preview.html",
    "ai-prompt-preview.html",
    "ai-reports.html"
  ],
  "legacy_metadata": {
    "collector-health.html": {
      "kind": "collector_health",
      "server": null,
      "title": "Состояние сбора",
      "roles": [
        "it",
        "technical"
      ],
      "focus_group": "operations",
      "navigation_priority": 70,
      "description": "Lag, timeout, repeated backlog и качество сбора по DC/каналам."
    },
    "autocollection.html": {
      "kind": "autocollection",
      "server": null,
      "title": "Состояние автосбора",
      "roles": [
        "it",
        "technical"
      ],
      "focus_group": "operations",
      "navigation_priority": 80,
      "description": "Текущий scheduled job, skipped-overlap, fairness и прогресс активного сбора."
    },
    "system-health.html": {
      "kind": "system_health",
      "server": null,
      "title": "Состояние системы",
      "roles": [
        "it",
        "technical"
      ],
      "focus_group": "operations",
      "navigation_priority": 110,
      "description": "Общее runtime-состояние сервиса и локальной среды проекта."
    },
    "storage-health.html": {
      "kind": "storage_health",
      "server": null,
      "title": "Storage Health",
      "roles": [
        "it"
      ],
      "focus_group": "operations",
      "navigation_priority": 90,
      "description": "Состояние raw/processed/logs/reports, retention и dry-run cleanup."
    },
    "db-status.html": {
      "kind": "db_status",
      "server": null,
      "title": "DB Backend Status",
      "roles": [
        "it",
        "technical"
      ],
      "focus_group": "operations",
      "navigation_priority": 95,
      "description": "PostgreSQL-only runtime: DSN, schema, connection and operational readiness."
    },
    "diagnostics.html": {
      "kind": "diagnostics",
      "server": null,
      "title": "Диагностика",
      "roles": [
        "it",
        "technical"
      ],
      "focus_group": "operations",
      "navigation_priority": 100,
      "description": "Self-test, release gate, watchdog, diagnostic bundle и быстрые проверки."
    },
    "findings.html": {
      "kind": "findings",
      "server": null,
      "title": "Findings",
      "roles": [
        "security"
      ],
      "focus_group": "security",
      "navigation_priority": 40,
      "description": "Сформированные выводы и гипотезы с evidence для ручной проверки."
    },
    "investigation.html": {
      "kind": "investigation",
      "server": null,
      "title": "Рабочее место расследования",
      "roles": [
        "security",
        "technical"
      ],
      "focus_group": "security",
      "navigation_priority": 50,
      "description": "Рабочее место расследования: pivots, цепочки, переходы к событиям."
    },
    "role-overview.html": {
      "kind": "role_overview",
      "server": null,
      "title": "Ролевые представления ИБ/ИТ",
      "roles": [
        "security",
        "it",
        "technical"
      ],
      "focus_group": "overview",
      "navigation_priority": 20,
      "description": "Поясняет, что видят ИБ, ИТ и технический слой, без удаления общих данных."
    },
    "ui-navigation.html": {
      "kind": "ui_navigation",
      "server": null,
      "title": "Карта навигации",
      "roles": [
        "security",
        "it",
        "technical"
      ],
      "focus_group": "overview",
      "navigation_priority": 25,
      "description": "Контрольная карта кнопок, отчетов и ролевой доступности интерфейса."
    },
    "security-events-monitor.html": {
      "kind": "security_events",
      "server": null,
      "title": "ИБ-мониторинг событий",
      "roles": [
        "security",
        "technical"
      ],
      "focus_group": "security",
      "navigation_priority": 30,
      "description": "Ключевые события Security за выбранный период: входы, группы, пароли, блокировки."
    },
    "ai-redaction-preview.html": {
      "kind": "ai_safety",
      "server": null,
      "title": "AI preview: безопасная подготовка",
      "roles": [
        "security",
        "it",
        "technical"
      ],
      "focus_group": "shared",
      "navigation_priority": 1000
    },
    "ai-prompt-preview.html": {
      "kind": "ai_prompt",
      "server": null,
      "title": "AI prompt: OpenAI API",
      "roles": [
        "security",
        "it",
        "technical"
      ],
      "focus_group": "shared",
      "navigation_priority": 1000
    },
    "ai-reports.html": {
      "kind": "ai_analysis",
      "server": null,
      "title": "AI-отчеты",
      "roles": [
        "security"
      ],
      "focus_group": "security",
      "navigation_priority": 60,
      "description": "AI-гипотезы после безопасной подготовки и redaction-preview."
    },
    "domain-security-overview.html": {
      "kind": "domain_overview",
      "server": null,
      "title": "Обзор безопасности домена",
      "roles": [
        "security",
        "it",
        "technical"
      ],
      "focus_group": "shared",
      "navigation_priority": 1000
    },
    "ai-analysis.html": {
      "kind": "ai_analysis",
      "server": null,
      "title": "AI-отчет",
      "roles": [
        "security",
        "it",
        "technical"
      ],
      "focus_group": "shared",
      "navigation_priority": 1000
    },
    "ai-openai-analysis.html": {
      "kind": "ai_analysis",
      "server": null,
      "title": "AI-анализ OpenAI",
      "roles": [
        "security",
        "it",
        "technical"
      ],
      "focus_group": "shared",
      "navigation_priority": 1000
    }
  }
}
""")!.AsObject();
}
