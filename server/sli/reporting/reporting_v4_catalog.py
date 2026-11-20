"""Static report-key, dataset and runtime-filter contracts for reporting_v4."""
from __future__ import annotations

from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.events.event_search import (
    ACCOUNT_MANAGEMENT_EVENT_IDS,
    AUTHENTICATION_EVENT_IDS,
    SERVICE_TASK_EVENT_IDS,
)

REPORT_LIMIT_MAX = 200
REPORT_GRANT_BRANCH_MAX = 32
FOCUS_REQUIRED_METRIC_MAX = 4
FOCUS_METRIC_MAX = 24
REPORT_DATA_TIMEOUT_MS = 50_000
UNSAFE_DEFINITION_KEYS = frozenset({"sql", "raw_sql", "query", "expression", "where", "having", "join"})
EXECUTABLE_DATASETS = frozenset({
    "entities.v2", "ad.audit.snapshot", "events.v2", "security.problems",
    "ad.accounts.privileged", "ad.accounts.vpn", "ad.gpo.governance",
})

GPO_APPLICATION_STATE_SQL = (
    "coalesce(nullif(version.attributes_json->'attributes'->>"
    "'application_state',''),nullif(version.attributes_json->'attributes'->>"
    "'status',''))"
)
GPO_LINK_COUNT_SQL = (
    "case when coalesce(version.attributes_json->'attributes'->>"
    "'link_count','') ~ '^[0-9]+$' then "
    "(version.attributes_json->'attributes'->>'link_count')::integer end"
)
GPO_EXECUTABLE_COUNT_SQL = " + ".join(
    "case when coalesce(version.attributes_json->'attributes'->>"
    f"'{field}','') ~ '^[0-9]+$' then "
    f"(version.attributes_json->'attributes'->>'{field}')::integer else 0 end"
    for field in (
        "gpo_startup_script_count",
        "gpo_logon_script_count",
        "gpo_scheduled_task_count",
        "gpo_service_count",
    )
)
GPO_SETTINGS_SQL = (
    "case when jsonb_typeof(version.attributes_json->'attributes'->'gpo_settings')='array' "
    "then version.attributes_json->'attributes'->'gpo_settings' else '[]'::jsonb end"
)

GPO_GOVERNANCE_FIELDS = frozenset({
    "object_id", "display_name", "natural_key", "application_state",
    "computer_enabled", "user_enabled", "link_count", "link_enabled_count",
    "link_enforced_count", "links", "wmi_filter_present", "wmi_filter_id",
    "permission_count", "permission_custom_count", "security_filtering_sids",
    "security_filtering_deny_sids", "startup_script_count",
    "logon_script_count", "scheduled_task_count", "service_count",
    "local_group_count", "settings", "modified_utc", "observed_at",
})
DATASET_FIELDS: dict[str, frozenset[str]] = {
    "ad.gpo.governance": GPO_GOVERNANCE_FIELDS,
}
GPO_GOVERNANCE_SELECT_SQL = f"""entity.id::text as object_id,
                       entity.display_name,entity.natural_key,
                       {GPO_APPLICATION_STATE_SQL} as application_state,
                       case when lower(coalesce(version.attributes_json->'attributes'->>'gpo_computer_enabled','')) in ('true','false') then (version.attributes_json->'attributes'->>'gpo_computer_enabled')::boolean end as computer_enabled,
                       case when lower(coalesce(version.attributes_json->'attributes'->>'gpo_user_enabled','')) in ('true','false') then (version.attributes_json->'attributes'->>'gpo_user_enabled')::boolean end as user_enabled,
                       {GPO_LINK_COUNT_SQL} as link_count,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_link_enabled_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_link_enabled_count')::integer end as link_enabled_count,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_link_enforced_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_link_enforced_count')::integer end as link_enforced_count,
                       coalesce(version.attributes_json->'attributes'->'links','[]'::jsonb) as links,
                       case when lower(coalesce(version.attributes_json->'attributes'->>'gpo_wmi_filter_present','')) in ('true','false') then (version.attributes_json->'attributes'->>'gpo_wmi_filter_present')::boolean end as wmi_filter_present,
                       nullif(version.attributes_json->'attributes'->>'gpo_wmi_filter_id','') as wmi_filter_id,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_permission_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_permission_count')::integer end as permission_count,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_permission_custom_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_permission_custom_count')::integer end as permission_custom_count,
                       coalesce(version.attributes_json->'attributes'->'gpo_security_filtering_sids','[]'::jsonb) as security_filtering_sids,
                       coalesce(version.attributes_json->'attributes'->'gpo_security_filtering_deny_sids','[]'::jsonb) as security_filtering_deny_sids,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_startup_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_startup_script_count')::integer end as startup_script_count,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_logon_script_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_logon_script_count')::integer end as logon_script_count,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_scheduled_task_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_scheduled_task_count')::integer end as scheduled_task_count,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_service_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_service_count')::integer end as service_count,
                       case when coalesce(version.attributes_json->'attributes'->>'gpo_local_group_count','') ~ '^[0-9]+$' then (version.attributes_json->'attributes'->>'gpo_local_group_count')::integer end as local_group_count,
                       {GPO_SETTINGS_SQL} as settings,
                       case when coalesce(version.attributes_json->'attributes'->>'modified_utc','') ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T' then (version.attributes_json->'attributes'->>'modified_utc')::timestamptz end as modified_utc,
                       greatest(version.last_observed_at_utc,entity.last_seen_utc) as observed_at"""

# SQL fragments are server-owned. Report definitions may only select a key and
# operator from these maps; definition values are always passed as parameters.
RUNTIME_FILTER_FIELDS: dict[str, dict[str, str]] = {
    "entities.v2": {
        "entity_type": "entity_type.value", "display_name": "entity.display_name",
    },
    "ad.audit.snapshot": {"entity_type": "entity_type.value"},
    "events.v2": {
        "event_id": "event.event_id", "channel": "channel.value",
        "time_created_utc": "event.time_created_utc",
    },
    "security.problems": {"severity": "findings.severity", "status": "findings.status"},
    "ad.accounts.privileged": {"privilege": "target_entity.display_name"},
    "ad.accounts.vpn": {
        "enabled": "(account.attributes_json->'attributes'->>'enabled')::boolean",
        "activity_state": "ad_user_activity_policy",
        "privileged_overlap": "exists(select 1 from ad_context_relation_versions filter_privileged where filter_privileged.source_entity_id=source_entity.id and filter_privileged.valid_to_utc is null and filter_privileged.relation_kind='member_of' and filter_privileged.source_section='privileged_membership')",
        "department": "account.attributes_json->'attributes'->>'department'",
    },
    "ad.gpo.governance": {
        "application_state": GPO_APPLICATION_STATE_SQL,
        "link_count": GPO_LINK_COUNT_SQL,
    },
}

RUNTIME_SORT_FIELDS: dict[str, dict[str, str]] = {
    "entities.v2": {"id": "entity.id", "entity_type": "entity_type.value", "display_name": "entity.display_name", "natural_key": "entity.natural_key", "last_seen_utc": "entity.last_seen_utc", "context_source": "context_source"},
    "ad.audit.snapshot": {
        "object_id": "entity.id", "display_name": "entity.display_name",
        "entity_type": "entity_type.value", "last_seen_utc": "entity.last_seen_utc",
        "context_source": "context_source", "enabled": "enabled",
        "is_inactive": "is_inactive", "password_never_expires": "password_never_expires",
        "locked_out": "locked_out",
    },
    "events.v2": {"id": "event.id", "time_created_utc": "event.time_created_utc", "event_id": "event.event_id", "channel": "channel.value", "subject_user_name": "event.subject_user_name", "target_user_name": "event.target_user_name"},
    "security.problems": {"title": "findings.title", "severity": "findings.severity", "status": "findings.status", "evidence_event_id": "findings.last_evidence_event_id"},
    "ad.accounts.privileged": {"object_id": "source_entity.id", "display_name": "source_entity.display_name", "natural_key": "source_entity.natural_key", "privilege_path": "privilege_path", "last_seen_utc": "last_seen_utc", "enabled": "enabled", "is_inactive": "is_inactive", "password_never_expires": "password_never_expires", "locked_out": "locked_out", "last_logon_utc": "last_logon_utc"},
    "ad.accounts.vpn": {"object_id": "source_entity.id", "display_name": "source_entity.display_name", "natural_key": "source_entity.natural_key", "enabled": "enabled", "last_logon_utc": "last_logon_utc", "activity_state": "activity_state", "password_never_expires": "password_never_expires", "admin_count": "admin_count", "department": "department", "title": "title", "email": "email", "privileged_overlap": "privileged_overlap", "observed_at": "observed_at"},
    "ad.gpo.governance": {
        "object_id": "entity.id", "display_name": "entity.display_name", "natural_key": "entity.natural_key",
        "observed_at": "observed_at", "modified_utc": "modified_utc",
        "application_state": "application_state", "link_count": "link_count",
        "link_enabled_count": "link_enabled_count", "link_enforced_count": "link_enforced_count",
        "permission_count": "permission_count", "scheduled_task_count": "scheduled_task_count",
        "service_count": "service_count", "scope": "scope", "purpose": "purpose",
        "review_reason": "review_reason", "settings": "settings", "signals": "signals",
        "next_steps": "next_steps",
    },
}

DEFAULT_ORDERS = {
    "entities.v2": "entity.last_seen_utc desc nulls last,entity.id desc",
    "ad.audit.snapshot": "entity.last_seen_utc desc nulls last,entity.id desc",
    "events.v2": "event.time_created_utc desc,event.id desc",
    "security.problems": "findings.id desc",
    "ad.accounts.privileged": "relation.last_observed_at_utc desc,relation.id desc",
    "ad.accounts.vpn": "privileged_overlap desc,enabled asc,last_logon_utc asc nulls first,source_entity.display_name",
    "ad.gpo.governance": "observed_at desc nulls last,entity.id desc",
}

VPN_ACCOUNT_ATTRIBUTES_LATERAL = """left join lateral (
                    select current.attributes_json,current.last_observed_at_utc
                    from ad_context_entity_versions current
                    where current.entity_id=source_entity.id
                      and current.source_section in ('directory_accounts','vpn_membership')
                      and current.valid_to_utc is null
                    order by case current.source_section
                                 when 'directory_accounts' then 0 else 1
                             end,
                             current.last_observed_at_utc desc,current.id desc
                    limit 1
                ) account on true"""


def _active_entity_predicate(*aliases: str) -> str:
    """Keep bounded entity joins merge-aware without scanning the active view."""
    return " and ".join(f"entity_v2_is_active({alias}.id)" for alias in aliases)


INTEGER_FILTER_FIELDS = frozenset({
    ("events.v2", "event_id"),
    ("ad.gpo.governance", "link_count"),
})
BOOLEAN_FILTER_FIELDS = frozenset({
    ("ad.accounts.vpn", "enabled"), ("ad.accounts.vpn", "privileged_overlap"),
})
EVENT_VIEW_EVENT_IDS = {
    "attention": sorted({
        int(item.get("event_id") or 0)
        for item in all_event_catalog_entries()
        if int(item.get("event_id") or 0) > 0 and (
            str(item.get("purpose_tier") or "").lower() == "critical"
            or str(item.get("base_risk") or item.get("severity") or "").lower()
            in {"critical", "high"}
        )
    }),
    "authentication": sorted(AUTHENTICATION_EVENT_IDS),
    "accounts": sorted(ACCOUNT_MANAGEMENT_EVENT_IDS),
    "tasks": sorted(SERVICE_TASK_EVENT_IDS),
}


def runtime_filter_expression(dataset_key: str, field: str) -> str | None:
    expression = RUNTIME_FILTER_FIELDS.get(dataset_key, {}).get(field)
    if expression != "ad_user_activity_policy":
        return expression
    from server.sli.reports.ad_hygiene_policy import inactivity_sql

    inactive = inactivity_sql("account.attributes_json->'attributes'", "account.last_observed_at_utc")
    return ("case when account.attributes_json->'attributes'->>'enabled' is null then 'unknown' "
            "when (account.attributes_json->'attributes'->>'enabled')::boolean is false then 'disabled' "
            f"when {inactive} is null then 'unknown' when {inactive} then 'inactive' else 'active' end")
