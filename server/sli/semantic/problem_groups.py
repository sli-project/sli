"""Read-only exact cohorts for the existing home queue and its finding drilldown."""
from __future__ import annotations

import json
import re
from datetime import date
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

COHORT_MAX_LENGTH = 4096

def cohort_value(value: str) -> str:
    """A typed exact tuple, not a hash that could merge distinct source objects."""
    try:
        if not isinstance(value, str) or len(value) > COHORT_MAX_LENGTH:
            raise ValueError
        item = json.loads(value)
        if not isinstance(item, list):
            raise ValueError
        if len(item) == 2 and item[0] == "finding":
            valid = type(item[1]) is int and item[1] > 0
        elif len(item) == 6 and item[0] == "queue":
            valid = (all(isinstance(x, str) and 0 < len(x) <= 2048 for x in item[1:4])
                     and len(item[1]) <= 512 and isinstance(item[4], list)
                     and all(isinstance(x, str) and 0 < len(x) <= 2048 for x in item[4])
                     and isinstance(item[5], str)
                     and date.fromisoformat(item[5]).isoformat() == item[5])
        else:
            membership = len(item) == 7 and item[0] == "membership"
            valid = membership or len(item) == 6 and item[0] == "object"
            if not valid:
                raise ValueError
            valid = (isinstance(item[1], str) and 0 < len(item[1]) <= 512
                     and all(type(x) is int and x > 0 for x in item[2:4])
                     and isinstance(item[-1], str) and date.fromisoformat(item[-1]).isoformat() == item[-1])
            names = item[4:-1]
            valid = valid and all(isinstance(x, str) and 0 < len(x) <= 2048 for x in names)
            if membership:
                valid = valid and all(re.fullmatch(r"S-1-(?:\d+-)*\d+", x) for x in names)
        if not valid:
            raise ValueError
        return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
    except (ValueError, TypeError, IndexError) as exc:
        raise ValueError("problem_cohort_invalid") from exc



def cohort_page(where, params, after_id):
    """Exact ID keyset used by cohort drilldown; totals keep the unpaged where."""
    if type(after_id) is not int or after_id <= 0:
        raise ValueError("invalid_cursor")
    return where + " and findings.id < ?", [*params, after_id]

def cohort_zone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ValueError, TypeError, ZoneInfoNotFoundError) as exc:
        raise ValueError("problem_cohort_timezone_invalid") from exc
    return value


# Keep this identical for aggregation and drilldown. It is evaluated only after
# the caller establishes the published, domain-authorized queue population.
# A missing/native/multi-object/day witness never becomes a guessed cohort.
COHORT_JOIN = f"""
    cross join (select ?::text as time_zone) cohort_config
    left join lateral (
        select count(*) as retained_count,
               count(*) filter(where e.event_id in (4728,4732,4756)) as membership_count,
               bool_and(coalesce(channel.value='Security' and provider.value='Microsoft-Windows-Security-Auditing',false)) as membership_source,
               count(distinct (e.domain_id,e.server_id,
                   timezone(cohort_config.time_zone,e.time_created_utc)::date,
                   e.target_user_sid,f.membership_member_sid)) as membership_identities,
               count(distinct (e.domain_id,e.server_id,
                   timezone(cohort_config.time_zone,e.time_created_utc)::date)) as source_days,
               bool_and(e.domain_id is not null and e.server_id is not null
                   and e.time_created_utc is not null) as source_complete,
               bool_and(e.target_user_sid ~ '^S-1-([0-9]+-)*[0-9]+$'
                   and f.membership_member_sid ~ '^S-1-([0-9]+-)*[0-9]+$'
                   and e.target_user_sid is not null and f.membership_member_sid is not null) as identities_complete,
               min(e.domain_id) as domain_id,min(e.server_id) as server_id,
               min(timezone(cohort_config.time_zone,e.time_created_utc)::date)::text as day,
               min(e.target_user_sid) as group_sid,min(f.membership_member_sid) as member_sid,
               case when count(distinct e.domain_id)=1 then min(d.fqdn) end as domain_name
        from finding_evidence fe join events_v2_core e on e.id=fe.event_id
        left join event_facts_v2 f on f.event_id=e.id
        left join storage_v2_channel channel on channel.id=e.channel_id
        left join storage_v2_provider provider on provider.id=e.provider_id
        left join domains d on d.id=e.domain_id
        where fe.finding_id=findings.id
    ) witness on true
    cross join lateral (
        select case
            when witness.retained_count=findings.evidence_count and witness.retained_count>0
                and witness.source_complete and witness.identities_complete and witness.membership_source
                and witness.membership_count=witness.retained_count and witness.membership_identities=1
            then jsonb_build_array('membership',findings.rule_code,witness.domain_id,witness.server_id,
                witness.member_sid,witness.group_sid,witness.day)
            when witness.retained_count=findings.evidence_count and witness.retained_count>0
                and witness.source_complete and witness.membership_count=0 and witness.source_days=1
                and nullif(btrim(findings.target),'') is not null and length(findings.target)<=2048
            then jsonb_build_array('object',findings.rule_code,witness.domain_id,witness.server_id,
                findings.target,witness.day)
            else jsonb_build_array('finding',findings.id)
        end as key
    ) raw_cohort
    cross join lateral (
        select case when length(raw_cohort.key::text)<={COHORT_MAX_LENGTH} then raw_cohort.key
                    else jsonb_build_array('finding',findings.id) end as key
    ) cohort
"""


# Preserve exact retained cohorts, including findings with no published actor.
# Native refs and expired payloads can additionally group by published identities
# when there is no complete retained witness. Unknown identities stay independent.
QUEUE_COHORT_JOIN = f"""
    cross join lateral (
        select cohort.key,cohort_config.time_zone
        from (select 1) cohort_seed
        {COHORT_JOIN}
    ) retained_cohort
    cross join lateral (
        select case
            when retained_cohort.key->>0 <> 'finding' then retained_cohort.key
            when nullif(btrim(findings.actor),'') is not null and length(findings.actor)<=2048
                and nullif(btrim(findings.target),'') is not null and length(findings.target)<=2048
                and timezone(retained_cohort.time_zone,findings.first_seen_utc::timestamptz)::date
                    =timezone(retained_cohort.time_zone,findings.last_seen_utc::timestamptz)::date
            then jsonb_build_array('queue',findings.rule_code,findings.actor,findings.target,
                coalesce((select jsonb_agg(distinct entity.display_name order by entity.display_name)
                    from finding_entities entity where entity.finding_id=findings.id
                      and entity.entity_role='container_entity'
                      and nullif(btrim(entity.display_name),'') is not null),'[]'::jsonb),
                timezone(retained_cohort.time_zone,findings.last_seen_utc::timestamptz)::date::text)
            else jsonb_build_array('finding',findings.id)
        end as key
    ) raw_cohort
    cross join lateral (
        select case when length(raw_cohort.key::text)<={COHORT_MAX_LENGTH} then raw_cohort.key
                    else jsonb_build_array('finding',findings.id) end as key
    ) cohort
"""


def queue_cohorts_cte(population, where, effective_status, accepted, *, cohort_join=COHORT_JOIN):
    """Group before paging, with the retained-witness digest contract by default.

    The maximum member ID orders pages independently of the representative,
    which keeps the most urgent status/severity visible for mixed cohorts.
    """
    return f"""with queue_population as materialized (
        select findings.id,cohort.key as problem_cohort,findings.severity,
               ({effective_status}) as status,({accepted}) as risk_accepted,
               count(*) over(partition by cohort.key) as occurrence_count,
               max(findings.id) over(partition by cohort.key) as queue_cursor_id,
               row_number() over(partition by cohort.key order by
                   case ({effective_status}) when 'new' then 1 when 'repeated' then 2
                       when 'confirmed' then 3 when 'active' then 4 when 'review' then 5
                       when 'false_positive' then 6 when 'closed' then 7 else 8 end,
                   case findings.severity when 'critical' then 1 when 'high' then 2
                       when 'medium' then 3 when 'low' then 4 else 5 end,
                   findings.id desc) as representative_rank
        {population}{cohort_join}{where}
    ), queue_groups as (
        select * from queue_population where representative_rank=1
    ) """


def home_cohorts(query, population, where, params, new_since, time_zone):
    """Aggregate every authorized finding, then retain eight bounded samples."""
    return query(
        f"""
        with population as materialized (
            select findings.id,findings.rule_code,findings.title,findings.severity,
                   findings.created_at,findings.last_seen_utc::timestamptz as last_seen,
                   nullif(btrim(findings.assigned_to),'') as assigned_to,
                   cohort.key as cohort,
                   case when witness.retained_count=findings.evidence_count and witness.retained_count>0
                       and witness.source_complete then witness.domain_name end as domain_name,
                   case when cohort.key->>0='membership'
                       then jsonb_build_array(witness.member_sid,witness.group_sid)
                       else jsonb_build_array(coalesce(nullif(btrim(findings.target),''),
                           nullif(btrim(findings.actor),''))) end as object_names,
                   case when cohort.key->>0<>'finding' then witness.day end as day,
                   jsonb_build_object('id',findings.id,'actor',findings.actor,'target',findings.target,
                       'evidence_count',findings.evidence_count) as representative
            {population}{COHORT_JOIN}{where}
        ), grouped as (
            select cohort,min(rule_code) as rule_code,min(title) as title,min(day) as day,
                   min(case severity when 'critical' then 0 when 'high' then 1
                       when 'medium' then 2 when 'low' then 3 else 4 end) as importance,
                   count(*) as total,
                   case when ?::timestamptz is null then null
                       else count(*) filter(where created_at > ?::timestamptz) end as new_count,
                   max(last_seen) as last_seen_utc,
                   string_agg(distinct assigned_to, ', ' order by assigned_to) as assigned_to,
                   count(*) filter(where assigned_to is null) as unassigned_count
            from population group by cohort
        )
        select grouped.*,sum(total) over() as total_problems,sum(new_count) over() as total_new,
               count(*) over() as total_groups,sample.representative,sample.object_names,sample.domain_name
        from grouped cross join lateral (
            select p.representative,p.object_names,p.domain_name from population p
            where p.cohort=grouped.cohort order by p.id desc limit 1
        ) sample
        order by (coalesce(new_count,0)>0) desc,importance,last_seen_utc desc nulls last,cohort
        limit 8
        """, (cohort_zone(time_zone), *params, new_since, new_since),
    )
