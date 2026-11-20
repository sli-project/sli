"""Fixed SQL generation for the unapplied scheduled report proposal."""

import re

from server.sli.semantic.problem_population import problem_population_filters, PROBLEM_POPULATION
from server.sli.semantic.problem_groups import queue_cohorts_cte


def security_aggregate_sql():
    """Generate fixed SQL, not an arbitrary SQL facility in the running service."""
    effective, accepted, clauses, params = problem_population_filters()
    assert not params
    clauses.extend([
        "((p_filters->>'severity') is null or findings.severity=p_filters->>'severity')",
        f"((p_filters->>'status') is null or ({effective})=p_filters->>'status')",
        f"(coalesce(p_filters->>'population','open')<>'attention' or ({effective}) in ('new','confirmed','repeated'))",
        f"(coalesce(p_filters->>'population','open')<>'open' or p_filters->>'status' is not null or ({effective}) in ('new','confirmed','repeated','active','review'))",
        "findings.last_seen_utc::timestamptz >= p_start",
        "findings.last_seen_utc::timestamptz < p_end",
    ])
    where = " where " + " and ".join(clauses)
    # Keep migration 285's retained-witness contract. The interactive queue also
    # supports published-identity repetitions without changing digest aggregates.
    population = PROBLEM_POPULATION.replace("s.*,u.username as responsible_username", "s.*")
    query = queue_cohorts_cte(population, where, effective, accepted).replace("?::text", "p_zone::text")
    query += f""", individual_counts as (
        select count(*) as total {population}{where}
    ), cohort_counts as (select count(*) as total from queue_groups)
    select jsonb_build_object('counts',jsonb_build_object(
        'individual',(select jsonb_build_object('total',total,'has_more',total>50) from individual_counts),
        'cohorts',(select jsonb_build_object('total',total,'has_more',total>50) from cohort_counts))) into v_result;
    """
    names = ("findings_active", "semantic_suppressions", "auth_users", "finding_evidence", "events_v2_core",
             "event_facts_v2", "storage_v2_channel", "storage_v2_provider", "domains",
             "is_semantic_finding_published_v1", "semantic_finding_suppressed_v160", "semantic_finding_in_domains_v265")
    query = re.sub(r"(?<![\w.])(" + "|".join(names) + r")\b", r"public.\1", query)
    assert "?" not in query
    return SECURITY_TEMPLATE.replace("@QUERY@", query)


SECURITY_TEMPLATE = """
-- Generated from the same population and exact queue-cohort builders.
create function public.report_security_candidate_counts(p_filters jsonb,p_zone text,p_start timestamptz,p_end timestamptz)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare v_result jsonb; v_heartbeat jsonb; v_refresh boolean := false; v_coverage boolean := false;
    v_domains bigint[]; v_page jsonb; v_generated timestamptz;
begin
    if p_filters is null or jsonb_typeof(p_filters)<>'object'
       or exists(select 1 from jsonb_object_keys(p_filters) k where k not in ('severity','status','population'))
       or exists(select 1 from jsonb_each(p_filters) e where jsonb_typeof(e.value)<>'string')
       or (p_filters ? 'severity' and p_filters->>'severity' not in ('critical','high','medium','low'))
       or (p_filters ? 'status' and p_filters->>'status' not in ('new','repeated','confirmed','active','review','false_positive','closed'))
       or (p_filters ? 'population' and p_filters->>'population' not in ('open','attention','all'))
       or p_start is null or p_end is null or p_end<=p_start or p_end-p_start>interval '32 days' then
        raise exception 'report_candidate_parameters_invalid';
    end if;
    @QUERY@
    v_generated:=clock_timestamp();
    select jsonb_build_object('status',case when status in ('running','idle') then status else 'other' end,
        'heartbeat_at',heartbeat_at,'expected_interval_seconds',expected_interval_seconds,
        'details_json',jsonb_build_object('runtime_mode',case when btrim(details_json->>'runtime_mode')
            in ('facts-v1','investigation-v1','findings-v1') then btrim(details_json->>'runtime_mode') end,
            'manual_runtime',case when details_json->'manual_runtime'='false'::jsonb then false else true end))
    into v_heartbeat from public.runtime_worker_heartbeats where worker_name='semantic' limit 1;
    begin
        select coalesce(last_status='failed',false) into v_refresh from public.findings_refresh_state
            where pipeline_name='events_to_findings_v1';
        perform max(id) from public.events_v2_core;
    exception when others then v_refresh:=true;
    end;
    begin
        select coalesce(array_agg(id order by id),'{}'::bigint[]) into v_domains from public.domains;
        if cardinality(v_domains)>0 then
            v_page:=public.read_password_detection_coverage(v_domains);
            v_coverage:=jsonb_typeof(v_page) is distinct from 'object'
                or jsonb_typeof(v_page->'rows') is distinct from 'array'
                or jsonb_typeof(v_page->'has_more') is distinct from 'boolean'
                or (v_page->>'has_more')::boolean or jsonb_array_length(v_page->'rows')=0
                or exists(select 1 from jsonb_array_elements(v_page->'rows') r
                    where r->>'policy_state' in ('unknown','disabled_last_known')
                       or r->>'frozen_episode_count'<>'0'
                       or r->>'policy_state'='enabled' and r->>'status'<>'healthy');
        end if;
    exception when others then v_coverage:=true;
    end;
    return v_result || jsonb_build_object('quality_inputs',jsonb_build_object(
        'heartbeat',coalesce(v_heartbeat,'{}'::jsonb),'refresh_limited',coalesce(v_refresh,false),
        'coverage_incomplete',coalesce(v_coverage,false)), 'generated_at',v_generated);
end $$;
alter function public.report_security_candidate_counts(jsonb,text,timestamptz,timestamptz) owner to adlog_storage_owner;
revoke all on function public.report_security_candidate_counts(jsonb,text,timestamptz,timestamptz) from public,adlog_report_producer;
grant execute on function public.report_security_candidate_counts(jsonb,text,timestamptz,timestamptz) to adlog_report_producer_owner;
"""
