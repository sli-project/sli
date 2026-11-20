-- Sigma stage 14: dormant, typed detection inputs for versioned risk policies.
begin;
select pg_advisory_xact_lock(hashtext('sli_detection_match_risk_v220'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=219 and name='finding_evidence_refs')
       or exists(select 1 from public.schema_migrations where version>=220) then
        raise exception 'migration 220 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.semantic_detection_matches (
    match_id text primary key check(match_id ~ '^[a-f0-9]{64}$'),
    rule_id text not null check(rule_id ~ '^[a-f0-9-]{36}$'),
    evaluation_mode text not null check(evaluation_mode in ('test','shadow','enabled')),
    occurred_at_utc timestamptz not null,
    evidence_key text not null check(evidence_key ~ '^[a-f0-9]{64}$'),
    document_json jsonb not null check(jsonb_typeof(document_json)='object'
        and octet_length(document_json::text)<=16384),
    created_at timestamptz not null default now(),
    check(document_json->>'rule_id' is not distinct from rule_id
        and document_json->>'evaluation_mode' is not distinct from evaluation_mode
        and document_json->>'conclusion_state' is not distinct from 'observed'
        and document_json->>'quality' is not distinct from 'good'
        and document_json->'suppressed' is not distinct from 'false'::jsonb)
);
create index idx_detection_match_risk_backlog
    on public.semantic_detection_matches(rule_id,evaluation_mode,occurred_at_utc,match_id);
create function public.reject_detection_match_mutation() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$ begin
    raise exception 'detection inputs are immutable';
end $$;
create trigger detection_match_immutable before update or delete on public.semantic_detection_matches
    for each row execute function public.reject_detection_match_mutation();
create trigger detection_match_no_truncate before truncate on public.semantic_detection_matches
    for each statement execute function public.reject_detection_match_mutation();
revoke all on function public.reject_detection_match_mutation() from public;
revoke all on public.semantic_detection_matches from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant select,insert on public.semantic_detection_matches to adlog_semantic_worker;
-- Existing non-detector aggregation may join this table; RLS returns no rows.
grant select on public.semantic_detection_matches to adlog_storage_worker;
alter table public.semantic_detection_matches enable row level security;
create policy detection_match_scope on public.semantic_detection_matches to adlog_semantic_worker
using (public.finding_evidence_scope_allowed(
    (document_json#>>'{evidence,scope,installation_id}')::uuid,
    document_json#>>'{evidence,scope,plugin_id}',document_json#>>'{evidence,scope,source_instance_id}',
    document_json#>>'{evidence,scope,source_generation}',document_json#>>'{evidence,scope,collection_scope_id}',
    document_json#>>'{evidence,storage_kind}'))
with check (public.resolve_finding_evidence_ref(
    (document_json#>>'{evidence,scope,installation_id}')::uuid,
    document_json#>>'{evidence,scope,plugin_id}',document_json#>>'{evidence,scope,source_instance_id}',
    document_json#>>'{evidence,scope,source_generation}',document_json#>>'{evidence,scope,collection_scope_id}',
    document_json#>>'{evidence,storage_kind}',document_json#>>'{evidence,native_id}',
    document_json#>>'{evidence,sha256}'));

alter table public.semantic_risk_policies
    drop constraint semantic_risk_policies_source_kind_check,
    add constraint semantic_risk_policies_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match'));
alter table public.semantic_risk_policy_subscriptions
    drop constraint semantic_risk_policy_subscriptions_source_kind_check,
    add constraint semantic_risk_policy_subscriptions_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match'));

alter table public.semantic_risk_evaluation_jobs
    add column detection_match_id text references public.semantic_detection_matches(match_id) on delete restrict,
    drop constraint semantic_risk_evaluation_jobs_source_kind_check,
    drop constraint semantic_risk_evaluation_source,
    add constraint semantic_risk_evaluation_jobs_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match')),
    add constraint semantic_risk_evaluation_source check (
        (source_kind='canonical_action' and canonical_action_id is not null
            and correlation_candidate_id is null and control_health_id is null and detection_match_id is null
            and source_reference=canonical_action_id::text)
        or (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and canonical_action_id is null and control_health_id is null and detection_match_id is null
            and source_reference=correlation_candidate_id::text)
        or (source_kind='control_health' and control_health_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and detection_match_id is null
            and source_reference=control_health_id::text)
        or (source_kind='detection_match' and detection_match_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and control_health_id is null
            and source_reference=detection_match_id)
    );

alter table public.semantic_scenario_steps
    add column detection_match_id text references public.semantic_detection_matches(match_id) on delete restrict,
    drop constraint semantic_scenario_steps_source_kind_check,
    drop constraint semantic_scenario_step_source,
    add constraint semantic_scenario_steps_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match')),
    add constraint semantic_scenario_step_source check (
        (source_kind='canonical_action' and canonical_action_id is not null
            and correlation_candidate_id is null and control_reference is null and detection_match_id is null)
        or (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and canonical_action_id is null and control_reference is null and detection_match_id is null)
        or (source_kind='control_health' and control_reference is not null
            and length(control_reference) between 1 and 160 and canonical_action_id is null
            and correlation_candidate_id is null and detection_match_id is null)
        or (source_kind='detection_match' and detection_match_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and control_reference is null)
    );
alter table public.semantic_risk_contributions
    add column detection_match_id text references public.semantic_detection_matches(match_id) on delete restrict,
    drop constraint semantic_risk_contributions_source_kind_check,
    drop constraint semantic_risk_contribution_source,
    add constraint semantic_risk_contributions_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match')),
    add constraint semantic_risk_contribution_source check (
        (source_kind='canonical_action' and canonical_action_id is not null
            and correlation_candidate_id is null and control_reference is null and detection_match_id is null)
        or (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and canonical_action_id is null and control_reference is null and detection_match_id is null)
        or (source_kind='control_health' and control_reference is not null
            and length(control_reference) between 1 and 160 and canonical_action_id is null
            and correlation_candidate_id is null and detection_match_id is null)
        or (source_kind='detection_match' and detection_match_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and control_reference is null)
    );

insert into public.schema_migrations(version,name) values(220,'detection_match_risk');
commit;
