-- N06: dormant QW semantic ingress; publication and notification bridge is N07.
begin;
select pg_advisory_xact_lock(hashtext('sli_qw_semantic_input_v228'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=227 and name='notification_telegram')
       or exists(select 1 from public.schema_migrations where version>=228) then
        raise exception 'migration 228 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.semantic_qw_signals (
    signal_id text primary key check(signal_id ~ '^[a-f0-9]{64}$'),
    evaluation_mode text not null check(evaluation_mode in ('test','shadow','enabled')),
    document_json jsonb not null check(jsonb_typeof(document_json)='object'
        and octet_length(document_json::text)<=524288
        and document_json->>'evaluation_mode' is not distinct from evaluation_mode
        and jsonb_typeof(document_json->'evidence_refs') is not distinct from 'array'
        and jsonb_array_length(document_json->'evidence_refs') between 1 and 256),
    created_at timestamptz not null default now()
);
create index idx_qw_signal_backlog on public.semantic_qw_signals(evaluation_mode,created_at,signal_id);
create function public.reject_qw_signal_mutation() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$ begin
    raise exception 'qw inputs are immutable';
end $$;
create trigger qw_signal_immutable before update or delete on public.semantic_qw_signals
    for each row execute function public.reject_qw_signal_mutation();
create trigger qw_signal_no_truncate before truncate on public.semantic_qw_signals
    for each statement execute function public.reject_qw_signal_mutation();
revoke all on function public.reject_qw_signal_mutation() from public;

-- SECURITY INVOKER: every reference is checked against the session login's
-- administrator-bound native sources, never the migration owner's authority.
create function public.qw_signal_evidence_allowed(document jsonb, verify boolean) returns boolean
language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce(bool_and(coalesce(case when verify then
        public.resolve_finding_evidence_ref(
            (ref#>>'{scope,installation_id}')::uuid,ref#>>'{scope,plugin_id}',
            ref#>>'{scope,source_instance_id}',ref#>>'{scope,source_generation}',
            ref#>>'{scope,collection_scope_id}',ref->>'storage_kind',ref->>'native_id',ref->>'sha256')
        else public.finding_evidence_scope_allowed(
            (ref#>>'{scope,installation_id}')::uuid,ref#>>'{scope,plugin_id}',
            ref#>>'{scope,source_instance_id}',ref#>>'{scope,source_generation}',
            ref#>>'{scope,collection_scope_id}',ref->>'storage_kind') end,false)),false)
    from jsonb_array_elements(document->'evidence_refs') ref
$$;
revoke all on function public.qw_signal_evidence_allowed(jsonb,boolean) from public;
grant execute on function public.qw_signal_evidence_allowed(jsonb,boolean) to adlog_semantic_worker;
revoke all on public.semantic_qw_signals from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant select,insert on public.semantic_qw_signals to adlog_semantic_worker;
-- The shared backlog also runs as the non-QW worker; RLS returns no QW rows.
grant select on public.semantic_qw_signals to adlog_storage_worker;
alter table public.semantic_qw_signals enable row level security;
create policy qw_signal_scope on public.semantic_qw_signals to adlog_semantic_worker
    using (public.qw_signal_evidence_allowed(document_json,false))
    with check (public.qw_signal_evidence_allowed(document_json,true));

alter table public.semantic_risk_policies
    drop constraint semantic_risk_policies_source_kind_check,
    add constraint semantic_risk_policies_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match','qw_signal'));
alter table public.semantic_risk_policy_subscriptions
    drop constraint semantic_risk_policy_subscriptions_source_kind_check,
    add constraint semantic_risk_policy_subscriptions_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match','qw_signal'));
alter table public.semantic_risk_evaluation_jobs
    add column qw_signal_id text references public.semantic_qw_signals(signal_id) on delete restrict,
    drop constraint semantic_risk_evaluation_jobs_source_kind_check,
    drop constraint semantic_risk_evaluation_source,
    add constraint semantic_risk_evaluation_jobs_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match','qw_signal')),
    add constraint semantic_risk_evaluation_source check (
        (source_kind='canonical_action' and canonical_action_id is not null
            and correlation_candidate_id is null and control_health_id is null and detection_match_id is null
            and qw_signal_id is null and source_reference=canonical_action_id::text)
        or (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and canonical_action_id is null and control_health_id is null and detection_match_id is null
            and qw_signal_id is null and source_reference=correlation_candidate_id::text)
        or (source_kind='control_health' and control_health_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and detection_match_id is null
            and qw_signal_id is null and source_reference=control_health_id::text)
        or (source_kind='detection_match' and detection_match_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and control_health_id is null
            and qw_signal_id is null and source_reference=detection_match_id)
        or (source_kind='qw_signal' and qw_signal_id is not null
            and canonical_action_id is null and correlation_candidate_id is null
            and control_health_id is null and detection_match_id is null and source_reference=qw_signal_id)
    );

insert into public.schema_migrations(version,name) values(228,'qw_semantic_input');
commit;
