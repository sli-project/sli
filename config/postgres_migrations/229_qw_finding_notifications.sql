-- N07: native QW episodes and atomic publication/outbox admission; no activation.
begin;
select pg_advisory_xact_lock(hashtext('sli_qw_finding_notifications_v229'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=228 and name='qw_semantic_input')
       or exists(select 1 from public.schema_migrations where version>=229) then
        raise exception 'migration 229 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.semantic_security_scenarios
    add column evidence_state text not null default 'ready' check(evidence_state in ('evidence_pending','ready'));

alter table public.semantic_scenario_steps
    add column qw_signal_id text references public.semantic_qw_signals(signal_id) on delete restrict,
    drop constraint semantic_scenario_steps_source_kind_check,
    drop constraint semantic_scenario_step_source,
    add constraint semantic_scenario_steps_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match','qw_signal')),
    add constraint semantic_scenario_step_source check (
        (source_kind='canonical_action' and canonical_action_id is not null
            and correlation_candidate_id is null and control_reference is null and detection_match_id is null and qw_signal_id is null)
        or (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and canonical_action_id is null and control_reference is null and detection_match_id is null and qw_signal_id is null)
        or (source_kind='control_health' and control_reference is not null
            and length(control_reference) between 1 and 160 and canonical_action_id is null
            and correlation_candidate_id is null and detection_match_id is null and qw_signal_id is null)
        or (source_kind='detection_match' and detection_match_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and control_reference is null and qw_signal_id is null)
        or (source_kind='qw_signal' and qw_signal_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and control_reference is null and detection_match_id is null)
    );
create index semantic_scenario_qw_members on public.semantic_scenario_steps(scenario_id,step_id)
    where source_kind='qw_signal';
alter table public.semantic_risk_contributions
    add column qw_signal_id text references public.semantic_qw_signals(signal_id) on delete restrict,
    drop constraint semantic_risk_contributions_source_kind_check,
    drop constraint semantic_risk_contribution_source,
    add constraint semantic_risk_contributions_source_kind_check
        check(source_kind in ('canonical_action','correlation_candidate','control_health','detection_match','qw_signal')),
    add constraint semantic_risk_contribution_source check (
        (source_kind='canonical_action' and canonical_action_id is not null
            and correlation_candidate_id is null and control_reference is null and detection_match_id is null and qw_signal_id is null)
        or (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and canonical_action_id is null and control_reference is null and detection_match_id is null and qw_signal_id is null)
        or (source_kind='control_health' and control_reference is not null
            and length(control_reference) between 1 and 160 and canonical_action_id is null
            and correlation_candidate_id is null and detection_match_id is null and qw_signal_id is null)
        or (source_kind='detection_match' and detection_match_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and control_reference is null and qw_signal_id is null)
        or (source_kind='qw_signal' and qw_signal_id is not null
            and canonical_action_id is null and correlation_candidate_id is null and control_reference is null and detection_match_id is null)
    );

alter table public.notification_outbox
    add column publication_scenario_id uuid references public.semantic_finding_publications(scenario_id) on delete restrict,
    drop constraint notification_outbox_object_kind_check,
    add constraint notification_outbox_object_kind_check check(object_kind in ('test_problem','semantic_finding')),
    add constraint notification_outbox_publication check (
        (object_kind='test_problem' and publication_scenario_id is null)
        or (object_kind='semantic_finding' and publication_scenario_id is not null and object_id=publication_scenario_id)
    );

-- Fixed SQL, no dynamic identifiers or payload. The semantic login gets EXECUTE
-- only, not the recipients table or unrestricted outbox INSERT/UPDATE privileges.
create function public.enqueue_qw_finding_notifications(p_scenario_id uuid) returns integer
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare added integer; required integer;
begin
    if not exists (
        select 1 from public.semantic_finding_publications publication
        join public.semantic_security_scenarios scenario on scenario.scenario_id=publication.scenario_id
        join public.semantic_risk_evaluation_results result on result.job_id=publication.first_job_id
        join public.semantic_risk_evaluation_jobs job on job.job_id=result.job_id
        join public.semantic_risk_policies policy using(policy_id,policy_version)
        join public.semantic_policy_admission admission using(policy_id,policy_version)
        where publication.scenario_id=p_scenario_id and result.scenario_id=p_scenario_id
          and scenario.evidence_state='ready'
          and result.evaluation_mode='enabled' and result.conclusion_state='observed'
          and job.source_kind='qw_signal' and admission.enabled is true
          and public.semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled'
    ) or not exists(select 1 from public.semantic_scenario_steps where scenario_id=p_scenario_id)
      or exists (
        select 1 from public.semantic_scenario_steps step
        left join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
        where step.scenario_id=p_scenario_id and (step.source_kind<>'qw_signal'
            or signal.evaluation_mode is distinct from 'enabled'
            or signal.document_json->>'conclusion_state' is distinct from 'observed'
            or public.qw_signal_evidence_allowed(signal.document_json,true) is not true)
    ) then
        raise exception 'qw_publication_unavailable';
    end if;
    perform pg_advisory_xact_lock(hashtext('notification_outbox_admission'));
    -- Lock approved bindings against revision/disable edits until publication
    -- commits. Recipient grants are re-resolved by the delivery worker.
    perform 1 from public.notification_subscriptions where enabled order by id for share;
    select count(*) into required from (
        select distinct recipient_user_id,channel from public.notification_subscriptions s
        where enabled and not exists (
            select 1 from public.notification_outbox j where j.object_kind='semantic_finding'
                and j.object_id=p_scenario_id and j.recipient_user_id=s.recipient_user_id and j.channel=s.channel)
    ) recipients;
    if required+(select count(*) from public.notification_outbox where state in ('pending','sending','retry'))>10000 then
        raise exception 'notification_queue_full';
    end if;
    insert into public.notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
                                         publication_scenario_id,recipient_user_id,channel)
    select gen_random_uuid(),s.id,s.revision,'semantic_finding',p_scenario_id,p_scenario_id,s.recipient_user_id,s.channel
    from (select distinct on(recipient_user_id,channel) * from public.notification_subscriptions
          where enabled order by recipient_user_id,channel,id) s
    on conflict(object_kind,object_id,recipient_user_id,channel) do nothing;
    get diagnostics added=row_count;
    return added;
end $$;
revoke all on function public.enqueue_qw_finding_notifications(uuid) from public,adlog_user,adlog_storage_worker;
grant execute on function public.enqueue_qw_finding_notifications(uuid) to adlog_semantic_worker;

-- Reference-only lookup, after the worker checks current owner/recipient grants.
create function public.notification_finding_object(p_scenario_id uuid) returns bigint
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select publication.finding_id from public.semantic_finding_publications publication
    join public.semantic_security_scenarios scenario using(scenario_id)
    where publication.scenario_id=p_scenario_id and scenario.evidence_state='ready'
$$;
revoke all on function public.notification_finding_object(uuid) from public;
grant execute on function public.notification_finding_object(uuid) to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(229,'qw_finding_notifications');
commit;
