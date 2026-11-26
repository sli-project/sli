begin;
select pg_advisory_xact_lock(hashtext('sli_problem_notification_transitions423'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=420 and name='password_rule_identity')
       or exists(select 1 from public.schema_migrations where version>=423) then
        raise exception 'problem_notification_transitions423_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;

alter table public.notification_outbox drop constraint notification_outbox_change_key_check;
alter table public.notification_outbox add constraint notification_outbox_change_key_check check(
    change_key ~ '^(initial|low|medium|high|critical)(:(historical_replay|history_import))?$'
    or (object_kind='semantic_finding' and change_key ~ '^(problem:[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}|reopen:[1-9][0-9]*)$'));

-- Each enabled binding receives one alert per committed problem transition.
-- Legacy producers retain their existing severity gate.
create or replace function public.notification_telegram_severity_gate() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$
begin
    if new.channel='telegram' and new.object_kind='semantic_finding'
       and (current_user<>'adlog_storage_owner' or (new.change_key not like 'problem:%' and new.change_key not like 'reopen:%'))
       and new.object_severity is distinct from 'high' and new.object_severity is distinct from 'critical' then
        return null;
    end if;
    return new;
end $$;

create function public.insert_problem_notification423(p_scenario uuid,p_key text,p_severity text,p_reason text,p_at timestamptz)
returns integer language plpgsql set search_path=pg_catalog,pg_temp as $$
declare added integer; required integer; minutes integer:=0; reason text:=p_reason; at_now timestamptz:=clock_timestamp();
begin
    if reason='historical_replay' and p_at>=at_now-interval '24 hours' then
        return 0;
    elsif reason='live' and p_at<at_now-interval '24 hours' then
        reason:='historical_replay';
    elsif reason='live' and p_at<at_now-interval '15 minutes' then
        reason:='pipeline_delay';
        minutes:=least(2147483647,floor(extract(epoch from (at_now-p_at))/60))::integer;
    end if;

    perform pg_advisory_xact_lock(hashtext('notification_outbox_admission'));
    perform 1 from public.notification_subscriptions where enabled order by id for share;
    if reason in ('live','pipeline_delay') then
        select count(distinct (s.recipient_user_id,s.channel)) into required
        from public.notification_subscriptions s where enabled and not exists (
            select 1 from public.notification_outbox j where j.object_kind='semantic_finding'
                and j.object_id=p_scenario and j.recipient_user_id=s.recipient_user_id
                and j.channel=s.channel and j.change_key=p_key);
        if required+(select count(*) from public.notification_outbox where state in ('pending','sending','retry'))>10000 then
            raise exception 'notification_queue_full';
        end if;
    end if;

    insert into public.notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
        publication_scenario_id,recipient_user_id,channel,change_key,object_severity,delivery_reason,delay_minutes,state,result_code)
    select gen_random_uuid(),s.id,s.revision,'semantic_finding',p_scenario,p_scenario,s.recipient_user_id,s.channel,
        p_key,p_severity,reason,minutes,case when reason in ('live','pipeline_delay') then 'pending' else 'cancelled' end,
        case when reason not in ('live','pipeline_delay') then reason end
    from (select distinct on(recipient_user_id,channel) * from public.notification_subscriptions
          where enabled order by recipient_user_id,channel,id) s
    on conflict(object_kind,object_id,recipient_user_id,channel,change_key) do nothing;
    get diagnostics added=row_count;
    return added;
end $$;
revoke all on function public.insert_problem_notification423(uuid,text,text,text,timestamptz) from public;

create function public.enqueue_problem_notification423(p_scenario uuid,p_job uuid) returns integer
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare current_job record; event_at timestamptz; latest_event timestamptz; reason text; finding bigint; severity text;
begin
    select f.id,f.severity into finding,severity
    from public.semantic_finding_publications p
    join public.findings f on f.id=p.finding_id
    join public.semantic_security_scenarios scenario on scenario.scenario_id=p.scenario_id
    join public.semantic_risk_evaluation_results first_result on first_result.job_id=p.first_job_id
        and first_result.scenario_id=p.scenario_id
    where p.scenario_id=p_scenario and scenario.evidence_state='ready'
        and first_result.evaluation_mode='enabled' and first_result.conclusion_state='observed';
    if not found then raise exception 'problem_notification_publication_unavailable'; end if;

    select job.source_kind,job.qw_signal_id,policy.definition_json into current_job
    from public.semantic_risk_evaluation_results result
    join public.semantic_risk_evaluation_jobs job on job.job_id=result.job_id
    join public.semantic_risk_policies policy using(policy_id,policy_version)
    join public.semantic_policy_admission admission using(policy_id,policy_version)
    where result.job_id=p_job and result.scenario_id=p_scenario
      and result.evaluation_mode='enabled' and result.conclusion_state='observed' and admission.enabled
      and public.semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled';
    if not found then raise exception 'problem_notification_publication_unavailable'; end if;

    if current_job.source_kind='qw_signal' then
        -- Keep native proof admission for every contributing step. Provenance
        -- and age belong to the contribution that caused this transition.
        if not exists (
            select 1 from public.semantic_finding_publications p
            join public.semantic_risk_evaluation_jobs job on job.job_id=p.first_job_id
            join public.semantic_risk_policies policy using(policy_id,policy_version)
            join public.semantic_policy_admission admission using(policy_id,policy_version)
            where p.scenario_id=p_scenario and job.source_kind='qw_signal' and admission.enabled
                and public.semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled'
        ) or exists (
            select 1 from public.semantic_scenario_steps step
            left join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
            where step.scenario_id=p_scenario and (step.source_kind<>'qw_signal'
                or signal.evaluation_mode is distinct from 'enabled'
                or signal.document_json->>'conclusion_state' is distinct from 'observed'
                or public.qw_signal_evidence_allowed(signal.document_json,true) is not true)
        ) then raise exception 'qw_publication_unavailable'; end if;

        select (signal.document_json->>'occurred_at_utc')::timestamptz,
               case when signal.document_json->>'rule_id' in ('qw.password-brute-force','qw.password-spray')
                    and public.password_is_catchup388(current_job.definition_json#>'{source_selector,execution}')
                    then 'historical_replay' else coalesce(signal.document_json->>'processing_mode','live') end
        into event_at,reason
        from public.semantic_scenario_steps step
        join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
        where step.scenario_id=p_scenario and step.qw_signal_id=current_job.qw_signal_id;
        if not found or event_at is null then raise exception 'qw_publication_unavailable'; end if;
    else
        if not public.dc_catalog_finding401(finding,p_scenario)
           or public.copy_dc_catalog_evidence401(finding,p_scenario) is null then
            raise exception 'dc_task_service401_publication_unavailable';
        end if;
        select max(c.time_created_utc) filter(where origin.module_id='sli.windows.ad-dc'
                    and exists(select 1 from public.semantic_processing_outbox normal
                        where normal.source_event_id=c.event_id and normal.job_kind='normalize_event' and normal.status='completed'
                        and normal.processor_version=n.normalizer_version)),
               max(c.time_created_utc),case when bool_and(origin.module_id is not distinct from 'sli.windows.ad-dc-history')
                    then 'history_import' else 'historical_replay' end
        into event_at,latest_event,reason
        from public.semantic_scenario_evidence e join public.normalized_events n using(normalized_event_id)
        join public.finding_event_copies337 c on c.finding_id=finding and c.event_id=n.source_event_id
            and c.time_created_utc=n.occurred_at_utc and c.source_sha256=n.source_event_sha256 and c.evidence_role='semantic_scenario'
        left join public.dc_catalog_event_origins401 origin on origin.event_id=c.event_id and origin.source_sha256=c.source_sha256
        where e.scenario_id=p_scenario;
        if event_at is not null then reason:='live';
        else event_at:=latest_event; end if;
    end if;

    return public.insert_problem_notification423(p_scenario,'problem:'||p_job,severity,reason,event_at);
end $$;
revoke all on function public.enqueue_problem_notification423(uuid,uuid) from public;
grant execute on function public.enqueue_problem_notification423(uuid,uuid) to adlog_semantic_worker;

-- A manual reopen may reuse a publication that has already delivered. The
-- audit record gives that action a durable identity in the same transaction.
create function public.notify_manual_problem_reopen423() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare scenario uuid; severity text;
begin
    select p.scenario_id,f.severity into scenario,severity
    from public.semantic_finding_publications p
    join public.findings f on f.id=p.finding_id
    join public.semantic_security_scenarios s on s.scenario_id=p.scenario_id
    join public.semantic_risk_evaluation_jobs job on job.job_id=p.first_job_id
    join public.semantic_risk_evaluation_results result on result.job_id=job.job_id and result.scenario_id=p.scenario_id
    where f.id=new.finding_id and f.status not in ('closed','false_positive') and s.evidence_state='ready'
      and result.evaluation_mode='enabled' and result.conclusion_state='observed'
      and (job.source_kind='qw_signal' or public.dc_catalog_finding401(f.id,p.scenario_id))
      and f.rule_code not in ('semantic.qw.nps-denials','semantic.qw.file-decoy','semantic.qw.file-acl-broad-write')
    order by p.created_at desc,p.scenario_id limit 1;
    if found then
        perform public.insert_problem_notification423(scenario,'reopen:'||new.id,severity,'live',null);
    end if;
    return new;
end $$;
revoke all on function public.notify_manual_problem_reopen423() from public;

-- The canonical legacy status history table belongs to adlog_user.
reset role;
create trigger notify_manual_problem_reopen423 after insert on public.finding_status_history for each row
when (new.old_status in ('closed','false_positive') and new.new_status not in ('closed','false_positive')
      and new.changed_by is distinct from 'semantic-worker')
execute function public.notify_manual_problem_reopen423();

insert into public.schema_migrations(version,name) values(423,'problem_notification_transitions');
commit;
