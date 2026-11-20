-- Decoy event-time label links and provenance-aware delivery; no activation.
begin;
select pg_advisory_xact_lock(hashtext('sli_decoy_delivery_context_v247'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=245 and name='file_decoy')
       or exists(select 1 from public.schema_migrations where version>=247) then
        raise exception 'migration 247 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.notification_outbox
    add column delivery_reason text not null default 'live'
        check(delivery_reason in ('live','pipeline_delay','historical_replay','history_import')),
    add column delay_minutes integer not null default 0 check(delay_minutes>=0);
alter table public.notification_outbox drop constraint notification_outbox_change_key_check;
alter table public.notification_outbox add constraint notification_outbox_change_key_check
    check(change_key in ('initial','medium','high','initial:historical_replay','initial:history_import'));
alter table public.notification_outbox drop constraint notification_outbox_result_code_check;
alter table public.notification_outbox add constraint notification_outbox_result_code_check
    check(result_code in ('simulated','subscription_changed','recipient_denied','access_unavailable',
        'transport_unavailable','accepted','smtp_not_configured','smtp_auth_failed','smtp_rejected',
        'smtp_unavailable','smtp_outcome_unknown','telegram_not_configured','telegram_auth_failed',
        'telegram_chat_denied','telegram_rejected','telegram_rate_limited','telegram_unavailable',
        'telegram_outcome_unknown','historical_replay','history_import'));

-- Reference-only bridge. Queue membership and field grants stay with the report.
create function public.finding_decoy_context(p_finding bigint) returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('decoy_id',context->>'label_id','decoy_revision',context->'label_revision')
    from public.semantic_finding_publications publication
    join public.semantic_scenario_steps step using(scenario_id)
    join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
    cross join lateral (select case signal.document_json->>'rule_id'
        when 'qw.account-decoy' then signal.document_json->'decoy_context'
        when 'qw.file-decoy' then signal.document_json->'file_decoy_context' end as context) label
    where publication.finding_id=p_finding and context is not null
    order by step.step_id limit 1
$$;
revoke all on function public.finding_decoy_context(bigint) from public;
grant execute on function public.finding_decoy_context(bigint) to adlog_user;

create or replace function public.enqueue_qw_finding_notifications(p_scenario_id uuid) returns integer
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare added integer; required integer; delivery_key text; severity text;
    decoy boolean; reason text := 'live'; minutes integer := 0; event_at timestamptz;
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
    select case when scenario_kind='qw.nps-denials' then risk_class else 'initial' end,risk_class
    into delivery_key,severity from public.semantic_security_scenarios where scenario_id=p_scenario_id;
    select scenario_kind in ('qw.account-decoy','qw.file-decoy')
      into decoy from public.semantic_security_scenarios where scenario_id=p_scenario_id;
    if decoy then
        -- Explicit provenance, never event age, distinguishes history from delay.
        -- Mixed episodes notify for their latest live observation.
        select case when bool_and(coalesce(signal.document_json->>'processing_mode','live')='history_import')
                    then 'history_import'
                    when bool_and(coalesce(signal.document_json->>'processing_mode','live') in ('historical_replay','history_import'))
                    then 'historical_replay' else 'live' end,
               max((signal.document_json->>'occurred_at_utc')::timestamptz)
                   filter(where coalesce(signal.document_json->>'processing_mode','live')='live')
        into reason,event_at
        from public.semantic_scenario_steps step
        join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
        where step.scenario_id=p_scenario_id;
        if reason='live' and event_at<clock_timestamp()-interval '15 minutes' then
            reason := 'pipeline_delay';
            minutes := least(2147483647,floor(extract(epoch from (clock_timestamp()-event_at))/60))::integer;
        end if;
    elsif exists(select 1 from public.semantic_security_scenarios where scenario_id=p_scenario_id
        and scenario_kind='qw.nps-denials' and last_seen_utc<clock_timestamp()-interval '15 minutes') then
        -- Preserve the separate threshold notification policy.
        return 0;
    end if;
    if delivery_key not in ('initial','medium','high') then
        raise exception 'qw_publication_unavailable';
    end if;
    if reason in ('historical_replay','history_import') then
        -- A suppression receipt must not consume a later live delivery's key.
        delivery_key := delivery_key || ':' || reason;
    end if;
    perform pg_advisory_xact_lock(hashtext('notification_outbox_admission'));
    -- Lock approved bindings against revision/disable edits until publication
    -- commits. Recipient grants are re-resolved by the delivery worker.
    perform 1 from public.notification_subscriptions where enabled order by id for share;
    select count(*) into required from (
        select distinct recipient_user_id,channel from public.notification_subscriptions s
        where enabled and not exists (
            select 1 from public.notification_outbox j where j.object_kind='semantic_finding'
                and j.object_id=p_scenario_id and j.recipient_user_id=s.recipient_user_id and j.channel=s.channel and j.change_key=delivery_key)
    ) recipients;
    if reason not in ('historical_replay','history_import') and required+(select count(*) from public.notification_outbox where state in ('pending','sending','retry'))>10000 then
        raise exception 'notification_queue_full';
    end if;
    insert into public.notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
                                         publication_scenario_id,recipient_user_id,channel,change_key,object_severity,
                                         delivery_reason,delay_minutes,state,result_code)
    select gen_random_uuid(),s.id,s.revision,'semantic_finding',p_scenario_id,p_scenario_id,s.recipient_user_id,s.channel,delivery_key,severity,
        reason,minutes,
        case when reason in ('historical_replay','history_import') then 'cancelled' else 'pending' end,
        case when reason in ('historical_replay','history_import') then reason else null end
    from (select distinct on(recipient_user_id,channel) * from public.notification_subscriptions
          where enabled order by recipient_user_id,channel,id) s
    on conflict(object_kind,object_id,recipient_user_id,channel,change_key) do nothing;
    get diagnostics added=row_count;
    return added;
end $$;

reset role;
update public.report_datasets_v4 set fields_json=fields_json ||
    '[{"key":"delivery_reason","category":"technical"},{"key":"delay_minutes","category":"technical"}]'::jsonb
    where dataset_key='notifications.deliveries' and version=1;
insert into public.schema_migrations(version,name) values(247,'decoy_delivery_context');
commit;
