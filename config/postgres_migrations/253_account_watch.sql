-- W02: dormant native WATCH input; requires the separately shipped W01 registry.
begin;
select pg_advisory_xact_lock(hashtext('sli_account_watch_v253'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=248 and name='entity_context_history_reads')
       or not exists(select 1 from public.schema_migrations where version=249 and name='watch_registry')
       or not exists(select 1 from public.schema_migrations where version=251 and name='workstation_access')
       or not exists(select 1 from information_schema.columns where table_schema='public'
           and table_name='notification_outbox' and column_name='delivery_reason')
       or exists(select 1 from public.schema_migrations where version>=253) then
        raise exception 'migration 253 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.semantic_account_watch_checks (
    checkpoint_key text not null check(checkpoint_key ~ '^[a-f0-9]{64}$'),
    normalized_event_id uuid not null,
    scope_json jsonb not null check(jsonb_typeof(scope_json)='object'),
    result_code text not null check(result_code in ('observed','no_match','not_applicable')),
    checked_at timestamptz not null default clock_timestamp(),
    primary key(checkpoint_key,normalized_event_id)
);
revoke all on public.semantic_account_watch_checks from public,adlog_user,adlog_semantic_worker;
grant select,insert on public.semantic_account_watch_checks to adlog_semantic_worker;
alter table public.semantic_account_watch_checks enable row level security;
create policy account_watch_scope on public.semantic_account_watch_checks to adlog_semantic_worker
    using(public.finding_evidence_scope_allowed((scope_json->>'installation_id')::uuid,
        scope_json->>'plugin_id',scope_json->>'source_instance_id',scope_json->>'source_generation','','core_event'))
    with check(public.finding_evidence_scope_allowed((scope_json->>'installation_id')::uuid,
        scope_json->>'plugin_id',scope_json->>'source_instance_id',scope_json->>'source_generation','','core_event'));

create function public.read_account_watch_events(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_checkpoint text,p_normalized uuid
) returns table(normalized_event_id uuid,source_event_id bigint,event_id integer,semantic_type text,
    occurred_at_utc timestamptz,roles_json jsonb,quality_json jsonb,sha256 text,entries jsonb,identities jsonb,event_item jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_plugin is distinct from 'sli.windows.ad-dc' or p_checkpoint is null
       or p_checkpoint !~ '^[a-f0-9]{64}$'
       or public.finding_evidence_scope_allowed(p_installation,p_plugin,p_source,p_generation,'','core_event') is not true then
        raise exception 'account_watch_source_denied' using errcode='42501';
    end if;
    return query
    with events as materialized (
        select n.*,e.event_id,e.domain_id,encode(e.normalized_hash,'hex') as native_sha256,
            to_jsonb(e)||jsonb_build_object('channel',channel.value,'provider_name',provider.value) as item
        from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
        join public.storage_v2_channel channel on channel.id=e.channel_id
        join public.storage_v2_provider provider on provider.id=e.provider_id
        where e.event_id in (4624,4625,4634,4647,4648,4672,4740,4767,4768,4769,4770,4771,4773,4776,
            4720,4722,4723,4724,4725,4726,4738,4781,4728,4732,4756,4729,4733,4757)
          and n.processing_status='normalized' and n.normalizer_id='windows.named-eventdata'
          and n.semantic_contract_version=1
          and n.source_event_sha256=e.normalized_hash and n.occurred_at_utc=e.time_created_utc
          and n.occurred_at_utc<=statement_timestamp()
          and exists(select 1 from public.watch_entry_versions w
              where w.active and w.collection_scope_id='ad-domain:'||e.domain_id
                and w.active_from<=n.occurred_at_utc and n.occurred_at_utc<w.expires_at
                and w.valid_from<=n.occurred_at_utc and (w.valid_to is null or n.occurred_at_utc<w.valid_to))
          and ((p_normalized is not null and n.normalized_event_id=p_normalized)
            or (p_normalized is null and not exists(
                select 1 from public.semantic_account_watch_checks c
                where c.checkpoint_key=p_checkpoint and c.normalized_event_id=n.normalized_event_id)
                and not exists(select 1 from public.normalized_events newer
                    where newer.source_event_id=n.source_event_id and newer.normalizer_id=n.normalizer_id
                    and (newer.normalized_at,newer.normalized_event_id)>(n.normalized_at,n.normalized_event_id))))
          and public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,'','core_event',
              n.source_event_id::text,encode(e.normalized_hash,'hex'))
        order by n.normalized_at,n.normalized_event_id limit 128
    )
    select e.normalized_event_id,e.source_event_id,e.event_id,e.semantic_type,e.occurred_at_utc,
        e.roles_json,e.quality_json,e.native_sha256,
        coalesce((select jsonb_agg(to_jsonb(w)) from (
            select d.id,d.revision,d.identity,d.active,d.active_from,d.expires_at,d.valid_from,d.valid_to
            from public.watch_entry_versions d
            where d.active and d.plugin_id='sli.ad' and d.collection_scope_id='ad-domain:'||e.domain_id
              and (d.identity->>'domain_id')::bigint=e.domain_id
              and d.active_from<=e.occurred_at_utc and e.occurred_at_utc<d.expires_at
              and d.valid_from<=e.occurred_at_utc and (d.valid_to is null or e.occurred_at_utc<d.valid_to)
            order by d.id,d.revision limit 129
        ) w),'[]'::jsonb),
        coalesce((select jsonb_agg(to_jsonb(i)) from (
            select role.key as role,role.value as key,
                jsonb_build_object('domain_id',r.domain_id,'entity_id',v.entity_id,
                    'sid',v.attributes_json#>>'{identity,object_sid}',
                    'guid',lower(v.attributes_json#>>'{identity,object_guid}')) as identity
            from public.ad_context_entity_versions v
            join public.ad_context_runs r on r.run_id=v.source_run_id
            cross join lateral jsonb_each_text(e.roles_json) role
            where r.status='completed' and r.domain_id=e.domain_id and v.source_section='directory_accounts'
              and v.attributes_json#>>'{identity,kind}'='ad_user'
              and v.valid_from_utc<=e.occurred_at_utc and (v.valid_to_utc is null or e.occurred_at_utc<v.valid_to_utc)
              and role.key in ('actor','affected_entity','session_principal')
              and (role.value='sid:'||(v.attributes_json#>>'{identity,object_sid}')
                or role.value='guid:'||lower(v.attributes_json#>>'{identity,object_guid}'))
            order by role.key,v.entity_id,v.id limit 257
        ) i),'[]'::jsonb),e.item
    from events e order by e.normalized_at,e.normalized_event_id;
end $$;
revoke all on function public.read_account_watch_events(uuid,text,text,text,text,uuid) from public;
grant execute on function public.read_account_watch_events(uuid,text,text,text,text,uuid) to adlog_semantic_worker;

-- Published priority only. Never disclose the protected reason/owner or enable
-- a TEST/SHADOW decoration by merely adding an account to the registry.
create index semantic_watch_event on public.semantic_qw_signals(
    (document_json#>>'{watch_context,source_event_id}'),(document_json#>>'{evidence_refs,0,sha256}'))
    where document_json->>'rule_id'='qw.account-watch';
create function public.account_watch_event_priority(p_event bigint,p_sha256 text) returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('base_severity',q.document_json->>'base_severity',
        'effective_severity',q.document_json->>'effective_severity','reason','watch')
    from public.semantic_qw_signals q
    where q.document_json->>'rule_id'='qw.account-watch' and q.evaluation_mode='enabled'
      and q.document_json->>'conclusion_state'='observed'
      and q.document_json#>>'{watch_context,source_event_id}'=p_event::text
      and q.document_json#>>'{evidence_refs,0,sha256}'=p_sha256
      and exists(select 1 from public.semantic_scenario_steps step
          join public.semantic_finding_publications publication using(scenario_id)
          where step.qw_signal_id=q.signal_id)
    order by case q.document_json->>'effective_severity'
        when 'critical' then 5 when 'high' then 4 when 'medium' then 3 when 'low' then 2 else 1 end desc
    limit 1
$$;
revoke all on function public.account_watch_event_priority(bigint,text) from public;
grant execute on function public.account_watch_event_priority(bigint,text) to adlog_user;
alter table public.notification_outbox drop constraint notification_outbox_change_key_check;
alter table public.notification_outbox add constraint notification_outbox_change_key_check
    check(change_key ~ '^(initial|low|medium|high|critical)(:(historical_replay|history_import))?$');
create or replace function public.enqueue_qw_finding_notifications(p_scenario_id uuid) returns integer
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare added integer; required integer; delivery_key text; severity text;
    contextual boolean; reason text := 'live'; minutes integer := 0; event_at timestamptz;
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
    select case when scenario_kind in ('qw.nps-denials','qw.account-watch') then risk_class else 'initial' end,risk_class
    into delivery_key,severity from public.semantic_security_scenarios where scenario_id=p_scenario_id;
    select scenario_kind in ('qw.account-decoy','qw.file-decoy','qw.account-watch')
      into contextual from public.semantic_security_scenarios where scenario_id=p_scenario_id;
    if contextual then
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
            if exists(select 1 from public.semantic_security_scenarios where scenario_id=p_scenario_id
                and scenario_kind='qw.account-watch') then
                return 0;
            end if;
            reason := 'pipeline_delay';
            minutes := least(2147483647,floor(extract(epoch from (clock_timestamp()-event_at))/60))::integer;
        end if;
    elsif exists(select 1 from public.semantic_security_scenarios where scenario_id=p_scenario_id
        and scenario_kind='qw.nps-denials' and last_seen_utc<clock_timestamp()-interval '15 minutes') then
        -- Preserve the separate threshold notification policy.
        return 0;
    end if;
    if delivery_key not in ('initial','low','medium','high','critical') then
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
insert into public.schema_migrations(version,name) values(253,'account_watch');
commit;
