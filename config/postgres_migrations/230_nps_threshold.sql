-- N08: source-bound NPS windows/checkpoint; no detector or policy activation.
begin;
select pg_advisory_xact_lock(hashtext('sli_nps_threshold_v230'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=229 and name='qw_finding_notifications')
       or exists(select 1 from public.schema_migrations where version>=230) then
        raise exception 'migration 230 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- The NPS module uses the existing attested core-event verifier: exact receipt,
-- agent, generation, log source and normalized hash. No source is auto-bound.
alter table public.finding_evidence_source_bindings
    drop constraint finding_evidence_source_bindings_check,
    add constraint finding_evidence_source_bindings_check check (
        (storage_kind='core_event' and plugin_id in ('sli.windows.ad-dc','sli.vpn-nps') and collection_scope_id=''
            and log_source_id is not null and agent_key is null and agent_id is not null)
        or (storage_kind='workstation_observation' and plugin_id='sli.workstations' and collection_scope_id=''
            and log_source_id is null and agent_key is not null and agent_id is null)
        or (storage_kind='file_audit_observation' and plugin_id='sli.file-audit' and collection_scope_id<>''
            and log_source_id is null and agent_key is null and agent_id is not null)
    );
alter table public.finding_evidence_refs
    drop constraint finding_evidence_refs_check,
    add constraint finding_evidence_refs_check check (
        (storage_kind='core_event' and plugin_id in ('sli.windows.ad-dc','sli.vpn-nps') and collection_scope_id=''
            and case when native_id ~ '^[1-9][0-9]{0,18}$' then native_id::numeric<9223372036854775808 else false end)
        or (storage_kind='workstation_observation' and plugin_id='sli.workstations' and collection_scope_id=''
            and native_id ~ '^[a-f0-9]{64}$')
        or (storage_kind='file_audit_observation' and plugin_id='sli.file-audit' and collection_scope_id<>''
            and native_id ~ '^[a-f0-9]{64}$')
    );

create table public.semantic_nps_threshold_state (
    checkpoint_key text primary key check(checkpoint_key ~ '^[a-f0-9]{64}$'),
    scope_json jsonb not null check(jsonb_typeof(scope_json)='object'),
    checkpoint_json jsonb not null check(jsonb_typeof(checkpoint_json)='object'
        and octet_length(checkpoint_json::text)<=1048576),
    updated_at timestamptz not null default clock_timestamp()
);
revoke all on public.semantic_nps_threshold_state from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant select,insert on public.semantic_nps_threshold_state to adlog_semantic_worker;
grant update(checkpoint_json,updated_at) on public.semantic_nps_threshold_state to adlog_semantic_worker;
alter table public.semantic_nps_threshold_state enable row level security;
create policy nps_threshold_scope on public.semantic_nps_threshold_state to adlog_semantic_worker
    using (public.finding_evidence_scope_allowed((scope_json->>'installation_id')::uuid,
        scope_json->>'plugin_id',scope_json->>'source_instance_id',scope_json->>'source_generation','','core_event'))
    with check (public.finding_evidence_scope_allowed((scope_json->>'installation_id')::uuid,
        scope_json->>'plugin_id',scope_json->>'source_instance_id',scope_json->>'source_generation','','core_event'));

create function public.nps_threshold_watermark(p_installation uuid,p_plugin text,p_source text,p_generation text,p_now timestamptz)
returns timestamptz language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select coalesce((inbox.packet#>>'{header,observed_at_utc}')::timestamptz,
                    (inbox.packet#>>'{continuity,to_utc}')::timestamptz)
    from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
        on r.oid=b.principal_oid and r.rolname=b.principal_name
        join public.sli_agent_packet_inbox inbox on inbox.envelope->>'agent_id'=b.agent_id::text
        join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id and receipt.agent_id=b.agent_id
    where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
      and b.source_instance_id=p_source and b.source_generation=p_generation and b.collection_scope_id=''
      and b.storage_kind='core_event' and inbox.imported_at is not null and inbox.envelope=receipt.envelope
      and receipt.receipt->>'status'='committed' and receipt.module_id=p_plugin
      and inbox.envelope->>'source_instance_id'=p_source and inbox.envelope->>'generation'=p_generation
      and coalesce((inbox.packet#>>'{header,observed_at_utc}')::timestamptz,
                   (inbox.packet#>>'{continuity,to_utc}')::timestamptz)<=p_now
    order by receipt.sequence desc limit 1
$$;
revoke all on function public.nps_threshold_watermark(uuid,text,text,text,timestamptz) from public;
grant execute on function public.nps_threshold_watermark(uuid,text,text,text,timestamptz) to adlog_semantic_worker;

-- Narrow SECURITY DEFINER read capability, never an unrestricted worker grant.
create function public.read_nps_threshold_events(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_from timestamptz,p_to timestamptz
) returns table(source_event_id bigint,occurred_at_utc timestamptz,facts_json jsonb,
                roles_json jsonb,quality_json jsonb,sha256 text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_plugin not in ('sli.windows.ad-dc','sli.vpn-nps') or p_from is null or p_to is null
       or p_from>=p_to or p_to-p_from>interval '2 hours'
       or public.finding_evidence_scope_allowed(p_installation,p_plugin,p_source,p_generation,'','core_event') is not true then
        raise exception 'nps_threshold_source_denied' using errcode='42501';
    end if;
    return query select n.source_event_id,n.occurred_at_utc,n.facts_json,n.roles_json,n.quality_json,
                        encode(e.normalized_hash,'hex')
    from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
    where e.event_id=6273 and n.semantic_type='remote_access.authentication.denied'
      and n.processing_status='normalized'
      and n.normalizer_id='windows.named-eventdata' and n.semantic_contract_version=1
      and n.occurred_at_utc>=p_from and n.occurred_at_utc<p_to
      and not exists(select 1 from public.normalized_events newer
          where newer.source_event_id=n.source_event_id and newer.normalizer_id=n.normalizer_id
            and (newer.normalized_at,newer.normalized_event_id)>(n.normalized_at,n.normalized_event_id))
      and public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,'','core_event',
          n.source_event_id::text,encode(e.normalized_hash,'hex'))
    order by n.occurred_at_utc desc,n.source_event_id limit 10001;
end $$;
revoke all on function public.read_nps_threshold_events(uuid,text,text,text,timestamptz,timestamptz) from public;
grant execute on function public.read_nps_threshold_events(uuid,text,text,text,timestamptz,timestamptz) to adlog_semantic_worker;

-- Completeness requires explicit acquisition interval attestations. A successful
-- read, an empty result, backfill_completed, or counts alone are insufficient.
-- Legacy NPS agents send status=not_proven and correctly remain partial.
create function public.nps_threshold_window_quality(
    p_installation uuid,p_plugin text,p_source text,p_generation text,
    p_from timestamptz,p_to timestamptz,p_now timestamptz
) returns text language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare covered tstzmultirange; latest timestamptz;
begin
    if p_from is null or p_to is null or p_now is null or p_from>=p_to or p_to>p_now
       or p_to-p_from>interval '1 hour'
       or public.finding_evidence_scope_allowed(p_installation,p_plugin,p_source,p_generation,'','core_event') is not true then
        raise exception 'nps_threshold_source_denied' using errcode='42501';
    end if;
    -- A drained packet carries the complete retained origin. Bound the recent
    -- packet page instead of aggregating an installation's entire history.
    with packets as (
    select inbox.packet,inbox.received_at
    from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
        on r.oid=b.principal_oid and r.rolname=b.principal_name
        join public.sli_agent_packet_inbox inbox on inbox.envelope->>'agent_id'=b.agent_id::text
        join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id and receipt.agent_id=b.agent_id
    where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
      and b.source_instance_id=p_source and b.source_generation=p_generation and b.collection_scope_id=''
      and b.storage_kind='core_event' and inbox.imported_at is not null and inbox.envelope=receipt.envelope
      and receipt.receipt->>'status'='committed' and receipt.module_id=p_plugin
      and inbox.envelope->>'source_instance_id'=p_source and inbox.envelope->>'generation'=p_generation
    order by receipt.sequence desc limit 64)
    select max(received_at),range_agg(case when packet#>>'{continuity,status}'='complete'
            and packet#>>'{continuity,from_utc}' is not null and packet#>>'{continuity,to_utc}' is not null then
        tstzrange((packet#>>'{continuity,from_utc}')::timestamptz,
                  (packet#>>'{continuity,to_utc}')::timestamptz,'[)') end)
    into latest,covered from packets;
    if latest is null then return 'not_collected'; end if;
    if latest<p_now-interval '5 minutes' then return 'stale'; end if;
    if covered is null or not covered @> tstzrange(p_from,p_to,'[)') then return 'partial'; end if;
    -- Receipts are admitted in signed cursor/sequence order. Pending imports
    -- in that chain invalidate completeness even when a later tail arrived.
    if exists(select 1 from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
        on r.oid=b.principal_oid and r.rolname=b.principal_name
        join public.sli_agent_packet_inbox inbox on inbox.envelope->>'agent_id'=b.agent_id::text
        join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id
        where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
          and b.source_instance_id=p_source and b.source_generation=p_generation
          and inbox.envelope=receipt.envelope and receipt.module_id=p_plugin
          and inbox.envelope->>'source_instance_id'=p_source and inbox.envelope->>'generation'=p_generation
          and inbox.received_at>=p_from and inbox.imported_at is null) then
        return 'partial';
    end if;
    if exists(select 1 from public.events_v2_core e
        where e.event_id=6273 and e.time_created_utc>=p_from and e.time_created_utc<p_to
          and public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,'','core_event',
              e.id::text,encode(e.normalized_hash,'hex'))
          and not exists(select 1 from public.normalized_events n where n.source_event_id=e.id
              and n.normalizer_id='windows.named-eventdata' and n.semantic_contract_version=1
              and n.processing_status='normalized' and n.semantic_type='remote_access.authentication.denied'
              and not exists(select 1 from public.normalized_events newer
                  where newer.source_event_id=n.source_event_id and newer.normalizer_id=n.normalizer_id
                    and (newer.normalized_at,newer.normalized_event_id)>(n.normalized_at,n.normalized_event_id)))) then
        return 'partial';
    end if;
    return 'good';
end $$;
revoke all on function public.nps_threshold_window_quality(uuid,text,text,text,timestamptz,timestamptz,timestamptz) from public;
grant execute on function public.nps_threshold_window_quality(uuid,text,text,text,timestamptz,timestamptz,timestamptz) to adlog_semantic_worker;

-- Snapshot the public severity at admission. Each NPS severity change is sent
-- once per recipient/channel; ordinary QW objects retain their initial key.
alter table public.notification_outbox
    add column change_key text not null default 'initial' check(change_key in ('initial','medium','high')),
    add column object_severity text check(object_severity in ('info','low','medium','high','critical')),
    add constraint notification_outbox_change unique(object_kind,object_id,recipient_user_id,channel,change_key);

-- Resolve the original PostgreSQL-generated (length-truncated) UNIQUE name.
do $$ declare old_constraint name; begin
    select conname into strict old_constraint from pg_catalog.pg_constraint
    where conrelid='public.notification_outbox'::regclass and contype='u'
      and pg_catalog.pg_get_constraintdef(oid)='UNIQUE (object_kind, object_id, recipient_user_id, channel)';
    execute format('alter table public.notification_outbox drop constraint %I',old_constraint);
end $$;

create or replace function public.enqueue_qw_finding_notifications(p_scenario_id uuid) returns integer
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare added integer; required integer; delivery_key text; severity text;
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
    -- Historical backfill stays in the queue/history without external dispatch.
    if exists(select 1 from public.semantic_security_scenarios where scenario_id=p_scenario_id
        and scenario_kind='qw.nps-denials' and last_seen_utc<clock_timestamp()-interval '15 minutes') then
        return 0;
    end if;
    if delivery_key not in ('initial','medium','high') then
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
                and j.object_id=p_scenario_id and j.recipient_user_id=s.recipient_user_id and j.channel=s.channel and j.change_key=delivery_key)
    ) recipients;
    if required+(select count(*) from public.notification_outbox where state in ('pending','sending','retry'))>10000 then
        raise exception 'notification_queue_full';
    end if;
    insert into public.notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
                                         publication_scenario_id,recipient_user_id,channel,change_key,object_severity)
    select gen_random_uuid(),s.id,s.revision,'semantic_finding',p_scenario_id,p_scenario_id,s.recipient_user_id,s.channel,delivery_key,severity
    from (select distinct on(recipient_user_id,channel) * from public.notification_subscriptions
          where enabled order by recipient_user_id,channel,id) s
    on conflict(object_kind,object_id,recipient_user_id,channel,change_key) do nothing;
    get diagnostics added=row_count;
    return added;
end $$;

reset role;
insert into public.schema_migrations(version,name) values(230,'nps_threshold');
commit;
