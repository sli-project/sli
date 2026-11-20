-- D03: dormant file-decoy reader; no source, policy or channel activation.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_decoy_v245'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=244 and name='account_decoy')
       or exists(select 1 from public.schema_migrations where version>=245) then
        raise exception 'migration 245 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.semantic_file_decoy_checks (
    checkpoint_key text not null check(checkpoint_key ~ '^[a-f0-9]{64}$'),
    observation_key text not null check(observation_key ~ '^[a-f0-9]{64}$'),
    scope_json jsonb not null check(jsonb_typeof(scope_json)='object' and octet_length(scope_json::text)<=4096),
    result_code text not null check(result_code in ('observed','no_match','not_applicable')),
    checked_at timestamptz not null default clock_timestamp(),
    primary key(checkpoint_key,observation_key)
);
revoke all on public.semantic_file_decoy_checks from public,adlog_user,adlog_semantic_worker;
grant select,insert on public.semantic_file_decoy_checks to adlog_semantic_worker;
alter table public.semantic_file_decoy_checks enable row level security;
create policy file_decoy_scope on public.semantic_file_decoy_checks to adlog_semantic_worker
    using(public.file_ransom_scope_allowed(scope_json)) with check(public.file_ransom_scope_allowed(scope_json));

-- Native context is read before action exclusions. Include pathless handle reuse
-- and boot boundaries as negative evidence; a truncated context proves nothing.
create function public.file_decoy_contexts(p_agent uuid,p_source text,p_generation text,p_native text)
returns jsonb language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce(jsonb_agg(q.normalized order by q.record_id),'[]'::jsonb)
    from (
        select c.normalized,c.record_id from sli_plugin_file_audit.observations o
        join sli_plugin_file_audit.observations c on c.agent_id=o.agent_id
          and c.source_instance_id=o.source_instance_id and c.generation=o.generation
          and c.policy_revision=o.policy_revision and c.record_id<o.record_id
          and c.observed_at between o.observed_at-interval '300 seconds' and o.observed_at
        where o.agent_id=p_agent and o.source_instance_id=p_source and o.generation=p_generation
          and o.evidence_key=p_native and o.event_id=4660
          and (c.event_id in (4608,1102) or (c.event_id in (4656,4659,4663,4658,4660)
            and c.normalized#>'{facts,subject_user_sid}'=o.normalized#>'{facts,subject_user_sid}'
            and c.normalized#>'{facts,logon_id_numeric}'=o.normalized#>'{facts,logon_id_numeric}'
            and c.normalized#>'{facts,server_process_id}'=o.normalized#>'{facts,server_process_id}'
            and c.normalized#>'{facts,handle_id}'=o.normalized#>'{facts,handle_id}'))
        order by c.record_id desc limit 129
    ) q
$$;
revoke all on function public.file_decoy_contexts(uuid,text,text,text) from public;

create function public.file_decoy_evidence_in_root(p_agent uuid,p_source text,p_generation text,p_collection text,p_native text)
returns boolean language sql stable set search_path=pg_catalog,pg_temp as $$
    with target as materialized (
        select o.* from sli_plugin_file_audit.observations o
        where o.agent_id=p_agent and o.source_instance_id=p_source and o.generation=p_generation
          and o.evidence_key=p_native
    ), context as materialized (
        select public.file_decoy_contexts(p_agent,p_source,p_generation,p_native) as items
    ), related as materialized (
        select c from context cross join lateral jsonb_array_elements(items) c
        where jsonb_array_length(items)<=128 and (c->>'record_id')::bigint>coalesce((
            select max((b->>'record_id')::bigint) from jsonb_array_elements(items) b
            where (b->>'event_id')::integer in (4608,1102)),0)
    ), candidates as materialized (
        select c from related where (c->>'record_id')::bigint>coalesce((
            select max((b.c->>'record_id')::bigint) from related b
            where (b.c->>'event_id')::integer in (4658,4660)),0)
    )
    select exists(select 1 from target o where
        exists(select 1 from jsonb_array_elements(o.normalized->'scopes') s where s->>'collection_scope_id'=p_collection)
        or (o.event_id=4660 and o.normalized#>>'{facts,outcome}'='success'
            and (o.normalized#>>'{facts,handle_id}')::numeric>0
            and o.normalized#>>'{facts,subject_user_sid}' is not null
            and o.normalized#>>'{facts,logon_id_numeric}' is not null
            and o.normalized#>>'{facts,server_process_id}' is not null
            and not exists(select 1 from candidates where c->>'path' is null)
            and (select count(distinct lower(replace(c->>'path','/','\'))) from candidates
                 where c#>>'{facts,outcome}'='success')=1
            and exists(select 1 from candidates cross join lateral jsonb_array_elements(c->'scopes') s
                where c#>>'{facts,outcome}'='success' and s->>'collection_scope_id'=p_collection)))
$$;
revoke all on function public.file_decoy_evidence_in_root(uuid,text,text,text,text) from public;

create function public.read_file_decoy_observations(s jsonb,p_agent uuid,p_checkpoint text,p_native text)
returns table(observation jsonb,contexts jsonb,labels jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if public.file_ransom_scope_allowed(s,p_agent) is not true or p_checkpoint is null
       or p_checkpoint !~ '^[a-f0-9]{64}$' then
        raise exception 'file_decoy_source_denied' using errcode='42501';
    end if;
    return query
    select o.normalized,public.file_decoy_contexts(p_agent,o.source_instance_id,o.generation,o.evidence_key),
        coalesce((select jsonb_agg(to_jsonb(label)) from (
            select d.id,d.revision,d.kind,d.identity,d.active,d.active_from,d.active_to
            from public.decoy_label_versions d where d.kind='file' and d.active and d.plugin_id='sli.file-audit'
              and d.device_id=p_agent::text and d.source_instance_id=o.source_instance_id
              and d.collection_scope_id=s->>'collection_scope_id'
              and d.active_from<=o.observed_at and (d.active_to is null or o.observed_at<d.active_to)
            order by d.id,d.revision limit 129
        ) label),'[]'::jsonb)
    from sli_plugin_file_audit.observations o
    join sli_plugin_file_audit.policy_revisions p on p.agent_id=o.agent_id
      and p.source_instance_id=o.source_instance_id and p.revision=o.policy_revision
    where o.agent_id=p_agent and o.source_instance_id=s->>'source_instance_id'
      and o.generation=s->>'source_generation' and o.observed_at<=statement_timestamp()
      and o.event_id in (4656,5145,4663,4660,4670)
      and coalesce(p.policy->>'source_kind','server')='server'
      and o.normalized->>'evidence_key'=o.evidence_key and o.normalized->>'payload_sha256'=o.payload_sha256
      and public.file_decoy_evidence_in_root(p_agent,o.source_instance_id,o.generation,s->>'collection_scope_id',o.evidence_key)
      and public.resolve_finding_evidence_ref((s->>'installation_id')::uuid,'sli.file-audit',o.source_instance_id,
          o.generation,s->>'collection_scope_id','file_audit_observation',o.evidence_key,o.payload_sha256)
      and ((p_native is not null and o.evidence_key=p_native) or (p_native is null and not exists(
          select 1 from public.semantic_file_decoy_checks c where c.checkpoint_key=p_checkpoint and c.observation_key=o.evidence_key)))
    order by o.observed_at,o.evidence_key limit 128;
end $$;
revoke all on function public.read_file_decoy_observations(jsonb,uuid,text,text) from public;
grant execute on function public.read_file_decoy_observations(jsonb,uuid,text,text) to adlog_semantic_worker;

-- A bounded application reader: the API authorizes every returned label version
-- before invoking it. Only admitted signals and their exact native witness join.
create function public.read_file_decoy_touches(p_label uuid,p_revision bigint,p_after text)
returns table(signal_id text,evaluation_mode text,context jsonb,observation jsonb)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select q.signal_id,q.evaluation_mode,q.document_json->'file_decoy_context',o.normalized
    from public.semantic_qw_signals q
    join public.decoy_label_versions d on d.id=p_label and d.revision=p_revision and d.kind='file'
    join sli_plugin_file_audit.observations o
      on o.evidence_key=q.document_json#>>'{file_decoy_context,observation_key}'
      and exists(select 1 from jsonb_array_elements(q.document_json->'evidence_refs') ref
          where ref->>'native_id'=o.evidence_key and ref->>'sha256'=o.payload_sha256
            and ref->>'storage_kind'='file_audit_observation'
            and ref#>>'{scope,collection_scope_id}'=d.collection_scope_id
            and ref#>>'{scope,source_instance_id}'=d.source_instance_id
            and ref#>>'{scope,source_generation}'=o.generation)
    where q.document_json->>'rule_id'='qw.file-decoy'
      and q.document_json#>>'{file_decoy_context,label_id}'=d.id::text
      and q.document_json#>>'{file_decoy_context,label_revision}'=d.revision::text
      and o.agent_id::text=d.device_id and o.source_instance_id=d.source_instance_id
      and (p_after is null or q.signal_id>p_after)
    order by q.signal_id limit 101
$$;
revoke all on function public.read_file_decoy_touches(uuid,bigint,text) from public;
grant execute on function public.read_file_decoy_touches(uuid,bigint,text) to adlog_user;

create function public.file_decoy_coverage(p_agent uuid,p_source text,p_scope text,p_revision text)
returns table(state text,read_audit_enabled boolean,lost_count bigint,window_end timestamptz)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select case when i.imported_at is not null and i.envelope=r.envelope
        and r.receipt->>'status'='committed' then r.envelope->>'continuity_state' else 'unknown' end,
        exists(select 1 from sli_plugin_file_audit.policy_revisions p
            cross join lateral jsonb_array_elements(p.policy->'roots') root
            where p.agent_id=p_agent and p.source_instance_id=p_source and p.revision::text=p_revision
              and root->>'collection_scope_id'=p_scope and root->>'important'='true'),
        (r.envelope->>'lost_count')::bigint,r.received_at
    from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
    where r.agent_id=p_agent and r.module_id='sli.file-audit'
      and r.envelope->>'source_instance_id'=p_source and r.envelope->>'policy_revision'=p_revision
    order by r.received_at desc,r.sequence desc limit 1
$$;
revoke all on function public.file_decoy_coverage(uuid,text,text,text) from public;
grant execute on function public.file_decoy_coverage(uuid,text,text,text) to adlog_user;

create or replace function public.resolve_finding_evidence_ref(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_collection text,
    p_kind text,p_native text,p_sha256 text
) returns boolean language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype;
begin
    if p_sha256 is null or p_sha256 !~ '^[a-f0-9]{64}$' or p_native is null then return false; end if;
    select a.* into b from public.finding_evidence_source_bindings a join pg_catalog.pg_roles r
        on r.oid=a.principal_oid and r.rolname=a.principal_name
        where r.rolname=session_user and a.installation_id=p_installation and a.plugin_id=p_plugin
          and a.source_instance_id=p_source and a.source_generation=p_generation
          and a.collection_scope_id=p_collection and a.storage_kind=p_kind;
    if not found then return false; end if;
    if p_kind='core_event' then
        if p_native !~ '^[1-9][0-9]{0,18}$' or p_native::numeric>=9223372036854775808 then return false; end if;
        return exists(select 1 from public.events_v2_core e
            join public.raw_log_files raw on raw.id=e.raw_log_file_id
            join public.sli_agent_packet_inbox inbox on raw.file_path='agent-packet:'||inbox.packet_id::text
            join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id
            where e.id=p_native::bigint and e.log_source_id=b.log_source_id
              and encode(e.normalized_hash,'hex')=p_sha256 and inbox.imported_at is not null
              and receipt.receipt->>'status'='committed' and inbox.envelope=receipt.envelope
              and receipt.module_id=p_plugin and inbox.envelope->>'agent_id'=b.agent_id::text
              and inbox.envelope->>'source_instance_id'=p_source
              and inbox.envelope->>'generation'=p_generation);
    elsif p_kind='workstation_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_workstations.observations o
            where o.id=p_native and o.agent_key=b.agent_key and o.observation_sha256=p_sha256
              and o.observation->>'generation'=p_generation and o.observation->>'agent_key'=b.agent_key
              and encode(sha256(convert_to(o.source_xml,'UTF8')),'hex')=o.observation->>'source_sha256');
    elsif p_kind='file_audit_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_file_audit.observations o
            where o.evidence_key=p_native and o.agent_id=b.agent_id and o.source_instance_id=p_source
              and o.generation=p_generation and o.payload_sha256=p_sha256
              and o.normalized->>'payload_sha256'=p_sha256 and o.normalized->>'evidence_key'=p_native
              and (o.collection_scope_id=p_collection
                   or public.file_ransom_evidence_in_root(b.agent_id,p_source,p_collection,p_native)
                   or public.file_decoy_evidence_in_root(b.agent_id,p_source,p_generation,p_collection,p_native)));
    end if;
    return false;
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
        and scenario_kind in ('qw.nps-denials','qw.account-decoy','qw.file-decoy') and last_seen_utc<clock_timestamp()-interval '15 minutes') then
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
insert into public.schema_migrations(version,name) values(245,'file_decoy');
commit;
