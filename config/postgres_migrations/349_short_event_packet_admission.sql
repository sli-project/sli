begin;
select pg_advisory_xact_lock(hashtext('sli_short_event_packet_admission349'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=342 and name='short_storage_retention')
       or exists(select 1 from public.schema_migrations where version>=349) then
        raise exception 'short_event_packet_admission349_preflight' using errcode='55000';
    end if;
end $$;
-- The package runner enters with SET ROLE adlog_storage_owner. Legacy state
-- and catalog tables belong to adlog_user; use the checked installer session
-- for this cross-owner copy and grants, without granting state reads to workers.
reset role;
grant select(id,fqdn,role) on public.servers to adlog_storage_owner;
grant select(id,name) on public.log_sources to adlog_storage_owner;
-- State projections retain event identity after hot retention. New short events
-- have the same durable allocation, without requiring an old core row.
insert into public.storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
select e.id,e.server_id,e.channel_id,e.event_record_id,e.time_created_utc,e.normalized_hash
from public.events_v2_core e
where e.id in (select evidence_event_id from public.entity_states union select source_event_db_id from public.entity_state_current)
on conflict(server_id,channel_id,event_record_id,time_created_utc) do nothing;
set local role adlog_storage_owner;
alter sequence public.storage_v2_event_id_seq owned by public.storage_v2_event_identity_allocations.id;
alter table public.entity_state_current drop constraint entity_state_current_source_event_db_id_fkey;
alter table public.entity_state_current add constraint entity_state_current_source_event_db_id_fkey
    foreign key(source_event_db_id) references public.storage_v2_event_identity_allocations(id) on delete restrict;
reset role;
alter table public.entity_states drop constraint entity_states_evidence_event_id_v2_fkey;
alter table public.entity_states add constraint entity_states_evidence_event_id_v2_fkey
    foreign key(evidence_event_id) references public.storage_v2_event_identity_allocations(id);
set local role adlog_storage_owner;

create or replace function public.attest_short_event337() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare origin jsonb; digest bytea; record_id bigint; admission_packet text; admission_ordinal text;
begin
    admission_packet:=new.method->>'$packet_id'; admission_ordinal:=new.method->>'$packet_ordinal';
    new.method:=new.method-'$origin'-'$packet_id'-'$packet_ordinal';
    new.source_sha256:=null; new.event_record_id:=null;
    if admission_packet is null or not pg_input_is_valid(admission_packet,'uuid')
       or admission_ordinal is null or admission_ordinal !~ '^[0-9]{1,9}$' then return new; end if;
    select jsonb_build_object('installation_id',installation.installation_id::text,'plugin_id','sli.windows.ad-dc',
        'source_instance_id',i.envelope->>'source_instance_id','source_generation',i.envelope->>'generation',
        'collection_scope_id','','agent_id',r.agent_id::text,'log_source_id',ls.id),a.normalized_hash,a.event_record_id
    into origin,digest,record_id
    from public.sli_agent_packet_inbox i
    join public.sli_agent_receipts r on r.packet_id=i.packet_id and r.envelope=i.envelope
    join public.sli_agent_stream_receipts stream on stream.packet_id=r.packet_id and stream.agent_id=r.agent_id
        and stream.module_id=r.module_id and stream.sequence=r.sequence and stream.collection_channel=i.collection_channel
    join public.sli_agents agent on agent.id=r.agent_id and agent.status='active'
    join public.sli_agent_module_bindings binding on binding.agent_id=r.agent_id and binding.module_id='sli.windows.ad-dc'
        and binding.source_instance_id=i.envelope->>'source_instance_id'
    join public.servers server on server.id::text=new.method->>'$server_id' and server.domain_id=new.domain_id
        and server.is_active and server.role='domain_controller'
        and coalesce(server.id::text=(select details->>'server_id' from public.sli_agent_audit
            where target=r.agent_id::text and action='issue' order by id desc limit 1),
            lower(binding.source_name) in (lower(server.hostname),lower(server.fqdn))
            or strpos(binding.source_name,'.')=0 and lower(binding.source_name)=split_part(lower(coalesce(nullif(server.fqdn,''),server.hostname)),'.',1)
            or strpos(coalesce(nullif(server.fqdn,''),server.hostname),'.')=0 and lower(server.hostname)=split_part(lower(binding.source_name),'.',1))
    join public.storage_v2_event_identity_allocations a on a.id=new.event_id and a.server_id=server.id
        and a.time_created_utc=new.time_created_utc
    join public.storage_v2_channel ch on ch.id=a.channel_id and ch.value=i.collection_channel
    join public.log_sources ls on ls.name=ch.value
    join public.event_source_representations_v2 rep on rep.event_id=a.id and rep.normalized_hash=a.normalized_hash
    cross join lateral (select i.event_rows->admission_ordinal::integer as doc) native
    cross join public.semantic_default_installation installation
    where i.packet_id=admission_packet::uuid and i.imported_at is not null
      and not exists(select 1 from public.sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
      and r.module_id in ('sli.windows.ad-dc','sli.windows.ad-dc-history') and r.receipt->>'status'='committed'
      and i.envelope->>'agent_id'=r.agent_id::text
      and exists(select 1 from jsonb_array_elements(agent.assigned_modules) m where m->>'module_id'=r.module_id and m->'enabled'='true'::jsonb)
      and nullif(i.envelope->>'generation','') is not null
      and i.collection_channel=new.method->>'$channel'
      and native.doc->>'xml'=rep.representation->>'xml'
      and (native.doc->>'record_id')::bigint=a.event_record_id
      and (native.doc->>'event_id')::integer=new.event_kind
      and (native.doc->>'time_created')::timestamptz=new.time_created_utc
      and native.doc->>'channel'=ch.value
      and rep.representation->>'provider_name'=new.method->>'$provider';
    if found then new.method:=new.method||jsonb_build_object('$origin',origin); new.source_sha256:=digest; new.event_record_id:=record_id; end if;
    return new;
end $$;
revoke all on function public.attest_short_event337() from public;

do $patch349$ declare definition text; patched text; begin
    select pg_get_functiondef('public.link_finding_evidence_ref(bigint,uuid,text,text,text,text,text,text,text)'::regprocedure) into strict definition;
    patched:=replace(definition,$mirror$            -- S3 still dual-writes the old store. Mirror its link only while
            -- that exact old event exists, so the single legacy switch can
            -- also display problems created on the short path.
            insert into public.finding_evidence(finding_id,event_id,evidence_role,note)
            select p_finding,e.id,'semantic_scenario','enabled semantic scenario evidence' from public.events_v2_core e
            where e.id=p_native::bigint and encode(e.normalized_hash,'hex')=p_sha256
            on conflict(finding_id,event_id,evidence_role) do nothing;
$mirror$,'');
    if patched=definition then raise exception 'short_event_packet_admission349_link_shape' using errcode='55000'; end if;
    execute patched;
end $patch349$;

create function public.write_short_events349(p_rows jsonb) returns table(groups bigint,summaries bigint,attested bigint)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    perform public.create_event_storage_partitions(d,d) from (
        select distinct ((value->>'time_created_utc')::timestamptz at time zone 'UTC')::date as d from jsonb_array_elements(p_rows)
    ) days order by d;
    return query
with incoming as materialized (
                select r.*,j.value->>'layer' as layer from jsonb_array_elements(p_rows) j
                cross join lateral jsonb_populate_record(null::public.event_hot,j.value) r
            ), inserted as (
                insert into public.event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                select event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields
                from incoming order by time_created_utc,event_id
                on conflict(time_created_utc,event_id) do nothing returning *
            ), facts as (
                insert into public.event_cold_facts
                select h.* from inserted h join incoming i using(time_created_utc,event_id) where i.layer='fact'
                on conflict(time_created_utc,event_id) do nothing returning event_id
            ), daily as materialized (
                select (h.time_created_utc at time zone 'UTC')::date as day,
                       h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,h.method,h.outcome,
                       count(*) as event_count,min(h.time_created_utc) as first_seen_utc,max(h.time_created_utc) as last_seen_utc
                from inserted h join incoming i using(time_created_utc,event_id) where i.layer='summary'
                group by (h.time_created_utc at time zone 'UTC')::date,
                         h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,h.method,h.outcome
            ), summaries as (
                insert into public.event_cold_daily as current(day,grouping_key,event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc)
                select day,sha256(convert_to(jsonb_build_array(event_kind,domain_id,actor,target,source,computer,method,outcome)::text,'UTF8')),
                       event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc
                from daily order by 1,2
                on conflict(day,grouping_key) do update set event_count=current.event_count+excluded.event_count,
                    first_seen_utc=least(current.first_seen_utc,excluded.first_seen_utc),
                    last_seen_utc=greatest(current.last_seen_utc,excluded.last_seen_utc)
                where (current.event_kind,current.domain_id,current.actor,current.target,current.source,current.computer,current.method,current.outcome)
                    is not distinct from (excluded.event_kind,excluded.domain_id,excluded.actor,excluded.target,excluded.source,excluded.computer,excluded.method,excluded.outcome)
                returning day
            )
            select (select count(*) from daily),(select count(*) from summaries),
                (select count(*) from incoming i where exists(
                    select 1 from inserted h where h.time_created_utc=i.time_created_utc and h.event_id=i.event_id and h.source_sha256 is not null)
                    or exists(select 1 from public.event_hot h where h.time_created_utc=i.time_created_utc and h.event_id=i.event_id and h.source_sha256 is not null));
end $$;
revoke all on function public.write_short_events349(jsonb) from public;
grant execute on function public.write_short_events349(jsonb) to adlog_user,adlog_storage_worker;
insert into public.schema_migrations(version,name) values(349,'short_event_packet_admission');
reset role;
commit;
