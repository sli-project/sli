begin;
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') or exists(select 1 from public.schema_migrations where version>349) then
        raise exception 'short_event_packet_admission349_rollback_preflight' using errcode='55000';
    end if;
end $$;
-- Refuse rollback if it would orphan a short-only projected state.
do $$ begin
    if exists(select 1 from public.entity_state_current s where not exists(select 1 from public.events_v2_core e where e.id=s.source_event_db_id))
       or exists(select 1 from public.entity_states s where s.evidence_event_id is not null and not exists(select 1 from public.events_v2_core e where e.id=s.evidence_event_id)) then
        raise exception 'short_event_packet_admission349_retained_states' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
alter sequence public.storage_v2_event_id_seq owned by public.events_v2_core.id;
alter table public.entity_state_current drop constraint entity_state_current_source_event_db_id_fkey;
alter table public.entity_state_current add constraint entity_state_current_source_event_db_id_fkey
    foreign key(source_event_db_id) references public.events_v2_core(id) on delete restrict;
reset role;
alter table public.entity_states drop constraint entity_states_evidence_event_id_v2_fkey;
alter table public.entity_states add constraint entity_states_evidence_event_id_v2_fkey
    foreign key(evidence_event_id) references public.events_v2_core(id);
set local role adlog_storage_owner;
do $patch349$ declare definition text; begin
    select pg_get_functiondef('public.link_finding_evidence_ref(bigint,uuid,text,text,text,text,text,text,text)'::regprocedure) into strict definition;
    execute replace(definition,$marker$            v_added:=public.copy_finding_event337(p_finding,p_native,p_sha256,'semantic_scenario','enabled semantic scenario evidence');
$marker$,$marker$            v_added:=public.copy_finding_event337(p_finding,p_native,p_sha256,'semantic_scenario','enabled semantic scenario evidence');
            -- S3 still dual-writes the old store. Mirror its link only while
            -- that exact old event exists, so the single legacy switch can
            -- also display problems created on the short path.
            insert into public.finding_evidence(finding_id,event_id,evidence_role,note)
            select p_finding,e.id,'semantic_scenario','enabled semantic scenario evidence' from public.events_v2_core e
            where e.id=p_native::bigint and encode(e.normalized_hash,'hex')=p_sha256
            on conflict(finding_id,event_id,evidence_role) do nothing;
$marker$);
end $patch349$;
drop function public.write_short_events349(jsonb);
create or replace function public.attest_short_event337() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare origin jsonb; digest bytea; record_id bigint;
begin
    new.method:=new.method-'$origin'; new.source_sha256:=null; new.event_record_id:=null;
    select jsonb_build_object('installation_id',installation.installation_id::text,'plugin_id','sli.windows.ad-dc',
        'source_instance_id',i.envelope->>'source_instance_id','source_generation',i.envelope->>'generation',
        'collection_scope_id','','agent_id',r.agent_id::text,'log_source_id',e.log_source_id),e.normalized_hash,e.event_record_id
    into origin,digest,record_id
    from public.events_v2_core e join public.raw_log_files raw on raw.id=e.raw_log_file_id
    join public.sli_agent_packet_inbox i on raw.file_path='agent-packet:'||i.packet_id::text
    join public.sli_agent_receipts r on r.packet_id=i.packet_id and r.envelope=i.envelope
    cross join public.semantic_default_installation installation
    where e.id=new.event_id and e.event_id=new.event_kind and e.time_created_utc=new.time_created_utc
      and e.domain_id=new.domain_id and e.server_id::text=new.method->>'$server_id'
      and r.module_id='sli.windows.ad-dc' and r.receipt->>'status'='committed'
      and i.envelope->>'agent_id'=r.agent_id::text
      and i.collection_channel=new.method->>'$channel';
    if found then new.method:=new.method||jsonb_build_object('$origin',origin); new.source_sha256:=digest; new.event_record_id:=record_id; end if;
    return new;
end $$;
revoke all on function public.attest_short_event337() from public;
delete from public.schema_migrations where version=349 and name='short_event_packet_admission';
reset role;
revoke select(id,fqdn,role) on public.servers from adlog_storage_owner;
revoke select(id,name) on public.log_sources from adlog_storage_owner;
commit;
