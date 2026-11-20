-- The server file collector publishes attested native rows into Storage V2 too.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_semantic_source_v190'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=200 and name='agent_gpo_change_history')
       or not exists(select 1 from public.schema_migrations where version=190 and name='agent_semantic_source')
       or exists(select 1 from public.schema_migrations where version>=201) then
        raise exception 'migration 201 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
create or replace function public.read_agent_semantic_source_v190(p_event_id bigint)
returns jsonb language sql stable security definer set search_path=pg_catalog,public as $$
    select case when count(*)=1
        then jsonb_agg(jsonb_build_object('core',to_jsonb(core),'event_row',event.row))->0 end
    from public.events_v2_core core
    join public.raw_log_files raw on raw.id=core.raw_log_file_id
    join public.sli_agent_packet_inbox inbox on inbox.packet_id=case
        when raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        then substr(raw.file_path,14)::uuid end
    join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id
    cross join lateral jsonb_array_elements(inbox.event_rows) event(row)
    where core.id=p_event_id and p_event_id>0
      and inbox.imported_at is not null and receipt.receipt->>'status'='committed'
      and inbox.envelope=receipt.envelope
      and (receipt.module_id='sli.windows.ad-dc' or (receipt.module_id='sli.file-audit'
        and inbox.packet->'header'->>'channel'='Security'
        and core.event_id in (4608,4624,4625,4634,4719,1102,4656,4658,4659,4660,4663,4664,4670,4907,5140,5142,5143,5144,5145,5168)))
      and event.row->>'record_id'=core.event_record_id::text
      and event.row->>'event_id'=core.event_id::text
      and (event.row->>'time_created')::timestamptz=core.time_created_utc
      and event.row->>'computer_name'=inbox.packet->'header'->>'source'
      and event.row->>'channel'=inbox.packet->'header'->>'channel'
$$;
revoke all on function public.read_agent_semantic_source_v190(bigint) from public;
grant execute on function public.read_agent_semantic_source_v190(bigint) to adlog_semantic_worker;
insert into public.schema_migrations(version,name) values(201,'file_audit_semantic_source');
commit;
