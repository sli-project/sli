-- Read one committed/imported agent event without exposing the packet inbox.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_semantic_source_v190'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 190 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=189 and name='agent_snapshot_publication_health')
       or exists(select 1 from public.schema_migrations where version>=190) then
        raise exception 'migration 190 requires exact predecessor and unused version 190';
    end if;
end $$;
-- raw_log_files predates Storage V2 and is owned by the runtime/migration
-- account on installed databases. Only its packet pointer is needed here.
grant select(id,file_path) on public.raw_log_files to adlog_storage_owner;
set local role adlog_storage_owner;

create function public.read_agent_semantic_source_v190(p_event_id bigint)
returns jsonb language sql stable security definer
set search_path=pg_catalog,public as $$
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
      and receipt.module_id='sli.windows.ad-dc'
      and event.row->>'record_id'=core.event_record_id::text
      and event.row->>'event_id'=core.event_id::text
      and (event.row->>'time_created')::timestamptz=core.time_created_utc
      and event.row->>'computer_name'=inbox.packet->'header'->>'source'
      and event.row->>'channel'=inbox.packet->'header'->>'channel'
$$;
revoke all on function public.read_agent_semantic_source_v190(bigint) from public;
grant execute on function public.read_agent_semantic_source_v190(bigint) to adlog_semantic_worker;
insert into public.schema_migrations(version,name) values(190,'agent_semantic_source');
commit;
