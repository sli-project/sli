begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_summary_v320'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=320 and name='semantic_import_summary')
       or exists(select 1 from public.schema_migrations where version>320) then
        raise exception 'semantic_summary_320_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record;begin
    for r in select * from public.semantic_summary_definitions320 loop execute r.definition;end loop;
end $$;
-- DROP TRIGGER requires the table owner, just like the forward DDL boundary.
reset role;
do $$ declare t text;begin
    foreach t in array array['sli_agent_packet_inbox','sli_agent_receipts','raw_log_files','events_v2_core','normalized_events'] loop
        execute format('drop trigger semantic_import_insert320 on public.%I',t);
        execute format('drop trigger semantic_import_update320 on public.%I',t);
        execute format('drop trigger semantic_import_old320 on public.%I',t);
        execute format('drop trigger semantic_import_delete320 on public.%I',t);
    end loop;
end $$;
set local role adlog_storage_owner;
drop function public.semantic_source_candidates320(uuid,jsonb,text,text,timestamptz,timestamptz,uuid);
drop function public.semantic_source_active320(uuid,text,text);
drop function public.semantic_channels_refresh320();
drop function public.semantic_t109_full320();
drop function public.semantic_default_full320();
drop function public.semantic_import_progress320();
drop function public.semantic_import_refresh320();
drop function public.semantic_default_refresh320();
drop function public.semantic_import_notify320();
drop index public.semantic_seen_scope320;
drop table public.semantic_source_pending320,public.semantic_source_cursor320,public.semantic_event_facts320,
    public.semantic_stream_facts320,public.semantic_packet_facts320,public.semantic_import_dirty320,
    public.semantic_import_state320,public.semantic_default_dirty320,public.semantic_default_state320,public.semantic_summary_definitions320;
delete from public.schema_migrations where version=320 and name='semantic_import_summary';
reset role;
commit;
