-- Exact prefix/fallback receipt facts; no producer state or access changes.
-- Ordinary transactional index builds take write-blocking locks and require
-- additional disk space. Apply through the existing controlled update path.
begin;
select pg_advisory_xact_lock(hashtext('sli_plugin_receipt_import_lookup_v282'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
                     where version=281 and name='agent_registration_hostname')
       or exists(select 1 from public.schema_migrations where version>=282) then
        raise exception 'migration 282 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

create index sli_agent_receipts_module_received
    on public.sli_agent_receipts(module_id,received_at desc) include(packet_id);
create index sli_agent_inbox_imported_prefix
    on public.sli_agent_packet_inbox(imported_at desc,packet_id)
    where imported_at is not null;

reset role;
insert into public.schema_migrations(version,name) values(282,'plugin_receipt_import_lookup');
commit;
