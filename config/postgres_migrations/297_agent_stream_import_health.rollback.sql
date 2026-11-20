-- Explicit operator rollback only; never invoked by runtime.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_stream_import_health_v297'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
                     where version=297 and name='agent_stream_import_health')
       or exists(select 1 from public.schema_migrations where version>297) then
        raise exception 'migration 297 rollback prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
lock table public.sli_agent_packet_inbox in share row exclusive mode;
drop trigger sli_agent_stream_import_health_write on public.sli_agent_packet_inbox;
drop function public.record_agent_stream_import_v297();
drop table public.sli_agent_stream_import_health;
delete from public.schema_migrations where version=297 and name='agent_stream_import_health';
commit;
