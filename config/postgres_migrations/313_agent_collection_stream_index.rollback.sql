-- Operator rollback: restore the pre-313 reader before dropping its index.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_agent_collection_stream_index_v313'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=313 and name='agent_collection_stream_index')
       or exists(select 1 from public.schema_migrations where version>313) then
        raise exception 'agent_collection_stream_index_313_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
lock table public.sli_agent_packet_inbox in share row exclusive mode;
drop trigger sli_agent_stream_receipts_write on public.sli_agent_packet_inbox;
drop function public.record_agent_stream_receipt_v313();
drop table public.sli_agent_stream_receipts;
delete from public.schema_migrations where version=313 and name='agent_collection_stream_index';
reset role;
commit;
