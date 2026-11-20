begin;
select pg_advisory_xact_lock(hashtext('sli_agent_receipt_summary391'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=390 and name='agent_console_enrollment')
       or exists(select 1 from public.schema_migrations where version>=391) then
        raise exception 'agent_receipt_summary391_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.sli_agents add column receipt_summary jsonb not null default '{}'::jsonb
    check (jsonb_typeof(receipt_summary)='object');
grant select (receipt_summary), update (receipt_summary) on public.sli_agents to adlog_storage_lifecycle_delete;
grant select (packet_id) on public.sli_agent_snapshot_chunks to adlog_storage_lifecycle_delete;
grant delete on public.sli_agent_receipts to adlog_storage_lifecycle_delete;

insert into public.schema_migrations(version,name) values(391,'agent_receipt_summary');
reset role;
commit;
