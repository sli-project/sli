begin;
select pg_advisory_xact_lock(hashtext('sli_agent_receipt_summary391'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=391 and name='agent_receipt_summary')
       or exists(select 1 from public.schema_migrations where version>391) then
        raise exception 'agent_receipt_summary391_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

lock table public.sli_agents in access exclusive mode;
do $$ begin
    -- Compacted receipts have already been deleted. Keep their summaries.
    if exists(select 1 from public.sli_agents where receipt_summary <> '{}'::jsonb) then
        raise exception 'agent_receipt_summary391_rollback_compacted_receipts' using errcode='55000';
    end if;
end $$;
revoke select (packet_id) on public.sli_agent_snapshot_chunks from adlog_storage_lifecycle_delete;
revoke delete on public.sli_agent_receipts from adlog_storage_lifecycle_delete;
alter table public.sli_agents drop column receipt_summary;

delete from public.schema_migrations where version=391 and name='agent_receipt_summary';
reset role;
commit;
