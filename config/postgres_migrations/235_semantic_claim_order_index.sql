-- Keep bounded semantic claims ordered without sorting the entire live backlog.
begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_claim_order_index_v235'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=233 and name='ad_operation_credentials')
       or exists(select 1 from public.schema_migrations where version>=235) then
        raise exception 'migration 235 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- Version and repair-scope filters remain in the claim. Expired leases still
-- compete in the same FIFO order, with FOR UPDATE SKIP LOCKED at execution.
create index idx_semantic_outbox_ordered_claim
    on public.semantic_processing_outbox
       (semantic_contract_version,processor_id,available_at,created_at,job_id)
    where status in ('queued','failed','leased') and attempt_count < max_attempts;

reset role;
insert into public.schema_migrations(version,name) values(235,'semantic_claim_order_index');
commit;
