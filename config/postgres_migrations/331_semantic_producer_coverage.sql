-- Compact, transactional producer decisions; no per-event skip receipts.
begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_producer_coverage_v331'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=330 and name='storage_lifecycle_agent_continuity')
       or exists(select 1 from public.schema_migrations where version>=331) then
        raise exception 'semantic_producer_coverage_331_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.semantic_producer_coverage (
    runtime_mode text not null check(runtime_mode in ('facts-v1','investigation-v1','findings-v1')),
    processor_version text not null,
    decided_ids int8multirange not null default '{}',
    primary key(runtime_mode,processor_version)
);
revoke all on public.semantic_producer_coverage from public;
grant select,insert,update on public.semantic_producer_coverage to adlog_storage_worker,adlog_semantic_worker;
grant select on public.semantic_producer_coverage to adlog_storage_lifecycle_delete;
-- A closed guard capability freezes missing as well as existing outbox rows.
create function public.lock_semantic_decisions_v331() returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    lock table public.semantic_processing_outbox in share mode nowait;
    lock table public.semantic_producer_coverage in share mode nowait;
end $$;
reset role;
grant select,update on public.semantic_producer_coverage to adlog_storage_lifecycle_guard;
-- SHARE requires table-level UPDATE, not v319's column-level row-lock grant.
-- The guard is NOLOGIN, unassumable, and exposes only the fixed lock function.
grant update on public.semantic_processing_outbox to adlog_storage_lifecycle_guard;
grant create on schema public to adlog_storage_lifecycle_guard;
alter function public.lock_semantic_decisions_v331() owner to adlog_storage_lifecycle_guard;
revoke create on schema public from adlog_storage_lifecycle_guard;
revoke all on function public.lock_semantic_decisions_v331() from public;
grant execute on function public.lock_semantic_decisions_v331() to adlog_storage_lifecycle_delete;
-- Old heartbeat checkpoints predate coverage receipts. Replay them once instead
-- of retroactively asserting decisions for unseen/late low-id source events.
update public.runtime_worker_heartbeats set details_json=details_json-'producer_cursors' where worker_name='semantic';
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(331,'semantic_producer_coverage');
reset role;
commit;
