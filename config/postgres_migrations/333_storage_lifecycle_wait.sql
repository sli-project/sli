begin;
select pg_advisory_xact_lock(hashtext('sli_storage_lifecycle_wait_v333'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=332 and name='semantic_backfill_window')
       or exists(select 1 from public.schema_migrations where version>=333) then
        raise exception 'storage_lifecycle_wait_333_preflight' using errcode='55000';
    end if;
end $$;
alter function public.lock_storage_lifecycle_tables_v319(text) owner to adlog_storage_owner;
alter function public.lock_semantic_decisions_v331() owner to adlog_storage_owner;
alter function public.lock_storage_lifecycle_events_v319(bigint[]) owner to adlog_storage_owner;
alter function public.lock_storage_lifecycle_facts_v319(bigint[]) owner to adlog_storage_owner;
alter function public.lock_storage_lifecycle_semantic_v319(bigint[]) owner to adlog_storage_owner;
set local role adlog_storage_owner;
create or replace function public.lock_storage_lifecycle_tables_v319(p_scope text) returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    case p_scope
    when 'history' then lock table public.events_v2_core in row exclusive mode;
    when 'evidence' then
        lock table public.event_entity_link_blocks_v2 in share mode;
        lock table public.investigation_events in share mode;
        lock table public.normalized_events in share mode;
        lock table public.canonical_action_evidence in share mode;
    when 'continuity' then
        lock table public.raw_log_files in share mode;
        lock table public.sli_agent_receipts in share mode;
        lock table public.sli_agent_packet_inbox in share mode;
        lock table public.source_capture_continuity_declarations in share mode;
    when 'file_actions' then lock table sli_plugin_file_audit.rule_actions in share mode;
    when 'file' then
        lock table sli_plugin_file_audit.retention_holds in share mode;
        lock table public.investigation_events in share mode;
        lock table sli_plugin_file_audit.rule_snapshots in share mode;
        lock table sli_plugin_file_audit.rule_actions in share mode;
    else raise exception 'storage_lifecycle_lock_scope_invalid' using errcode='22023';
    end case;
end $$;
create or replace function public.lock_semantic_decisions_v331() returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    lock table public.semantic_processing_outbox in share mode;
    lock table public.semantic_producer_coverage in share mode;
end $$;
create or replace function public.lock_storage_lifecycle_events_v319(p_ids bigint[]) returns setof public.events_v2_core
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if cardinality(p_ids)>1000 then raise exception 'storage_lifecycle_lock_budget_invalid'; end if;
    return query select t.* from public.events_v2_core t where t.id=any(p_ids) order by t.id for update;
end $$;
create or replace function public.lock_storage_lifecycle_facts_v319(p_ids bigint[]) returns setof public.event_facts_v2
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if cardinality(p_ids)>1000 then raise exception 'storage_lifecycle_lock_budget_invalid'; end if;
    return query select t.* from public.event_facts_v2 t where t.event_id=any(p_ids) order by t.event_id for update;
end $$;
create or replace function public.lock_storage_lifecycle_semantic_v319(p_ids bigint[]) returns setof public.semantic_processing_outbox
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if cardinality(p_ids)>1000 then raise exception 'storage_lifecycle_lock_budget_invalid'; end if;
    return query select t.* from public.semantic_processing_outbox t where t.source_event_id=any(p_ids) order by t.source_event_id for update;
end $$;
reset role;
alter function public.lock_storage_lifecycle_events_v319(bigint[]) owner to adlog_storage_lifecycle_guard;
alter function public.lock_storage_lifecycle_facts_v319(bigint[]) owner to adlog_storage_lifecycle_guard;
alter function public.lock_storage_lifecycle_semantic_v319(bigint[]) owner to adlog_storage_lifecycle_guard;
alter function public.lock_storage_lifecycle_tables_v319(text) owner to adlog_storage_lifecycle_guard;
alter function public.lock_semantic_decisions_v331() owner to adlog_storage_lifecycle_guard;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(333,'storage_lifecycle_wait');
reset role;
commit;
