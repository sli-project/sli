-- Serialize v321 evidence publication with hot-layer deletion.
begin;
select pg_advisory_xact_lock(hashtext('sli_storage_lifecycle_evidence_lock_v328'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=327 and name='detector_remaining_paths')
       or exists(select 1 from public.schema_migrations where version>=328) then
        raise exception 'storage_lifecycle_328_preflight' using errcode='55000';
    end if;
end $$;
-- The guard has no members. Transfer ownership only inside this DDL transaction
-- so the replacement is defined under the canonical storage owner.
alter function public.lock_storage_lifecycle_tables_v319(text) owner to adlog_storage_owner;
set local role adlog_storage_owner;
create or replace function public.lock_storage_lifecycle_tables_v319(p_scope text) returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    case p_scope
    when 'history' then lock table public.events_v2_core in row exclusive mode nowait;
    when 'evidence' then
        lock table public.event_entity_link_blocks_v2 in share mode nowait;
        lock table public.investigation_events in share mode nowait;
        lock table public.normalized_events in share mode nowait;
        lock table public.canonical_action_evidence in share mode nowait;
    when 'file_actions' then lock table sli_plugin_file_audit.rule_actions in share mode nowait;
    when 'file' then
        lock table sli_plugin_file_audit.retention_holds in share mode nowait;
        lock table public.investigation_events in share mode nowait;
        lock table sli_plugin_file_audit.rule_snapshots in share mode nowait;
        lock table sli_plugin_file_audit.rule_actions in share mode nowait;
    else raise exception 'storage_lifecycle_lock_scope_invalid' using errcode='22023';
    end case;
end $$;
reset role;
alter function public.lock_storage_lifecycle_tables_v319(text) owner to adlog_storage_lifecycle_guard;
-- SHARE requires UPDATE privilege; the NOLOGIN guard remains unassumable.
grant update on public.normalized_events,public.canonical_action_evidence to adlog_storage_lifecycle_guard;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(328,'storage_lifecycle_evidence_lock');
reset role;
commit;
