-- Restore exact definitions and authority before removing acceleration indexes.
begin;
select pg_advisory_xact_lock(hashtext('sli_detector_query_paths_v324'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=323 and name='workstation_projection_drain')
       or to_regclass('public.detector_definitions324') is null
       or exists(select 1 from public.schema_migrations where version>324) then
        raise exception 'detector_query_paths_324_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record;begin
    for r in select * from public.detector_definitions324 loop execute r.definition;end loop;
end $$;
drop view if exists public.detector_active_entities324;
-- Only disposable watch acceleration is removed. Findings/checkpoints survive.
with old as (delete from public.semantic_source_cursor320 where kind='watch' returning *)
delete from public.semantic_source_pending320 p using old c
where (p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint)=
      (c.principal_oid,c.principal_name,c.scope_key,c.kind,c.checkpoint);
alter table public.semantic_source_cursor320 drop column if exists pending_after324;
reset role;
commit;
drop index concurrently if exists public.detector_receipt_gap324;
drop index concurrently if exists public.detector_inbox_pending324;
drop index concurrently if exists sli_plugin_file_audit.detector_file_handle324;
drop index concurrently if exists sli_plugin_file_audit.detector_file_boundary324;
drop index concurrently if exists public.detector_directory_domain324;
drop index concurrently if exists public.detector_native_scope324;
drop index concurrently if exists public.detector_native_packet324;
begin;
set local role adlog_storage_owner;
drop table public.detector_definitions324;
delete from public.schema_migrations where version=324 and name='detector_query_paths';
reset role;
commit;
