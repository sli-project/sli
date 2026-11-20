-- Add the existing file-discovery equality lookup; preserve all source authority.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_source_lookup_index_v266'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=265 and name='file_acl_semantic_bridge')
       or exists(select 1 from public.schema_migrations where version>=266) then
        raise exception 'migration 266 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_file_audit_owner;
create index file_audit_source_lookup_index
    on sli_plugin_file_audit.observations(agent_id,collection_scope_id,policy_revision);
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(266,'file_audit_source_lookup_index');
commit;
