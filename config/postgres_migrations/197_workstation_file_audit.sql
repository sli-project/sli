-- Shared file-audit reports retain the administrator-authored source kind.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_file_audit_v197'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=196 and name='agent_msi_update_result')
       or exists(select 1 from public.schema_migrations where version>=197) then
        raise exception 'migration 197 prerequisites failed';
    end if;
end $$;
set local role adlog_file_audit_owner;
create or replace function sli_plugin_file_audit.report_roots()
returns jsonb language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select coalesce(jsonb_agg(q.root order by q.agent_id,q.source_instance_id,q.scope_id),'[]'::jsonb)
    from (
        select p.agent_id,p.source_instance_id,r->>'collection_scope_id' as scope_id,
            r||jsonb_build_object('agent_id',p.agent_id,'source_instance_id',p.source_instance_id,
                'source_name',coalesce(p.policy->>'source_name',p.source_instance_id),
                'source_kind',coalesce(p.policy->>'source_kind','server'),'policy_revision',p.revision) as root
        from (select distinct on(agent_id,source_instance_id) *
              from sli_plugin_file_audit.policy_revisions order by agent_id,source_instance_id,revision desc) p,
             jsonb_array_elements(p.policy->'roots') r
        order by p.agent_id,p.source_instance_id,r->>'collection_scope_id' limit 1001
    ) q
$$;
revoke all on function sli_plugin_file_audit.report_roots() from public;
grant execute on function sli_plugin_file_audit.report_roots() to adlog_user;
reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(197,'workstation_file_audit');
commit;
