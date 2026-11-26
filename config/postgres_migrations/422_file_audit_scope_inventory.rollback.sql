begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_file_audit_scope_inventory422'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or exists(select 1 from public.schema_migrations where version>422)
       or not exists(select 1 from public.schema_migrations where version=422 and name='file_audit_scope_inventory') then
        raise exception 'file_audit_scope_inventory422_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_file_audit_owner;
drop trigger file_audit_catalog_inventory422 on sli_plugin_file_audit.access_snapshots;
drop trigger file_audit_policy_source422 on sli_plugin_file_audit.policy_revisions;

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
reset role;
set local role adlog_storage_owner;
revoke select(source_instance_id,source_kind,display_name) on public.acquisition_source_instances from adlog_file_audit_owner;
drop function public.store_file_audit_catalog_inventory422();
drop function public.register_file_audit_policy_source422();
drop function public.register_file_audit_source422(uuid,text);
drop trigger file_audit_catalog_source422 on public.sli_file_audit_smb_catalog;
drop function public.clear_file_audit_catalog_source422();
alter table public.sli_file_audit_smb_catalog drop column scope_inventory,drop column inventory_revision;
revoke select(agent_id,source_id,supported_until,request_id,expires_at,result_status,native_status,shares),
       insert(agent_id,source_id,supported_until),
       update(source_id,supported_until,request_id,expires_at,result_status,native_status,shares)
    on public.sli_file_audit_smb_catalog from adlog_user;
grant select,insert,update on public.sli_file_audit_smb_catalog to adlog_user;
delete from public.acquisition_source_instances where organization_scope='platform'
    and source_kind='sli.file-audit.server' and adapter_binding='sli.file-audit'
    and endpoint_identity=source_instance_id;
reset role;
delete from public.schema_migrations where version=422 and name='file_audit_scope_inventory';
commit;
