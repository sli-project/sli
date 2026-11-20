begin;
select pg_advisory_xact_lock(hashtext('workstation_inventory_job_v287'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=287 and name='workstation_inventory_job')
       or exists(select 1 from public.schema_migrations where version>287)
       or exists(select 1 from sli_jobs.jobs where source_instance_id like 'workstations:inventory:%'
           and state in ('queued','leased','retry_wait')) then
        raise exception 'migration 287 rollback prerequisites failed';
    end if;
end $$;
grant create on schema public to sli_job_owner;
set local role sli_job_owner;
create or replace function public.core_workstation_job_binding_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select public.core_workstation_retention_binding_v192(p_spec)
        or public.core_workstation_projection_binding_v1(p_spec)
$$;
reset role;
revoke create on schema public from sli_job_owner;
drop function public.publish_workstation_inventory_v1(uuid,uuid,bigint,text,jsonb,text);
drop function public.read_workstation_inventory_input_v1(uuid,uuid,bigint);
drop function public.read_workstation_inventory_job_sources_v1();
drop function sli_plugin_workstations.inventory_inputs_v1(bigint);
drop function public.core_workstation_inventory_scope_v1(uuid,uuid,bigint);
drop function public.core_workstation_inventory_lease_v1(uuid,uuid,bigint);
drop function public.core_workstation_inventory_binding_v1(jsonb);
drop function public.core_workstation_inventory_receipt_v1(uuid,uuid,bigint,text,jsonb,jsonb,text);
do $$ begin
    if exists(select 1 from pg_roles where rolname='sli_workstation_inventory_owner') then
        execute 'drop owned by sli_workstation_inventory_owner';
        -- Roles are cluster-wide; another installed database may still own
        -- this feature's objects. Its authority must survive this DB rollback.
        if not exists(select 1 from pg_shdepend where refobjid=(select oid from pg_roles
            where rolname='sli_workstation_inventory_owner') and dbid<>0
            and dbid<>(select oid from pg_database where datname=current_database())) then
            execute 'drop role sli_workstation_inventory_owner';
        end if;
    end if;
end $$;
delete from public.schema_migrations where version=287 and name='workstation_inventory_job';
commit;
