begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_import_isolation376'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=375 and name='password_first_batch')
       or exists(select 1 from public.schema_migrations where version>=376) then
        raise exception 'workstation_import_isolation376_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Expose only the activation bit to purpose-specific workers. They retain no
-- direct access to the lifecycle registry or the general plugin-state reader.
create function public.workstation_runtime_enabled_v376() returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.plugin_installations_v1
        where plugin_id='sli.workstations' and package_lifecycle='registered'
          and desired_activation='enabled_manual')
$$;
revoke all on function public.workstation_runtime_enabled_v376() from public;
grant execute on function public.workstation_runtime_enabled_v376()
    to adlog_user,sli_job_dispatcher_light,sli_job_executor_light,sli_job_publisher_light;
insert into public.schema_migrations(version,name) values(376,'workstation_import_isolation');
reset role;
commit;
