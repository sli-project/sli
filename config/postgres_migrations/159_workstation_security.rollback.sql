-- Rollback refuses evidence or grants; disabling navigation preserves history.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_security_v159'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'rollback 159 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=159 and name='workstation_security')
       or exists(select 1 from public.schema_migrations where version>159) then
        raise exception 'rollback 159 prerequisites failed';
    end if;
    if exists(select 1 from sli_plugin_workstations.observations)
       or exists(select 1 from public.access_package_reports where report_key like 'workstations.%')
       or exists(select 1 from public.access_report_assignments where report_key like 'workstations.%') then
        raise exception 'rollback 159 refuses evidence or assigned report grants';
    end if;
end $$;
delete from public.report_registry_v4 where owner_name='sli.workstations' and version=1;
delete from public.report_datasets_v4 where dataset_key='workstations.security' and version=1;
drop table sli_plugin_workstations.observations;
drop schema sli_plugin_workstations;
revoke select(key,value) on public.platform_settings from adlog_workstations_retention;
drop role adlog_workstations_retention;
delete from public.schema_migrations where version=159 and name='workstation_security';
commit;
