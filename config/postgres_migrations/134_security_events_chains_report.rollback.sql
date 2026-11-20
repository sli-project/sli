begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_security_events_chains_report_v134'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 134 and name = 'security_events_chains_report'
  ) then
    raise exception 'migration 134 rollback requires exact marker';
  end if;
  if exists (
    select 1
    from public.access_subject_packages assignment
    join public.access_packages package on package.id=assignment.package_id
    where package.package_key='security_investigation_reader'
  ) then
    raise exception 'migration 134 rollback refuses assigned security investigation package';
  end if;
end
$$;

delete from public.access_package_reports
where report_key='security.events.chains';

delete from public.report_registry_v4
where report_key='security.events.chains' and version=1;

delete from public.report_datasets_v4
where dataset_key='security.events.atomic' and version=1;

delete from public.access_role_packages role_package
using public.access_packages package
where role_package.package_id=package.id
  and role_package.coarse_role='admin'
  and package.package_key='security_investigation_reader';

delete from public.access_packages
where package_key='security_investigation_reader';

delete from public.schema_migrations
where version = 134 and name = 'security_events_chains_report';

commit;
