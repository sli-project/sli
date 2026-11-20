begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_users_report_domain_scope'));

do $$
begin
    if (select count(*) from domains domain where lower(domain.fqdn)='example.local') <> 1 then
        raise exception 'users report requires exactly one registered example.local DNS domain';
    end if;
end $$;

update access_package_reports assignment
set scope_json=jsonb_build_object(
    'kind','domain',
    'ids',jsonb_build_array(domain.id)
)
from domains domain
where assignment.report_key='ad.users'
  and lower(domain.fqdn)='example.local';

insert into schema_migrations(version,name) values(100,'users_report_domain_scope')
on conflict(version) do update set name=excluded.name;

commit;
