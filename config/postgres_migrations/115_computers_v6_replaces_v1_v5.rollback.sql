begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_v6_replaces_v1_v5_rollback'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=115 and name='computers_v6_replaces_v1_v5'
    ) then
        raise exception 'computers report cutover rollback requires migration 115';
    end if;
    if (select count(*) from domains where lower(fqdn)='example.local') <> 1 then
        raise exception 'computers report cutover rollback requires exactly one example.local domain';
    end if;
end $$;

update report_registry_v4
set status='published'
where report_key in ('ad.computers','ad.computers.v5');

update report_registry_v4
set name='Компьютеры — по референсу', status='published'
where report_key='ad.computers.v6' and version=1;

insert into access_package_reports(
    package_id,report_key,field_categories,allowed_actions,scope_json
)
select
    package.id,
    report.report_key,
    array['identity_basic','technical','security'],
    array['view','export'],
    jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))
from access_packages package
cross join domains domain
cross join (values ('ad.computers'::text),('ad.computers.v5'::text)) report(report_key)
where package.package_key='ad_auditor'
  and lower(domain.fqdn)='example.local'
on conflict(package_id,report_key) do update set
    field_categories=excluded.field_categories,
    allowed_actions=excluded.allowed_actions,
    scope_json=excluded.scope_json;

delete from schema_migrations where version=115;

do $$
begin
    if exists(
        select 1 from report_registry_v4
        where report_key in ('ad.computers','ad.computers.v5') and status <> 'published'
    ) then
        raise exception 'legacy computers reports were not republished';
    end if;
    if (
        select name='Компьютеры — по референсу' and status='published'
        from report_registry_v4
        where report_key='ad.computers.v6' and version=1
    ) is not true then
        raise exception 'ad.computers.v6 reference name was not restored';
    end if;
    if (
        select count(*) from access_package_reports
        where report_key in ('ad.computers','ad.computers.v5')
    ) < 2 then
        raise exception 'legacy computers report package grants were not restored';
    end if;
end $$;

commit;
