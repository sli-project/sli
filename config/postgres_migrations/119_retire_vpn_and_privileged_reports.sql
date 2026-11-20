begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_hide_legacy_vpn_retire_privileged'));

do $$
begin
    if (select count(*) from report_registry_v4 where report_key in ('vpn.audit','ad.privileged')) <> 2 then
        raise exception 'catalog correction requires exactly one vpn.audit and one ad.privileged registration';
    end if;
    if not exists (
        select 1 from report_registry_v4
        where report_key='vpn.audit' and name='VPN-доступ и актуальность владельцев'
    ) then
        raise exception 'vpn.audit registration identity mismatch';
    end if;
    if not exists (
        select 1 from report_registry_v4
        where report_key='ad.privileged' and name='Привилегированные учётные записи'
    ) then
        raise exception 'ad.privileged registration identity mismatch';
    end if;
end $$;

-- vpn.audit remains the internal access anchor for the working vpn.connections report.
update report_registry_v4
set status='published'
where report_key='vpn.audit';

update report_registry_v4
set status='retired'
where report_key='ad.privileged';

delete from access_package_reports
where report_key='ad.privileged';

with mapping(package_key,report_key,fields,actions) as (values
    ('ad_auditor','vpn.audit',array['identity_basic','technical','security','privilege','hr','contact'],array['view','create_task','export'])
)
insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select package.id,mapping.report_key,mapping.fields,mapping.actions,'{"kind":"all"}'::jsonb
from mapping
join access_packages package on package.package_key=mapping.package_key
on conflict(package_id,report_key) do update set
    field_categories=excluded.field_categories,
    allowed_actions=excluded.allowed_actions,
    scope_json=excluded.scope_json;

insert into schema_migrations(version,name)
values(119,'hide_legacy_vpn_retire_privileged_report')
on conflict(version) do update set name=excluded.name;

do $$
begin
    if not exists(select 1 from report_registry_v4 where report_key='vpn.audit' and status='published') then
        raise exception 'vpn.audit access anchor is not published';
    end if;
    if not exists(select 1 from report_registry_v4 where report_key='ad.privileged' and status='retired') then
        raise exception 'ad.privileged was not retired';
    end if;
    if not exists(select 1 from access_package_reports where report_key='vpn.audit') then
        raise exception 'vpn.audit package grant is missing';
    end if;
    if exists(select 1 from access_package_reports where report_key='ad.privileged') then
        raise exception 'ad.privileged package grants remain';
    end if;
end $$;

commit;
