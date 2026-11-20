begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_hide_legacy_vpn_retire_privileged_rollback'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=119 and name='hide_legacy_vpn_retire_privileged_report'
    ) then
        raise exception 'catalog correction rollback requires migration 119';
    end if;
end $$;

update report_registry_v4
set status='published'
where report_key in ('vpn.audit','ad.privileged');

with mapping(package_key,report_key,fields,actions) as (values
    ('ad_auditor','vpn.audit',array['identity_basic','technical','security','privilege','hr','contact'],array['view','create_task','export']),
    ('ad_auditor','ad.privileged',array['identity_basic','security','privilege','technical'],array['view','create_task','export'])
)
insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select package.id,mapping.report_key,mapping.fields,mapping.actions,'{"kind":"all"}'::jsonb
from mapping
join access_packages package on package.package_key=mapping.package_key
on conflict(package_id,report_key) do update set
    field_categories=excluded.field_categories,
    allowed_actions=excluded.allowed_actions,
    scope_json=excluded.scope_json;

delete from schema_migrations
where version=119;

do $$
begin
    if (select count(*) from report_registry_v4 where report_key in ('vpn.audit','ad.privileged') and status='published') <> 2 then
        raise exception 'catalog reports were not republished';
    end if;
    if (select count(*) from access_package_reports where report_key in ('vpn.audit','ad.privileged')) < 2 then
        raise exception 'package grants were not restored';
    end if;
end $$;

commit;
