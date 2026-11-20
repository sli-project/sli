begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_v2_replaces_legacy_catalog'));

do $$
begin
    if (select count(*) from report_registry_v4 where report_key in ('ad.gpo.review','ad.gpo.v2')) <> 2 then
        raise exception 'GPO catalog cutover requires exactly one legacy and one V2 registration';
    end if;
    if not exists (
        select 1 from report_registry_v4
        where report_key='ad.gpo.review' and name='GPO — example.local'
    ) then
        raise exception 'legacy GPO registration identity mismatch';
    end if;
    if not exists (
        select 1 from report_registry_v4
        where report_key='ad.gpo.v2' and name='Групповые политики — example.local'
    ) then
        raise exception 'GPO V2 registration identity mismatch';
    end if;
end $$;

insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select existing.package_id,'ad.gpo.v2',array['identity_basic','technical','security','privilege'],array['view','export'],existing.scope_json
from access_package_reports existing
where existing.report_key='ad.gpo.review'
on conflict(package_id,report_key) do update set
    field_categories=excluded.field_categories,
    allowed_actions=excluded.allowed_actions,
    scope_json=excluded.scope_json;

update report_registry_v4
set status='published'
where report_key='ad.gpo.v2';

update report_registry_v4
set status='retired'
where report_key='ad.gpo.review';

delete from access_package_reports
where report_key='ad.gpo.review';

insert into schema_migrations(version,name)
values(120,'gpo_v2_replaces_legacy_catalog')
on conflict(version) do update set name=excluded.name;

do $$
begin
    if not exists(select 1 from report_registry_v4 where report_key='ad.gpo.v2' and status='published') then
        raise exception 'ad.gpo.v2 is not published';
    end if;
    if not exists(select 1 from report_registry_v4 where report_key='ad.gpo.review' and status='retired') then
        raise exception 'ad.gpo.review was not retired';
    end if;
    if not exists(select 1 from access_package_reports where report_key='ad.gpo.v2') then
        raise exception 'ad.gpo.v2 package grant is missing';
    end if;
    if exists(select 1 from access_package_reports where report_key='ad.gpo.review') then
        raise exception 'legacy GPO package grants remain';
    end if;
end $$;

commit;
