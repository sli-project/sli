begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_v2_replaces_legacy_catalog_rollback'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=120 and name='gpo_v2_replaces_legacy_catalog'
    ) then
        raise exception 'GPO catalog cutover rollback requires migration 120';
    end if;
end $$;

update report_registry_v4
set status='published'
where report_key='ad.gpo.review';

insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select existing.package_id,'ad.gpo.review',array['identity_basic','security','technical'],array['view','create_task','export'],existing.scope_json
from access_package_reports existing
where existing.report_key='ad.gpo.v2'
on conflict(package_id,report_key) do update set
    field_categories=excluded.field_categories,
    allowed_actions=excluded.allowed_actions,
    scope_json=excluded.scope_json;

delete from schema_migrations
where version=120;

do $$
begin
    if not exists(select 1 from report_registry_v4 where report_key='ad.gpo.review' and status='published') then
        raise exception 'legacy GPO report was not republished';
    end if;
    if not exists(select 1 from access_package_reports where report_key='ad.gpo.review') then
        raise exception 'legacy GPO package grant was not restored';
    end if;
end $$;

commit;
