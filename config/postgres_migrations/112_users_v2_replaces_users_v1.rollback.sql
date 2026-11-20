begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_users_v2_replaces_users_v1_rollback'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=112 and name='users_v2_replaces_users_v1'
    ) then
        raise exception 'users report cutover rollback requires migration 112';
    end if;
    if (select count(*) from domains where lower(fqdn)='example.local') <> 1 then
        raise exception 'users report cutover rollback requires exactly one example.local domain';
    end if;
end $$;

update report_registry_v4
set status='published'
where report_key='ad.users';

update report_registry_v4
set name='Пользователи — по референсу', status='published'
where report_key='ad.users.v2' and version=1;

update report_registry_v4
set purpose='Отдельный интерактивный evidence-first отчёт по пользователям AD на основе утверждённого reference V1.1; существующий ad.users не изменяется'
where report_key='ad.users.v2' and version=1;

insert into access_package_reports(
    package_id,report_key,field_categories,allowed_actions,scope_json
)
select
    package.id,
    'ad.users',
    array['identity_basic','technical','security','privilege','hr','contact'],
    array['view','export','start_case','accept_risk'],
    jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))
from access_packages package
cross join domains domain
where package.package_key='ad_auditor'
  and lower(domain.fqdn)='example.local'
on conflict(package_id,report_key) do update set
    field_categories=excluded.field_categories,
    allowed_actions=excluded.allowed_actions,
    scope_json=excluded.scope_json;

delete from schema_migrations
where version=112;

do $$
begin
    if (select status from report_registry_v4 where report_key='ad.users') <> 'published' then
        raise exception 'ad.users was not republished';
    end if;
    if (
        select
            name='Пользователи — по референсу'
            and purpose='Отдельный интерактивный evidence-first отчёт по пользователям AD на основе утверждённого reference V1.1; существующий ad.users не изменяется'
            and status='published'
        from report_registry_v4
        where report_key='ad.users.v2' and version=1
    ) is not true then
        raise exception 'ad.users.v2 name was not restored';
    end if;
    if not exists(select 1 from access_package_reports where report_key='ad.users') then
        raise exception 'ad.users package grant was not restored';
    end if;
end $$;

commit;
