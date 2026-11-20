begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_users_v2_replaces_users_v1'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=111 and name='users_report_v2_source_snapshot_identity'
    ) then
        raise exception 'users report cutover requires migration 111';
    end if;
    if (select count(*) from report_registry_v4 where report_key='ad.users') <> 1 then
        raise exception 'users report cutover requires exactly one ad.users registration';
    end if;
    if (select count(*) from report_registry_v4 where report_key='ad.users.v2' and version=1) <> 1 then
        raise exception 'users report cutover requires ad.users.v2 version 1';
    end if;
end $$;

update report_registry_v4
set name='Пользователи — example.local', status='published'
where report_key='ad.users.v2' and version=1;

update report_registry_v4
set purpose='Интерактивный evidence-first отчёт по пользователям AD на основе утверждённого reference V1.1'
where report_key='ad.users.v2' and version=1;

update report_registry_v4
set status='retired'
where report_key='ad.users';

delete from access_package_reports
where report_key='ad.users';

insert into schema_migrations(version,name)
values(112,'users_v2_replaces_users_v1')
on conflict(version) do update set name=excluded.name;

do $$
begin
    if (select status from report_registry_v4 where report_key='ad.users') <> 'retired' then
        raise exception 'ad.users was not retired';
    end if;
    if (
        select
            name='Пользователи — example.local'
            and purpose='Интерактивный evidence-first отчёт по пользователям AD на основе утверждённого reference V1.1'
            and status='published'
        from report_registry_v4
        where report_key='ad.users.v2' and version=1
    ) is not true then
        raise exception 'ad.users.v2 was not published under the replacement name';
    end if;
    if exists(select 1 from access_package_reports where report_key='ad.users') then
        raise exception 'ad.users package grants remain after retirement';
    end if;
end $$;

commit;
