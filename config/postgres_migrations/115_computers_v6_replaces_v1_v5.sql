begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_v6_replaces_v1_v5'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=114 and name='computers_v6_source_snapshot'
    ) then
        raise exception 'computers report cutover requires migration 114';
    end if;
    if (select count(*) from report_registry_v4 where report_key='ad.computers') <> 1 then
        raise exception 'computers report cutover requires exactly one ad.computers registration';
    end if;
    if (select count(*) from report_registry_v4 where report_key='ad.computers.v5' and version=1) <> 1 then
        raise exception 'computers report cutover requires ad.computers.v5 version 1';
    end if;
    if (select count(*) from report_registry_v4 where report_key='ad.computers.v6' and version=1) <> 1 then
        raise exception 'computers report cutover requires ad.computers.v6 version 1';
    end if;
end $$;

update report_registry_v4
set name='Компьютеры — example.local', status='published'
where report_key='ad.computers.v6' and version=1;

update report_registry_v4
set status='retired'
where report_key in ('ad.computers','ad.computers.v5');

delete from access_package_reports
where report_key in ('ad.computers','ad.computers.v5');

insert into schema_migrations(version,name)
values(115,'computers_v6_replaces_v1_v5')
on conflict(version) do update set name=excluded.name;

do $$
begin
    if exists(
        select 1 from report_registry_v4
        where report_key in ('ad.computers','ad.computers.v5') and status <> 'retired'
    ) then
        raise exception 'legacy computers reports were not retired';
    end if;
    if (
        select name='Компьютеры — example.local' and status='published'
        from report_registry_v4
        where report_key='ad.computers.v6' and version=1
    ) is not true then
        raise exception 'ad.computers.v6 was not published under the replacement name';
    end if;
    if exists(
        select 1 from access_package_reports
        where report_key in ('ad.computers','ad.computers.v5')
    ) then
        raise exception 'legacy computers report package grants remain after retirement';
    end if;
end $$;

commit;
