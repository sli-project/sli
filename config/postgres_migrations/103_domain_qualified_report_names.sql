begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_domain_qualified_report_names'));

do $$
begin
    if (select count(*) from domains domain where lower(domain.fqdn)='example.local') <> 1 then
        raise exception 'report naming requires exactly one registered example.local DNS domain';
    end if;
end $$;

update report_datasets_v4
set name=case dataset_key
    when 'ad.audit.snapshot' then 'example.local'
    when 'ad.accounts.users' then 'Пользователи — example.local'
    when 'ad.assets.computers' then 'Компьютеры — example.local'
end
where version=1
  and dataset_key in ('ad.audit.snapshot','ad.accounts.users','ad.assets.computers');

update report_registry_v4
set name=case report_key
    when 'ad.state' then 'example.local'
    when 'ad.users' then 'Пользователи — example.local'
    when 'ad.computers' then 'Компьютеры — example.local'
end
where version=1
  and report_key in ('ad.state','ad.users','ad.computers');

insert into schema_migrations(version,name) values(103,'domain_qualified_report_names')
on conflict(version) do update set name=excluded.name;

commit;
