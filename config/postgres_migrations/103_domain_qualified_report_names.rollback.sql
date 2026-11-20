begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_domain_qualified_report_names'));

update report_datasets_v4
set name=case dataset_key
    when 'ad.audit.snapshot' then 'Active Directory'
    when 'ad.accounts.users' then 'Пользователи Active Directory'
    when 'ad.assets.computers' then 'Компьютеры Active Directory'
end
where version=1
  and dataset_key in ('ad.audit.snapshot','ad.accounts.users','ad.assets.computers');

update report_registry_v4
set name=case report_key
    when 'ad.state' then 'Active Directory'
    when 'ad.users' then 'Пользователи'
    when 'ad.computers' then 'Компьютеры'
end
where version=1
  and report_key in ('ad.state','ad.users','ad.computers');

delete from schema_migrations where version=103 and name='domain_qualified_report_names';

commit;
