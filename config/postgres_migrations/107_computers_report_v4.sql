begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_report_v4'));
do $$ begin
  if (select count(*) from domains where lower(fqdn)='example.local') <> 1 then
    raise exception 'computers v4 report requires exactly one registered example.local DNS domain';
  end if;
end $$;
insert into report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values('ad.assets.computers.v4',1,'Компьютеры Active Directory v4','ad_computer',
'[{"key":"entity_id","label":"ID объекта","category":"identity_basic"},{"key":"display_name","label":"Компьютер","category":"identity_basic"},{"key":"natural_key","label":"Учётная запись","category":"technical"},{"key":"dns_host_name","label":"DNS-имя","category":"technical"},{"key":"distinguished_name","label":"DN","category":"technical"},{"key":"enabled","label":"Состояние записи AD","category":"security"},{"key":"computer_type","label":"Тип по наблюдаемой ОС","category":"technical"},{"key":"operating_system","label":"Операционная система","category":"technical"},{"key":"operating_system_version","label":"Версия ОС","category":"technical"},{"key":"activity","label":"Приблизительная AD-активность","category":"security"},{"key":"evidence","label":"Состояние доказательств","category":"security"},{"key":"risks","label":"Квалифицированные причины внимания","category":"security"},{"key":"observed_at_utc","label":"Наблюдалось","category":"security"}]'::jsonb,
'[{"key":"view","ops":["eq"]},{"key":"risk_key","ops":["eq"]},{"key":"enabled","ops":["eq"]},{"key":"type","ops":["eq"]},{"key":"os","ops":["eq"]},{"key":"os_version","ops":["eq"]},{"key":"ou","ops":["contains"]},{"key":"q","ops":["contains"]}]'::jsonb,
'["view","export"]'::jsonb,'published')
on conflict(dataset_key,version) do update set name=excluded.name,object_type=excluded.object_type,fields_json=excluded.fields_json,filters_json=excluded.filters_json,actions_json=excluded.actions_json,status=excluded.status;
insert into report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at)
select 'ad.computers.v4',1,'Компьютеры v4','AD / ИТ','Рабочий отчёт V1 с исправленными когортами AD, явными evidence-ограничениями и сохранёнными сценариями инвентаризации',dataset.id,
jsonb_build_object('target_path','/computers-v4-report','required_capabilities',array['objects.view'],'field_categories',array['identity_basic','technical','security'],'actions',array['view','export'],'default_sort',jsonb_build_array(),'columns',dataset.fields_json,'filters',dataset.filters_json,'export_policy','controlled'),
'restricted','published',now() from report_datasets_v4 dataset where dataset.dataset_key='ad.assets.computers.v4' and dataset.version=1
on conflict(report_key,version) do update set name=excluded.name,owner_name=excluded.owner_name,purpose=excluded.purpose,dataset_id=excluded.dataset_id,definition_json=excluded.definition_json,sensitivity=excluded.sensitivity,status='published',published_at=coalesce(report_registry_v4.published_at,now());
insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select package.id,'ad.computers.v4',array['identity_basic','technical','security'],array['view','export'],jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))
from access_packages package cross join domains domain where package.package_key='ad_auditor' and lower(domain.fqdn)='example.local'
on conflict(package_id,report_key) do update set field_categories=excluded.field_categories,allowed_actions=excluded.allowed_actions,scope_json=excluded.scope_json;
insert into schema_migrations(version,name) values(107,'computers_report_v4') on conflict(version) do update set name=excluded.name;
commit;
