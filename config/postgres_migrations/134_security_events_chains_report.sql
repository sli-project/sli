begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_security_events_chains_report_v134'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 133 and name = 'runtime_collection_history_restoration'
  ) then
    raise exception 'migration 134 requires exact migration 133 runtime_collection_history_restoration';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 134 and name is distinct from 'security_events_chains_report'
  ) then
    raise exception 'migration version 134 is already owned by another contract';
  end if;
end
$$;

insert into public.access_packages(package_key,name,description)
values(
  'security_investigation_reader',
  'ИБ · чтение расследований',
  'События безопасности, точные доказательства и сохранённые объяснимые связи без изменения источников'
)
on conflict(package_key) do update set
  name=excluded.name,description=excluded.description,updated_at=now();

with mapping(capability_key) as (values
  ('workspace.view'),('reports.catalog'),('reports.export'),('objects.view'),
  ('objects.groups'),('objects.privileges'),
  ('events.view'),('evidence.exact'),('investigations.view'),('investigations.manage'),
  ('semantic.review'),('field.identity_basic'),('field.security'),('field.technical'),
  ('field.privilege'),
  ('field.raw_evidence')
)
insert into public.access_package_capabilities(package_id,capability_id)
select package.id,capability.id
from public.access_packages package
cross join mapping
join public.access_capabilities capability on capability.capability_key=mapping.capability_key
where package.package_key='security_investigation_reader'
on conflict do nothing;

insert into public.access_role_packages(coarse_role,package_id)
select 'admin',package.id
from public.access_packages package
where package.package_key='security_investigation_reader'
on conflict do nothing;

insert into public.report_datasets_v4(
  dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status
)
values(
  'security.events.atomic',1,'Действия безопасности','security_event',
  '[
    {"key":"time_created_utc","label":"Время","category":"security"},
    {"key":"event_id","label":"Event ID","category":"technical"},
    {"key":"event_family","label":"Категория","category":"security"},
    {"key":"actor","label":"Исполнитель","category":"security"},
    {"key":"affected_account","label":"Затронутая учётная запись","category":"security"},
    {"key":"member","label":"Участник группы","category":"security"},
    {"key":"group","label":"Группа","category":"security"},
    {"key":"source_host","label":"Источник","category":"technical"},
    {"key":"outcome","label":"Результат","category":"security"},
    {"key":"evidence","label":"Исходное доказательство","category":"raw_evidence"}
  ]'::jsonb,
  '[
    {"key":"time_from","ops":["gte"]},{"key":"time_to","ops":["lt"]},
    {"key":"timezone","ops":["eq"]},{"key":"domain_id","ops":["eq"]},
    {"key":"category","ops":["eq"]},{"key":"event_id","ops":["eq"]},
    {"key":"outcome","ops":["eq"]},{"key":"actor","ops":["eq"]},
    {"key":"target","ops":["eq"]},{"key":"group","ops":["eq"]},
    {"key":"source","ops":["eq"]},{"key":"q","ops":["contains"]}
  ]'::jsonb,
  '["view","export","start_case"]'::jsonb,
  'published'
)
on conflict(dataset_key,version) do update set
  name=excluded.name,object_type=excluded.object_type,fields_json=excluded.fields_json,
  filters_json=excluded.filters_json,actions_json=excluded.actions_json,status=excluded.status;

insert into public.report_registry_v4(
  report_key,version,name,owner_name,purpose,dataset_id,definition_json,
  sensitivity,status,published_at
)
select
  'security.events.chains',1,'Действия безопасности','ИБ',
  'Проверяемая история действий, доказанные последовательности и явные пробелы покрытия без автоматического обвинительного вывода',
  dataset.id,
  jsonb_build_object(
    'target_path','/security-events-report',
    'required_capabilities',array['events.view','evidence.exact'],
    'field_categories',array['identity_basic','security','technical','raw_evidence'],
    'actions',array['view','export','start_case'],
    'default_sort',jsonb_build_array('time_created_utc','desc'),
    'columns',dataset.fields_json,
    'filters',dataset.filters_json,
    'export_policy','controlled'
  ),
  'confidential','published',now()
from public.report_datasets_v4 dataset
where dataset.dataset_key='security.events.atomic' and dataset.version=1
on conflict(report_key,version) do update set
  name=excluded.name,owner_name=excluded.owner_name,purpose=excluded.purpose,
  dataset_id=excluded.dataset_id,definition_json=excluded.definition_json,
  sensitivity=excluded.sensitivity,status='published',
  published_at=coalesce(report_registry_v4.published_at,now());

with mapping(package_key) as (values
  ('security_analyst'),('security_investigation_reader')
)
insert into public.access_package_reports(
  package_id,report_key,field_categories,allowed_actions,scope_json
)
select package.id,'security.events.chains',
       array['identity_basic','security','technical','raw_evidence'],
       array['view','export','start_case'],'{"kind":"all"}'::jsonb
from mapping
join public.access_packages package on package.package_key=mapping.package_key
on conflict(package_id,report_key) do update set
  field_categories=excluded.field_categories,
  allowed_actions=excluded.allowed_actions,
  scope_json=excluded.scope_json;

insert into public.schema_migrations(version,name)
values (134, 'security_events_chains_report')
on conflict(version) do nothing;

commit;
