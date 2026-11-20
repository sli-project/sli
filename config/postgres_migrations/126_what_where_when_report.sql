begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_what_where_when_report_v126'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=125 and name='what_where_when_projection') then
    raise exception 'what where when report requires migration 125';
  end if;
  if (select count(*) from domains where lower(fqdn)='example.local') <> 1 then
    raise exception 'what where when report requires exactly one registered example.local domain';
  end if;
end $$;

revoke all on what_where_when_observations from public;
revoke all on what_where_when_projection_state from public;

insert into access_capabilities(capability_key,label,description)
values('field.computer_logon_observation','Наблюдения входов на ПК','Минимальные приблизительные наблюдения: имя ПК, доменный пользователь и время')
on conflict(capability_key) do update set label=excluded.label,description=excluded.description;

insert into access_package_capabilities(package_id,capability_id)
select package.id,capability.id
from access_packages package cross join access_capabilities capability
where package.package_key in ('security_analyst','project_operations')
  and capability.capability_key='field.computer_logon_observation'
on conflict do nothing;

insert into report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values(
  'ad.authentication.computer-logons',1,'Наблюдения входов на рабочие станции','ad_computer',
  '[{"key":"entity_id","label":"ID ПК","category":"computer_logon_observation"},{"key":"display_name","label":"Компьютер","category":"computer_logon_observation"},{"key":"last_observed_logon_at_utc","label":"Последнее наблюдение","category":"computer_logon_observation"},{"key":"login_count","label":"Число входов","category":"computer_logon_observation"},{"key":"user_name","label":"Доменный пользователь","category":"computer_logon_observation"},{"key":"observed_at_utc","label":"Время наблюдения UTC","category":"computer_logon_observation"}]'::jsonb,
  '[{"key":"q","ops":["contains"]},{"key":"from_utc","ops":["gte"]},{"key":"to_utc_exclusive","ops":["lt"]}]'::jsonb,
  '["view"]'::jsonb,'published'
)
on conflict(dataset_key,version) do update set
  name=excluded.name,object_type=excluded.object_type,fields_json=excluded.fields_json,
  filters_json=excluded.filters_json,actions_json=excluded.actions_json,status=excluded.status;

insert into report_registry_v4(
  report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at
)
select
  'ad.computer-logons',1,'что где когда','AD / ИТ',
  'Приблизительная история успешных входов доменных пользователей на рабочие станции example.local',
  dataset.id,
  jsonb_build_object(
    'target_path','/what-where-when-report',
    'required_capabilities',array['objects.view'],
    'field_categories',array['computer_logon_observation'],
    'actions',array['view'],
    'default_sort',jsonb_build_array('display_name','asc'),
    'columns',dataset.fields_json,
    'filters',dataset.filters_json,
    'export_policy','disabled'
  ),
  'restricted','published',now()
from report_datasets_v4 dataset
where dataset.dataset_key='ad.authentication.computer-logons' and dataset.version=1
on conflict(report_key,version) do update set
  name=excluded.name,owner_name=excluded.owner_name,purpose=excluded.purpose,dataset_id=excluded.dataset_id,
  definition_json=excluded.definition_json,sensitivity=excluded.sensitivity,status='published',
  published_at=coalesce(report_registry_v4.published_at,now());

insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select package.id,'ad.computer-logons',array['computer_logon_observation'],array['view'],
       jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))
from access_packages package cross join domains domain
where package.package_key in ('security_analyst','project_operations')
  and lower(domain.fqdn)='example.local'
on conflict(package_id,report_key) do update set
  field_categories=excluded.field_categories,
  allowed_actions=excluded.allowed_actions,
  scope_json=excluded.scope_json;

insert into schema_migrations(version,name)
values(126,'what_where_when_report')
on conflict(version) do update set name=excluded.name;
commit;
