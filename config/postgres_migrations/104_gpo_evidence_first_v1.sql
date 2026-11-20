begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_evidence_first_v1'));

update report_datasets_v4
set name='GPO — example.local',
    fields_json='[
      {"key":"object_id","label":"ID объекта","category":"identity_basic"},
      {"key":"display_name","label":"GPO","category":"identity_basic"},
      {"key":"natural_key","label":"Идентификатор GPO","category":"identity_basic"},
      {"key":"application_state","label":"Состояние применения","category":"security"},
      {"key":"computer_enabled","label":"Компьютерная часть включена","category":"security"},
      {"key":"user_enabled","label":"Пользовательская часть включена","category":"security"},
      {"key":"link_count","label":"Связи","category":"security"},
      {"key":"link_enabled_count","label":"Включённые связи","category":"security"},
      {"key":"link_enforced_count","label":"Принудительные связи","category":"security"},
      {"key":"links","label":"Наблюдаемые связи","category":"security"},
      {"key":"wmi_filter_present","label":"WMI-фильтр назначен","category":"security"},
      {"key":"wmi_filter_id","label":"WMI-фильтр","category":"security"},
      {"key":"permission_count","label":"Настроенные разрешения","category":"security"},
      {"key":"permission_custom_count","label":"Нестандартные разрешения","category":"security"},
      {"key":"security_filtering_sids","label":"Security Filtering — allow SID","category":"security"},
      {"key":"security_filtering_deny_sids","label":"Security Filtering — deny SID","category":"security"},
      {"key":"startup_script_count","label":"Startup scripts","category":"security"},
      {"key":"logon_script_count","label":"Logon scripts","category":"security"},
      {"key":"scheduled_task_count","label":"Scheduled tasks","category":"security"},
      {"key":"service_count","label":"Services","category":"security"},
      {"key":"local_group_count","label":"Local groups","category":"security"},
      {"key":"modified_utc","label":"Изменена","category":"security"},
      {"key":"observed_at","label":"Наблюдалось","category":"security"}
    ]'::jsonb,
    filters_json='[
      {"key":"application_state","ops":["eq"]},
      {"key":"link_count","ops":["eq"]},
      {"key":"has_executable_components","ops":["eq"]}
    ]'::jsonb,
    actions_json='["view","create_task","export"]'::jsonb
where dataset_key='ad.gpo.governance' and version=1;

update report_registry_v4 report
set name='GPO — example.local',
    purpose='Наблюдаемые факты GPMC, применение и очередь ручной проверки без автоматического изменения GPO',
    definition_json=jsonb_set(
      jsonb_set(
        jsonb_set(
          jsonb_set(report.definition_json,'{columns}',dataset.fields_json,true),
          '{filters}',dataset.filters_json,true
        ),
        '{actions}',dataset.actions_json,true
      ),
      '{export_policy}','"controlled"'::jsonb,true
    )
from report_datasets_v4 dataset
where report.dataset_id=dataset.id
  and report.report_key='ad.gpo.review'
  and report.version=1
  and dataset.dataset_key='ad.gpo.governance'
  and dataset.version=1;

update access_package_reports
set allowed_actions=(
  select array_agg(distinct action order by action)
  from unnest(allowed_actions || array['export']) action
)
where report_key='ad.gpo.review';

insert into schema_migrations(version,name) values(104,'gpo_evidence_first_v1')
on conflict(version) do update set name=excluded.name;

commit;
