begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_stage6_report_workspaces'));

update report_datasets_v4
set fields_json = '[
  {"key":"display_name","label":"Объект","category":"identity_basic"},
  {"key":"entity_type","label":"Тип","category":"identity_basic"},
  {"key":"last_seen_utc","label":"Наблюдалось","category":"security"},
  {"key":"context_source","label":"Источник","category":"technical"}
]'::jsonb
where dataset_key='ad.audit.snapshot' and version=1;

update report_datasets_v4
set fields_json = '[
  {"key":"display_name","label":"Учётная запись","category":"identity_basic"},
  {"key":"natural_key","label":"Login","category":"technical"},
  {"key":"privilege_path","label":"Путь получения","category":"privilege"},
  {"key":"last_seen_utc","label":"Наблюдалось","category":"security"}
]'::jsonb
where dataset_key='ad.accounts.privileged' and version=1;

update report_datasets_v4
set fields_json = '[
  {"key":"display_name","label":"Пользователь","category":"identity_basic"},
  {"key":"natural_key","label":"Учётная запись","category":"technical"},
  {"key":"enabled","label":"Включена","category":"security"},
  {"key":"last_logon_utc","label":"Последний вход","category":"security"},
  {"key":"activity_state","label":"Состояние активности","category":"security"},
  {"key":"password_never_expires","label":"Срок действия пароля не ограничен","category":"security"},
  {"key":"admin_count","label":"Признак защищённой учётной записи","category":"privilege"},
  {"key":"department","label":"Подразделение","category":"hr"},
  {"key":"title","label":"Должность","category":"hr"},
  {"key":"email","label":"Рабочая почта","category":"contact"},
  {"key":"privileged_overlap","label":"Есть привилегированное членство","category":"privilege"},
  {"key":"observed_at","label":"Наблюдалось","category":"security"}
]'::jsonb
where dataset_key='ad.accounts.vpn' and version=1;

update report_datasets_v4
set fields_json = '[
  {"key":"display_name","label":"GPO","category":"identity_basic"},
  {"key":"priority","label":"Приоритет","category":"security"},
  {"key":"owner","label":"Владелец","category":"identity_basic"},
  {"key":"observed_at","label":"Наблюдалось","category":"security"}
]'::jsonb
where dataset_key='ad.gpo.governance' and version=1;

update report_registry_v4 report
set definition_json = jsonb_set(
    report.definition_json,
    '{columns}',
    dataset.fields_json,
    true
)
from report_datasets_v4 dataset
where report.dataset_id=dataset.id
  and report.status='published'
  and report.report_key in ('ad.state','ad.privileged','vpn.audit','ad.gpo.review')
  and dataset.version=1;

delete from schema_migrations
where version=41 and name='stage6_report_workspaces';

commit;
