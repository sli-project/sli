begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_evidence_first_v1_rollback'));

update report_datasets_v4
set name='GPO — очередь ручной проверки',
    fields_json='[
      {"key":"object_id","label":"ID объекта","category":"identity_basic"},
      {"key":"display_name","label":"GPO","category":"identity_basic"},
      {"key":"natural_key","label":"Идентификатор GPO","category":"identity_basic"},
      {"key":"priority","label":"Приоритет","category":"security"},
      {"key":"owner","label":"Владелец","category":"identity_basic"},
      {"key":"observed_at","label":"Наблюдалось","category":"security"},
      {"key":"application_state","label":"Состояние применения","category":"security"},
      {"key":"link_count","label":"Количество связей","category":"security"},
      {"key":"scope","label":"Область применения","category":"security"},
      {"key":"purpose","label":"Назначение","category":"identity_basic"},
      {"key":"review_reason","label":"Причина проверки","category":"security"},
      {"key":"settings","label":"Контрольные настройки","category":"security"},
      {"key":"signals","label":"Сигналы и пересечения","category":"security"},
      {"key":"next_steps","label":"Следующие шаги","category":"security"}
    ]'::jsonb,
    filters_json='[]'::jsonb,
    actions_json='["view","create_task"]'::jsonb
where dataset_key='ad.gpo.governance' and version=1;

update report_registry_v4 report
set name='GPO — очередь ручной проверки',
    purpose='Приоритеты governance без прямого изменения GPO',
    definition_json=jsonb_set(
      jsonb_set(
        jsonb_set(
          jsonb_set(report.definition_json,'{columns}',dataset.fields_json,true),
          '{filters}',dataset.filters_json,true
        ),
        '{actions}',dataset.actions_json,true
      ),
      '{export_policy}','"disabled"'::jsonb,true
    )
from report_datasets_v4 dataset
where report.dataset_id=dataset.id
  and report.report_key='ad.gpo.review'
  and report.version=1
  and dataset.dataset_key='ad.gpo.governance'
  and dataset.version=1;

update access_package_reports
set allowed_actions=array_remove(allowed_actions,'export')
where report_key='ad.gpo.review';

delete from schema_migrations where version=104 and name='gpo_evidence_first_v1';

commit;
