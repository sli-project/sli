begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_active_directory_report_v1_rollback'));

delete from schema_migrations where version=102 and name='active_directory_report_v1';

update report_datasets_v4
set name='Состояние и риски Active Directory',
    object_type='entity',
    fields_json='[
      {"key":"display_name","label":"Объект","category":"identity_basic"},
      {"key":"entity_type","label":"Тип","category":"identity_basic"},
      {"key":"last_seen_utc","label":"Наблюдалось","category":"security"},
      {"key":"context_source","label":"Источник","category":"technical"}
    ]'::jsonb,
    filters_json='[{"key":"entity_type","ops":["eq","in"]}]'::jsonb,
    actions_json='["view","create_task"]'::jsonb
where dataset_key='ad.audit.snapshot' and version=1;

update report_registry_v4 report
set name='Состояние и риски Active Directory',
    purpose='Домен, DC, accounts, computers и контекст AD',
    definition_json=jsonb_build_object(
        'target_path','/objects',
        'required_capabilities',array['objects.view'],
        'field_categories',array['identity_basic','security','technical'],
        'actions',array['view','create_task'],
        'default_sort',jsonb_build_array(),
        'columns',dataset.fields_json,
        'filters',dataset.filters_json,
        'export_policy','disabled'
    )
from report_datasets_v4 dataset
where report.report_key='ad.state' and report.version=1
  and dataset.dataset_key='ad.audit.snapshot' and dataset.version=1;

update access_package_reports assignment
set allowed_actions=array['view','create_task']
from access_packages package
where assignment.package_id=package.id and assignment.report_key='ad.state'
  and package.package_key='ad_auditor';

commit;
