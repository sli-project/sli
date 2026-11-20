begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_active_directory_report_v1'));

update report_datasets_v4
set name='Active Directory',
    object_type='ad_infrastructure',
    fields_json='[
      {"key":"entity_id","label":"ID объекта","category":"identity_basic"},
      {"key":"entity_type","label":"Тип инфраструктуры","category":"identity_basic"},
      {"key":"display_name","label":"Объект","category":"identity_basic"},
      {"key":"source_section","label":"Источник сбора","category":"technical"},
      {"key":"domain_controller","label":"Контроллер домена","category":"technical"},
      {"key":"replication_link","label":"Связь репликации","category":"technical"},
      {"key":"domain_trust","label":"Доверие домена","category":"security"},
      {"key":"risk_keys","label":"Квалифицированные риски","category":"security"},
      {"key":"observed_at_utc","label":"Наблюдалось","category":"security"}
    ]'::jsonb,
    filters_json='[
      {"key":"view","ops":["eq"]},
      {"key":"risk_key","ops":["eq"]},
      {"key":"q","ops":["contains"]}
    ]'::jsonb,
    actions_json='["view","export"]'::jsonb,
    status='published'
where dataset_key='ad.audit.snapshot' and version=1;

update report_registry_v4 report
set name='Active Directory',
    owner_name='AD / ИТ',
    purpose='Работоспособность и защищённость домена, контроллеров, репликации, DNS, политик и доверий',
    definition_json=jsonb_build_object(
        'target_path','/ad-report',
        'required_capabilities',array['objects.view'],
        'field_categories',array['identity_basic','technical','security'],
        'actions',array['view','export'],
        'default_sort',jsonb_build_array(),
        'columns',dataset.fields_json,
        'filters',dataset.filters_json,
        'export_policy','controlled'
    ),
    status='published',
    published_at=coalesce(report.published_at,now())
from report_datasets_v4 dataset
where report.report_key='ad.state' and report.version=1
  and dataset.dataset_key='ad.audit.snapshot' and dataset.version=1;

update access_package_reports assignment
set field_categories=array['identity_basic','technical','security'],
    allowed_actions=array['view','export'],
    scope_json=jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))
from access_packages package
cross join domains domain
where assignment.package_id=package.id and assignment.report_key='ad.state'
  and package.package_key='ad_auditor' and lower(domain.fqdn)='example.local';

insert into schema_migrations(version,name) values(102,'active_directory_report_v1')
on conflict(version) do update set name=excluded.name;

commit;
