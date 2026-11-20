begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_audit_vpn_gpo_source'));

insert into report_datasets_v4(
    dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status
) values (
    'ad.accounts.vpn',1,'VPN-доступ через группы Active Directory','ad_user',
    '[
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
    ]'::jsonb,
    '[
      {"key":"enabled","ops":["eq"]},
      {"key":"activity_state","ops":["eq","in"]},
      {"key":"privileged_overlap","ops":["eq"]},
      {"key":"department","ops":["eq","contains"]}
    ]'::jsonb,
    '["view","create_task","export"]'::jsonb,
    'published'
)
on conflict(dataset_key,version) do update set
    name=excluded.name,
    object_type=excluded.object_type,
    fields_json=excluded.fields_json,
    filters_json=excluded.filters_json,
    actions_json=excluded.actions_json,
    status=excluded.status;

insert into report_registry_v4(
    report_key,version,name,owner_name,purpose,dataset_id,definition_json,
    sensitivity,status,published_at
)
select
    'vpn.audit',1,'VPN-доступ и актуальность владельцев','AD / ИТ',
    'Проверка пользователей, получающих VPN-доступ через явно заданные группы Active Directory',
    dataset.id,
    jsonb_build_object(
        'target_path','/vpn-report',
        'required_capabilities',array['objects.groups'],
        'field_categories',array['identity_basic','technical','security','privilege','hr','contact'],
        'actions',array['view','create_task','export'],
        'default_sort',jsonb_build_array(
            jsonb_build_object('field','privileged_overlap','direction','desc'),
            jsonb_build_object('field','activity_state','direction','asc')
        ),
        'columns',dataset.fields_json,
        'filters',dataset.filters_json,
        'export_policy','controlled'
    ),
    'confidential','published',now()
from report_datasets_v4 dataset
where dataset.dataset_key='ad.accounts.vpn' and dataset.version=1
on conflict(report_key,version) do update set
    name=excluded.name,
    owner_name=excluded.owner_name,
    purpose=excluded.purpose,
    dataset_id=excluded.dataset_id,
    definition_json=excluded.definition_json,
    sensitivity=excluded.sensitivity,
    status='published',
    published_at=coalesce(report_registry_v4.published_at,now());

insert into access_package_reports(
    package_id,report_key,field_categories,allowed_actions,scope_json
)
select
    package.id,'vpn.audit',
    array['identity_basic','technical','security','privilege','hr','contact'],
    array['view','create_task','export'],
    '{"kind":"all"}'::jsonb
from access_packages package
where package.package_key='ad_auditor'
on conflict(package_id,report_key) do update set
    field_categories=excluded.field_categories,
    allowed_actions=excluded.allowed_actions,
    scope_json=excluded.scope_json;

insert into schema_migrations(version,name) values(36,'ad_audit_vpn_gpo_source')
on conflict(version) do update set name=excluded.name;

commit;
