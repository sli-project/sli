begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_report_v5'));

do $$ begin
  if (select count(*) from domains where lower(fqdn)='example.local') <> 1 then
    raise exception 'computers v5 report requires exactly one registered example.local DNS domain';
  end if;
end $$;

create table if not exists computers_report_v5_snapshots (
  snapshot_id bigserial primary key,
  domain_id bigint not null references domains(id) on delete restrict,
  source_run_id uuid references ad_context_runs(run_id) on delete restrict,
  contract_id text not null check(contract_id='sli.computers-report.v5'),
  schema_version integer not null default 1 check(schema_version=1),
  scope_json jsonb not null,
  scope_sha256 bytea not null check(octet_length(scope_sha256)=32),
  bucket_start_utc timestamptz not null,
  captured_at_utc timestamptz not null,
  source_observed_at_utc timestamptz,
  source_state text not null check(source_state in ('available','empty','partial','stale')),
  object_count integer not null check(object_count>=0),
  payload_json jsonb not null check(jsonb_typeof(payload_json)='object'),
  payload_sha256 bytea not null check(octet_length(payload_sha256)=32),
  created_at timestamptz not null default now(),
  unique(domain_id,scope_sha256,bucket_start_utc,contract_id,schema_version),
  check(bucket_start_utc<=captured_at_utc),
  check(source_observed_at_utc is null or source_observed_at_utc<=captured_at_utc)
);
create index if not exists idx_computers_report_v5_snapshots_latest
  on computers_report_v5_snapshots(domain_id,scope_sha256,captured_at_utc desc,snapshot_id desc);
create index if not exists idx_computers_report_v5_snapshots_retention
  on computers_report_v5_snapshots(captured_at_utc,snapshot_id);

insert into report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values('ad.assets.computers.v5',1,'Компьютеры Active Directory v5','ad_computer',
'[{"key":"entity_id","label":"ID объекта","category":"identity_basic"},{"key":"display_name","label":"Компьютер","category":"identity_basic"},{"key":"natural_key","label":"Учётная запись","category":"technical"},{"key":"dns_host_name","label":"DNS-имя","category":"technical"},{"key":"distinguished_name","label":"DN","category":"technical"},{"key":"enabled","label":"Состояние записи AD","category":"security"},{"key":"computer_type","label":"Тип по наблюдаемой ОС","category":"technical"},{"key":"operating_system","label":"Операционная система","category":"technical"},{"key":"operating_system_version","label":"Версия ОС","category":"technical"},{"key":"activity","label":"Приблизительная AD-активность","category":"security"},{"key":"quality_issues","label":"Качество данных","category":"security"},{"key":"reasons","label":"Причины внимания","category":"security"},{"key":"semantic_findings","label":"Точная опубликованная семантика","category":"security"},{"key":"observed_at_utc","label":"Наблюдалось","category":"security"}]'::jsonb,
'[{"key":"view","ops":["eq"]},{"key":"reason_code","ops":["eq"]},{"key":"quality_code","ops":["eq"]},{"key":"enabled","ops":["eq"]},{"key":"type","ops":["eq"]},{"key":"os","ops":["eq"]},{"key":"os_version","ops":["eq"]},{"key":"ou","ops":["contains"]},{"key":"q","ops":["contains"]}]'::jsonb,
'["view","export"]'::jsonb,'published')
on conflict(dataset_key,version) do update set name=excluded.name,object_type=excluded.object_type,fields_json=excluded.fields_json,filters_json=excluded.filters_json,actions_json=excluded.actions_json,status=excluded.status;

insert into report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at)
select 'ad.computers.v5',1,'Компьютеры v5','AD / ИТ','Интерактивный evidence-first отчёт по утверждённому AD Inventory Evidence reference с изменениями, качеством данных и точной опубликованной семантикой',dataset.id,
jsonb_build_object('target_path','/computers-v5-report','required_capabilities',array['objects.view'],'field_categories',array['identity_basic','technical','security'],'actions',array['view','export'],'default_sort',jsonb_build_array(),'columns',dataset.fields_json,'filters',dataset.filters_json,'export_policy','controlled'),
'restricted','published',now() from report_datasets_v4 dataset where dataset.dataset_key='ad.assets.computers.v5' and dataset.version=1
on conflict(report_key,version) do update set name=excluded.name,owner_name=excluded.owner_name,purpose=excluded.purpose,dataset_id=excluded.dataset_id,definition_json=excluded.definition_json,sensitivity=excluded.sensitivity,status='published',published_at=coalesce(report_registry_v4.published_at,now());

insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select package.id,'ad.computers.v5',array['identity_basic','technical','security'],array['view','export'],jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))
from access_packages package cross join domains domain where package.package_key='ad_auditor' and lower(domain.fqdn)='example.local'
on conflict(package_id,report_key) do update set field_categories=excluded.field_categories,allowed_actions=excluded.allowed_actions,scope_json=excluded.scope_json;

update report_registry_v4 set status='retired' where report_key in ('ad.computers.v2','ad.computers.v4');
update report_datasets_v4 set status='retired' where dataset_key in ('ad.assets.computers.v2','ad.assets.computers.v4');
delete from access_package_reports where report_key in ('ad.computers.v2','ad.computers.v4');

insert into schema_migrations(version,name) values(108,'computers_report_v5') on conflict(version) do update set name=excluded.name;

do $$ begin
  if exists(select 1 from pg_roles where rolname='adlog_user') then
    execute 'grant select,insert,delete on computers_report_v5_snapshots to adlog_user';
    execute 'grant usage,select on sequence computers_report_v5_snapshots_snapshot_id_seq to adlog_user';
  end if;
end $$;
commit;
