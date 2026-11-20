begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_report_v2_reference'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=115 and name='computers_v6_replaces_v1_v5') then
    raise exception 'gpo report v2 requires migration 115';
  end if;
  if (select count(*) from domains where lower(fqdn)='example.local') <> 1 then
    raise exception 'gpo report v2 requires exactly one registered example.local DNS domain';
  end if;
  if not exists(select 1 from report_registry_v4 where report_key='ad.gpo.review' and version=1) then
    raise exception 'gpo report v2 requires existing ad.gpo.review only as access-scope source';
  end if;
end $$;

create table if not exists gpo_report_v2_source_snapshots (
  snapshot_id bigserial primary key,
  domain_id bigint not null references domains(id) on delete restrict,
  source_run_id uuid not null,
  schema_version text not null check(schema_version='sli.ad-gpo.snapshot/1.0'),
  collector_version text not null,
  collection_status text not null check(collection_status in ('complete','partial','failed')),
  import_status text not null default 'completed' check(import_status='completed'),
  source_started_at_utc timestamptz not null,
  source_completed_at_utc timestamptz not null,
  source_observed_at_utc timestamptz not null,
  gpo_count integer not null check(gpo_count between 0 and 10000),
  scope_count integer not null check(scope_count>=0),
  link_count integer not null check(link_count>=0),
  setting_count integer not null check(setting_count>=0),
  permission_count integer not null check(permission_count>=0),
  wmi_filter_count integer not null check(wmi_filter_count>=0),
  payload_json jsonb not null check(
    jsonb_typeof(payload_json)='object'
    and payload_json->>'schema_version'=schema_version
    and coalesce((payload_json->>'demo')::boolean,false)=false
    and jsonb_typeof(payload_json->'gpos')='array'
    and jsonb_typeof(payload_json->'scopes')='array'
    and jsonb_typeof(payload_json->'links')='array'
    and jsonb_typeof(payload_json->'settings')='array'
    and jsonb_typeof(payload_json->'permissions')='array'
    and jsonb_typeof(payload_json->'wmi_filters')='array'
  ),
  payload_sha256 bytea not null check(octet_length(payload_sha256)=32),
  created_at timestamptz not null default now(),
  unique(domain_id,source_run_id),
  check(source_started_at_utc<=source_completed_at_utc),
  check(source_completed_at_utc<=created_at + interval '5 minutes')
);
create index if not exists idx_gpo_report_v2_source_snapshots_latest
  on gpo_report_v2_source_snapshots(domain_id,source_completed_at_utc desc,snapshot_id desc);
create index if not exists idx_gpo_report_v2_source_snapshots_retention
  on gpo_report_v2_source_snapshots(created_at,snapshot_id);

insert into report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values(
  'ad.gpo.reference.v2',1,'Групповые политики — reference 1.0','gpo',
  '[{"key":"gpos","label":"GPO","category":"identity_basic"},{"key":"scopes","label":"Области применения","category":"technical"},{"key":"links","label":"Связи","category":"security"},{"key":"settings","label":"Настройки","category":"security"},{"key":"permissions","label":"Права","category":"privilege"},{"key":"wmi_filters","label":"WMI-фильтры","category":"technical"},{"key":"source_states","label":"Качество источников","category":"security"}]'::jsonb,
  '[{"key":"view","ops":["eq"]},{"key":"q","ops":["contains"]},{"key":"reason","ops":["eq"]},{"key":"source_status","ops":["eq"]},{"key":"stale_days","ops":["eq"]}]'::jsonb,
  '["view","export"]'::jsonb,'published'
)
on conflict(dataset_key,version) do update set name=excluded.name,object_type=excluded.object_type,fields_json=excluded.fields_json,filters_json=excluded.filters_json,actions_json=excluded.actions_json,status=excluded.status;

insert into report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at)
select 'ad.gpo.v2',1,'Групповые политики — example.local','AD / ИБ',
       'Самостоятельный evidence-first отчёт по GPO из sli.ad-gpo.snapshot/1.0; не является RSoP и не изменяет ad.gpo.review',
       dataset.id,
       jsonb_build_object(
         'target_path','/gpo-v2-report',
         'required_capabilities',array['objects.view'],
         'field_categories',array['identity_basic','technical','security','privilege'],
         'actions',array['view','export'],
         'default_view','attention',
         'snapshot_contract','sli.ad-gpo.snapshot/1.0',
         'previous_snapshot','latest-two-compatible-completed',
         'pagination',false,
         'export_policy','controlled-client-from-authorized-snapshot'
       ),
       'restricted','published',now()
from report_datasets_v4 dataset
where dataset.dataset_key='ad.gpo.reference.v2' and dataset.version=1
on conflict(report_key,version) do update set name=excluded.name,owner_name=excluded.owner_name,purpose=excluded.purpose,dataset_id=excluded.dataset_id,definition_json=excluded.definition_json,sensitivity=excluded.sensitivity,status='published',published_at=coalesce(report_registry_v4.published_at,now());

insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select existing.package_id,'ad.gpo.v2',array['identity_basic','technical','security','privilege'],array['view','export'],existing.scope_json
from access_package_reports existing
where existing.report_key='ad.gpo.review'
on conflict(package_id,report_key) do update set field_categories=excluded.field_categories,allowed_actions=excluded.allowed_actions,scope_json=excluded.scope_json;

insert into schema_migrations(version,name) values(116,'gpo_report_v2_reference')
on conflict(version) do update set name=excluded.name;

do $$ begin
  if exists(select 1 from pg_roles where rolname='adlog_user') then
    execute 'grant select,insert,delete on gpo_report_v2_source_snapshots to adlog_user';
    execute 'grant usage,select on sequence gpo_report_v2_source_snapshots_snapshot_id_seq to adlog_user';
  end if;
end $$;
commit;
