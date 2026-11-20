begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_users_report_v2_reference'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=109 and name='computers_v5_snapshot_heartbeat') then
    raise exception 'users v2 reference report requires migration 109';
  end if;
  if (select count(*) from domains where lower(fqdn)='example.local') <> 1 then
    raise exception 'users v2 reference report requires exactly one registered example.local DNS domain';
  end if;
end $$;

create table if not exists users_report_v2_snapshots (
  snapshot_id bigserial primary key,
  domain_id bigint not null references domains(id) on delete restrict,
  contract_id text not null check(contract_id='sli.users-report.v2'),
  schema_version integer not null default 1 check(schema_version=1),
  scope_json jsonb not null,
  scope_sha256 bytea not null check(octet_length(scope_sha256)=32),
  bucket_start_utc timestamptz not null,
  captured_at_utc timestamptz not null,
  source_observed_at_utc timestamptz,
  source_state text not null check(source_state in ('complete','partial')),
  user_count integer not null check(user_count>=0),
  payload_json jsonb not null check(jsonb_typeof(payload_json)='object'),
  payload_sha256 bytea not null check(octet_length(payload_sha256)=32),
  created_at timestamptz not null default now(),
  unique(domain_id,scope_sha256,bucket_start_utc,contract_id,schema_version),
  check(bucket_start_utc<=captured_at_utc)
);
create index if not exists idx_users_report_v2_snapshots_latest
  on users_report_v2_snapshots(domain_id,scope_sha256,captured_at_utc desc,snapshot_id desc);
create index if not exists idx_users_report_v2_snapshots_retention
  on users_report_v2_snapshots(captured_at_utc,snapshot_id);

insert into report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values('ad.accounts.users.reference.v2',1,'Пользователи Active Directory — reference V1.1','ad_user',
'[{"key":"displayName","label":"Пользователь","category":"identity_basic"},{"key":"samAccountName","label":"Логин","category":"technical"},{"key":"userPrincipalName","label":"UPN","category":"technical"},{"key":"enabled","label":"Состояние AD","category":"security"},{"key":"lockedOut","label":"Блокировка","category":"security"},{"key":"accountExpirationDate","label":"Срок учётной записи","category":"security"},{"key":"organization","label":"Организация","category":"hr"},{"key":"contacts","label":"Контакты","category":"contact"},{"key":"memberships","label":"Членство в группах","category":"privilege"},{"key":"activity","label":"Активность","category":"security"},{"key":"sourceStates","label":"Состояния источников","category":"security"}]'::jsonb,
'[{"key":"view","ops":["eq"]},{"key":"account","ops":["eq"]},{"key":"ou","ops":["eq"]},{"key":"department","ops":["eq"]},{"key":"company","ops":["eq"]},{"key":"manager","ops":["eq"]},{"key":"group","ops":["eq"]},{"key":"group_relation","ops":["eq"]},{"key":"profile","ops":["eq"]},{"key":"source","ops":["eq"]},{"key":"q","ops":["contains"]}]'::jsonb,
'["view","export"]'::jsonb,'published')
on conflict(dataset_key,version) do update set name=excluded.name,object_type=excluded.object_type,fields_json=excluded.fields_json,filters_json=excluded.filters_json,actions_json=excluded.actions_json,status=excluded.status;

insert into report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at)
select 'ad.users.v2',1,'Пользователи — по референсу','AD / ИБ','Отдельный интерактивный evidence-first отчёт по пользователям AD на основе утверждённого reference V1.1; существующий ad.users не изменяется',dataset.id,
jsonb_build_object('target_path','/users-v2-report','required_capabilities',array['objects.view'],'field_categories',array['identity_basic','technical','security','privilege','hr','contact'],'actions',array['view','export'],'default_sort',jsonb_build_array(),'columns',dataset.fields_json,'filters',dataset.filters_json,'export_policy','controlled-client-from-authorized-snapshot'),
'restricted','published',now() from report_datasets_v4 dataset where dataset.dataset_key='ad.accounts.users.reference.v2' and dataset.version=1
on conflict(report_key,version) do update set name=excluded.name,owner_name=excluded.owner_name,purpose=excluded.purpose,dataset_id=excluded.dataset_id,definition_json=excluded.definition_json,sensitivity=excluded.sensitivity,status='published',published_at=coalesce(report_registry_v4.published_at,now());

insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select existing.package_id,'ad.users.v2',array['identity_basic','technical','security','privilege','hr','contact'],array['view','export'],existing.scope_json
from access_package_reports existing
where existing.report_key='ad.users'
on conflict(package_id,report_key) do update set field_categories=excluded.field_categories,allowed_actions=excluded.allowed_actions,scope_json=excluded.scope_json;

alter table runtime_worker_heartbeats drop constraint if exists runtime_worker_heartbeats_name;
alter table runtime_worker_heartbeats add constraint runtime_worker_heartbeats_name check (
  worker_name in (
    'collection','ad_context_snapshot','computers_v5_snapshot','users_v2_snapshot','storage_v2_outbox',
    'storage_lifecycle','post_collection','entity_state','semantic'
  )
);

insert into schema_migrations(version,name) values(110,'users_report_v2_reference')
on conflict(version) do update set name=excluded.name;

do $$ begin
  if exists(select 1 from pg_roles where rolname='adlog_user') then
    execute 'grant select,insert,delete on users_report_v2_snapshots to adlog_user';
    execute 'grant usage,select on sequence users_report_v2_snapshots_snapshot_id_seq to adlog_user';
  end if;
end $$;
commit;
