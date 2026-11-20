begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_v6_source_snapshot'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=113 and name='computers_report_v6') then
    raise exception 'computers v6 source snapshot requires migration 113';
  end if;
end $$;

create table computers_v6_source_snapshots (
  source_snapshot_id bigserial primary key,
  domain_id bigint not null references domains(id) on delete restrict,
  snapshot_uuid uuid not null,
  schema_version text not null default '2.0' check(schema_version='2.0'),
  source_started_at_utc timestamptz not null,
  source_completed_at_utc timestamptz not null,
  captured_at_utc timestamptz not null,
  query_dc text not null check(length(btrim(query_dc))>0),
  search_base text,
  collector_version text not null check(length(btrim(collector_version))>0),
  collector_sha256 bytea not null check(
    octet_length(collector_sha256)=32
    and collector_sha256=decode('caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5','hex')
  ),
  collection_status text not null check(collection_status in ('complete','partial','failed')),
  base_inventory_status text not null check(
    base_inventory_status in ('observed','failed','access_denied','parse_error')
  ),
  object_count integer not null check(object_count between 0 and 250000),
  source_options_json jsonb not null check(
    jsonb_typeof(source_options_json)='object'
    and source_options_json ?& array[
      'server','search_base','skip_dns','collect_ad_site','collect_exact_last_logon'
    ]
  ),
  payload_json jsonb not null check(
    jsonb_typeof(payload_json)='object'
    and jsonb_typeof(payload_json->'metadata')='object'
    and jsonb_typeof(payload_json->'objects')='array'
    and octet_length(payload_json::text) <= 67108864
    and jsonb_array_length(payload_json->'objects')=object_count
    and payload_json->>'schema_version'=schema_version
    and payload_json->'metadata'->>'snapshot_id'=snapshot_uuid::text
    and payload_json->'metadata'->>'collection_status'=collection_status
    and (payload_json->'metadata'->>'object_count')::integer=object_count
  ),
  payload_sha256 bytea not null check(octet_length(payload_sha256)=32),
  collector_exit_code integer not null check(collector_exit_code>=0),
  created_at timestamptz not null default now(),
  unique(domain_id,snapshot_uuid),
  check(source_started_at_utc<=source_completed_at_utc),
  check(source_completed_at_utc<=captured_at_utc),
  check(
    (base_inventory_status='observed' and collection_status in ('complete','partial'))
    or (base_inventory_status<>'observed' and collection_status='failed' and object_count=0)
  )
);

create index idx_computers_v6_source_snapshots_latest
  on computers_v6_source_snapshots(
    domain_id,source_completed_at_utc desc,source_snapshot_id desc
  );
create index idx_computers_v6_source_snapshots_retention
  on computers_v6_source_snapshots(captured_at_utc,source_snapshot_id);

alter table runtime_worker_heartbeats
  drop constraint if exists runtime_worker_heartbeats_name;
alter table runtime_worker_heartbeats
  add constraint runtime_worker_heartbeats_name check (
    worker_name in (
      'collection','ad_context_snapshot','computers_v5_snapshot',
      'computers_v6_snapshot','computers_v6_source','users_v2_snapshot',
      'storage_v2_outbox','storage_lifecycle','post_collection',
      'entity_state','semantic'
    )
  );

insert into schema_migrations(version,name)
values(114,'computers_v6_source_snapshot')
on conflict(version) do update set name=excluded.name;

do $$ begin
  if exists(select 1 from pg_roles where rolname='adlog_user') then
    execute 'grant select,insert,delete on computers_v6_source_snapshots to adlog_user';
    execute 'grant usage,select on sequence computers_v6_source_snapshots_source_snapshot_id_seq to adlog_user';
  end if;
end $$;
commit;
