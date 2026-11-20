begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_what_where_when_projection_v125'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=124 and name='ad_snapshot_coordinator_heartbeat') then
    raise exception 'what where when projection requires migration 124';
  end if;
  if (select count(*) from domains where lower(fqdn)='example.local') <> 1 then
    raise exception 'what where when projection requires exactly one registered example.local domain';
  end if;
end $$;

create table what_where_when_projection_state (
  singleton boolean primary key default true check(singleton),
  initial_cutoff_utc timestamptz not null,
  high_water_event_id bigint not null default 0 check(high_water_event_id>=0),
  backfill_completed boolean not null default false,
  computer_source_snapshot_id bigint references computers_v6_source_snapshots(source_snapshot_id) on delete restrict,
  user_snapshot_id bigint references users_report_v2_snapshots(snapshot_id) on delete restrict,
  filtered_count bigint not null default 0 check(filtered_count>=0),
  unmatched_count bigint not null default 0 check(unmatched_count>=0),
  ambiguous_count bigint not null default 0 check(ambiguous_count>=0),
  last_cycle_at_utc timestamptz,
  updated_at timestamptz not null default now()
);
insert into what_where_when_projection_state(singleton,initial_cutoff_utc)
values(true, transaction_timestamp()-interval '365 days');

create table what_where_when_observations (
  projection_id bigserial primary key,
  source_event_id bigint not null unique,
  source_event_hash bytea not null check(octet_length(source_event_hash)=32),
  computer_object_guid uuid not null,
  computer_name text not null check(length(btrim(computer_name)) between 1 and 512),
  user_name text not null check(length(btrim(user_name)) between 1 and 512),
  observed_at_utc timestamptz not null,
  computer_source_snapshot_id bigint not null references computers_v6_source_snapshots(source_snapshot_id) on delete restrict,
  user_snapshot_id bigint not null references users_report_v2_snapshots(snapshot_id) on delete restrict,
  created_at timestamptz not null default now()
);
create index idx_what_where_when_observations_computer_time
  on what_where_when_observations(computer_object_guid,observed_at_utc desc,projection_id desc);
create index idx_what_where_when_observations_retention
  on what_where_when_observations(observed_at_utc,projection_id);

alter table runtime_worker_heartbeats drop constraint if exists runtime_worker_heartbeats_name;
alter table runtime_worker_heartbeats add constraint runtime_worker_heartbeats_name check (
  worker_name in (
    'collection','ad_context_snapshot','ad_snapshot_manifest_coordinator',
    'computers_v5_snapshot','computers_v6_snapshot','computers_v6_source',
    'users_v2_snapshot','storage_v2_outbox','storage_lifecycle','post_collection',
    'entity_state','semantic','what_where_when_projection'
  )
);

insert into schema_migrations(version,name)
values(125,'what_where_when_projection');

do $$ begin
  if exists(select 1 from pg_roles where rolname='adlog_user') then
    execute 'grant select,insert,update on what_where_when_projection_state to adlog_user';
    execute 'grant select,insert,delete on what_where_when_observations to adlog_user';
    execute 'grant usage,select on sequence what_where_when_observations_projection_id_seq to adlog_user';
  end if;
end $$;
commit;
