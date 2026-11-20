-- RUNTIME-WORKER-OBSERVABILITY-1: durable, payload-free worker heartbeats.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_runtime_worker_heartbeats_v32'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=31 and name='entity_state_conflict_key_privilege'
    ) then
        raise exception 'migration 032 requires schema migration 031';
    end if;
end
$$;

create table if not exists runtime_worker_heartbeats (
    worker_name text primary key,
    worker_id text not null,
    process_pid integer not null check (process_pid > 0),
    status text not null,
    phase text,
    expected_interval_seconds integer not null check (expected_interval_seconds between 1 and 86400),
    details_json jsonb not null default '{}'::jsonb,
    started_at timestamptz not null,
    heartbeat_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint runtime_worker_heartbeats_name check (
        worker_name in ('collection','storage_v2_outbox','post_collection','entity_state','semantic')
    )
);

revoke all on table runtime_worker_heartbeats from public;
grant select, insert, update on table runtime_worker_heartbeats to adlog_user;
grant select, insert, update on table runtime_worker_heartbeats to adlog_storage_worker;

insert into schema_migrations(version,name)
values (32,'runtime_worker_heartbeats')
on conflict(version) do update set name=excluded.name;

commit;
