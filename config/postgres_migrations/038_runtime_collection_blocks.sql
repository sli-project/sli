-- Fail-closed collection circuit breaker. No event payloads are stored here.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_runtime_collection_blocks_v38'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=37 and name='platform_owner_access'
    ) then
        raise exception 'migration 038 requires exact migration 037 platform_owner_access';
    end if;
    if exists (
        select 1 from schema_migrations
        where version=38 and name<>'runtime_collection_blocks'
    ) then
        raise exception 'migration version 038 is already owned by another contract';
    end if;
end
$$;

create table if not exists runtime_collection_blocks (
    singleton_id smallint primary key default 1 check (singleton_id = 1),
    active boolean not null default true,
    reason_code text not null,
    retry_policy text not null,
    operator_action text not null,
    source_worker_id text,
    source_job_id bigint,
    source_server text,
    evidence_json jsonb not null default '{}'::jsonb,
    observed_count bigint not null default 1 check (observed_count > 0),
    first_seen_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    last_probe_at timestamptz,
    last_probe_result text,
    cleared_at timestamptz,
    cleared_by text,
    updated_at timestamptz not null default now()
);

revoke all on table runtime_collection_blocks from public;
do $$
begin
    if exists(select 1 from pg_roles where rolname='adlog_user') then
        execute 'grant select, insert, update on runtime_collection_blocks to adlog_user';
    end if;
    if exists(select 1 from pg_roles where rolname='adlog_storage_worker') then
        execute 'grant select, insert, update on runtime_collection_blocks to adlog_storage_worker';
    end if;
end $$;

insert into schema_migrations(version,name)
values (38,'runtime_collection_blocks')
on conflict(version) do nothing;

commit;
