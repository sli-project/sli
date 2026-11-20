begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_entity_state_projection'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 019 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=18 and name='investigation_public_identity'
    ) then
        raise exception 'migration 019 requires schema migration 018';
    end if;
end
$$;

-- Migration 017 created these legacy objects as adlog_user.  Delegate their
-- exact worker privileges before switching to the least-privilege semantic
-- owner, which cannot grant privileges on objects it does not own.
grant insert on entity_states to adlog_storage_worker;
grant usage on sequence entity_states_id_seq to adlog_storage_worker;
grant usage, create on schema public to adlog_storage_owner;
grant references on entities_v2, events_v2_core to adlog_storage_owner;
grant select, insert, update on schema_migrations to adlog_storage_owner;
grant usage, select on sequence schema_migrations_id_seq to adlog_storage_owner;

set local role adlog_storage_owner;

create table if not exists entity_state_projection_jobs (
    job_id uuid primary key,
    job_schema_version smallint not null default 1,
    source_event_db_id integer not null,
    candidate_states jsonb not null,
    status text not null default 'queued' check (status in ('queued','running','completed','failed','quarantined')),
    attempt_count integer not null default 0 check (attempt_count >= 0),
    max_attempts integer not null default 5 check (max_attempts between 1 and 20),
    available_at timestamptz not null default now(),
    lease_token uuid,
    lease_until timestamptz,
    heartbeat_at timestamptz,
    last_error text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    completed_at timestamptz,
    unique(source_event_db_id),
    constraint entity_state_projection_payload_array check (jsonb_typeof(candidate_states) = 'array'),
    constraint entity_state_projection_payload_bounded check (jsonb_array_length(candidate_states) between 1 and 64)
);

create index if not exists idx_entity_state_projection_claim
    on entity_state_projection_jobs(status, available_at, lease_until, source_event_db_id);

create table if not exists entity_state_current (
    entity_id integer not null references entities_v2(id) on delete restrict,
    state_type text not null,
    status text not null,
    projection_status text not null default 'normal' check (projection_status in ('normal','unknown','conflict')),
    observed_at timestamptz not null,
    source_event_db_id integer not null references events_v2_core(id) on delete restrict,
    rule_id text not null,
    rule_version text not null,
    details_json jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now(),
    primary key(entity_id, state_type)
);

create index if not exists idx_entity_state_current_observed
    on entity_state_current(observed_at desc, source_event_db_id desc);

revoke all on table entity_state_projection_jobs, entity_state_current from public;
grant select, insert on entity_state_projection_jobs to adlog_user;
grant select on entity_state_current to adlog_user;
grant select, insert, update on entity_state_projection_jobs, entity_state_current to adlog_storage_worker;

insert into schema_migrations(version, name)
values (19, 'entity_state_projection')
on conflict(version) do update set name=excluded.name;
commit;
