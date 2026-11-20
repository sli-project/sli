begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_investigation_cases'));

create table if not exists investigations (
    id bigserial primary key,
    title text not null,
    status text not null default 'new' check (status in ('new','active','review','confirmed','closed')),
    owner text null,
    created_by text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    closed_at timestamptz null
);
create index if not exists investigations_status_updated_idx on investigations(status, updated_at desc);

create table if not exists investigation_events (
    investigation_id bigint not null references investigations(id) on delete cascade,
    event_db_id bigint not null references events(id) on delete restrict,
    relation_status text not null default 'confirmed' check (relation_status in ('confirmed','excluded')),
    added_by text not null,
    added_at timestamptz not null default now(),
    primary key (investigation_id, event_db_id)
);

create table if not exists investigation_notes (
    id bigserial primary key,
    investigation_id bigint not null references investigations(id) on delete cascade,
    body text not null check (length(body) between 1 and 4000),
    created_by text not null,
    created_at timestamptz not null default now()
);

create table if not exists investigation_audit (
    id bigserial primary key,
    investigation_id bigint not null references investigations(id) on delete cascade,
    action text not null,
    actor text not null,
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
create index if not exists investigation_audit_case_created_idx on investigation_audit(investigation_id, created_at desc);

insert into schema_migrations(version, name)
values (15, 'investigation_cases')
on conflict(version) do update set name=excluded.name;

commit;
