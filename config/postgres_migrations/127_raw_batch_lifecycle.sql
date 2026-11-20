begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_raw_batch_lifecycle_v127'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=126 and name='what_where_when_report') then
    raise exception 'raw batch lifecycle requires migration 126';
  end if;
end $$;

create table if not exists raw_batch_lifecycle (
    batch_identity text primary key,
    manifest_hash text not null,
    server text not null,
    raw_path text not null,
    trace_id text not null,
    expected_channels integer not null default 0 check(expected_channels >= 0),
    committed_channels integer not null default 0 check(committed_channels >= 0),
    import_outcome text not null default 'unknown'
        check(import_outcome in ('unknown','succeeded','failed')),
    cursor_outcome text not null default 'unknown'
        check(cursor_outcome in ('unknown','committed','not_committed')),
    cleanup_outcome text not null default 'retained'
        check(cleanup_outcome in ('retained','delete_authorized','deleted','delete_failed')),
    import_error text,
    cleanup_error text,
    created_at timestamptz not null default now(),
    import_recorded_at timestamptz,
    cursor_recorded_at timestamptz,
    cleanup_recorded_at timestamptz,
    updated_at timestamptz not null default now(),
    constraint raw_batch_lifecycle_identity_sha256 check(batch_identity ~ '^[0-9a-f]{64}$'),
    constraint raw_batch_lifecycle_manifest_sha256 check(manifest_hash ~ '^[0-9a-f]{64}$'),
    unique(raw_path, manifest_hash)
);

create index if not exists idx_raw_batch_lifecycle_trace
    on raw_batch_lifecycle(trace_id, server);
create index if not exists idx_raw_batch_lifecycle_retained
    on raw_batch_lifecycle(updated_at desc)
    where cleanup_outcome <> 'deleted';

do $$ begin
  if not exists(select 1 from pg_roles where rolname='adlog_user') then
    raise exception 'runtime role adlog_user is required';
  end if;
end $$;

revoke all on table raw_batch_lifecycle from public;
revoke all on table raw_batch_lifecycle from adlog_user;
grant select, insert, update on table raw_batch_lifecycle to adlog_user;

insert into schema_migrations(version, name)
values (127, 'raw_batch_lifecycle')
on conflict(version) do update set name=excluded.name;
commit;
