-- Persisted, bounded authorization for the Storage V2 direct runtime.
-- Migration 089 remains intentionally outside this cutover.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_runtime_authorization_v91'));

do $$
begin
    if not exists(select 1 from schema_migrations where version=90) then
        raise exception 'Migration 090 is required before migration 091';
    end if;
end
$$;

create table storage_v2_runtime_authorizations (
    singleton boolean primary key default true check (singleton),
    route text not null check (route in ('v2_primary_compat','v2')),
    authority text not null,
    preflight_digest text not null check (preflight_digest ~ '^[0-9a-f]{64}$'),
    authorization_digest text not null check (authorization_digest ~ '^[0-9a-f]{64}$'),
    archive_root text not null check (length(btrim(archive_root)) > 0),
    evidence jsonb not null,
    authorized_by text not null,
    authorized_at timestamptz not null default now(),
    expires_at timestamptz not null,
    revoked_at timestamptz,
    check (expires_at > authorized_at)
);

grant select on table storage_v2_runtime_authorizations to adlog_storage_owner;

do $$
begin
    if exists(select 1 from pg_roles where rolname='adlog_migration_runner') then
        grant select,insert,update,delete on table storage_v2_runtime_authorizations
            to adlog_migration_runner;
    end if;
end
$$;

insert into schema_migrations(version,name)
values (91,'storage_v2_runtime_authorization')
on conflict(version) do update set name=excluded.name;

commit;
