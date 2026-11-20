-- Migration 147 — domain controller collection targets edited in «Первичная настройка».
--
-- Owner decision 2026-10-02: the collection targets that lived only in the file
-- config/domain_controllers.json are kept in the database and added, disabled
-- and enabled by an administrator on /app/setup. The existing "servers" table
-- records machines seen in collected data (no connection address, no DNS
-- readback evidence, no enabled flag), so it is not reused.
--
-- hostname is the short logical name used in reports; connect_address is the FQDN
-- the collector connects to (never an IP literal; the server validates it).
-- owner_confirmed_ip is optional DNS readback evidence, never an endpoint.
-- domain_id may be empty for rows imported from the file when no registered
-- domain matches. Rows are never deleted, only disabled. The migration reads
-- no files: the one-shot import is scripts/maintenance/import_domain_controllers_from_file.py.
--
-- Additive: one new table, no change to existing rows.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_domain_controller_targets_v147'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 146 and name = 'platform_settings'
  ) then
    raise exception 'migration 147 requires exact migration 146 platform_settings';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 147 and name is distinct from 'domain_controller_targets'
  ) then
    raise exception 'migration version 147 is already owned by another contract';
  end if;
end
$$;

create table if not exists public.domain_controller_targets (
    id bigint generated always as identity primary key,
    hostname text not null check (length(hostname) between 1 and 63),
    connect_address text not null check (length(connect_address) between 3 and 253),
    domain_id bigint references public.domains(id) on delete restrict,
    owner_confirmed_ip inet,
    enabled boolean not null default true,
    source text not null default 'interface' check (source in ('interface', 'file_import')),
    created_by text not null check (length(created_by) between 1 and 256),
    created_at timestamptz not null default now(),
    updated_by text not null check (length(updated_by) between 1 and 256),
    updated_at timestamptz not null default now()
);

create unique index if not exists domain_controller_targets_hostname_key
    on public.domain_controller_targets (lower(hostname));
create index if not exists domain_controller_targets_domain_idx
    on public.domain_controller_targets (domain_id);

grant select, insert, update on public.domain_controller_targets to adlog_user;

insert into schema_migrations(version, name)
values (147, 'domain_controller_targets')
on conflict(version) do update set name=excluded.name;

commit;
