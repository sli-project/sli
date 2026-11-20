-- Migration 146 — platform settings edited on the «Настройки платформы» page.
--
-- Owner decision 2026-10-01: installation-wide settings such as the report
-- domain (previously only the ADLOG_REPORT_DOMAIN_FQDN environment variable)
-- are kept in the database and edited by an administrator in the interface.
-- Only keys known to server/sli/core/platform_settings.py are written; the
-- server validates each value before storing it. Every change is also written
-- to the access audit journal by the server.
--
-- Additive: one new table, no change to existing rows.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_platform_settings_v146'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 145 and name = 'ad_context_domain_sid_grant'
  ) then
    raise exception 'migration 146 requires exact migration 145 ad_context_domain_sid_grant';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 146 and name is distinct from 'platform_settings'
  ) then
    raise exception 'migration version 146 is already owned by another contract';
  end if;
end
$$;

create table if not exists public.platform_settings (
    key text primary key check (key ~ '^[a-z][a-z0-9_.]{1,63}$'),
    value text not null check (length(value) <= 1024),
    updated_by text not null check (length(updated_by) between 1 and 256),
    updated_at timestamptz not null default now()
);

grant select, insert, update on public.platform_settings to adlog_user;

insert into schema_migrations(version, name)
values (146, 'platform_settings')
on conflict(version) do update set name=excluded.name;

commit;
