select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_projection_retention_v129')
);

do $$
begin
  if exists (
    select 1 from public.schema_migrations
    where version = 129
      and name is distinct from 'ad_snapshot_projection_retention'
  ) then
    raise exception 'migration 129 is already registered with a different name';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 121
      and name = 'ad_snapshot_manifest_foundation'
  ) then
    raise exception 'migration 129 requires 121 ad_snapshot_manifest_foundation';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 122
      and name = 'ad_snapshot_runtime_grants'
  ) then
    raise exception 'migration 129 requires 122 ad_snapshot_runtime_grants';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 128
      and name = 'ad_snapshot_v2_schedule'
  ) then
    raise exception 'migration 129 requires 128 ad_snapshot_v2_schedule';
  end if;

  if to_regclass('public.ad_snapshot_manifests') is null
     or to_regclass('public.ad_snapshot_projection_receipts') is null then
    raise exception 'migration 129 requires manifest and projection receipt tables';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'adlog_user') then
    raise exception 'migration 129 requires runtime role adlog_user';
  end if;
end
$$;

create table if not exists public.ad_snapshot_projection_outputs (
  manifest_id uuid not null references public.ad_snapshot_manifests(manifest_id) on delete restrict,
  projection_key text not null,
  projection_version integer not null,
  input_sha256 bytea not null check (octet_length(input_sha256) = 32),
  output_sha256 bytea not null check (octet_length(output_sha256) = 32),
  output_identity text not null,
  payload_json jsonb not null,
  created_at timestamptz not null default now(),
  primary key(manifest_id, projection_key, projection_version),
  unique(output_identity),
  constraint ad_snapshot_projection_outputs_allowlist_check check (
    (projection_key = 'ad.users.v2' and projection_version = 1)
    or (projection_key = 'ad.computers.v6' and projection_version = 1)
    or (projection_key = 'ad.gpo.v2' and projection_version = 1)
    or (projection_key = 'ad.state' and projection_version = 1)
  ),
  constraint ad_snapshot_projection_outputs_identity_check check (
    output_identity = manifest_id::text || ':' || projection_key || ':v' || projection_version::text
  )
);

create or replace function public.ad_snapshot_projection_output_reject_mutation()
returns trigger language plpgsql as $$
begin
  raise exception 'AD snapshot projection outputs are immutable';
end
$$;

drop trigger if exists trg_ad_snapshot_projection_outputs_immutable
  on public.ad_snapshot_projection_outputs;
create trigger trg_ad_snapshot_projection_outputs_immutable
before update or delete or truncate on public.ad_snapshot_projection_outputs
for each statement execute function public.ad_snapshot_projection_output_reject_mutation();

alter table public.ad_snapshot_projection_receipts
  drop constraint if exists ad_snapshot_projection_receipts_completed_output_check;
alter table public.ad_snapshot_projection_receipts
  add constraint ad_snapshot_projection_receipts_completed_output_check
  check (
    status <> 'completed'
    or (
      input_sha256 is not null
      and output_sha256 is not null
      and output_identity is not null
      and octet_length(input_sha256) = 32
      and octet_length(output_sha256) = 32
      and output_identity = manifest_id::text || ':' || projection_key || ':v' || projection_version::text
    )
  ) not valid;

revoke all on table public.ad_snapshot_projection_outputs from public;
revoke all on table public.ad_snapshot_projection_outputs from adlog_user;
grant select, insert on table public.ad_snapshot_projection_outputs to adlog_user;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'adlog_context_worker') then
    execute 'revoke all on table public.ad_snapshot_projection_outputs from adlog_context_worker';
    execute 'grant select, insert on table public.ad_snapshot_projection_outputs to adlog_context_worker';
  end if;
end
$$;

do $$
begin
  if not has_table_privilege('adlog_user', 'public.ad_snapshot_projection_outputs', 'SELECT')
     or not has_table_privilege('adlog_user', 'public.ad_snapshot_projection_outputs', 'INSERT')
     or has_table_privilege('adlog_user', 'public.ad_snapshot_projection_outputs', 'UPDATE')
     or has_table_privilege('adlog_user', 'public.ad_snapshot_projection_outputs', 'DELETE')
     or has_table_privilege('adlog_user', 'public.ad_snapshot_projection_outputs', 'TRUNCATE')
     or has_table_privilege('adlog_user', 'public.ad_snapshot_projection_outputs', 'REFERENCES')
     or has_table_privilege('adlog_user', 'public.ad_snapshot_projection_outputs', 'TRIGGER') then
    raise exception 'migration 129 adlog_user output privilege readback failed';
  end if;

  if exists (select 1 from pg_roles where rolname = 'adlog_context_worker')
     and (
       not has_table_privilege('adlog_context_worker', 'public.ad_snapshot_projection_outputs', 'SELECT')
       or not has_table_privilege('adlog_context_worker', 'public.ad_snapshot_projection_outputs', 'INSERT')
       or has_table_privilege('adlog_context_worker', 'public.ad_snapshot_projection_outputs', 'UPDATE')
       or has_table_privilege('adlog_context_worker', 'public.ad_snapshot_projection_outputs', 'DELETE')
       or has_table_privilege('adlog_context_worker', 'public.ad_snapshot_projection_outputs', 'TRUNCATE')
       or has_table_privilege('adlog_context_worker', 'public.ad_snapshot_projection_outputs', 'REFERENCES')
       or has_table_privilege('adlog_context_worker', 'public.ad_snapshot_projection_outputs', 'TRIGGER')
     ) then
    raise exception 'migration 129 adlog_context_worker output privilege readback failed';
  end if;
end
$$;

insert into public.schema_migrations(version, name)
values (129, 'ad_snapshot_projection_retention')
on conflict(version) do nothing;
