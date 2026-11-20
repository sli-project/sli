select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_delete_authorization_v132')
);

do $$
begin
  if exists (
    select 1
    from public.schema_migrations
    where version = 132
      and name is distinct from 'ad_snapshot_delete_authorization'
  ) then
    raise exception 'migration 132 is already registered with a different name';
  end if;

  if not exists (
    select 1
    from public.schema_migrations
    where version = 131
      and name = 'ad_snapshot_seven_day_ring'
  ) then
    raise exception 'migration 132 requires 131 ad_snapshot_seven_day_ring';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'adlog_user') then
    raise exception 'migration 132 requires runtime role adlog_user';
  end if;

  if to_regclass('public.ad_snapshot_manifests') is null
     or to_regclass('public.ad_snapshot_manifest_sources') is null
     or to_regclass('public.ad_snapshot_projection_outputs') is null then
    raise exception 'migration 132 requires manifest, manifest source, and projection output tables';
  end if;

  if to_regprocedure('public.expire_ad_snapshot_seven_day_ring(uuid)') is null then
    raise exception 'migration 132 requires the seven-day expiry procedure';
  end if;
end
$$;

-- A custom GUC can be set by any connected role.  The former 131 gate therefore
-- accepted a direct DELETE after adlog_user forged expiry_active.  These trigger
-- functions intentionally run as the DML invoker and only let the trusted
-- SECURITY DEFINER expiry procedure through: it changes CURRENT_USER to postgres
-- while preserving SESSION_USER as the authenticated adlog_user runtime role.
create or replace function public.ad_snapshot_manifest_reject_mutation()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if tg_op = 'DELETE'
     and current_user = 'postgres'
     and session_user = 'adlog_user' then
    return null;
  end if;

  raise exception 'AD snapshot manifests are immutable';
end
$$;
alter function public.ad_snapshot_manifest_reject_mutation() security invoker;
alter function public.ad_snapshot_manifest_reject_mutation() reset all;
alter function public.ad_snapshot_manifest_reject_mutation() set search_path = pg_catalog;
alter function public.ad_snapshot_manifest_reject_mutation() owner to postgres;
revoke all on function public.ad_snapshot_manifest_reject_mutation() from public;
revoke all on function public.ad_snapshot_manifest_reject_mutation() from adlog_user;

create or replace function public.ad_snapshot_projection_output_reject_mutation()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if tg_op = 'DELETE'
     and current_user = 'postgres'
     and session_user = 'adlog_user' then
    return null;
  end if;

  raise exception 'AD snapshot projection outputs are immutable';
end
$$;
alter function public.ad_snapshot_projection_output_reject_mutation() security invoker;
alter function public.ad_snapshot_projection_output_reject_mutation() reset all;
alter function public.ad_snapshot_projection_output_reject_mutation() set search_path = pg_catalog;
alter function public.ad_snapshot_projection_output_reject_mutation() owner to postgres;
revoke all on function public.ad_snapshot_projection_output_reject_mutation() from public;
revoke all on function public.ad_snapshot_projection_output_reject_mutation() from adlog_user;

-- Rebind every protected relation explicitly so no legacy trigger definition
-- continues to route deletes through the forgeable 131 gate.
drop trigger if exists trg_ad_snapshot_manifests_immutable
  on public.ad_snapshot_manifests;
create trigger trg_ad_snapshot_manifests_immutable
before update or delete or truncate on public.ad_snapshot_manifests
for each statement execute function public.ad_snapshot_manifest_reject_mutation();

drop trigger if exists trg_ad_snapshot_manifest_sources_immutable
  on public.ad_snapshot_manifest_sources;
create trigger trg_ad_snapshot_manifest_sources_immutable
before update or delete or truncate on public.ad_snapshot_manifest_sources
for each statement execute function public.ad_snapshot_manifest_reject_mutation();

drop trigger if exists trg_ad_snapshot_projection_outputs_immutable
  on public.ad_snapshot_projection_outputs;
create trigger trg_ad_snapshot_projection_outputs_immutable
before update or delete or truncate on public.ad_snapshot_projection_outputs
for each statement execute function public.ad_snapshot_projection_output_reject_mutation();

-- The only delete route remains the already-sealed expiry procedure.  It is
-- SECURITY DEFINER-owned by postgres and callable only by the runtime role.
revoke all on procedure public.expire_ad_snapshot_seven_day_ring(uuid) from public;
grant execute on procedure public.expire_ad_snapshot_seven_day_ring(uuid) to adlog_user;

do $$
begin
  if has_table_privilege('adlog_user', 'public.ad_snapshot_manifests', 'DELETE') then
    raise exception 'migration 132 direct ad_snapshot_manifests delete privilege readback failed';
  end if;

  if has_table_privilege('adlog_user', 'public.ad_snapshot_manifest_sources', 'DELETE') then
    raise exception 'migration 132 direct ad_snapshot_manifest_sources delete privilege readback failed';
  end if;

  if has_table_privilege('adlog_user', 'public.ad_snapshot_projection_outputs', 'DELETE') then
    raise exception 'migration 132 direct ad_snapshot_projection_outputs delete privilege readback failed';
  end if;

  if not exists (
    select 1
    from pg_proc procedure_row
    join pg_namespace namespace_row on namespace_row.oid = procedure_row.pronamespace
    where namespace_row.nspname = 'public'
      and procedure_row.proname = 'expire_ad_snapshot_seven_day_ring'
      and procedure_row.prokind = 'p'
      and procedure_row.prosecdef
      and pg_get_userbyid(procedure_row.proowner) = 'postgres'
      and has_function_privilege('adlog_user', procedure_row.oid, 'EXECUTE')
      and not has_function_privilege('public', procedure_row.oid, 'EXECUTE')
  ) then
    raise exception 'migration 132 sealed expiry procedure readback failed';
  end if;

  if not exists (
    select 1
    from pg_proc manifest_gate
    join pg_namespace namespace_row on namespace_row.oid = manifest_gate.pronamespace
    where namespace_row.nspname = 'public'
      and manifest_gate.proname = 'ad_snapshot_manifest_reject_mutation'
      and not manifest_gate.prosecdef
      and pg_get_userbyid(manifest_gate.proowner) = 'postgres'
      and pg_get_functiondef(manifest_gate.oid) like '%current_user = ''postgres''%'
      and pg_get_functiondef(manifest_gate.oid) like '%session_user = ''adlog_user''%'
      and pg_get_functiondef(manifest_gate.oid) not like '%ad_snapshot_retention.expiry_active%'
  ) then
    raise exception 'migration 132 manifest delete gate readback failed';
  end if;

  if not exists (
    select 1
    from pg_proc output_gate
    join pg_namespace namespace_row on namespace_row.oid = output_gate.pronamespace
    where namespace_row.nspname = 'public'
      and output_gate.proname = 'ad_snapshot_projection_output_reject_mutation'
      and not output_gate.prosecdef
      and pg_get_userbyid(output_gate.proowner) = 'postgres'
      and pg_get_functiondef(output_gate.oid) like '%current_user = ''postgres''%'
      and pg_get_functiondef(output_gate.oid) like '%session_user = ''adlog_user''%'
      and pg_get_functiondef(output_gate.oid) not like '%ad_snapshot_retention.expiry_active%'
  ) then
    raise exception 'migration 132 projection output delete gate readback failed';
  end if;

  if not exists (
    select 1
    from pg_trigger trigger_row
    join pg_class relation_row on relation_row.oid = trigger_row.tgrelid
    join pg_namespace namespace_row on namespace_row.oid = relation_row.relnamespace
    where not trigger_row.tgisinternal
      and namespace_row.nspname = 'public'
      and relation_row.relname in (
        'ad_snapshot_manifests',
        'ad_snapshot_manifest_sources'
      )
      and trigger_row.tgname in (
        'trg_ad_snapshot_manifests_immutable',
        'trg_ad_snapshot_manifest_sources_immutable'
      )
      and trigger_row.tgfoid = 'public.ad_snapshot_manifest_reject_mutation()'::regprocedure
    group by trigger_row.tgfoid
    having count(*) = 2
  ) then
    raise exception 'migration 132 manifest trigger binding readback failed';
  end if;

  if not exists (
    select 1
    from pg_trigger trigger_row
    join pg_class relation_row on relation_row.oid = trigger_row.tgrelid
    join pg_namespace namespace_row on namespace_row.oid = relation_row.relnamespace
    where not trigger_row.tgisinternal
      and namespace_row.nspname = 'public'
      and relation_row.relname = 'ad_snapshot_projection_outputs'
      and trigger_row.tgname = 'trg_ad_snapshot_projection_outputs_immutable'
      and trigger_row.tgfoid = 'public.ad_snapshot_projection_output_reject_mutation()'::regprocedure
  ) then
    raise exception 'migration 132 projection output trigger binding readback failed';
  end if;
end
$$;

insert into public.schema_migrations(version, name)
values (132, 'ad_snapshot_delete_authorization')
on conflict(version) do update set name = excluded.name;
