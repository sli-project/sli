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
    raise exception 'refusing migration 129 rollback: version is registered with a different name';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 129
      and name = 'ad_snapshot_projection_retention'
  ) then
    raise exception 'refusing migration 129 rollback: migration is not registered';
  end if;

  if exists (select 1 from public.ad_snapshot_projection_outputs) then
    raise exception 'refusing migration 129 rollback: immutable projection outputs exist';
  end if;

  if exists (
    select 1
    from public.ad_snapshot_projection_receipts
    where status = 'completed'
      and (
        input_sha256 is not null
        or output_sha256 is not null
        or output_identity is not null
      )
  ) then
    raise exception 'refusing migration 129 rollback: completed receipts rely on output identity or hash';
  end if;
end
$$;

revoke all on table public.ad_snapshot_projection_outputs from public;
revoke all on table public.ad_snapshot_projection_outputs from adlog_user;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'adlog_context_worker') then
    execute 'revoke all on table public.ad_snapshot_projection_outputs from adlog_context_worker';
  end if;
end
$$;

drop trigger if exists trg_ad_snapshot_projection_outputs_immutable
  on public.ad_snapshot_projection_outputs;
drop function if exists public.ad_snapshot_projection_output_reject_mutation();
alter table public.ad_snapshot_projection_receipts
  drop constraint if exists ad_snapshot_projection_receipts_completed_output_check;
drop table if exists public.ad_snapshot_projection_outputs;

delete from public.schema_migrations
where version = 129 and name = 'ad_snapshot_projection_retention';
