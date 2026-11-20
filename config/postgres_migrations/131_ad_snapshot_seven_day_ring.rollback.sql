select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_seven_day_ring_v131')
);

do $$
begin
  if exists (
    select 1 from public.schema_migrations
    where version = 131
      and name is distinct from 'ad_snapshot_seven_day_ring'
  ) then
    raise exception 'refusing migration 131 rollback: version is registered with a different name';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 131
      and name = 'ad_snapshot_seven_day_ring'
  ) then
    raise exception 'refusing migration 131 rollback: migration is not registered';
  end if;

  -- Before 131, observation snapshot references were mandatory. Only their
  -- post-expiry nulls make rollback destructive; projection state was nullable.
  if exists (
    select 1
    from public.what_where_when_observations
    where computer_source_snapshot_id is null
       or user_snapshot_id is null
  ) then
    raise exception 'refusing migration 131 rollback: What-Where-When null snapshot references exist';
  end if;
end
$$;

drop procedure if exists public.expire_ad_snapshot_seven_day_ring(uuid);

create or replace function public.ad_snapshot_manifest_reject_mutation()
returns trigger
language plpgsql
as $$
begin
  return null;
end
$$;
alter function public.ad_snapshot_manifest_reject_mutation() security invoker;
alter function public.ad_snapshot_manifest_reject_mutation() reset all;
alter function public.ad_snapshot_manifest_reject_mutation() owner to postgres;

create or replace function public.ad_snapshot_projection_output_reject_mutation()
returns trigger
language plpgsql
as $$
begin
  return null;
end
$$;
alter function public.ad_snapshot_projection_output_reject_mutation() security invoker;
alter function public.ad_snapshot_projection_output_reject_mutation() reset all;
alter function public.ad_snapshot_projection_output_reject_mutation() owner to postgres;

alter table public.what_where_when_observations
  drop constraint if exists what_where_when_observations_computer_source_snapshot_id_fkey;
alter table public.what_where_when_observations
  drop constraint if exists what_where_when_observations_user_snapshot_id_fkey;
alter table public.what_where_when_projection_state
  drop constraint if exists www_projection_state_computer_source_snapshot_fkey;
alter table public.what_where_when_projection_state
  drop constraint if exists what_where_when_projection_state_user_snapshot_id_fkey;

alter table public.what_where_when_observations
  add constraint what_where_when_observations_computer_source_snapshot_id_fkey
  foreign key (computer_source_snapshot_id)
  references public.computers_v6_source_snapshots(source_snapshot_id)
  on delete restrict;
alter table public.what_where_when_observations
  add constraint what_where_when_observations_user_snapshot_id_fkey
  foreign key (user_snapshot_id)
  references public.users_report_v2_snapshots(snapshot_id)
  on delete restrict;
alter table public.what_where_when_projection_state
  add constraint what_where_when_projection_sta_computer_source_snapshot_id_fkey
  foreign key (computer_source_snapshot_id)
  references public.computers_v6_source_snapshots(source_snapshot_id)
  on delete restrict;
alter table public.what_where_when_projection_state
  add constraint what_where_when_projection_state_user_snapshot_id_fkey
  foreign key (user_snapshot_id)
  references public.users_report_v2_snapshots(snapshot_id)
  on delete restrict;

alter table public.what_where_when_observations
  alter column computer_source_snapshot_id set not null;
alter table public.what_where_when_observations
  alter column user_snapshot_id set not null;

delete from public.schema_migrations
where version = 131 and name = 'ad_snapshot_seven_day_ring';
