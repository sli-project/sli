select pg_advisory_xact_lock(
  hashtext('ad_log_reports_what_where_when_hourly_compaction_v130')
);

-- Compaction touches about a million derived rows; keep this one transaction bounded
-- by the controller, not by the runtime connection's short statement timeout.
set local statement_timeout = '15min';

do $$
begin
  if exists (
    select 1 from public.schema_migrations
    where version = 130
      and name is distinct from 'what_where_when_hourly_compaction'
  ) then
    raise exception 'migration 130 is already registered with a different name';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 125
      and name = 'what_where_when_projection'
  ) then
    raise exception 'migration 130 requires 125 what_where_when_projection';
  end if;

  if to_regclass('public.what_where_when_observations') is null then
    raise exception 'migration 130 requires what_where_when_observations';
  end if;

  if not pg_try_advisory_xact_lock(
    hashtext('ad_log_reports_runtime_what_where_when_projection')
  ) then
    raise exception 'migration 130 requires the what_where_when_projection worker to be stopped';
  end if;
end
$$;

alter table public.what_where_when_observations
  add column if not exists user_key text;
alter table public.what_where_when_observations
  add column if not exists observed_hour_local timestamp without time zone;

update public.what_where_when_observations
set user_key = lower(user_name),
    observed_hour_local = date_trunc(
      'hour', observed_at_utc at time zone 'Asia/Novosibirsk'
    )
where user_key is null
   or observed_hour_local is null;

with ranked as (
  select
    projection_id,
    row_number() over (
      partition by computer_object_guid, user_key, observed_hour_local
      order by observed_at_utc asc, projection_id asc
    ) as rank_in_hour
  from public.what_where_when_observations
)
delete from public.what_where_when_observations observation
using ranked
where observation.projection_id = ranked.projection_id
  and ranked.rank_in_hour > 1;

alter table public.what_where_when_observations
  alter column user_key set not null;
alter table public.what_where_when_observations
  alter column observed_hour_local set not null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conrelid = 'public.what_where_when_observations'::regclass
      and conname = 'what_where_when_observations_hourly_identity'
  ) then
    alter table public.what_where_when_observations
      add constraint what_where_when_observations_hourly_identity
      unique (computer_object_guid, user_key, observed_hour_local);
  end if;
end
$$;

do $$
begin
  if exists (
    select 1
    from public.what_where_when_observations
    where user_key is null
       or observed_hour_local is null
  ) then
    raise exception 'migration 130 backfill left null hourly keys';
  end if;

  if exists (
    select 1
    from public.what_where_when_observations
    group by computer_object_guid, user_key, observed_hour_local
    having count(*) > 1
  ) then
    raise exception 'migration 130 hourly compaction readback found duplicate buckets';
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conrelid = 'public.what_where_when_observations'::regclass
      and conname = 'what_where_when_observations_hourly_identity'
      and contype = 'u'
      and convalidated
  ) then
    raise exception 'migration 130 hourly identity constraint readback failed';
  end if;
end
$$;

insert into public.schema_migrations(version,name)
values(130,'what_where_when_hourly_compaction')
on conflict(version) do nothing;
