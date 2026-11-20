begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_users_v2_source_snapshots'));

do $$ begin
  if not exists(
    select 1 from schema_migrations
    where version=110 and name='users_report_v2_reference'
  ) then
    raise exception 'users v2 source snapshot identity requires migration 110';
  end if;
  if exists(
    select 1 from users_report_v2_snapshots
    where source_observed_at_utc is null
  ) then
    raise exception 'users v2 source snapshot identity requires non-null source observation timestamps';
  end if;
end $$;

alter table users_report_v2_snapshots
  drop constraint users_report_v2_snapshots_domain_id_scope_sha256_bucket_sta_key;
alter table users_report_v2_snapshots
  alter column source_observed_at_utc set not null;
alter table users_report_v2_snapshots
  add constraint users_report_v2_snapshots_source_observed_unique
  unique(domain_id,scope_sha256,source_observed_at_utc,contract_id,schema_version);

create index if not exists idx_users_report_v2_snapshots_source_observed
  on users_report_v2_snapshots(
    domain_id,scope_sha256,source_observed_at_utc desc,snapshot_id desc
  );

insert into schema_migrations(version,name)
values(111,'users_report_v2_source_snapshot_identity')
on conflict(version) do update set name=excluded.name;

commit;
