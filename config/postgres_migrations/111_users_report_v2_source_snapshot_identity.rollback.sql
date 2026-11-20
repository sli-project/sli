begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_users_v2_source_snapshots'));

do $$ begin
  if exists(
    select 1
    from users_report_v2_snapshots
    group by domain_id,scope_sha256,bucket_start_utc,contract_id,schema_version
    having count(*) > 1
  ) then
    raise exception 'rollback would discard multiple Users V2 snapshots from one schedule bucket';
  end if;
end $$;

drop index if exists idx_users_report_v2_snapshots_source_observed;
alter table users_report_v2_snapshots
  drop constraint if exists users_report_v2_snapshots_source_observed_unique;
alter table users_report_v2_snapshots
  alter column source_observed_at_utc drop not null;
alter table users_report_v2_snapshots
  add constraint users_report_v2_snapshots_domain_id_scope_sha256_bucket_sta_key
  unique(domain_id,scope_sha256,bucket_start_utc,contract_id,schema_version);

delete from schema_migrations
where version=111 and name='users_report_v2_source_snapshot_identity';

commit;
