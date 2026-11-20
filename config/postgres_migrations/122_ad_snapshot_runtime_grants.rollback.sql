select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_runtime_grants_v122')
);

do $$
begin
  if exists (
    select 1
    from schema_migrations
    where version = 122
      and name is distinct from 'ad_snapshot_runtime_grants'
  ) then
    raise exception 'refusing migration 122 rollback: version is registered with a different name';
  end if;
end
$$;

revoke select, insert on table ad_snapshot_manifests from adlog_user;
revoke select, insert on table ad_snapshot_manifest_sources from adlog_user;
revoke select, insert, update on table ad_snapshot_projection_receipts from adlog_user;

delete from schema_migrations
where version = 122 and name = 'ad_snapshot_runtime_grants';
