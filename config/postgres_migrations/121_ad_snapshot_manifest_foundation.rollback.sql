select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_snapshot_manifest_foundation'));

do $$ begin
  if exists(select 1 from ad_snapshot_manifests)
     or exists(select 1 from ad_snapshot_manifest_sources)
     or exists(select 1 from ad_snapshot_projection_receipts) then
    raise exception 'refusing rollback: AD snapshot manifest rows exist or projection receipt rows exist';
  end if;
end $$;

drop table if exists ad_snapshot_projection_receipts;
drop table if exists ad_snapshot_manifest_sources;
drop table if exists ad_snapshot_manifests;
drop function if exists ad_snapshot_manifest_reject_mutation();

delete from schema_migrations
where version=121 and name='ad_snapshot_manifest_foundation';
