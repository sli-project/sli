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
    raise exception 'migration 122 is already registered with a different name';
  end if;

  if not exists (
    select 1
    from schema_migrations
    where version = 121
      and name = 'ad_snapshot_manifest_foundation'
  ) then
    raise exception 'migration 121 ad_snapshot_manifest_foundation is required';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'adlog_user') then
    raise exception 'runtime role adlog_user is required';
  end if;

  if to_regclass('public.ad_snapshot_manifests') is null
     or to_regclass('public.ad_snapshot_manifest_sources') is null
     or to_regclass('public.ad_snapshot_projection_receipts') is null then
    raise exception 'migration 122 requires all migration 121 manifest and receipt tables';
  end if;
end
$$;

grant select, insert on table ad_snapshot_manifests to adlog_user;
grant select, insert on table ad_snapshot_manifest_sources to adlog_user;
grant select, insert, update on table ad_snapshot_projection_receipts to adlog_user;

do $$
begin
  if not has_table_privilege('adlog_user', 'ad_snapshot_manifests', 'SELECT')
     or not has_table_privilege('adlog_user', 'ad_snapshot_manifests', 'INSERT')
     or not has_table_privilege('adlog_user', 'ad_snapshot_manifest_sources', 'SELECT')
     or not has_table_privilege('adlog_user', 'ad_snapshot_manifest_sources', 'INSERT')
     or not has_table_privilege('adlog_user', 'ad_snapshot_projection_receipts', 'SELECT')
     or not has_table_privilege('adlog_user', 'ad_snapshot_projection_receipts', 'INSERT')
     or not has_table_privilege('adlog_user', 'ad_snapshot_projection_receipts', 'UPDATE') then
    raise exception 'migration 122 required runtime privilege readback failed';
  end if;

  if has_table_privilege('adlog_user', 'ad_snapshot_manifests', 'UPDATE')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifests', 'DELETE')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifests', 'TRUNCATE')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifests', 'REFERENCES')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifests', 'TRIGGER')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifest_sources', 'UPDATE')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifest_sources', 'DELETE')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifest_sources', 'TRUNCATE')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifest_sources', 'REFERENCES')
     or has_table_privilege('adlog_user', 'ad_snapshot_manifest_sources', 'TRIGGER')
     or has_table_privilege('adlog_user', 'ad_snapshot_projection_receipts', 'DELETE')
     or has_table_privilege('adlog_user', 'ad_snapshot_projection_receipts', 'TRUNCATE')
     or has_table_privilege('adlog_user', 'ad_snapshot_projection_receipts', 'REFERENCES')
     or has_table_privilege('adlog_user', 'ad_snapshot_projection_receipts', 'TRIGGER') then
    raise exception 'migration 122 forbidden runtime privilege readback failed';
  end if;
end
$$;

insert into schema_migrations(version, name)
values (122, 'ad_snapshot_runtime_grants')
on conflict(version) do nothing;
