begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_v2_snapshot_ingest_select_grant'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=117 and name='gpo_v2_snapshot_ingest_grant') then
    raise exception 'migration 117 gpo_v2_snapshot_ingest_grant is required';
  end if;
end $$;

grant select on gpo_report_v2_source_snapshots to adlog_context_worker;

insert into schema_migrations(version,name)
values(118,'gpo_v2_snapshot_ingest_select_grant')
on conflict(version) do nothing;
commit;
