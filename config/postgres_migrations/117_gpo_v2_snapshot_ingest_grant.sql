begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_v2_snapshot_ingest_grant'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=116 and name='gpo_report_v2_reference') then
    raise exception 'migration 116 gpo_report_v2_reference is required';
  end if;
end $$;

grant insert on gpo_report_v2_source_snapshots to adlog_context_worker;
grant usage, select on sequence gpo_report_v2_source_snapshots_snapshot_id_seq to adlog_context_worker;

insert into schema_migrations(version,name)
values(117,'gpo_v2_snapshot_ingest_grant')
on conflict(version) do nothing;
commit;
