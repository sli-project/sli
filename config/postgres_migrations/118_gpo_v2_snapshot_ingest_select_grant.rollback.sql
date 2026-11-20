begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_v2_snapshot_ingest_select_grant'));

revoke select on gpo_report_v2_source_snapshots from adlog_context_worker;
delete from schema_migrations where version=118 and name='gpo_v2_snapshot_ingest_select_grant';
commit;
