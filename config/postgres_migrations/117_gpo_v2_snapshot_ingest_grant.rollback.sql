begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_v2_snapshot_ingest_grant'));

revoke insert on gpo_report_v2_source_snapshots from adlog_context_worker;
revoke usage, select on sequence gpo_report_v2_source_snapshots_snapshot_id_seq from adlog_context_worker;
delete from schema_migrations where version=117 and name='gpo_v2_snapshot_ingest_grant';
commit;
