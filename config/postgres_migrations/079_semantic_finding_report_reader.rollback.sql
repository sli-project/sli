begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_semantic_finding_report_reader_v79')
);

set local role adlog_storage_owner;

revoke all on function is_semantic_finding_published_v1(bigint)
    from public,adlog_user;
drop function if exists is_semantic_finding_published_v1(bigint);

delete from schema_migrations
where version=79 and name='semantic_finding_report_reader';

commit;
