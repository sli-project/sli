begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_stage6_report_access_requests'));

drop table if exists report_access_requests_v4;

alter table report_registry_v4
    drop column if exists request_profile_json,
    drop column if exists requestable,
    drop column if exists discoverable;

delete from schema_migrations
where version=40 and name='stage6_report_access_requests';

commit;
