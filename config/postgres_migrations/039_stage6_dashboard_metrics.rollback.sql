begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_stage6_dashboard_metrics'));

update report_registry_v4
set definition_json = definition_json - 'dashboard_metrics'
where report_key in (
    'security.queue',
    'ad.privileged',
    'vpn.audit',
    'ad.gpo.review'
);

delete from schema_migrations
where version=39 and name='stage6_dashboard_metrics';

commit;
