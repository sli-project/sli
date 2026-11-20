begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_stage6_report_workspace_routes_rollback'));

with routes(report_key,target_path) as (values
  ('security.queue','/scenarios'),
  ('ad.state','/objects'),
  ('ad.privileged','/objects?view=privileged'),
  ('ad.gpo.review','/reports/ad.gpo.review'),
  ('vpn.audit','/vpn-report')
)
update report_registry_v4 report
set definition_json = jsonb_set(
  report.definition_json,
  '{target_path}',
  to_jsonb(routes.target_path),
  true
)
from routes
where report.report_key=routes.report_key
  and report.status='published';

delete from schema_migrations where version=42;

commit;
