begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_stage6_report_workspace_routes'));

with routes(report_key,target_path) as (values
  ('security.queue','/problems'),
  ('ad.state','/ad-report'),
  ('ad.privileged','/privileged-report'),
  ('ad.gpo.review','/gpo-report'),
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

insert into schema_migrations(version,name)
values(42,'stage6_report_workspace_routes')
on conflict(version) do update set name=excluded.name;

commit;
