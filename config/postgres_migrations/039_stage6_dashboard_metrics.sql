begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_stage6_dashboard_metrics'));

update report_registry_v4
set definition_json = jsonb_set(
    definition_json,
    '{dashboard_metrics}',
    '[
      {
        "key":"security.open_problems",
        "label":"Проблемы ИБ",
        "caption":"в доступном срезе очереди",
        "kind":"required",
        "value_path":"summary.total_items",
        "freshness_path":"summary.latest_observed_at_utc",
        "unit":null,
        "icon":"warning",
        "tone":"bad",
        "priority":10,
        "target_path":"/problems",
        "filters":{},
        "default_selected":false
      }
    ]'::jsonb,
    true
)
where report_key = 'security.queue' and status = 'published';

update report_registry_v4
set definition_json = jsonb_set(
    definition_json,
    '{dashboard_metrics}',
    '[
      {
        "key":"ad.privileged_relations",
        "label":"Привилегированные связи",
        "caption":"подтверждено отчётом",
        "kind":"required",
        "value_path":"summary.total_relations",
        "freshness_path":"summary.latest_observed_at_utc",
        "unit":null,
        "icon":"key",
        "tone":"accent",
        "priority":20,
        "target_path":"/privileged-report",
        "filters":{},
        "default_selected":false
      }
    ]'::jsonb,
    true
)
where report_key = 'ad.privileged' and status = 'published';

update report_registry_v4
set definition_json = jsonb_set(
    definition_json,
    '{dashboard_metrics}',
    '[
      {
        "key":"ad.vpn_disabled_accounts",
        "label":"Отключённые VPN-учётные записи",
        "caption":"в назначенных VPN-группах",
        "kind":"optional",
        "value_path":"summary.disabled_users",
        "freshness_path":"summary.latest_observed_at_utc",
        "unit":null,
        "icon":"lock",
        "tone":"warn",
        "priority":30,
        "target_path":"/vpn-report",
        "filters":{"activity_state":"disabled"},
        "default_selected":true
      }
    ]'::jsonb,
    true
)
where report_key = 'vpn.audit' and status = 'published';

update report_registry_v4
set definition_json = jsonb_set(
    definition_json,
    '{dashboard_metrics}',
    '[
      {
        "key":"ad.gpo_manual_review",
        "label":"GPO на ручной проверке",
        "caption":"требуют решения специалиста",
        "kind":"optional",
        "value_path":"summary.manual_review_count",
        "freshness_path":"summary.latest_observed_at_utc",
        "unit":null,
        "icon":"settings",
        "tone":"good",
        "priority":40,
        "target_path":"/gpo-report",
        "filters":{},
        "default_selected":true
      }
    ]'::jsonb,
    true
)
where report_key = 'ad.gpo.review' and status = 'published';

insert into schema_migrations(version,name)
values(39,'stage6_dashboard_metrics')
on conflict(version) do update set name=excluded.name;

commit;
