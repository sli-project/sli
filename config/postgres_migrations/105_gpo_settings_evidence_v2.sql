begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_settings_evidence_v2'));

update report_datasets_v4
set fields_json = fields_json || '[{"key":"settings","label":"Наблюдаемые настройки GPO","category":"security","source":"gpmc_xml","state":"observed_or_not_collected"}]'::jsonb
where dataset_key='ad.gpo.governance'
  and version=1
  and not exists (
    select 1 from jsonb_array_elements(fields_json) field
    where field->>'key'='settings'
  );

update report_registry_v4 report
set definition_json = jsonb_set(
      report.definition_json,
      '{columns}',
      coalesce(report.definition_json->'columns','[]'::jsonb)
        || '[{"key":"settings","label":"Наблюдаемые настройки GPO","category":"security"}]'::jsonb,
      true
    )
where report.report_key='ad.gpo.review'
  and report.version=1
  and not exists (
    select 1
    from jsonb_array_elements(coalesce(report.definition_json->'columns','[]'::jsonb)) field
    where field->>'key'='settings'
  );

insert into schema_migrations(version,name)
values(105,'105_gpo_settings_evidence_v2')
on conflict(version) do update set name=excluded.name;

commit;
