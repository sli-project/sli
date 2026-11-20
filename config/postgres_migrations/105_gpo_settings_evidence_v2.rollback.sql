begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_settings_evidence_v2_rollback'));

update report_datasets_v4
set fields_json = coalesce((
      select jsonb_agg(field order by ordinal)
      from jsonb_array_elements(fields_json) with ordinality item(field, ordinal)
      where field->>'key' <> 'settings'
    ), '[]'::jsonb)
where dataset_key='ad.gpo.governance'
  and version=1;

update report_registry_v4 report
set definition_json = jsonb_set(
      report.definition_json,
      '{columns}',
      coalesce((
        select jsonb_agg(field order by ordinal)
        from jsonb_array_elements(coalesce(report.definition_json->'columns','[]'::jsonb))
             with ordinality item(field, ordinal)
        where field->>'key' <> 'settings'
      ), '[]'::jsonb),
      true
    )
where report.report_key='ad.gpo.review'
  and report.version=1;

delete from schema_migrations where version=105;

commit;
