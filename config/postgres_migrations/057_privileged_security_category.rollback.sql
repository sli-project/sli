-- Hide the security category again without modifying any grant or assignment.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_privileged_security_v57'));

update report_registry_v4 registry
set definition_json=jsonb_set(
        registry.definition_json,
        '{field_categories}',
        coalesce((
            select jsonb_agg(item.value order by item.ordinality)
            from jsonb_array_elements(
                coalesce(registry.definition_json->'field_categories','[]'::jsonb)
            ) with ordinality item(value,ordinality)
            where item.value <> '"security"'::jsonb
        ), '[]'::jsonb),
        true
    ),
    request_profile_json=jsonb_set(
        registry.request_profile_json,
        '{field_categories}',
        coalesce((
            select jsonb_agg(item.value order by item.ordinality)
            from jsonb_array_elements(
                coalesce(registry.request_profile_json->'field_categories','[]'::jsonb)
            ) with ordinality item(value,ordinality)
            where item.value <> '"security"'::jsonb
        ), '[]'::jsonb),
        true
    )
where registry.report_key='ad.privileged'
  and registry.status='published';

delete from schema_migrations
where version=57 and name='privileged_security_category';

commit;
