begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_privileged_state_v56'));

update report_datasets_v4 dataset
set fields_json=(
    select coalesce(jsonb_agg(item order by ordinal), '[]'::jsonb)
    from jsonb_array_elements(dataset.fields_json) with ordinality fields(item, ordinal)
    where item->>'key' not in (
        'enabled','is_inactive','password_never_expires','locked_out','last_logon_utc'
    )
)
where dataset.dataset_key='ad.accounts.privileged' and dataset.version=1;

update report_registry_v4 registry
set definition_json=jsonb_set(
    registry.definition_json,
    '{columns}',
    (
        select coalesce(jsonb_agg(item order by ordinal), '[]'::jsonb)
        from jsonb_array_elements(registry.definition_json->'columns')
             with ordinality columns(item, ordinal)
        where item->>'key' not in (
            'enabled','is_inactive','password_never_expires','locked_out','last_logon_utc'
        )
    )
)
where registry.report_key='ad.privileged' and registry.status='published';

delete from schema_migrations
where version=56 and name='privileged_account_state_fields';

commit;
