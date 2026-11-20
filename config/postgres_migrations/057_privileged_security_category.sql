-- Publish the existing security fields only through grants that already allow
-- that category. Package and direct assignments remain unchanged.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_privileged_security_v57'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=56 and name='privileged_account_state_fields'
    ) then
        raise exception 'migration 057 requires migration 056';
    end if;
    if not exists (
        select 1
        from report_registry_v4 registry
        join report_datasets_v4 dataset on dataset.id=registry.dataset_id
        where registry.report_key='ad.privileged'
          and registry.status='published'
          and dataset.dataset_key='ad.accounts.privileged'
          and dataset.version=1
    ) then
        raise exception 'migration 057 requires published ad.privileged v1';
    end if;
end
$$;

update report_registry_v4 registry
set definition_json=jsonb_set(
        registry.definition_json,
        '{field_categories}',
        coalesce(registry.definition_json->'field_categories','[]'::jsonb)
        || case
            when coalesce(registry.definition_json->'field_categories','[]'::jsonb)
                 ? 'security'
            then '[]'::jsonb else '["security"]'::jsonb
           end,
        true
    ),
    request_profile_json=jsonb_set(
        registry.request_profile_json,
        '{field_categories}',
        coalesce(registry.request_profile_json->'field_categories','[]'::jsonb)
        || case
            when coalesce(registry.request_profile_json->'field_categories','[]'::jsonb)
                 ? 'security'
            then '[]'::jsonb else '["security"]'::jsonb
           end,
        true
    )
where registry.report_key='ad.privileged'
  and registry.status='published';

insert into schema_migrations(version,name)
values (57,'privileged_security_category')
on conflict(version) do update set name=excluded.name;

commit;
