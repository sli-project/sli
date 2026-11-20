-- Add already-collected account state to the published privileged dataset.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_privileged_state_v56'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=55 and name='semantic_finding_publication'
    ) then
        raise exception 'migration 056 requires migration 055';
    end if;
    if not exists (
        select 1 from report_datasets_v4
        where dataset_key='ad.accounts.privileged' and version=1
    ) then
        raise exception 'migration 056 requires ad.accounts.privileged v1';
    end if;
end
$$;

with additions(item, ordinal) as (values
    ('{"key":"enabled","label":"Включена","category":"security"}'::jsonb, 1),
    ('{"key":"is_inactive","label":"Неактивна","category":"security"}'::jsonb, 2),
    ('{"key":"password_never_expires","label":"Пароль без срока","category":"security"}'::jsonb, 3),
    ('{"key":"locked_out","label":"Заблокирована","category":"security"}'::jsonb, 4),
    ('{"key":"last_logon_utc","label":"Последний вход","category":"security"}'::jsonb, 5)
)
update report_datasets_v4 dataset
set fields_json=dataset.fields_json || coalesce((
    select jsonb_agg(additions.item order by additions.ordinal)
    from additions
    where not exists (
        select 1 from jsonb_array_elements(dataset.fields_json) current
        where current->>'key'=additions.item->>'key'
    )
), '[]'::jsonb)
where dataset.dataset_key='ad.accounts.privileged' and dataset.version=1;

with additions(item, ordinal) as (values
    ('{"key":"enabled","label":"Включена","category":"security"}'::jsonb, 1),
    ('{"key":"is_inactive","label":"Неактивна","category":"security"}'::jsonb, 2),
    ('{"key":"password_never_expires","label":"Пароль без срока","category":"security"}'::jsonb, 3),
    ('{"key":"locked_out","label":"Заблокирована","category":"security"}'::jsonb, 4),
    ('{"key":"last_logon_utc","label":"Последний вход","category":"security"}'::jsonb, 5)
)
update report_registry_v4 registry
set definition_json=jsonb_set(
    registry.definition_json,
    '{columns}',
    registry.definition_json->'columns' || coalesce((
        select jsonb_agg(additions.item order by additions.ordinal)
        from additions
        where not exists (
            select 1 from jsonb_array_elements(registry.definition_json->'columns') current
            where current->>'key'=additions.item->>'key'
        )
    ), '[]'::jsonb)
)
where registry.report_key='ad.privileged' and registry.status='published';

insert into schema_migrations(version,name)
values (56,'privileged_account_state_fields')
on conflict(version) do update set name=excluded.name;

commit;
