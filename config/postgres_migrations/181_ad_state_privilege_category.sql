-- Publish AD change categories without widening any existing access assignment.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_state_privilege_category_v181'));

do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 181 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=180 and name='report_api_key') then
        raise exception 'migration 181 requires migration 180 report_api_key';
    end if;
    if exists(select 1 from public.schema_migrations where version=181) then
        raise exception 'migration 181 already applied';
    end if;
    if not exists(select 1 from public.report_registry_v4 where report_key='ad.state' and status='published') then
        raise exception 'migration 181 requires published ad.state';
    end if;
    if exists (
        select 1 from public.report_datasets_v4 dataset
        join public.report_registry_v4 report on report.dataset_id=dataset.id,
             jsonb_array_elements(dataset.fields_json) field
        where report.report_key='ad.state' and report.status='published'
          and field->>'key'='group_id' and field->>'category' is distinct from 'privilege'
    ) then
        raise exception 'migration 181 refuses conflicting group_id category';
    end if;
end $$;

update public.report_datasets_v4 dataset
set fields_json=dataset.fields_json || '[{"key":"group_id","label":"ID привилегированной группы","category":"privilege"}]'::jsonb
where exists(select 1 from public.report_registry_v4 report
             where report.dataset_id=dataset.id and report.report_key='ad.state' and report.status='published')
  and not exists(select 1 from jsonb_array_elements(dataset.fields_json) field where field->>'key'='group_id');

update public.report_registry_v4 report
set definition_json=jsonb_set(
        report.definition_json,'{field_categories}',
        coalesce(report.definition_json->'field_categories','[]'::jsonb)
        || case when coalesce(report.definition_json->'field_categories','[]'::jsonb) ? 'privilege'
                then '[]'::jsonb else '["privilege"]'::jsonb end,true),
    request_profile_json=jsonb_set(
        coalesce(report.request_profile_json,'{}'::jsonb),'{field_categories}',
        coalesce(report.request_profile_json->'field_categories','[]'::jsonb)
        || case when coalesce(report.request_profile_json->'field_categories','[]'::jsonb) ? 'privilege'
                then '[]'::jsonb else '["privilege"]'::jsonb end,true)
where report.report_key='ad.state' and report.status='published';

insert into public.schema_migrations(version,name) values(181,'ad_state_privilege_category');
commit;
