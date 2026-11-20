-- Publish queue field groups and grant administrators a dedicated read-only package.
begin;
select pg_advisory_xact_lock(hashtext('sli_admin_problem_evidence_v259'));
set local lock_timeout='5s';
do $$ begin
    if not exists(select 1 from public.schema_migrations where version=258 and name='workstation_device_seen')
       or exists(select 1 from public.schema_migrations where version>=259)
       or not exists(select 1 from public.report_registry_v4 r join public.report_datasets_v4 d on d.id=r.dataset_id
                     where r.report_key='security.queue' and r.status='published' and d.dataset_key='security.problems')
       or (select count(*) from public.access_capabilities where capability_key in
           ('workspace.view','field.security','field.identity_basic','field.technical','field.raw_evidence','evidence.exact')) <> 6 then
        raise exception 'migration 259 prerequisites failed';
    end if;
end $$;

-- The PDP intersects dataset, definition, capability and atomic grant categories.
-- Register missing field classes; keep existing fields and unrelated definitions.
update public.report_datasets_v4 d
set fields_json=d.fields_json || (
    select coalesce(jsonb_agg(field),'[]'::jsonb)
    from jsonb_array_elements('[{"key":"actor","label":"Actor","category":"identity_basic"},{"key":"source","label":"Source","category":"technical"},{"key":"evidence_event_id","label":"Evidence DB ID","category":"raw_evidence"}]'::jsonb) field
    where not exists(select 1 from jsonb_array_elements(d.fields_json) existing
                     where existing->>'category'=field->>'category')
)
where d.dataset_key='security.problems'
  and exists(select 1 from public.report_registry_v4 r
             where r.dataset_id=d.id and r.report_key='security.queue' and r.status='published');

update public.report_registry_v4 r
set definition_json=jsonb_set(r.definition_json,'{field_categories}',
    coalesce(r.definition_json->'field_categories','[]'::jsonb) || (
        select coalesce(jsonb_agg(category),'[]'::jsonb)
        from jsonb_array_elements('["security","identity_basic","technical","raw_evidence"]'::jsonb) category
        where not coalesce(r.definition_json->'field_categories','[]'::jsonb) @> jsonb_build_array(category)
    ))
where r.report_key='security.queue' and r.status='published';

-- Do not add these capabilities to shared operations/access-management packages.
insert into public.access_packages(package_key,name,description)
values('admin_problem_evidence','Security problem evidence','Administrator read access to security problem fields and exact evidence');

insert into public.access_package_capabilities(package_id,capability_id)
select p.id,c.id from public.access_packages p cross join public.access_capabilities c
where p.package_key='admin_problem_evidence'
  and c.capability_key in ('workspace.view','field.security','field.identity_basic','field.technical','field.raw_evidence','evidence.exact');

insert into public.access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select id,'security.queue',array['security','identity_basic','technical','raw_evidence'],array['view'],'{"kind":"all"}'::jsonb
from public.access_packages where package_key='admin_problem_evidence';

with assigned as (
    insert into public.access_role_packages(coarse_role,package_id)
    select 'admin',id from public.access_packages where package_key='admin_problem_evidence'
    returning coarse_role
)
insert into public.access_audit_v4(actor_type,action,subject_type,target_type,target_key,reason,outcome,details_json)
select 'system','package_assignment_created','role','package','admin_problem_evidence',
       'Default administrator access to security problem evidence','ok',
       jsonb_build_object('migration',259,'coarse_role','admin','effect','allow',
                          'report_key','security.queue','scope',jsonb_build_object('kind','all'),
                          'field_categories',jsonb_build_array('security','identity_basic','technical','raw_evidence'),
                          'allowed_actions',jsonb_build_array('view'))
from assigned;

insert into public.schema_migrations(version,name) values(259,'admin_problem_evidence');
commit;
