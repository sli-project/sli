-- Align the security event dataset with its existing report identity grant.
begin;
select pg_advisory_xact_lock(hashtext('sli_security_event_identity_category_v205'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=204 and name='agent_gpo_history_slot_timestamp')
       or exists(select 1 from public.schema_migrations where version>=205) then
        raise exception 'migration 205 prerequisites failed';
    end if;
end $$;

update public.report_datasets_v4 set fields_json=(
    select jsonb_agg(case when field->>'key' in ('actor','affected_account','member','group')
        then jsonb_set(field,'{category}','"identity_basic"'::jsonb) else field end order by ordinal)
    from jsonb_array_elements(fields_json) with ordinality as fields(field,ordinal)
) where dataset_key='security.events.atomic' and version=1;

update public.report_registry_v4 report set definition_json=jsonb_set(report.definition_json,'{columns}',dataset.fields_json)
from public.report_datasets_v4 dataset
where report.dataset_id=dataset.id and report.report_key='security.events.chains' and report.version=1
    and dataset.dataset_key='security.events.atomic' and dataset.version=1;

insert into public.schema_migrations(version,name) values(205,'security_event_identity_category');
commit;
