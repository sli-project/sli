-- Repair only technical exact-logon names, from the latest trusted directory record.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_directory_display_names_v213'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=212 and name='file_audit_page_evidence')
       or exists(select 1 from public.schema_migrations where version>=213) then
        raise exception 'migration 213 prerequisites failed';
    end if;
end $$;

-- Read using the migration principal, as in the AD identity bridge migrations.
-- The repair contains no new identities and cannot borrow names across domains.
create temporary table ad_directory_name_repair on commit drop as
select entity.id as entity_id,entity.domain_id,entity_type.value as entity_type,
       trusted.record_key,trusted.observed_at,trusted.display_name
from public.entities_v2 entity
join public.storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
cross join lateral (
    select version.attributes_json->>'record_key' as record_key,
           version.attributes_json->>'observed_at_utc' as observed_at,
           coalesce(nullif(btrim(version.attributes_json->'attributes'->>'display_name'),''),
                    nullif(btrim(version.attributes_json->'attributes'->>'sam_account_name'),'')) as display_name
    from public.ad_context_entity_versions version
    join public.ad_context_runs run on run.run_id=version.source_run_id
    join public.ad_context_sections section on section.run_id=run.run_id and section.section_name=version.source_section
    where version.entity_id=entity.id and version.source_section='directory_accounts'
      and run.domain_id=entity.domain_id and run.status='completed' and section.status='complete'
      and version.attributes_json->'identity'->>'kind'=entity_type.value
    order by version.last_observed_at_utc desc,version.id desc
    limit 1
) trusted
where entity_type.value in ('ad_user','ad_computer')
  and entity.display_name ~ '^ad:.*:exact-logon$'
  and trusted.display_name is not null
  and trusted.display_name !~ '^ad:.*:exact-logon$';

grant select on ad_directory_name_repair to adlog_storage_owner;
set local role adlog_storage_owner;
with repaired as (
update public.entities_v2 entity
set display_name=repair.display_name,migrated_at=now(),
    source_core_sha256=sha256(convert_to(jsonb_build_object(
        'entity_type',repair.entity_type,'natural_key',repair.record_key,
        'display_name',repair.display_name,'domain_id',repair.domain_id,
        'observed_at_utc',repair.observed_at)::text,'UTF8'))
from ad_directory_name_repair repair
where entity.id=repair.entity_id and entity.domain_id=repair.domain_id
  and entity.display_name ~ '^ad:.*:exact-logon$'
returning entity.id as entity_id,entity.display_name
)
update public.entity_details_v2 details
set attributes_json=details.attributes_json || jsonb_build_object('display_name',repair.display_name),
    source_details_sha256=sha256(convert_to((details.attributes_json || jsonb_build_object('display_name',repair.display_name))::text,'UTF8')),
    migrated_at=now()
from repaired repair
where details.entity_id=repair.entity_id;
insert into public.schema_migrations(version,name) values(213,'ad_directory_display_names');
commit;
