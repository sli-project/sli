-- Move AD Context identity ownership from legacy observed_entities to Storage V2.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_context_entities_v2_v34'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'member') then
        raise exception 'migration 034 requires membership in adlog_storage_owner';
    end if;
    if not exists (select 1 from schema_migrations where version=33) then
        raise exception 'migration 034 requires migration 033';
    end if;
end
$$;

do $$
begin
    if not exists (select 1 from pg_roles where rolname='adlog_context_worker') then
        create role adlog_context_worker nologin nosuperuser nocreatedb nocreaterole noinherit;
    end if;
end
$$;

create sequence if not exists entities_v2_id_seq;
alter sequence entities_v2_id_seq owner to adlog_storage_owner;
alter sequence entities_v2_id_seq owned by entities_v2.id;
alter table entities_v2 alter column id set default nextval('entities_v2_id_seq');

insert into storage_v2_entity_type(value)
select distinct legacy.entity_type
from observed_entities legacy
join (
    select entity_id from ad_context_entity_aliases
    union select entity_id from ad_context_entity_versions
    union select source_entity_id from ad_context_relation_versions
    union select target_entity_id from ad_context_relation_versions
) context_identity on context_identity.entity_id=legacy.id
on conflict(value) do nothing;

insert into entities_v2(
    id,entity_type_id,natural_key,display_name,domain_id,server_id,
    first_seen_utc,last_seen_utc,source_core_sha256
)
select legacy.id,entity_type.id,legacy.natural_key,legacy.display_name,
       legacy.domain_id,legacy.server_id,
       nullif(legacy.first_seen_utc,'')::timestamptz,
       nullif(legacy.last_seen_utc,'')::timestamptz,
       sha256(convert_to(jsonb_build_object(
           'id',legacy.id,'entity_type',legacy.entity_type,
           'natural_key',legacy.natural_key,'display_name',legacy.display_name,
           'domain_id',legacy.domain_id,'server_id',legacy.server_id,
           'first_seen_utc',legacy.first_seen_utc,'last_seen_utc',legacy.last_seen_utc
       )::text,'UTF8'))
from observed_entities legacy
join storage_v2_entity_type entity_type on entity_type.value=legacy.entity_type
join (
    select entity_id from ad_context_entity_aliases
    union select entity_id from ad_context_entity_versions
    union select source_entity_id from ad_context_relation_versions
    union select target_entity_id from ad_context_relation_versions
) context_identity on context_identity.entity_id=legacy.id
on conflict(id) do update set
    display_name=excluded.display_name,
    first_seen_utc=least(entities_v2.first_seen_utc,excluded.first_seen_utc),
    last_seen_utc=greatest(entities_v2.last_seen_utc,excluded.last_seen_utc),
    source_core_sha256=excluded.source_core_sha256;

insert into entity_details_v2(entity_id,attributes_json,source_details_sha256)
select legacy.id,
       coalesce(nullif(legacy.attributes_json,''),'{}')::jsonb,
       sha256(convert_to(coalesce(nullif(legacy.attributes_json,''),'{}')::jsonb::text,'UTF8'))
from observed_entities legacy
join (
    select entity_id from ad_context_entity_aliases
    union select entity_id from ad_context_entity_versions
    union select source_entity_id from ad_context_relation_versions
    union select target_entity_id from ad_context_relation_versions
) context_identity on context_identity.entity_id=legacy.id
on conflict(entity_id) do update set
    attributes_json=entity_details_v2.attributes_json || excluded.attributes_json,
    source_details_sha256=sha256(convert_to((entity_details_v2.attributes_json || excluded.attributes_json)::text,'UTF8')),
    migrated_at=now();

select setval('entities_v2_id_seq',greatest(coalesce((select max(id) from entities_v2),1),1),true);

alter table ad_context_entity_aliases drop constraint if exists ad_context_entity_aliases_entity_id_fkey;
alter table ad_context_entity_versions drop constraint if exists ad_context_entity_versions_entity_id_fkey;
alter table ad_context_relation_versions drop constraint if exists ad_context_relation_versions_source_entity_id_fkey;
alter table ad_context_relation_versions drop constraint if exists ad_context_relation_versions_target_entity_id_fkey;

alter table ad_context_entity_aliases add constraint ad_context_entity_aliases_entity_id_v2_fkey
    foreign key(entity_id) references entities_v2(id) on delete cascade not valid;
alter table ad_context_entity_versions add constraint ad_context_entity_versions_entity_id_v2_fkey
    foreign key(entity_id) references entities_v2(id) on delete cascade not valid;
alter table ad_context_relation_versions add constraint ad_context_relation_versions_source_entity_id_v2_fkey
    foreign key(source_entity_id) references entities_v2(id) on delete cascade not valid;
alter table ad_context_relation_versions add constraint ad_context_relation_versions_target_entity_id_v2_fkey
    foreign key(target_entity_id) references entities_v2(id) on delete cascade not valid;

alter table ad_context_entity_aliases validate constraint ad_context_entity_aliases_entity_id_v2_fkey;
alter table ad_context_entity_versions validate constraint ad_context_entity_versions_entity_id_v2_fkey;
alter table ad_context_relation_versions validate constraint ad_context_relation_versions_source_entity_id_v2_fkey;
alter table ad_context_relation_versions validate constraint ad_context_relation_versions_target_entity_id_v2_fkey;

insert into schema_migrations(version,name) values(34,'ad_context_entities_v2')
on conflict(version) do update set name=excluded.name;

grant select on domains,schema_migrations to adlog_context_worker;
grant select,insert,update on
    ad_context_runs,ad_context_sections,ad_context_entity_aliases,
    ad_context_entity_versions,ad_context_relation_versions,ad_context_evidence
    to adlog_context_worker;
grant select,insert,update on
    storage_v2_entity_type,entities_v2,entity_details_v2
    to adlog_context_worker;
grant usage,select on sequence
    ad_context_entity_aliases_id_seq,ad_context_entity_versions_id_seq,
    ad_context_relation_versions_id_seq,ad_context_evidence_id_seq,
    storage_v2_entity_type_id_seq,entities_v2_id_seq
    to adlog_context_worker;

commit;
