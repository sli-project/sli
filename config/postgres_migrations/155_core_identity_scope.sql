-- Generic observations and explicit associations reuse the existing entity IDs.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_core_identity_scope_v155'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 155 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from schema_migrations where version=154 and name='core_job_queue') then
        raise exception 'migration 155 requires exact migration 154 core_job_queue';
    end if;
    if not exists(select 1 from schema_migrations where version=34 and name='ad_context_entities_v2')
       or not exists(select 1 from schema_migrations where version=45 and name='ad_context_shared_entity_identity')
       or not exists(select 1 from schema_migrations where version=90 and name='storage_v2_direct_identity') then
        raise exception 'migration 155 requires the shared entity identity contract 034/045/090';
    end if;
    if exists(select 1 from schema_migrations where version=155) then
        raise exception 'migration 155 already applied';
    end if;
end $$;

-- REFERENCES must be delegated by the original owners before switching role (019).
grant references on entities_v2,auth_users to adlog_storage_owner;
grant select(id,entity_type_id,display_name,natural_key,domain_id) on entities_v2 to adlog_storage_owner;
grant select(id,value) on storage_v2_entity_type to adlog_storage_owner;
set local role adlog_storage_owner;

create table core_entity_identifiers (
    entity_id integer not null references entities_v2(id) on delete restrict,
    entity_kind text not null check (entity_kind in ('principal','device','group')),
    namespace text not null check (length(trim(namespace)) between 1 and 256),
    scope_id text not null check (length(trim(scope_id)) between 1 and 256),
    value text not null check (length(trim(value)) between 1 and 256),
    strength text not null check (strength in ('stable','alias')),
    created_at_utc timestamptz not null default clock_timestamp(),
    primary key(entity_id,entity_kind,namespace,scope_id,value,strength)
);
create unique index core_entity_identifiers_stable
    on core_entity_identifiers(entity_kind,namespace,scope_id,value) where strength='stable';

create table core_entity_observations (
    observation_sha256 bytea primary key check (octet_length(observation_sha256)=32),
    plugin_id text not null check (length(trim(plugin_id)) between 1 and 256),
    source_instance_id text not null check (length(trim(source_instance_id)) between 1 and 256),
    entity_kind text not null check (entity_kind in ('principal','device','group')),
    entity_id integer references entities_v2(id) on delete restrict,
    observed_at_utc timestamptz not null,
    identifiers_json jsonb not null check (jsonb_typeof(identifiers_json)='array' and jsonb_array_length(identifiers_json) between 1 and 64),
    evidence_refs text[] not null check (cardinality(evidence_refs) between 1 and 64 and array_position(evidence_refs,null) is null),
    resolution text not null check (resolution in ('resolved','provisional','unresolved','ambiguous')),
    candidate_ids integer[] not null default '{}',
    reason text check (reason in ('no_stable_identifier','conflicting_stable_identifiers','directory_identifier_conflict')),
    created_at_utc timestamptz not null default clock_timestamp(),
    check ((resolution in ('resolved','provisional')) = (entity_id is not null)),
    check (resolution<>'ambiguous' or cardinality(candidate_ids)>1),
    check (resolution='resolved' or reason is not null)
);
create index core_entity_observations_source on core_entity_observations(plugin_id,source_instance_id,observed_at_utc);

-- Append-only decisions. Multiple targets remain candidates, never an automatic merge.
create table core_entity_associations (
    id bigint generated always as identity primary key,
    source_entity_id integer not null references entities_v2(id) on delete restrict,
    target_entity_id integer not null references entities_v2(id) on delete restrict,
    relation text not null check (relation='directory_computer'),
    actor_id bigint not null references auth_users(id) on delete restrict,
    evidence_refs text[] not null check (cardinality(evidence_refs) between 1 and 64 and array_position(evidence_refs,null) is null),
    created_at_utc timestamptz not null default clock_timestamp(),
    check (source_entity_id<>target_entity_id)
);
create index core_entity_associations_source on core_entity_associations(source_entity_id,relation,target_entity_id);

-- Scoped readers need resource provenance, not raw identifiers/evidence refs.
create view core_entity_scope_resources with (security_barrier=true) as
select o.plugin_id,o.source_instance_id,e.id as entity_id,t.value as entity_type,
       e.display_name,e.natural_key,
       case when t.value in ('device','ad_computer','asset','workstation') then e.natural_key end as device_id,
       case when e.domain_id is not null then 'ad-domain:' || e.domain_id::text end as collection_scope_id,
       o.resolution,o.observed_at_utc
from core_entity_observations o join entities_v2 e on e.id=o.entity_id
join storage_v2_entity_type t on t.id=e.entity_type_id;

create function core_identity_immutable_v155() returns trigger
language plpgsql set search_path=pg_catalog,public as $$
begin
    raise exception 'core identity evidence is append-only';
end $$;
create trigger core_entity_identifiers_immutable before update or delete on core_entity_identifiers
    for each row execute function core_identity_immutable_v155();
create trigger core_entity_observations_immutable before update or delete on core_entity_observations
    for each row execute function core_identity_immutable_v155();
create trigger core_entity_associations_immutable before update or delete on core_entity_associations
    for each row execute function core_identity_immutable_v155();
revoke all on function core_identity_immutable_v155() from public;

revoke all on core_entity_identifiers,core_entity_observations,core_entity_associations from public,adlog_user;
revoke all on core_entity_scope_resources from public;
grant select on core_entity_scope_resources to adlog_user;
grant select,insert on core_entity_identifiers,core_entity_observations to adlog_storage_worker,adlog_context_worker;
grant select,insert on core_entity_associations to adlog_user;
grant usage,select on sequence core_entity_associations_id_seq to adlog_user;
-- Legacy report assignments retain scope_json, role/package grants and IDs.
-- The generic adapter reads those grants; no blanket source access is backfilled.
insert into schema_migrations(version,name) values(155,'core_identity_scope');
commit;
