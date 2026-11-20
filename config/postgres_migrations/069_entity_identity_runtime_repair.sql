begin;

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=68 and name='entity_identity_merge_r7'
    ) then
        raise exception 'migration 069 requires migration 068';
    end if;
    if exists (select 1 from schema_migrations where version=69) then
        raise exception 'schema migration 069 is already registered';
    end if;
end
$$;

set local role adlog_storage_owner;

-- The link writer must not need direct SELECT on merge evidence. The owner-
-- executed trigger exposes only the allow/deny decision and keeps the merge
-- table unavailable to the worker role.
create or replace function reject_merged_entity_link_block()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public
as $$
begin
    if exists (
        select 1 from public.entity_identity_merges_v2
        where source_entity_id=new.entity_id
    ) then
        raise exception 'link block targets a merged provisional entity %',
            new.entity_id;
    end if;
    return new;
end
$$;

alter function reject_merged_entity_link_block() owner to adlog_storage_owner;
revoke all on function reject_merged_entity_link_block() from public;

-- Migration 068 used a lateral aggregate behind a security-barrier view. It
-- executed the merge lookup once per entity (7.4 million times in production).
-- Aggregate the very small merge set once, then join it to the entity spine.
create or replace view entities_v2_active
with (security_barrier=true)
as
select entity.id,entity.entity_type_id,entity.natural_key,entity.display_name,
       entity.domain_id,entity.server_id,
       least(entity.first_seen_utc,merged_observation.first_seen_utc)
           as first_seen_utc,
       greatest(entity.last_seen_utc,merged_observation.last_seen_utc)
           as last_seen_utc,
       entity.source_core_sha256,entity.migrated_at
from entities_v2 entity
left join entity_identity_merges_v2 merged_source
  on merged_source.source_entity_id=entity.id
left join (
    select merged.target_entity_id,
           min(source_entity.first_seen_utc) as first_seen_utc,
           max(source_entity.last_seen_utc) as last_seen_utc
    from entity_identity_merges_v2 merged
    join entities_v2 source_entity
      on source_entity.id=merged.source_entity_id
    group by merged.target_entity_id
) merged_observation
  on merged_observation.target_entity_id=entity.id
where merged_source.source_entity_id is null;

revoke all on table entities_v2_active from public;
grant select on table entities_v2_active to adlog_user,adlog_storage_worker;

reset role;

insert into schema_migrations(version,name)
values(69,'entity_identity_runtime_repair')
on conflict(version) do nothing;

commit;
