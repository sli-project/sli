-- Stage 8 I3: immutable R7 evidence and persistent provisional identity remap.
-- Applying this migration does not merge an entity or enqueue a replay.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_entity_identity_merge_r7_v68')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 068 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=55 and name='semantic_finding_publication'
    ) then
        raise exception 'migration 068 requires schema migration 055';
    end if;
    if to_regclass('entities_v2') is null
       or to_regclass('event_entity_link_blocks_v2') is null
       or to_regclass('events_v2_core') is null
       or to_regclass('normalized_events') is null
       or to_regclass('semantic_security_scenarios') is null
       or to_regclass('semantic_finding_publications') is null
       or to_regclass('findings') is null then
        raise exception 'migration 068 prerequisites are missing';
    end if;
end
$$;

-- The NOLOGIN schema owner needs only bounded read access to expose the
-- active-finding view; runtime ownership and DML stay with their current roles.
grant select on table findings to adlog_storage_owner;

set local role adlog_storage_owner;

create table if not exists entity_identity_merges_v2 (
    merge_id uuid primary key,
    source_entity_id integer not null unique
        references entities_v2(id) on delete restrict,
    target_entity_id integer not null
        references entities_v2(id) on delete restrict,
    source_natural_key text not null,
    target_natural_key text not null,
    plan_sha256 bytea not null check (octet_length(plan_sha256)=32),
    source_core_sha256_before bytea not null
        check (octet_length(source_core_sha256_before)=32),
    target_core_sha256_before bytea not null
        check (octet_length(target_core_sha256_before)=32),
    source_links_before integer not null check (source_links_before >= 0),
    target_links_before integer not null check (target_links_before >= 0),
    target_links_after integer not null check (target_links_after >= 0),
    source_links_sha256 bytea not null
        check (octet_length(source_links_sha256)=32),
    target_links_before_sha256 bytea not null
        check (octet_length(target_links_before_sha256)=32),
    target_links_after_sha256 bytea not null
        check (octet_length(target_links_after_sha256)=32),
    affected_events integer not null check (affected_events >= 0),
    affected_events_sha256 bytea not null
        check (octet_length(affected_events_sha256)=32),
    semantic_replay_events integer not null check (semantic_replay_events >= 0),
    evidence_json jsonb not null check (
        jsonb_typeof(evidence_json)='object'
        and octet_length(evidence_json::text) <= 65536
    ),
    merged_by text not null default session_user
        check (length(merged_by) between 1 and 256),
    merged_at timestamptz not null default now(),
    constraint entity_identity_merge_distinct check (
        source_entity_id <> target_entity_id
        and source_natural_key <> target_natural_key
    ),
    constraint entity_identity_merge_key_bounds check (
        length(source_natural_key) between 1 and 1024
        and length(target_natural_key) between 1 and 1024
    ),
    constraint entity_identity_merge_link_balance check (
        target_links_after between target_links_before
        and target_links_before + source_links_before
    ),
    unique(source_natural_key),
    unique(source_entity_id,target_entity_id)
);

create table if not exists entity_identity_merge_events_v2 (
    merge_id uuid not null references entity_identity_merges_v2(merge_id)
        on delete restrict,
    source_event_id integer not null references events_v2_core(id)
        on delete restrict,
    source_role_ids smallint[] not null,
    semantic_replay_required boolean not null,
    created_at timestamptz not null default now(),
    primary key(merge_id,source_event_id),
    constraint entity_identity_merge_event_roles check (
        cardinality(source_role_ids) between 1 and 32
    )
);

create table if not exists entity_identity_semantic_replays_v2 (
    merge_id uuid not null references entity_identity_merges_v2(merge_id)
        on delete restrict,
    source_event_id integer not null references events_v2_core(id)
        on delete restrict,
    old_normalized_event_id uuid not null
        references normalized_events(normalized_event_id) on delete restrict,
    new_normalized_event_id uuid not null
        references normalized_events(normalized_event_id) on delete restrict,
    replay_job_id uuid not null references semantic_processing_outbox(job_id)
        on delete restrict,
    created_at timestamptz not null default now(),
    primary key(merge_id,source_event_id,old_normalized_event_id),
    constraint entity_identity_semantic_replay_changed check (
        old_normalized_event_id <> new_normalized_event_id
    )
);

create table if not exists entity_identity_scenario_supersessions_v2 (
    merge_id uuid not null references entity_identity_merges_v2(merge_id)
        on delete restrict,
    old_scenario_id uuid not null
        references semantic_security_scenarios(scenario_id) on delete restrict,
    new_scenario_id uuid not null
        references semantic_security_scenarios(scenario_id) on delete restrict,
    created_at timestamptz not null default now(),
    primary key(merge_id,old_scenario_id,new_scenario_id),
    constraint entity_identity_scenario_supersession_changed check (
        old_scenario_id <> new_scenario_id
    )
);

create table if not exists entity_identity_finding_supersessions_v2 (
    merge_id uuid not null references entity_identity_merges_v2(merge_id)
        on delete restrict,
    old_scenario_id uuid not null,
    new_scenario_id uuid not null,
    old_finding_id bigint not null references findings(id) on delete restrict,
    new_finding_id bigint not null references findings(id) on delete restrict,
    created_at timestamptz not null default now(),
    primary key(merge_id,old_finding_id,new_finding_id),
    foreign key(merge_id,old_scenario_id,new_scenario_id)
        references entity_identity_scenario_supersessions_v2(
            merge_id,old_scenario_id,new_scenario_id
        ) on delete restrict,
    constraint entity_identity_finding_supersession_changed check (
        old_finding_id <> new_finding_id
    )
);

create or replace function enforce_entity_identity_merge_immutability()
returns trigger language plpgsql as $$
begin
    raise exception 'entity identity merge evidence is immutable';
end
$$;

drop trigger if exists trg_entity_identity_merges_immutable
    on entity_identity_merges_v2;
create trigger trg_entity_identity_merges_immutable
before update or delete on entity_identity_merges_v2
for each row execute function enforce_entity_identity_merge_immutability();

drop trigger if exists trg_entity_identity_merge_events_immutable
    on entity_identity_merge_events_v2;
create trigger trg_entity_identity_merge_events_immutable
before update or delete on entity_identity_merge_events_v2
for each row execute function enforce_entity_identity_merge_immutability();

drop trigger if exists trg_entity_identity_semantic_replays_immutable
    on entity_identity_semantic_replays_v2;
create trigger trg_entity_identity_semantic_replays_immutable
before update or delete on entity_identity_semantic_replays_v2
for each row execute function enforce_entity_identity_merge_immutability();

drop trigger if exists trg_entity_identity_scenario_supersessions_immutable
    on entity_identity_scenario_supersessions_v2;
create trigger trg_entity_identity_scenario_supersessions_immutable
before update or delete on entity_identity_scenario_supersessions_v2
for each row execute function enforce_entity_identity_merge_immutability();

drop trigger if exists trg_entity_identity_finding_supersessions_immutable
    on entity_identity_finding_supersessions_v2;
create trigger trg_entity_identity_finding_supersessions_immutable
before update or delete on entity_identity_finding_supersessions_v2
for each row execute function enforce_entity_identity_merge_immutability();

create or replace function reject_merged_entity_link_block()
returns trigger language plpgsql as $$
begin
    if exists (
        select 1 from entity_identity_merges_v2
        where source_entity_id=new.entity_id
    ) then
        raise exception 'link block targets a merged provisional entity %',
            new.entity_id;
    end if;
    return new;
end
$$;

drop trigger if exists trg_event_entity_link_block_reject_merged
    on event_entity_link_blocks_v2;
create trigger trg_event_entity_link_block_reject_merged
before insert or update on event_entity_link_blocks_v2
for each row execute function reject_merged_entity_link_block();

create or replace function validate_entity_identity_merge_flat_graph()
returns trigger language plpgsql as $$
begin
    if exists (
        select 1 from entity_identity_merges_v2
        where target_entity_id=new.source_entity_id
           or source_entity_id=new.target_entity_id
    ) then
        raise exception 'entity identity merge chains and cycles are forbidden';
    end if;
    if exists (
        select 1 from entities_v2 source_row
        join entities_v2 target_row on target_row.id=new.target_entity_id
        where source_row.id=new.source_entity_id
          and source_row.entity_type_id <> target_row.entity_type_id
    ) then
        raise exception 'entity identity merge types differ';
    end if;
    return new;
end
$$;

drop trigger if exists trg_entity_identity_merge_flat_graph
    on entity_identity_merges_v2;
create trigger trg_entity_identity_merge_flat_graph
before insert on entity_identity_merges_v2
for each row execute function validate_entity_identity_merge_flat_graph();

create or replace function resolve_entity_identity_v2(candidate integer)
returns integer
language sql stable security definer
set search_path=pg_catalog,public
as $$
    select coalesce(
        (select target_entity_id from public.entity_identity_merges_v2
         where source_entity_id=candidate),
        candidate
    )
$$;

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
left join lateral (
    select min(source_entity.first_seen_utc) as first_seen_utc,
           max(source_entity.last_seen_utc) as last_seen_utc
    from entity_identity_merges_v2 merged
    join entities_v2 source_entity
      on source_entity.id=merged.source_entity_id
    where merged.target_entity_id=entity.id
) merged_observation on true
where merged_source.source_entity_id is null;

create or replace view findings_active
with (security_barrier=true)
as
select finding.*,
       (superseded.old_finding_id is not null) as identity_superseded,
       superseded.new_finding_id as superseded_by_finding_id
from findings finding
left join entity_identity_finding_supersessions_v2 superseded
  on superseded.old_finding_id=finding.id
where superseded.old_finding_id is null
   or finding.status<>'new'
   or finding.assigned_to is not null;

revoke all on table entity_identity_merges_v2,
    entity_identity_merge_events_v2,
    entity_identity_semantic_replays_v2,
    entity_identity_scenario_supersessions_v2,
    entity_identity_finding_supersessions_v2
from public;
revoke all on function resolve_entity_identity_v2(integer) from public;
revoke all on table entities_v2_active from public;
revoke all on table findings_active from public;

grant execute on function resolve_entity_identity_v2(integer)
to adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant select on table entities_v2_active to adlog_user,adlog_storage_worker;
grant select(source_natural_key,target_natural_key,merge_id)
on entity_identity_merges_v2 to adlog_semantic_worker;
grant select on entity_identity_merge_events_v2 to adlog_semantic_worker;
grant select,insert on entity_identity_semantic_replays_v2,
    entity_identity_scenario_supersessions_v2,
    entity_identity_finding_supersessions_v2
to adlog_semantic_worker;
grant select on entity_identity_scenario_supersessions_v2 to adlog_user;
grant select on entity_identity_finding_supersessions_v2,
    findings_active to adlog_user;

insert into schema_migrations(version,name)
values(68,'entity_identity_merge_r7')
on conflict(version) do nothing;

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=68 and name='entity_identity_merge_r7'
    ) then
        raise exception 'migration 068 marker conflict';
    end if;
end
$$;

commit;
