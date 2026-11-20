-- Stage 8: retain immutable semantic/R7 source identity after hot-core expiry.
-- This migration copies identity only. Raw XML/EventData remain archive-only.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_semantic_source_retention_decoupling_v71')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 071 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=70 and name='entity_identity_bounded_lookup'
    ) then
        raise exception 'migration 071 requires schema migration 070';
    end if;
    if to_regclass('events_v2_core') is null
       or to_regclass('normalized_events') is null
       or to_regclass('semantic_processing_outbox') is null
       or to_regclass('entity_identity_merge_events_v2') is null
       or to_regclass('entity_identity_semantic_replays_v2') is null then
        raise exception 'migration 071 prerequisites are missing';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=71 and name='semantic_source_retention_decoupling'
    ) and 4 <> (
        select count(*)
        from pg_constraint
        where contype='f'
          and confrelid='events_v2_core'::regclass
          and conrelid in (
              'semantic_processing_outbox'::regclass,
              'normalized_events'::regclass,
              'entity_identity_merge_events_v2'::regclass,
              'entity_identity_semantic_replays_v2'::regclass
          )
    ) then
        raise exception 'migration 071 requires exactly four Stage 8 source FKs';
    end if;
end
$$;

grant select on table events_v2_core,storage_v2_provider,
    storage_v2_channel,storage_v2_computer to adlog_storage_owner;

set local role adlog_storage_owner;

alter table semantic_processing_outbox
    add column if not exists source_identity_json jsonb;
alter table normalized_events
    add column if not exists source_identity_json jsonb;
alter table entity_identity_merge_events_v2
    add column if not exists source_event_sha256 bytea,
    add column if not exists source_occurred_at_utc timestamptz;
alter table entity_identity_semantic_replays_v2
    add column if not exists source_event_sha256 bytea,
    add column if not exists source_occurred_at_utc timestamptz;

-- Migration 068 makes both R7 evidence tables fully immutable. 071 must
-- enrich the already accepted evidence row without leaving that protection
-- disabled. ACCESS EXCLUSIVE locks prevent concurrent writers, the exact
-- trigger names/state are verified, and transactional DDL restores the
-- original state automatically if any later statement fails.
lock table entity_identity_merge_events_v2,
    entity_identity_semantic_replays_v2 in access exclusive mode;

do $$
begin
    if 2 <> (
        select count(*)
        from pg_trigger
        where not tgisinternal
          and tgenabled='O'
          and (
            (tgrelid='entity_identity_merge_events_v2'::regclass
             and tgname='trg_entity_identity_merge_events_immutable')
            or
            (tgrelid='entity_identity_semantic_replays_v2'::regclass
             and tgname='trg_entity_identity_semantic_replays_immutable')
          )
    ) then
        raise exception 'migration 071 requires both enabled R7 immutability triggers';
    end if;
end
$$;

update semantic_processing_outbox job
set source_identity_json=jsonb_build_object(
    'id',source.id,
    'server_id',source.server_id,
    'domain_id',source.domain_id,
    'log_source_id',source.log_source_id,
    'event_id',source.event_id,
    'time_created_utc',source.time_created_utc,
    'normalized_hash',encode(source.normalized_hash,'hex'),
    'correlation_id',source.correlation_id,
    'migrated_at',source.migrated_at,
    'provider_name',provider.value,
    'channel',channel.value,
    'computer',computer.value
)
from events_v2_core source
join storage_v2_channel channel on channel.id=source.channel_id
left join storage_v2_provider provider on provider.id=source.provider_id
left join storage_v2_computer computer on computer.id=source.computer_id
where source.id=job.source_event_id
  and job.source_identity_json is null;

update normalized_events normalized
set source_identity_json=jsonb_build_object(
    'id',source.id,
    'server_id',source.server_id,
    'domain_id',source.domain_id,
    'log_source_id',source.log_source_id,
    'event_id',source.event_id,
    'time_created_utc',source.time_created_utc,
    'normalized_hash',encode(source.normalized_hash,'hex'),
    'correlation_id',source.correlation_id,
    'migrated_at',source.migrated_at,
    'provider_name',provider.value,
    'channel',channel.value,
    'computer',computer.value
)
from events_v2_core source
join storage_v2_channel channel on channel.id=source.channel_id
left join storage_v2_provider provider on provider.id=source.provider_id
left join storage_v2_computer computer on computer.id=source.computer_id
where source.id=normalized.source_event_id
  and normalized.source_identity_json is null;

alter table entity_identity_merge_events_v2
    disable trigger trg_entity_identity_merge_events_immutable;
alter table entity_identity_semantic_replays_v2
    disable trigger trg_entity_identity_semantic_replays_immutable;

update entity_identity_merge_events_v2 evidence
set source_event_sha256=source.normalized_hash,
    source_occurred_at_utc=source.time_created_utc
from events_v2_core source
where source.id=evidence.source_event_id
  and (evidence.source_event_sha256 is null
       or evidence.source_occurred_at_utc is null);

update entity_identity_semantic_replays_v2 replay
set source_event_sha256=normalized.source_event_sha256,
    source_occurred_at_utc=normalized.occurred_at_utc
from normalized_events normalized
where normalized.normalized_event_id=replay.old_normalized_event_id
  and (replay.source_event_sha256 is null
       or replay.source_occurred_at_utc is null);

alter table entity_identity_merge_events_v2
    enable trigger trg_entity_identity_merge_events_immutable;
alter table entity_identity_semantic_replays_v2
    enable trigger trg_entity_identity_semantic_replays_immutable;

do $$
begin
    if 2 <> (
        select count(*)
        from pg_trigger
        where not tgisinternal
          and tgenabled='O'
          and (
            (tgrelid='entity_identity_merge_events_v2'::regclass
             and tgname='trg_entity_identity_merge_events_immutable')
            or
            (tgrelid='entity_identity_semantic_replays_v2'::regclass
             and tgname='trg_entity_identity_semantic_replays_immutable')
          )
    ) then
        raise exception 'migration 071 failed to restore R7 immutability triggers';
    end if;
end
$$;

do $$
begin
    if exists (
        select 1 from semantic_processing_outbox
        where source_identity_json is null
    ) or exists (
        select 1 from normalized_events
        where source_identity_json is null
    ) or exists (
        select 1 from entity_identity_merge_events_v2
        where source_event_sha256 is null or source_occurred_at_utc is null
    ) or exists (
        select 1 from entity_identity_semantic_replays_v2
        where source_event_sha256 is null or source_occurred_at_utc is null
    ) then
        raise exception 'migration 071 source identity backfill is incomplete';
    end if;
end
$$;

alter table semantic_processing_outbox
    alter column source_identity_json set not null;
alter table normalized_events
    alter column source_identity_json set not null;
alter table entity_identity_merge_events_v2
    alter column source_event_sha256 set not null,
    alter column source_occurred_at_utc set not null;
alter table entity_identity_semantic_replays_v2
    alter column source_event_sha256 set not null,
    alter column source_occurred_at_utc set not null;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conrelid='semantic_processing_outbox'::regclass
          and conname='semantic_processing_outbox_source_identity_v2'
    ) then
        alter table semantic_processing_outbox
            add constraint semantic_processing_outbox_source_identity_v2 check (
                jsonb_typeof(source_identity_json)='object'
                and octet_length(source_identity_json::text) <= 4096
                and source_identity_json ?& array[
                    'id','server_id','domain_id','log_source_id','event_id',
                    'time_created_utc','normalized_hash','migrated_at','channel'
                ]
                and source_identity_json->>'normalized_hash' ~ '^[0-9a-f]{64}$'
                and not source_identity_json ?| array[
                    'raw_xml','event_data','event_data_json'
                ]
            );
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='normalized_events'::regclass
          and conname='normalized_events_source_identity_v2'
    ) then
        alter table normalized_events
            add constraint normalized_events_source_identity_v2 check (
                jsonb_typeof(source_identity_json)='object'
                and octet_length(source_identity_json::text) <= 4096
                and source_identity_json ?& array[
                    'id','server_id','domain_id','log_source_id','event_id',
                    'time_created_utc','normalized_hash','migrated_at','channel'
                ]
                and source_identity_json->>'normalized_hash' ~ '^[0-9a-f]{64}$'
                and not source_identity_json ?| array[
                    'raw_xml','event_data','event_data_json'
                ]
            );
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='entity_identity_merge_events_v2'::regclass
          and conname='entity_identity_merge_event_source_hash'
    ) then
        alter table entity_identity_merge_events_v2
            add constraint entity_identity_merge_event_source_hash check (
                octet_length(source_event_sha256)=32
            );
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='entity_identity_semantic_replays_v2'::regclass
          and conname='entity_identity_semantic_replay_source_hash'
    ) then
        alter table entity_identity_semantic_replays_v2
            add constraint entity_identity_semantic_replay_source_hash check (
                octet_length(source_event_sha256)=32
            );
    end if;
end
$$;

create or replace function enforce_semantic_source_identity_immutability()
returns trigger language plpgsql as $$
begin
    if new.source_event_id is distinct from old.source_event_id
       or new.source_identity_json is distinct from old.source_identity_json then
        raise exception 'semantic source identity is immutable';
    end if;
    return new;
end
$$;

drop trigger if exists trg_semantic_outbox_source_identity_immutable
    on semantic_processing_outbox;
create trigger trg_semantic_outbox_source_identity_immutable
before update on semantic_processing_outbox
for each row execute function enforce_semantic_source_identity_immutability();

drop trigger if exists trg_normalized_event_source_identity_immutable
    on normalized_events;
create trigger trg_normalized_event_source_identity_immutable
before update on normalized_events
for each row execute function enforce_semantic_source_identity_immutability();

do $$
declare
    item record;
begin
    for item in
        select conrelid::regclass as table_name,conname
        from pg_constraint
        where contype='f'
          and confrelid='events_v2_core'::regclass
          and conrelid in (
              'semantic_processing_outbox'::regclass,
              'normalized_events'::regclass,
              'entity_identity_merge_events_v2'::regclass,
              'entity_identity_semantic_replays_v2'::regclass
          )
    loop
        execute format(
            'alter table %s drop constraint %I',
            item.table_name,item.conname
        );
    end loop;
    if exists (
        select 1 from pg_constraint
        where contype='f'
          and confrelid='events_v2_core'::regclass
          and conrelid in (
              'semantic_processing_outbox'::regclass,
              'normalized_events'::regclass,
              'entity_identity_merge_events_v2'::regclass,
              'entity_identity_semantic_replays_v2'::regclass
          )
    ) then
        raise exception 'migration 071 did not remove all four retention blockers';
    end if;
end
$$;

insert into schema_migrations(version,name)
values(71,'semantic_source_retention_decoupling')
on conflict(version) do nothing;

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=71 and name='semantic_source_retention_decoupling'
    ) then
        raise exception 'migration 071 marker conflict';
    end if;
end
$$;

commit;
