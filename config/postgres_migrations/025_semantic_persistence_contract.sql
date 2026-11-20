-- SEMANTIC-PERSISTENCE-1: complete the durable normalization/action envelope.
-- Source-only migration. It does not enqueue jobs, register a worker, query AD,
-- create findings, or change the active collection/runtime route.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_persistence_contract_v25'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 025 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=24 and name='canonical_action_state_evidence'
    ) then
        raise exception 'migration 025 requires schema migration 024';
    end if;
    if to_regclass('normalized_events') is null
       or to_regclass('canonical_actions') is null
       or to_regclass('semantic_processing_outbox') is null then
        raise exception 'migration 025 requires semantic foundation tables';
    end if;
end
$$;

-- The migration reads immutable V2 source rows while running as the semantic
-- owner.  Keep this explicit so no-owner restores do not depend on historical
-- table ownership.
grant select on events_v2_core to adlog_storage_owner;

set local role adlog_storage_owner;

alter table normalized_events
    add column if not exists semantic_type text,
    add column if not exists occurred_at_utc timestamptz,
    add column if not exists source_ingested_at timestamptz,
    add column if not exists roles_json jsonb not null default '{}'::jsonb;

update normalized_events normalized
set semantic_type = coalesce(nullif(normalized.facts_json->>'semantic_type', ''), 'event.unknown'),
    occurred_at_utc = source.time_created_utc,
    source_ingested_at = source.migrated_at
from events_v2_core source
where source.id = normalized.source_event_id
  and (
      normalized.semantic_type is null
      or normalized.occurred_at_utc is null
      or normalized.source_ingested_at is null
  );

alter table normalized_events
    alter column semantic_type set not null,
    alter column occurred_at_utc set not null,
    alter column source_ingested_at set not null;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conrelid='normalized_events'::regclass
          and conname='normalized_events_semantic_type_bounded'
    ) then
        alter table normalized_events
            add constraint normalized_events_semantic_type_bounded
            check (length(semantic_type) between 1 and 160);
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='normalized_events'::regclass
          and conname='normalized_events_roles_object'
    ) then
        alter table normalized_events
            add constraint normalized_events_roles_object
            check (jsonb_typeof(roles_json)='object');
    end if;
end
$$;

do $$
declare
    constraint_name text;
begin
    select conname into constraint_name
    from pg_constraint
    where conrelid='canonical_action_evidence'::regclass
      and contype='c'
      and pg_get_constraintdef(oid) like '%entity_role%';
    if constraint_name is not null then
        execute format(
            'alter table canonical_action_evidence drop constraint %I',
            constraint_name
        );
    end if;
    alter table canonical_action_evidence
        add constraint canonical_action_evidence_entity_role_check
        check (
            entity_role is null or entity_role in (
                'actor','session_principal','affected_entity','target_entity',
                'container_entity','source_host','source_ip','context',
                'affected','target','container','source'
            )
        );
end
$$;

alter table canonical_actions
    add column if not exists canonical_deduplication_key bytea;

update canonical_actions
set canonical_deduplication_key=contribution_key
where canonical_deduplication_key is null;

alter table canonical_actions
    alter column canonical_deduplication_key set not null;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conrelid='canonical_actions'::regclass
          and conname='canonical_actions_dedup_key_length'
    ) then
        alter table canonical_actions
            add constraint canonical_actions_dedup_key_length
            check (octet_length(canonical_deduplication_key)=32);
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='canonical_actions'::regclass
          and conname='canonical_actions_dedup_identity_unique'
    ) then
        alter table canonical_actions
            add constraint canonical_actions_dedup_identity_unique
            unique (
                semantic_contract_version,
                assembler_id,
                assembler_version,
                canonical_deduplication_key
            );
    end if;
end
$$;

alter table semantic_processing_outbox
    add column if not exists source_id bigint,
    add column if not exists domain_id bigint,
    add column if not exists partition_key text,
    add column if not exists occurred_at_utc timestamptz,
    add column if not exists emitted_at timestamptz not null default now();

update semantic_processing_outbox job
set source_id=source.log_source_id,
    domain_id=source.domain_id,
    partition_key=source.server_id::text || ':' || source.channel_id::text,
    occurred_at_utc=source.time_created_utc
from events_v2_core source
where source.id=job.source_event_id
  and (
      job.source_id is null
      or job.domain_id is null
      or job.partition_key is null
      or job.occurred_at_utc is null
  );

alter table semantic_processing_outbox
    alter column source_id set not null,
    alter column domain_id set not null,
    alter column partition_key set not null,
    alter column occurred_at_utc set not null;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conrelid='semantic_processing_outbox'::regclass
          and conname='semantic_processing_outbox_partition_bounded'
    ) then
        alter table semantic_processing_outbox
            add constraint semantic_processing_outbox_partition_bounded
            check (length(partition_key) between 1 and 160);
    end if;
end
$$;

create index if not exists idx_normalized_events_semantic_time
    on normalized_events(semantic_type, occurred_at_utc desc, normalized_event_id);
create index if not exists idx_semantic_outbox_partition_claim
    on semantic_processing_outbox(partition_key, status, available_at, created_at);

insert into schema_migrations(version,name)
values (25,'semantic_persistence_contract')
on conflict(version) do update set name=excluded.name;

commit;
