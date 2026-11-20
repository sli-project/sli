-- FOUNDATION-1: durable semantic processing contract.
-- Source-only migration.  No worker or runtime path consumes these tables until
-- the separately gated semantic shadow-mode implementation is accepted.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_processing_foundation_v22'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 022 requires membership in adlog_storage_owner';
    end if;
    if to_regclass('events_v2_core') is null then
        raise exception 'migration 022 requires events_v2_core';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=21 and name='storage_v2_entity_detail_kind'
    ) then
        raise exception 'migration 022 requires schema migration 021';
    end if;
end
$$;

set local role adlog_storage_owner;

-- A normalized event is a versioned semantic interpretation of one immutable
-- Storage V2 event.  The application supplies UUIDs and hashes; no extension
-- (and therefore no implicit database-side UUID generation) is required.
create table if not exists normalized_events (
    normalized_event_id uuid primary key,
    source_event_id integer not null references events_v2_core(id) on delete restrict,
    semantic_contract_version integer not null check (semantic_contract_version > 0),
    normalizer_id text not null check (length(normalizer_id) between 1 and 160),
    normalizer_version text not null check (length(normalizer_version) between 1 and 80),
    processing_status text not null check (processing_status in ('normalized', 'ignored', 'quarantined', 'failed')),
    normalized_at timestamptz not null default now(),
    source_event_sha256 bytea not null check (octet_length(source_event_sha256) = 32),
    semantic_sha256 bytea not null check (octet_length(semantic_sha256) = 32),
    facts_json jsonb not null default '{}'::jsonb check (jsonb_typeof(facts_json) = 'object'),
    quality_json jsonb not null default '{}'::jsonb check (jsonb_typeof(quality_json) = 'object'),
    failure_code text,
    failure_detail text,
    created_at timestamptz not null default now(),
    constraint normalized_events_failure_detail check (
        (processing_status in ('quarantined', 'failed') and failure_code is not null)
        or (processing_status in ('normalized', 'ignored') and failure_code is null and failure_detail is null)
    ),
    unique (source_event_id, semantic_contract_version, normalizer_id, normalizer_version),
    unique (source_event_id, semantic_contract_version, semantic_sha256)
);

-- A canonical action groups one or more normalized events without assigning a
-- risk verdict.  contribution_key is a deterministic, caller-supplied SHA-256
-- identity that makes retries idempotent and permits future replay revisions.
create table if not exists canonical_actions (
    canonical_action_id uuid primary key,
    action_kind text not null check (length(action_kind) between 1 and 160),
    action_status text not null check (action_status in ('observed', 'confirmed', 'superseded', 'quarantined')),
    semantic_contract_version integer not null check (semantic_contract_version > 0),
    assembler_id text not null check (length(assembler_id) between 1 and 160),
    assembler_version text not null check (length(assembler_version) between 1 and 80),
    occurred_at_utc timestamptz not null,
    contribution_key bytea not null check (octet_length(contribution_key) = 32),
    action_sha256 bytea not null check (octet_length(action_sha256) = 32),
    attributes_json jsonb not null default '{}'::jsonb check (jsonb_typeof(attributes_json) = 'object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (semantic_contract_version, assembler_id, assembler_version, contribution_key)
);

-- Evidence is ordered and typed explicitly so a state confirmation remains
-- evidence of an action instead of becoming a duplicate action itself.
create table if not exists canonical_action_evidence (
    canonical_action_id uuid not null references canonical_actions(canonical_action_id) on delete restrict,
    normalized_event_id uuid not null references normalized_events(normalized_event_id) on delete restrict,
    evidence_role text not null check (evidence_role in ('primary', 'supporting', 'state_confirmation', 'context')),
    entity_role text check (entity_role is null or entity_role in ('actor', 'session_principal', 'affected', 'target', 'container', 'source', 'context')),
    evidence_order smallint not null check (evidence_order between 0 and 32767),
    relation_confidence numeric(4,3) not null default 1.000 check (relation_confidence >= 0 and relation_confidence <= 1),
    created_at timestamptz not null default now(),
    primary key (canonical_action_id, normalized_event_id, evidence_role),
    unique (canonical_action_id, evidence_order)
);

-- Outbox rows intentionally carry only an event reference and versioned
-- processor identity.  They must never duplicate raw XML or EventData payloads.
create table if not exists semantic_processing_outbox (
    job_id uuid primary key,
    source_event_id integer not null references events_v2_core(id) on delete restrict,
    job_kind text not null check (job_kind in ('normalize_event', 'assemble_action', 'semantic_replay')),
    semantic_contract_version integer not null check (semantic_contract_version > 0),
    processor_id text not null check (length(processor_id) between 1 and 160),
    processor_version text not null check (length(processor_version) between 1 and 80),
    idempotency_key bytea not null check (octet_length(idempotency_key) = 32),
    status text not null default 'queued' check (status in ('queued', 'leased', 'completed', 'failed', 'quarantined')),
    attempt_count integer not null default 0 check (attempt_count >= 0),
    max_attempts integer not null default 5 check (max_attempts between 1 and 20),
    available_at timestamptz not null default now(),
    lease_token uuid,
    lease_until timestamptz,
    heartbeat_at timestamptz,
    payload_json jsonb not null default '{}'::jsonb check (jsonb_typeof(payload_json) = 'object'),
    last_error_code text,
    last_error_detail text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    completed_at timestamptz,
    constraint semantic_processing_outbox_lease check (
        (status = 'leased' and lease_token is not null and lease_until is not null)
        or (status <> 'leased' and lease_token is null and lease_until is null)
    ),
    constraint semantic_processing_outbox_terminal check (
        (status = 'completed' and completed_at is not null and last_error_code is null)
        or (status in ('failed', 'quarantined') and last_error_code is not null)
        or status in ('queued', 'leased')
    ),
    unique (idempotency_key),
    unique (source_event_id, job_kind, semantic_contract_version, processor_id, processor_version)
);

create index if not exists idx_normalized_events_source
    on normalized_events(source_event_id, normalized_at desc);
create index if not exists idx_canonical_actions_occurred
    on canonical_actions(action_kind, occurred_at_utc desc, canonical_action_id);
create index if not exists idx_canonical_action_evidence_event
    on canonical_action_evidence(normalized_event_id, canonical_action_id);
create index if not exists idx_semantic_processing_outbox_claim
    on semantic_processing_outbox(status, available_at, lease_until, created_at);

revoke all on table normalized_events, canonical_actions, canonical_action_evidence, semantic_processing_outbox from public;
grant select, insert on semantic_processing_outbox to adlog_user;
grant select on normalized_events, canonical_actions, canonical_action_evidence to adlog_user;
grant select, insert, update on normalized_events, canonical_actions, canonical_action_evidence, semantic_processing_outbox to adlog_storage_worker;

insert into schema_migrations(version, name)
values (22, 'semantic_processing_foundation')
on conflict(version) do update set name=excluded.name;

commit;
