-- SEMANTIC-CORRELATION-1: durable rule, candidate and bounded replay state.
-- Source-only migration. It does not register a worker, enable correlation,
-- create scenarios/findings, calculate risk or touch collection/live AD.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_correlation_v26'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 026 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=25 and name='semantic_persistence_contract'
    ) then
        raise exception 'migration 026 requires schema migration 025';
    end if;
end
$$;

set local role adlog_storage_owner;

create table if not exists semantic_correlation_rules (
    rule_id text not null check (length(rule_id) between 1 and 160),
    rule_version integer not null check (rule_version > 0),
    rule_kind text not null check (rule_kind in (
        'action','sequence','all_of','any_of','count','distinct_count','rate',
        'state_equals','state_changed','relationship_added','relationship_removed',
        'graph_path_created','graph_path_removed','metric_threshold','absence',
        'time_condition','entity_classification'
    )),
    lifecycle_status text not null default 'draft' check (lifecycle_status in (
        'draft','validated','test','shadow','enabled','disabled','deprecated'
    )),
    definition_json jsonb not null check (jsonb_typeof(definition_json)='object'),
    definition_sha256 bytea not null check (octet_length(definition_sha256)=32),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key(rule_id,rule_version),
    unique(rule_id,rule_version,definition_sha256)
);

create unique index if not exists uq_semantic_correlation_rule_enabled
    on semantic_correlation_rules(rule_id) where lifecycle_status='enabled';

create or replace function enforce_semantic_correlation_rule_immutability()
returns trigger language plpgsql as $$
begin
    if old.lifecycle_status <> 'draft' and (
        new.rule_kind is distinct from old.rule_kind
        or new.definition_json is distinct from old.definition_json
        or new.definition_sha256 is distinct from old.definition_sha256
    ) then
        raise exception 'non-draft semantic correlation rule definition is immutable';
    end if;
    new.updated_at = now();
    return new;
end
$$;

drop trigger if exists trg_semantic_correlation_rule_immutability
    on semantic_correlation_rules;
create trigger trg_semantic_correlation_rule_immutability
before update on semantic_correlation_rules
for each row execute function enforce_semantic_correlation_rule_immutability();

create table if not exists semantic_correlation_candidates (
    candidate_id uuid primary key,
    rule_id text not null,
    rule_version integer not null,
    relation_kind text not null check (length(relation_kind) between 1 and 200),
    candidate_status text not null default 'matched' check (candidate_status in (
        'open','matched','expired','quarantined'
    )),
    candidate_key bytea not null check (octet_length(candidate_key)=32),
    partition_key text not null check (length(partition_key) between 1 and 160),
    window_start_utc timestamptz not null,
    window_end_utc timestamptz not null,
    confidence text not null check (confidence in ('low','medium','high')),
    explanation text not null check (length(explanation) between 1 and 2000),
    evidence_count integer not null default 0 check (evidence_count >= 0),
    first_matched_at timestamptz not null default now(),
    last_matched_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    foreign key(rule_id,rule_version)
        references semantic_correlation_rules(rule_id,rule_version) on delete restrict,
    constraint semantic_correlation_candidate_window
        check (
            window_end_utc >= window_start_utc
            and window_end_utc <= window_start_utc + interval '24 hours'
        ),
    unique(rule_id,rule_version,candidate_key)
);

create table if not exists semantic_correlation_candidate_evidence (
    candidate_id uuid not null references semantic_correlation_candidates(candidate_id) on delete restrict,
    normalized_event_id uuid not null references normalized_events(normalized_event_id) on delete restrict,
    evidence_order smallint not null check (evidence_order between 0 and 32767),
    created_at timestamptz not null default now(),
    primary key(candidate_id,normalized_event_id),
    unique(candidate_id,evidence_order)
);

create table if not exists semantic_correlation_replays (
    replay_id uuid primary key,
    rule_id text not null,
    rule_version integer not null,
    range_start_utc timestamptz not null,
    range_end_utc timestamptz not null,
    idempotency_key bytea not null unique check (octet_length(idempotency_key)=32),
    replay_status text not null default 'queued' check (replay_status in (
        'queued','leased','completed','failed','quarantined'
    )),
    attempt_count integer not null default 0 check (attempt_count >= 0),
    max_attempts integer not null default 5 check (max_attempts between 1 and 20),
    available_at timestamptz not null default now(),
    lease_token uuid,
    lease_until timestamptz,
    heartbeat_at timestamptz,
    checkpoint_utc timestamptz,
    processed_events bigint not null default 0 check (processed_events >= 0),
    matched_candidates bigint not null default 0 check (matched_candidates >= 0),
    last_error_code text,
    last_error_detail text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    completed_at timestamptz,
    foreign key(rule_id,rule_version)
        references semantic_correlation_rules(rule_id,rule_version) on delete restrict,
    constraint semantic_correlation_replay_range check (
        range_end_utc > range_start_utc
        and range_end_utc <= range_start_utc + interval '7 days'
    ),
    constraint semantic_correlation_replay_lease check (
        (replay_status='leased' and lease_token is not null and lease_until is not null)
        or (replay_status<>'leased' and lease_token is null and lease_until is null)
    ),
    constraint semantic_correlation_replay_terminal check (
        (replay_status='completed' and completed_at is not null and last_error_code is null)
        or (replay_status in ('failed','quarantined') and last_error_code is not null)
        or replay_status in ('queued','leased')
    )
);

create index if not exists idx_semantic_correlation_candidate_partition
    on semantic_correlation_candidates(partition_key,window_end_utc desc,candidate_id);
create index if not exists idx_semantic_correlation_candidate_evidence_event
    on semantic_correlation_candidate_evidence(normalized_event_id,candidate_id);
create index if not exists idx_semantic_correlation_replay_claim
    on semantic_correlation_replays(replay_status,available_at,lease_until,created_at);

revoke all on table semantic_correlation_rules,
    semantic_correlation_candidates,
    semantic_correlation_candidate_evidence,
    semantic_correlation_replays from public;
grant select on semantic_correlation_rules,
    semantic_correlation_candidates,
    semantic_correlation_candidate_evidence,
    semantic_correlation_replays to adlog_user;
grant select,insert,update on semantic_correlation_rules,
    semantic_correlation_candidates,
    semantic_correlation_candidate_evidence,
    semantic_correlation_replays to adlog_storage_worker;

insert into schema_migrations(version,name)
values (26,'semantic_correlation_foundation')
on conflict(version) do update set name=excluded.name;

commit;
