begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_context_foundation'));

create table if not exists ad_context_runs (
    run_id uuid primary key,
    source_pack_id text not null,
    source_pack_version text not null,
    domain_id bigint not null references domains(id) on delete restrict,
    mode text not null check (mode in ('full', 'targeted', 'reconcile')),
    observed_at_utc timestamptz not null,
    bundle_sha256 bytea not null check (octet_length(bundle_sha256) = 32),
    status text not null check (status in ('importing', 'completed', 'failed')),
    created_at timestamptz not null default now(),
    completed_at timestamptz
);

create table if not exists ad_context_sections (
    run_id uuid not null references ad_context_runs(run_id) on delete cascade,
    section_name text not null,
    status text not null check (status in ('complete', 'partial', 'failed', 'skipped')),
    record_count integer not null check (record_count >= 0),
    duration_ms bigint not null default 0 check (duration_ms >= 0),
    error_code text,
    primary key (run_id, section_name)
);

create table if not exists ad_context_entity_aliases (
    id bigserial primary key,
    entity_id bigint not null references observed_entities(id) on delete cascade,
    domain_id bigint not null references domains(id) on delete restrict,
    alias_type text not null check (alias_type in ('object_guid', 'object_sid', 'distinguished_name', 'sam_account_name')),
    alias_value text not null,
    normalized_value text not null,
    first_seen_utc timestamptz not null,
    last_seen_utc timestamptz not null,
    source_run_id uuid not null references ad_context_runs(run_id) on delete restrict,
    unique (domain_id, alias_type, normalized_value)
);

create table if not exists ad_context_entity_versions (
    id bigserial primary key,
    entity_id bigint not null references observed_entities(id) on delete cascade,
    source_section text not null,
    valid_from_utc timestamptz not null,
    valid_to_utc timestamptz,
    last_observed_at_utc timestamptz not null,
    content_sha256 bytea not null check (octet_length(content_sha256) = 32),
    attributes_json jsonb not null,
    source_run_id uuid not null references ad_context_runs(run_id) on delete restrict,
    check (valid_to_utc is null or valid_to_utc >= valid_from_utc)
);

create unique index if not exists uq_ad_context_entity_version_open
    on ad_context_entity_versions(entity_id, source_section) where valid_to_utc is null;

create table if not exists ad_context_relation_versions (
    id bigserial primary key,
    relation_key text not null,
    relation_kind text not null check (relation_kind in ('member_of')),
    source_entity_id bigint not null references observed_entities(id) on delete cascade,
    target_entity_id bigint not null references observed_entities(id) on delete cascade,
    source_section text not null,
    domain_id bigint not null references domains(id) on delete restrict,
    valid_from_utc timestamptz not null,
    valid_to_utc timestamptz,
    last_observed_at_utc timestamptz not null,
    content_sha256 bytea not null check (octet_length(content_sha256) = 32),
    attributes_json jsonb not null,
    source_run_id uuid not null references ad_context_runs(run_id) on delete restrict,
    check (source_entity_id <> target_entity_id),
    check (valid_to_utc is null or valid_to_utc >= valid_from_utc)
);

create unique index if not exists uq_ad_context_relation_version_open
    on ad_context_relation_versions(domain_id, relation_key) where valid_to_utc is null;
create index if not exists idx_ad_context_relation_source_current
    on ad_context_relation_versions(source_entity_id, relation_kind) where valid_to_utc is null;
create index if not exists idx_ad_context_relation_target_current
    on ad_context_relation_versions(target_entity_id, relation_kind) where valid_to_utc is null;

create table if not exists ad_context_evidence (
    id bigserial primary key,
    evidence_key text not null unique,
    evidence_type text not null check (evidence_type in ('entity_observation', 'relation_observation', 'data_quality')),
    source_pack_id text not null,
    source_run_id uuid not null references ad_context_runs(run_id) on delete restrict,
    observed_at_utc timestamptz not null,
    locator_json jsonb not null,
    integrity_sha256 bytea not null check (octet_length(integrity_sha256) = 32),
    created_at timestamptz not null default now()
);

create table if not exists ad_context_event_links (
    event_db_id bigint not null,
    context_evidence_id bigint not null references ad_context_evidence(id) on delete restrict,
    rule_code text not null,
    relation_status text not null check (relation_status in ('confirmed', 'current_only', 'excluded')),
    explanation text not null,
    created_at timestamptz not null default now(),
    primary key (event_db_id, context_evidence_id, rule_code)
);

comment on column ad_context_event_links.event_db_id is
    'Stable event evidence ID validated by application against events or events_v2_core';

create table if not exists investigation_context_evidence (
    investigation_id bigint not null references investigations(id) on delete cascade,
    context_evidence_id bigint not null references ad_context_evidence(id) on delete restrict,
    relation_status text not null default 'confirmed' check (relation_status in ('confirmed', 'excluded')),
    added_by text not null,
    added_at timestamptz not null default now(),
    primary key (investigation_id, context_evidence_id)
);

insert into schema_migrations(version, name)
values (17, 'ad_context_foundation')
on conflict(version) do update set name=excluded.name;

commit;
