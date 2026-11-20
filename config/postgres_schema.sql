-- PostgreSQL schema for Security Log Intelligence / ad_log_reports.
-- DB-0.1 readiness stage. Safe to run repeatedly.
-- This schema mirrors the current SQLite schema while preparing high-volume tables
-- for PostgreSQL ingest and bounded report queries.

begin;

create table if not exists schema_migrations (
    id bigserial primary key,
    version integer not null unique,
    name text not null,
    applied_at timestamptz not null default now()
);

create table if not exists forests (
    id bigserial primary key,
    name text not null unique,
    description text,
    created_at timestamptz not null default now()
);

create table if not exists domains (
    id bigserial primary key,
    forest_id bigint not null references forests(id),
    fqdn text not null,
    netbios_name text,
    domain_sid text,
    created_at timestamptz not null default now(),
    unique(forest_id, fqdn)
);

create table if not exists sites (
    id bigserial primary key,
    domain_id bigint not null references domains(id),
    name text not null,
    site_type text not null default 'unknown',
    location text,
    created_at timestamptz not null default now(),
    unique(domain_id, name)
);

create table if not exists servers (
    id bigserial primary key,
    domain_id bigint not null references domains(id),
    site_id bigint references sites(id),
    hostname text not null,
    fqdn text,
    role text not null default 'unknown',
    os_name text,
    os_version text,
    os_language text,
    is_active boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique(domain_id, hostname)
);

create table if not exists log_sources (
    id bigserial primary key,
    name text not null unique,
    provider text,
    description text
);

create table if not exists collection_runs (
    id bigserial primary key,
    run_started_at timestamptz not null,
    run_finished_at timestamptz,
    mode text not null,
    status text not null default 'started',
    tool_version text,
    notes text
);

create table if not exists archive_settings (
    key text primary key,
    value text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists collection_channel_state (
    server_hostname text not null,
    channel text not null,
    archive_start_utc text not null,
    last_collection_start_utc text,
    last_successful_collection_utc text,
    last_event_time_utc text,
    last_event_record_id bigint,
    backfill_completed boolean not null default false,
    updated_at timestamptz not null default now(),
    primary key (server_hostname, channel)
);

create table if not exists collector_channel_runs (
    id bigserial primary key,
    job_id bigint,
    server text not null,
    channel text not null,
    started_utc text,
    finished_utc text,
    status text not null,
    inserted bigint not null default 0,
    skipped bigint not null default 0,
    count bigint not null default 0,
    partial_count bigint not null default 0,
    latest_event_record_id bigint,
    lag_minutes integer,
    timeout_seconds integer,
    limit_used integer,
    adaptive_action text,
    error text,
    query_duration_ms integer,
    import_duration_ms integer,
    import_queue_wait_ms integer,
    import_retry_count integer,
    report_duration_ms integer,
    total_duration_ms integer,
    events_per_second double precision,
    last_record_id_delta bigint,
    lag_delta_minutes integer,
    collection_mode text,
    requested_collection_mode text,
    cursor_strategy text,
    cursor_fallback_reason text,
      collector_backend text,
      backend_reason text,
      partial_kind text,
      failure_stage text,
      cursor_commit_allowed boolean,
      created_at timestamptz not null default now()
);

create table if not exists collector_cursor_audit (
    id bigserial primary key,
    job_id bigint,
    trace_id text,
    server text not null,
    channel text not null,
    collection_status text not null,
    import_inserted bigint not null default 0,
    import_skipped bigint not null default 0,
    old_record_id bigint,
    proposed_record_id bigint,
    new_record_id bigint,
    old_event_time_utc text,
    proposed_event_time_utc text,
    new_event_time_utc text,
    decision text not null,
    reason text not null,
    cursor_strategy text,
    cursor_fallback_reason text,
    created_at timestamptz not null default now()
);

create index if not exists idx_collector_cursor_audit_server_channel
    on collector_cursor_audit(server, channel, id desc);
create index if not exists idx_collector_cursor_audit_created
    on collector_cursor_audit(created_at desc);

create table if not exists collector_adaptive_state (
    server text not null,
    channel text not null,
    current_limit integer not null,
    consecutive_completed integer not null default 0,
    recovery_mode boolean not null default false,
    last_status text,
    last_lag_minutes integer,
    last_action text,
    updated_at timestamptz not null default now(),
    primary key(server, channel)
);

create table if not exists collector_stage_metrics (
    id bigserial primary key,
    job_id bigint,
    server text,
    channel text,
    backend text,
    stage text not null,
    status text not null default 'completed',
    duration_ms integer,
    events_count bigint,
    bytes_count bigint,
    error text,
    created_at timestamptz not null default now()
);

create table if not exists raw_log_files (
    id bigserial primary key,
    collection_run_id bigint references collection_runs(id),
    server_id bigint not null references servers(id),
    log_source_id bigint not null references log_sources(id),
    file_path text not null unique,
    file_format text not null,
    sha256 text not null,
    size_bytes bigint,
    event_count bigint,
    exported_at text,
    imported_at timestamptz not null default now(),
    unique(server_id, log_source_id, sha256)
);

create table if not exists raw_batch_lifecycle (
    batch_identity text primary key,
    manifest_hash text not null,
    server text not null,
    raw_path text not null,
    trace_id text not null,
    expected_channels integer not null default 0 check(expected_channels >= 0),
    committed_channels integer not null default 0 check(committed_channels >= 0),
    import_outcome text not null default 'unknown'
        check(import_outcome in ('unknown','succeeded','failed')),
    cursor_outcome text not null default 'unknown'
        check(cursor_outcome in ('unknown','committed','not_committed')),
    cleanup_outcome text not null default 'retained'
        check(cleanup_outcome in ('retained','delete_authorized','deleted','delete_failed')),
    import_error text,
    cleanup_error text,
    created_at timestamptz not null default now(),
    import_recorded_at timestamptz,
    cursor_recorded_at timestamptz,
    cleanup_recorded_at timestamptz,
    updated_at timestamptz not null default now(),
    constraint raw_batch_lifecycle_identity_sha256 check(batch_identity ~ '^[0-9a-f]{64}$'),
    constraint raw_batch_lifecycle_manifest_sha256 check(manifest_hash ~ '^[0-9a-f]{64}$'),
    unique(raw_path, manifest_hash)
);

create index if not exists idx_raw_batch_lifecycle_trace
    on raw_batch_lifecycle(trace_id, server);
create index if not exists idx_raw_batch_lifecycle_retained
    on raw_batch_lifecycle(updated_at desc)
    where cleanup_outcome <> 'deleted';

-- AD snapshot manifest contract (migration 128 current shape).
create table if not exists ad_snapshot_manifests (
    manifest_id uuid primary key,
    domain_id bigint not null references domains(id) on delete restrict,
    domain_sid text not null check(length(btrim(domain_sid)) > 0),
    domain_dns text not null check(length(btrim(domain_dns)) > 0),
    slot_start_utc timestamptz not null,
    assembled_at_utc timestamptz not null,
    contract_version text not null,
    schedule_timezone text,
    scheduled_local_at timestamp without time zone,
    coverage_state text not null check(coverage_state in ('complete', 'partial')),
    manifest_sha256 bytea not null check(octet_length(manifest_sha256) = 32),
    created_at timestamptz not null default now(),
    unique(domain_id, slot_start_utc, contract_version),
    constraint ad_snapshot_manifests_contract_version_check check (contract_version in (
        'sli.ad-snapshot-manifest/1.0',
        'sli.ad-snapshot-manifest/2.0'
    )),
    constraint ad_snapshot_manifests_slot_start_utc_check check (
        (
            contract_version = 'sli.ad-snapshot-manifest/1.0'
            and schedule_timezone is null
            and scheduled_local_at is null
            and (
                (slot_start_utc at time zone 'UTC') = date_trunc('day', slot_start_utc at time zone 'UTC')
                or (slot_start_utc at time zone 'UTC') = date_trunc('day', slot_start_utc at time zone 'UTC') + interval '12 hours'
            )
        )
        or
        (
            contract_version = 'sli.ad-snapshot-manifest/2.0'
            and schedule_timezone = 'Asia/Novosibirsk'
            and scheduled_local_at is not null
            and scheduled_local_at = date_trunc('minute', scheduled_local_at)
            and scheduled_local_at::time in (time '06:00:00', time '18:00:00')
            and slot_start_utc = scheduled_local_at at time zone 'Asia/Novosibirsk'
        )
    ),
    check(assembled_at_utc >= slot_start_utc)
);

create table if not exists ad_snapshot_manifest_sources (
    manifest_id uuid not null references ad_snapshot_manifests(manifest_id) on delete restrict,
    family text not null check(family in (
        'ad_context_base', 'ad_privileged_membership', 'ad_vpn_membership',
        'ad_domain_posture', 'ad_domain_health', 'ad_gpo_governance',
        'users_v2', 'computers_v6', 'gpo_v2'
    )),
    contract_id text not null check(length(btrim(contract_id)) > 0),
    source_id text not null check(length(btrim(source_id)) > 0),
    observed_at_utc timestamptz not null,
    source_state text not null check(source_state in ('complete', 'partial', 'failed')),
    payload_sha256 bytea not null check(octet_length(payload_sha256) = 32),
    reason_code text,
    primary key(manifest_id, family),
    check((source_state = 'complete' and reason_code is null)
        or (source_state <> 'complete' and reason_code is not null
            and length(btrim(reason_code)) > 0))
);

create table if not exists ad_snapshot_projection_receipts (
    manifest_id uuid not null references ad_snapshot_manifests(manifest_id) on delete restrict,
    projection_key text not null check(projection_key in ('ad.users.v2', 'ad.computers.v6', 'ad.gpo.v2', 'ad.state')),
    projection_version integer not null check(projection_version = 1),
    status text not null check(status in ('pending', 'running', 'completed', 'failed')),
    attempt_count integer not null default 0 check(attempt_count between 0 and 16),
    lease_owner text,
    lease_expires_at timestamptz,
    input_sha256 bytea check(input_sha256 is null or octet_length(input_sha256) = 32),
    output_sha256 bytea check(output_sha256 is null or octet_length(output_sha256) = 32),
    output_identity text,
    last_error text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key(manifest_id, projection_key, projection_version),
    check((status = 'running') = (lease_owner is not null and lease_expires_at is not null))
);

create or replace function ad_snapshot_manifest_apply_v2_schedule_header()
returns trigger language plpgsql as $$
declare
    expected_local_at timestamp without time zone;
begin
    if new.contract_version = 'sli.ad-snapshot-manifest/2.0' then
        expected_local_at := new.slot_start_utc at time zone 'Asia/Novosibirsk';
        if new.schedule_timezone is null then
            new.schedule_timezone := 'Asia/Novosibirsk';
        elsif new.schedule_timezone <> 'Asia/Novosibirsk' then
            raise exception 'v2 AD snapshot manifests require Asia/Novosibirsk schedule_timezone';
        end if;
        if new.scheduled_local_at is null then
            new.scheduled_local_at := expected_local_at;
        elsif new.scheduled_local_at is distinct from expected_local_at then
            raise exception 'v2 AD snapshot scheduled_local_at must match slot_start_utc';
        end if;
    elsif new.contract_version = 'sli.ad-snapshot-manifest/1.0' then
        if new.schedule_timezone is not null or new.scheduled_local_at is not null then
            raise exception 'v1 AD snapshot manifests cannot declare a schedule header';
        end if;
    end if;
    return new;
end
$$;

drop trigger if exists trg_ad_snapshot_manifests_v2_schedule_header on ad_snapshot_manifests;
create trigger trg_ad_snapshot_manifests_v2_schedule_header
before insert on ad_snapshot_manifests
for each row execute function ad_snapshot_manifest_apply_v2_schedule_header();

create or replace function ad_snapshot_manifest_reject_mutation()
returns trigger language plpgsql as $$
begin
    raise exception 'AD snapshot manifests are immutable';
end
$$;

drop trigger if exists trg_ad_snapshot_manifests_immutable on ad_snapshot_manifests;
create trigger trg_ad_snapshot_manifests_immutable
before update or delete or truncate on ad_snapshot_manifests
for each statement execute function ad_snapshot_manifest_reject_mutation();

drop trigger if exists trg_ad_snapshot_manifest_sources_immutable on ad_snapshot_manifest_sources;
create trigger trg_ad_snapshot_manifest_sources_immutable
before update or delete or truncate on ad_snapshot_manifest_sources
for each statement execute function ad_snapshot_manifest_reject_mutation();

create index if not exists idx_ad_snapshot_manifests_slot
    on ad_snapshot_manifests(domain_id, slot_start_utc desc, manifest_id);

create index if not exists idx_ad_snapshot_projection_receipts_claim
    on ad_snapshot_projection_receipts(status, lease_expires_at, attempt_count, created_at);

-- AD snapshot projection output contract (migration 129 current shape).
create table if not exists ad_snapshot_projection_outputs (
    manifest_id uuid not null references ad_snapshot_manifests(manifest_id) on delete restrict,
    projection_key text not null,
    projection_version integer not null,
    input_sha256 bytea not null check(octet_length(input_sha256) = 32),
    output_sha256 bytea not null check(octet_length(output_sha256) = 32),
    output_identity text not null,
    payload_json jsonb not null,
    created_at timestamptz not null default now(),
    primary key(manifest_id, projection_key, projection_version),
    unique(output_identity),
    constraint ad_snapshot_projection_outputs_allowlist_check check (
        (projection_key = 'ad.users.v2' and projection_version = 1)
        or (projection_key = 'ad.computers.v6' and projection_version = 1)
        or (projection_key = 'ad.gpo.v2' and projection_version = 1)
        or (projection_key = 'ad.state' and projection_version = 1)
    ),
    constraint ad_snapshot_projection_outputs_identity_check check (
        output_identity = manifest_id::text || ':' || projection_key || ':v' || projection_version::text
    )
);

create or replace function ad_snapshot_projection_output_reject_mutation()
returns trigger language plpgsql as $$
begin
    raise exception 'AD snapshot projection outputs are immutable';
end
$$;

drop trigger if exists trg_ad_snapshot_projection_outputs_immutable on ad_snapshot_projection_outputs;
create trigger trg_ad_snapshot_projection_outputs_immutable
before update or delete or truncate on ad_snapshot_projection_outputs
for each statement execute function ad_snapshot_projection_output_reject_mutation();

alter table ad_snapshot_projection_receipts
    drop constraint if exists ad_snapshot_projection_receipts_completed_output_check;
alter table ad_snapshot_projection_receipts
    add constraint ad_snapshot_projection_receipts_completed_output_check
    check (
        status <> 'completed'
        or (
            input_sha256 is not null
            and output_sha256 is not null
            and output_identity is not null
            and octet_length(input_sha256) = 32
            and octet_length(output_sha256) = 32
            and output_identity = manifest_id::text || ':' || projection_key || ':v' || projection_version::text
        )
    ) not valid;

revoke all on table ad_snapshot_projection_outputs from public;
revoke all on table ad_snapshot_projection_outputs from adlog_user;
grant select, insert on table ad_snapshot_projection_outputs to adlog_user;
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'adlog_context_worker') then
        execute 'revoke all on table ad_snapshot_projection_outputs from adlog_context_worker';
        execute 'grant select, insert on table ad_snapshot_projection_outputs to adlog_context_worker';
    end if;
end
$$;

create table if not exists events (
    id bigserial primary key,
    raw_log_file_id bigint references raw_log_files(id),
    server_id bigint not null references servers(id),
    domain_id bigint not null references domains(id),
    site_id bigint references sites(id),
    log_source_id bigint not null references log_sources(id),
    event_record_id bigint,
    event_id integer not null,
    version integer,
    level integer,
    task integer,
    opcode integer,
    keywords text,
    provider_name text,
    provider_guid text,
    channel text not null,
    computer text,
    time_created_utc text not null,
    time_created_local text,
    record_xml text,
    message_text text,
    event_data_json text,
    subject_user_sid text,
    subject_user_name text,
    subject_domain_name text,
    target_user_sid text,
    target_user_name text,
    target_domain_name text,
    ip_address text,
    workstation_name text,
    logon_id text,
    correlation_id text,
    normalized_at timestamptz not null default now(),
    normalized_hash text,
    unique(server_id, channel, event_record_id, time_created_utc)
);

create table if not exists event_links (
    id bigserial primary key,
    source_event_id bigint not null references events(id),
    target_event_id bigint not null references events(id),
    link_type text not null,
    confidence double precision not null default 0.0,
    created_at timestamptz not null default now(),
    unique(source_event_id, target_event_id, link_type)
);

create table if not exists observed_entities (
    id bigserial primary key,
    entity_type text not null,
    natural_key text not null,
    display_name text not null,
    domain_id bigint references domains(id),
    server_id bigint references servers(id),
    first_seen_utc text,
    last_seen_utc text,
    attributes_json text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique(entity_type, natural_key)
);

create table if not exists event_entity_links (
    id bigserial primary key,
    event_id bigint not null references events(id),
    entity_id bigint not null references observed_entities(id),
    link_role text not null,
    confidence double precision not null default 1.0,
    evidence_json text,
    extracted_from text,
    attributes_json text,
    created_at timestamptz not null default now(),
    unique(event_id, entity_id, link_role)
);

create table if not exists entity_states (
    id bigserial primary key,
    entity_id bigint not null references observed_entities(id),
    state_type text not null,
    severity text not null default 'info',
    status text not null default 'observed',
    observed_at_utc text not null,
    summary text,
    evidence_event_id bigint references events(id),
    details_json text,
    created_at timestamptz not null default now(),
    unique(entity_id, state_type, evidence_event_id)
);

create table if not exists detection_rules (
    id bigserial primary key,
    code text not null unique,
    name text not null,
    description text,
    severity_default text not null,
    enabled boolean not null default true,
    version text not null default '1'
);

create table if not exists detections (
    id bigserial primary key,
    detection_rule_id bigint not null references detection_rules(id),
    primary_event_id bigint references events(id),
    server_id bigint not null references servers(id),
    domain_id bigint not null references domains(id),
    site_id bigint references sites(id),
    detected_at timestamptz not null default now(),
    severity text not null,
    status text not null default 'new',
    facts_json text,
    evidence_event_ids_json text
);

create table if not exists ai_analysis (
    id bigserial primary key,
    detection_id bigint not null references detections(id),
    model_name text not null,
    prompt_version text not null,
    analyzed_at timestamptz not null default now(),
    risk text not null,
    confidence text not null,
    summary text,
    facts_json text,
    assumptions_json text,
    recommendations_json text,
    raw_response_json text
);

create table if not exists ai_reviews (
    id bigserial primary key,
    ai_analysis_id bigint not null references ai_analysis(id),
    reviewer_model_name text not null,
    reviewed_at timestamptz not null default now(),
    report_is_valid boolean not null,
    unsafe_recommendations_json text,
    missing_evidence_json text,
    issues_json text,
    final_decision text not null,
    raw_response_json text
);

create table if not exists reports (
    id bigserial primary key,
    title text not null,
    report_type text not null,
    period_start_utc text,
    period_end_utc text,
    generated_at timestamptz not null default now(),
    file_path text,
    status text not null default 'draft'
);

create table if not exists report_items (
    id bigserial primary key,
    report_id bigint not null references reports(id),
    detection_id bigint references detections(id),
    ai_analysis_id bigint references ai_analysis(id),
    sort_order integer not null default 0
);

create table if not exists findings (
    id bigserial primary key,
    fingerprint text not null unique,
    rule_code text not null,
    title text not null,
    severity text not null,
    confidence double precision not null default 0.65,
    status text not null default 'new',
    first_seen_utc text,
    last_seen_utc text,
    actor text,
    target text,
    source text,
    summary text,
    why_it_matters text,
    recommended_action text,
    evidence_count bigint not null default 0,
    status_reason text,
    assigned_to text,
    closed_at text,
    repeat_count bigint not null default 0,
    last_evidence_event_id bigint,
    last_repeat_detected_at text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists finding_evidence (
    id bigserial primary key,
    finding_id bigint not null references findings(id) on delete cascade,
    event_id bigint not null references events(id),
    evidence_role text not null default 'supporting_event',
    note text,
    created_at timestamptz not null default now(),
    unique(finding_id, event_id, evidence_role)
);

create table if not exists finding_entities (
    id bigserial primary key,
    finding_id bigint not null references findings(id) on delete cascade,
    entity_id bigint references observed_entities(id),
    entity_type text,
    display_name text,
    entity_role text not null default 'context',
    created_at timestamptz not null default now(),
    unique(finding_id, entity_id, entity_role)
);

create table if not exists finding_status_history (
    id bigserial primary key,
    finding_id bigint not null references findings(id) on delete cascade,
    old_status text,
    new_status text not null,
    changed_at timestamptz not null default now(),
    changed_by text not null default 'system',
    note text
);

create table if not exists findings_refresh_state (
    pipeline_name text primary key,
    last_event_id bigint not null default 0,
    bootstrap_event_id bigint not null default 0,
    last_status text not null default 'ready',
    last_started_at timestamptz,
    last_completed_at timestamptz,
    last_failed_at timestamptz,
    last_duration_ms bigint,
    last_scanned_events bigint not null default 0,
    last_matched_events bigint not null default 0,
    last_created_findings bigint not null default 0,
    last_updated_findings bigint not null default 0,
    last_evidence_added bigint not null default 0,
    last_manual_status_preserved bigint not null default 0,
    last_has_more boolean not null default false,
    last_error text,
    updated_at timestamptz not null default now()
);

create table if not exists storage_lifecycle_snapshots (
    id bigserial primary key,
    captured_at timestamptz not null default now(),
    source text not null,
    source_job_id bigint,
    source_run_id text unique,
    database_bytes bigint not null default 0,
    events_estimated_rows bigint not null default 0,
    events_max_id bigint not null default 0,
    events_last_24h bigint not null default 0,
    raw_bytes bigint not null default 0,
    raw_archive_bytes bigint not null default 0,
    backups_bytes bigint not null default 0,
    logs_bytes bigint not null default 0,
    reports_bytes bigint not null default 0,
    artifacts_bytes bigint not null default 0,
    disk_total_bytes bigint not null default 0,
    disk_used_bytes bigint not null default 0,
    disk_free_bytes bigint not null default 0,
    disk_free_percent numeric(7,3) not null default 0,
    table_stats_json jsonb not null default '[]'::jsonb,
    scan_meta_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create table if not exists post_collection_jobs (
    id bigserial primary key,
    source_job_id bigint not null,
    durable_job_id text not null unique,
    status text not null,
    servers_json jsonb not null default '[]'::jsonb,
    queued_at timestamptz not null default now(),
    started_at timestamptz,
    finished_at timestamptz,
    report_path text,
    error_id text,
    error_message text,
    worker_id text,
    attempt_count integer not null default 0,
    max_attempts integer not null default 2,
    heartbeat_at timestamptz,
    worker_lease_until timestamptz,
    phase text not null default 'queued',
    findings_status text not null default 'queued',
    findings_started_at timestamptz,
    findings_finished_at timestamptz,
    findings_duration_ms bigint,
    findings_scanned_events bigint,
    findings_matched_events bigint,
    findings_created bigint,
    findings_updated bigint,
    findings_evidence_added bigint,
    findings_watermark_before bigint,
    findings_watermark_after bigint,
    findings_error_id text,
    findings_error_message text,
    findings_result_json jsonb,
    updated_at timestamptz not null default now()
);

create table if not exists ai_api_runs (
    id bigserial primary key,
    provider text not null default 'openai_api',
    model text not null,
    prompt_version text not null,
    redaction_level text not null,
    status text not null default 'prepared',
    query_summary_json text,
    prompt_file_path text,
    request_file_path text,
    result_file_path text,
    report_file_path text,
    ai_call_performed boolean not null default false,
    validation_errors_json text,
    created_at timestamptz not null default now(),
    completed_at text
);

-- High-value indexes for collector status, bounded reports and investigation queries.
create index if not exists idx_collector_channel_runs_server_channel_time on collector_channel_runs(server, channel, created_at);
create index if not exists idx_collector_stage_metrics_job_server_channel on collector_stage_metrics(job_id, server, channel, created_at);
create index if not exists idx_events_time on events(time_created_utc);
create index if not exists idx_events_server_time on events(server_id, time_created_utc);
create index if not exists idx_events_domain_time on events(domain_id, time_created_utc);
create index if not exists idx_events_site_time on events(site_id, time_created_utc);
create index if not exists idx_events_event_id_time on events(event_id, time_created_utc);
create index if not exists idx_events_subject_user_time on events(subject_user_name, time_created_utc);
create index if not exists idx_events_target_user_time on events(target_user_name, time_created_utc);
create index if not exists idx_events_ip_time on events(ip_address, time_created_utc);
create index if not exists idx_events_logon_id_time on events(logon_id, time_created_utc);
create index if not exists idx_events_channel_event_time on events(channel, event_id, time_created_utc);
create index if not exists idx_observed_entities_type on observed_entities(entity_type);
create index if not exists idx_event_entity_links_event on event_entity_links(event_id);
create index if not exists idx_event_entity_links_entity on event_entity_links(entity_id);
create index if not exists idx_event_entity_links_role on event_entity_links(link_role);
create index if not exists idx_event_links_target on event_links(target_event_id);
create index if not exists idx_entity_states_entity on entity_states(entity_id, observed_at_utc);
create index if not exists idx_detections_status on detections(status, detected_at);
create index if not exists idx_findings_status_severity on findings(status, severity, last_seen_utc);
create index if not exists idx_findings_rule on findings(rule_code, last_seen_utc);
create index if not exists idx_finding_evidence_event on finding_evidence(event_id);
create index if not exists idx_finding_entities_name on finding_entities(display_name);
create index if not exists idx_post_collection_jobs_status on post_collection_jobs(status, queued_at);
create index if not exists idx_post_collection_jobs_source_job_id on post_collection_jobs(source_job_id);
create index if not exists idx_post_collection_jobs_lease on post_collection_jobs(status, worker_lease_until);
create index if not exists idx_storage_lifecycle_snapshots_captured on storage_lifecycle_snapshots(captured_at desc);
create index if not exists idx_storage_lifecycle_snapshots_source_job_id on storage_lifecycle_snapshots(source_job_id);
create index if not exists idx_ai_api_runs_status_time on ai_api_runs(status, created_at);

insert into schema_migrations(version, name) values
(1, 'initial_postgres_schema'),
(2, 'stage_4_1_persistent_findings'),
(3, 'stage_4_3_ai_api_prompt_runs'),
(4, 'stage_4_4_ai_report_pipeline'),
(5, 'db_0_1_postgres_readiness'),
(6, 'findings_pg1_incremental_pipeline'),
(7, 'storage_lifecycle2_measurement_and_backup_rehearsal'),
(8, 'ops_stability1_runtime_contracts')
on conflict(version) do nothing;

insert into log_sources(name, provider, description) values
('Security', 'Microsoft-Windows-Security-Auditing', 'Windows Security Event Log'),
('System', null, 'Windows System Event Log'),
('Application', null, 'Windows Application Event Log'),
('Directory Service', 'Microsoft-Windows-ActiveDirectory_DomainService', 'Active Directory Domain Services log'),
('DNS Server', 'Microsoft-Windows-DNS-Server-Service', 'DNS Server log'),
('Windows PowerShell', 'PowerShell', 'Windows PowerShell classic log'),
('Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', 'PowerShell operational log'),
('Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-TaskScheduler', 'Task Scheduler operational log')
on conflict(name) do nothing;

insert into detection_rules(code, name, description, severity_default, enabled, version) values
('AD-LOG-CLEARED', 'Security log cleared', 'Security event log was cleared or audit trail was interrupted.', 'critical', true, '1'),
('AD-PRIV-GROUP-CHANGE', 'Privileged group membership changed', 'Membership of a privileged AD group changed.', 'high', true, '1'),
('AD-USER-CREATED-OR-ENABLED', 'User account created or enabled', 'User account was created or enabled.', 'medium', true, '1'),
('AD-ACCOUNT-LOCKOUT', 'Account lockout', 'User account lockout was detected.', 'medium', true, '1'),
('AD-MANY-FAILED-LOGONS', 'Many failed logons', 'Multiple failed logons were detected for the same principal or source.', 'medium', true, '1'),
('AD-SUCCESS-AFTER-FAILURES', 'Successful logon after failures', 'Successful logon after repeated failed logons.', 'high', true, '1'),
('AD-SPECIAL-LOGON', 'Special logon', 'Privileged logon was detected.', 'medium', true, '1'),
('AD-AUDIT-POLICY-CHANGE', 'Audit policy changed', 'Audit policy was changed.', 'high', true, '1'),
('AD-KERBEROS-ANOMALY', 'Kerberos anomaly candidate', 'Kerberos authentication or service ticket anomaly candidate.', 'medium', true, '1'),
('AD-POWERSHELL-ACTIVITY', 'PowerShell activity candidate', 'PowerShell activity that may require review.', 'medium', true, '1')
on conflict(code) do nothing;

commit;
