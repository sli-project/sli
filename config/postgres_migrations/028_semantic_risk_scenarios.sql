-- SEMANTIC-RISK-1: durable scenarios, independent assessments and contributions.
-- Source-only. No producer/worker registration, findings, UI or live AD access.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_risk_v28'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 028 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=27 and name='semantic_dispatch_foundation'
    ) then
        raise exception 'migration 028 requires schema migration 027';
    end if;
end
$$;

set local role adlog_storage_owner;

create table if not exists semantic_security_scenarios (
    scenario_id uuid primary key,
    scenario_kind text not null check (length(scenario_kind) between 1 and 200),
    result_class text not null check (result_class in (
        'security_incident','security_exposure','control_gap'
    )),
    scenario_status text not null default 'open' check (scenario_status in (
        'open','under_review','resolved','dismissed'
    )),
    identity_key bytea not null check (octet_length(identity_key)=32),
    scenario_key bytea not null unique check (octet_length(scenario_key)=32),
    partition_key text not null check (length(partition_key) between 1 and 160),
    strict_keys_json jsonb not null check (jsonb_typeof(strict_keys_json)='object'),
    merge_window_seconds integer not null check (merge_window_seconds between 1 and 86400),
    title text not null check (length(title) between 1 and 300),
    explanation text not null check (length(explanation) between 1 and 2000),
    first_seen_utc timestamptz not null,
    last_seen_utc timestamptz not null,
    risk_class text not null check (risk_class in (
        'critical','high','medium','low','info','unknown'
    )),
    raw_score numeric(14,4) not null default 0 check (raw_score between 0 and 100000),
    display_score smallint not null default 0 check (display_score between 0 and 100),
    hard_critical boolean not null default false,
    confidence text not null default 'unknown' check (confidence in (
        'high','medium','low','unknown'
    )),
    confidence_score smallint not null default 0 check (confidence_score between 0 and 100),
    confidence_factors_json jsonb not null default '{}'::jsonb
        check (jsonb_typeof(confidence_factors_json)='object'),
    coverage_status text not null default 'unknown' check (coverage_status in (
        'complete','partial','unavailable','unknown'
    )),
    step_count integer not null default 0 check (step_count >= 0),
    evidence_count integer not null default 0 check (evidence_count >= 0),
    contribution_count integer not null default 0 check (contribution_count >= 0),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint semantic_scenario_time_window check (
        last_seen_utc >= first_seen_utc
        and last_seen_utc <= first_seen_utc + interval '24 hours'
    ),
    constraint semantic_scenario_hard_critical check (
        not hard_critical or risk_class='critical'
    )
);

create table if not exists semantic_scenario_steps (
    step_id uuid primary key,
    scenario_id uuid not null references semantic_security_scenarios(scenario_id) on delete restrict,
    step_key bytea not null unique check (octet_length(step_key)=32),
    source_kind text not null check (source_kind in (
        'canonical_action','correlation_candidate','control_health'
    )),
    canonical_action_id uuid references canonical_actions(canonical_action_id) on delete restrict,
    correlation_candidate_id uuid references semantic_correlation_candidates(candidate_id) on delete restrict,
    control_reference text,
    occurred_at_utc timestamptz not null,
    title text not null check (length(title) between 1 and 300),
    explanation text not null check (length(explanation) between 1 and 2000),
    confidence text not null check (confidence in ('high','medium','low','unknown')),
    confidence_score smallint not null check (confidence_score between 0 and 100),
    confidence_factors_json jsonb not null check (jsonb_typeof(confidence_factors_json)='object'),
    created_at timestamptz not null default now(),
    constraint semantic_scenario_step_source check (
        (source_kind='canonical_action' and canonical_action_id is not null
            and correlation_candidate_id is null and control_reference is null)
        or (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and canonical_action_id is null and control_reference is null)
        or (source_kind='control_health' and control_reference is not null
            and length(control_reference) between 1 and 160
            and canonical_action_id is null and correlation_candidate_id is null)
    )
);

create table if not exists semantic_scenario_evidence (
    scenario_id uuid not null references semantic_security_scenarios(scenario_id) on delete restrict,
    normalized_event_id uuid not null references normalized_events(normalized_event_id) on delete restrict,
    evidence_order smallint not null check (evidence_order between 0 and 32767),
    created_at timestamptz not null default now(),
    primary key(scenario_id,normalized_event_id),
    unique(scenario_id,evidence_order)
);

create table if not exists semantic_risk_contributions (
    contribution_id uuid primary key,
    scenario_id uuid not null references semantic_security_scenarios(scenario_id) on delete restrict,
    contribution_key bytea not null unique check (octet_length(contribution_key)=32),
    source_kind text not null check (source_kind in (
        'canonical_action','correlation_candidate','control_health'
    )),
    canonical_action_id uuid references canonical_actions(canonical_action_id) on delete restrict,
    correlation_candidate_id uuid references semantic_correlation_candidates(candidate_id) on delete restrict,
    control_reference text,
    policy_id text not null check (length(policy_id) between 1 and 160),
    policy_version integer not null check (policy_version > 0),
    policy_sha256 bytea not null check (octet_length(policy_sha256)=32),
    risk_class text not null check (risk_class in (
        'critical','high','medium','low','info'
    )),
    raw_score numeric(14,4) not null check (raw_score between 0 and 100000),
    display_points smallint not null check (display_points between 0 and 100),
    hard_critical boolean not null default false,
    rationale text not null check (length(rationale) between 1 and 2000),
    created_at timestamptz not null default now(),
    constraint semantic_risk_contribution_source check (
        (source_kind='canonical_action' and canonical_action_id is not null
            and correlation_candidate_id is null and control_reference is null)
        or (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and canonical_action_id is null and control_reference is null)
        or (source_kind='control_health' and control_reference is not null
            and length(control_reference) between 1 and 160
            and canonical_action_id is null and correlation_candidate_id is null)
    ),
    constraint semantic_risk_contribution_hard_critical check (
        not hard_critical or risk_class='critical'
    )
);

create or replace function enforce_semantic_risk_contribution_immutability()
returns trigger language plpgsql as $$
begin
    raise exception 'semantic risk contributions are immutable';
end
$$;

drop trigger if exists trg_semantic_risk_contribution_immutability
    on semantic_risk_contributions;
create trigger trg_semantic_risk_contribution_immutability
before update on semantic_risk_contributions
for each row execute function enforce_semantic_risk_contribution_immutability();

create table if not exists semantic_scenario_coverage_history (
    coverage_id uuid primary key,
    scenario_id uuid not null references semantic_security_scenarios(scenario_id) on delete restrict,
    assessment_key bytea not null check (octet_length(assessment_key)=32),
    control_id text not null check (length(control_id) between 1 and 160),
    coverage_status text not null check (coverage_status in (
        'complete','partial','unavailable','unknown'
    )),
    reason text not null check (length(reason) between 1 and 2000),
    observed_at_utc timestamptz not null,
    created_at timestamptz not null default now(),
    unique(scenario_id,assessment_key)
);

create index if not exists idx_semantic_scenario_identity_window
    on semantic_security_scenarios(identity_key,scenario_status,last_seen_utc desc,scenario_id);
create index if not exists idx_semantic_scenario_partition_time
    on semantic_security_scenarios(partition_key,last_seen_utc desc,scenario_id);
create index if not exists idx_semantic_scenario_step_scenario
    on semantic_scenario_steps(scenario_id,occurred_at_utc,step_id);
create index if not exists idx_semantic_scenario_evidence_event
    on semantic_scenario_evidence(normalized_event_id,scenario_id);
create index if not exists idx_semantic_risk_contribution_scenario
    on semantic_risk_contributions(scenario_id,created_at,contribution_id);
create index if not exists idx_semantic_scenario_coverage_latest
    on semantic_scenario_coverage_history(scenario_id,control_id,observed_at_utc desc,coverage_id);

revoke all on table semantic_security_scenarios,
    semantic_scenario_steps,
    semantic_scenario_evidence,
    semantic_risk_contributions,
    semantic_scenario_coverage_history from public;
grant select on table semantic_security_scenarios,
    semantic_scenario_steps,
    semantic_scenario_evidence,
    semantic_risk_contributions,
    semantic_scenario_coverage_history to adlog_user;
grant select,insert,update on table semantic_security_scenarios
    to adlog_storage_worker;
grant select,insert on table semantic_scenario_steps,
    semantic_scenario_evidence,
    semantic_risk_contributions,
    semantic_scenario_coverage_history to adlog_storage_worker;

insert into schema_migrations(version,name)
values (28,'semantic_risk_scenarios')
on conflict(version) do update set name=excluded.name;

commit;
