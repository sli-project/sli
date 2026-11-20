-- SEMANTIC-RISK-RUNTIME-1: versioned policies, control health and leased evaluation.
-- Additive and fail-closed. It registers no worker and creates no findings.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_risk_runtime_v29'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 029 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=28 and name='semantic_risk_scenarios'
    ) then
        raise exception 'migration 029 requires schema migration 028';
    end if;
end
$$;

set local role adlog_storage_owner;

create table if not exists semantic_risk_policies (
    policy_id text not null check (length(policy_id) between 1 and 160),
    policy_version integer not null check (policy_version > 0),
    source_kind text not null check (source_kind in (
        'correlation_candidate','control_health'
    )),
    lifecycle_status text not null default 'draft' check (lifecycle_status in (
        'draft','validated','test','shadow','enabled','disabled','deprecated'
    )),
    definition_json jsonb not null check (jsonb_typeof(definition_json)='object'),
    definition_sha256 bytea not null check (octet_length(definition_sha256)=32),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key(policy_id,policy_version),
    unique(policy_id,policy_version,definition_sha256)
);

create unique index if not exists uq_semantic_risk_policy_enabled
    on semantic_risk_policies(policy_id) where lifecycle_status='enabled';

create or replace function enforce_semantic_risk_policy_immutability()
returns trigger language plpgsql as $$
begin
    if old.lifecycle_status <> 'draft' and (
        new.source_kind is distinct from old.source_kind
        or new.definition_json is distinct from old.definition_json
        or new.definition_sha256 is distinct from old.definition_sha256
    ) then
        raise exception 'non-draft semantic risk policy definition is immutable';
    end if;
    new.updated_at=now();
    return new;
end
$$;

drop trigger if exists trg_semantic_risk_policy_immutability
    on semantic_risk_policies;
create trigger trg_semantic_risk_policy_immutability
before update on semantic_risk_policies
for each row execute function enforce_semantic_risk_policy_immutability();

create table if not exists semantic_risk_policy_subscriptions (
    policy_id text not null,
    policy_version integer not null,
    source_kind text not null check (source_kind in (
        'correlation_candidate','control_health'
    )),
    selector_value text not null check (length(selector_value) between 1 and 200),
    definition_sha256 bytea not null check (octet_length(definition_sha256)=32),
    created_at timestamptz not null default now(),
    primary key(policy_id,policy_version),
    foreign key(policy_id,policy_version)
        references semantic_risk_policies(policy_id,policy_version) on delete restrict
);

create or replace function enforce_semantic_risk_subscription_draft_only()
returns trigger language plpgsql as $$
declare
    status text;
begin
    if tg_op in ('UPDATE','DELETE') then
        select lifecycle_status into status from semantic_risk_policies
        where policy_id=old.policy_id and policy_version=old.policy_version;
        if status is distinct from 'draft' then
            raise exception 'semantic risk policy subscription is immutable outside draft';
        end if;
    end if;
    if tg_op in ('INSERT','UPDATE') then
        select lifecycle_status into status from semantic_risk_policies
        where policy_id=new.policy_id and policy_version=new.policy_version;
        if status is distinct from 'draft' then
            raise exception 'semantic risk policy subscription is immutable outside draft';
        end if;
    end if;
    if tg_op='DELETE' then return old; end if;
    return new;
end
$$;

drop trigger if exists trg_semantic_risk_subscription_draft_only
    on semantic_risk_policy_subscriptions;
create trigger trg_semantic_risk_subscription_draft_only
before insert or update or delete on semantic_risk_policy_subscriptions
for each row execute function enforce_semantic_risk_subscription_draft_only();

create table if not exists semantic_control_health_observations (
    observation_id uuid primary key,
    observation_key bytea not null unique check (octet_length(observation_key)=32),
    control_id text not null check (length(control_id) between 1 and 160),
    partition_key text not null check (length(partition_key) between 1 and 160),
    coverage_status text not null check (coverage_status in (
        'complete','partial','unavailable','unknown'
    )),
    reason text not null check (length(reason) between 1 and 2000),
    observed_at_utc timestamptz not null,
    source_reference text not null check (length(source_reference) between 1 and 320),
    created_at timestamptz not null default now()
);

create or replace function enforce_semantic_control_health_immutability()
returns trigger language plpgsql as $$
begin
    raise exception 'semantic control health observations are immutable';
end
$$;

drop trigger if exists trg_semantic_control_health_immutability
    on semantic_control_health_observations;
create trigger trg_semantic_control_health_immutability
before update on semantic_control_health_observations
for each row execute function enforce_semantic_control_health_immutability();

create table if not exists semantic_risk_evaluation_jobs (
    job_id uuid primary key,
    policy_id text not null,
    policy_version integer not null,
    source_kind text not null check (source_kind in (
        'correlation_candidate','control_health'
    )),
    correlation_candidate_id uuid references semantic_correlation_candidates(candidate_id) on delete restrict,
    control_health_id uuid references semantic_control_health_observations(observation_id) on delete restrict,
    source_reference text not null check (length(source_reference) between 1 and 320),
    evaluation_mode text not null check (evaluation_mode in ('test','shadow','enabled')),
    idempotency_key bytea not null unique check (octet_length(idempotency_key)=32),
    evaluation_status text not null default 'queued' check (evaluation_status in (
        'queued','leased','completed','failed','quarantined'
    )),
    attempt_count integer not null default 0 check (attempt_count >= 0),
    max_attempts integer not null default 5 check (max_attempts between 1 and 20),
    available_at timestamptz not null default now(),
    lease_token uuid,
    lease_until timestamptz,
    heartbeat_at timestamptz,
    last_error_code text,
    last_error_detail text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    completed_at timestamptz,
    foreign key(policy_id,policy_version)
        references semantic_risk_policies(policy_id,policy_version) on delete restrict,
    constraint semantic_risk_evaluation_source check (
        (source_kind='correlation_candidate' and correlation_candidate_id is not null
            and control_health_id is null
            and source_reference=correlation_candidate_id::text)
        or (source_kind='control_health' and control_health_id is not null
            and correlation_candidate_id is null
            and source_reference=control_health_id::text)
    ),
    constraint semantic_risk_evaluation_lease check (
        (evaluation_status='leased' and lease_token is not null and lease_until is not null)
        or (evaluation_status<>'leased' and lease_token is null and lease_until is null)
    ),
    constraint semantic_risk_evaluation_terminal check (
        (evaluation_status='completed' and completed_at is not null and last_error_code is null)
        or (evaluation_status in ('failed','quarantined') and last_error_code is not null)
        or evaluation_status in ('queued','leased')
    ),
    unique(policy_id,policy_version,source_kind,source_reference,evaluation_mode)
);

create table if not exists semantic_risk_evaluation_results (
    job_id uuid primary key references semantic_risk_evaluation_jobs(job_id) on delete restrict,
    scenario_id uuid references semantic_security_scenarios(scenario_id) on delete restrict,
    evaluation_mode text not null check (evaluation_mode in ('test','shadow','enabled')),
    risk_class text not null check (risk_class in ('critical','high','medium','low','info')),
    raw_score numeric(14,4) not null check (raw_score between 0 and 100000),
    display_score smallint not null check (display_score between 0 and 100),
    hard_critical boolean not null,
    confidence text not null check (confidence in ('high','medium','low','unknown')),
    confidence_score smallint not null check (confidence_score between 0 and 100),
    coverage_status text not null check (coverage_status in (
        'complete','partial','unavailable','unknown'
    )),
    evaluation_ms integer not null check (evaluation_ms >= 0),
    created_at timestamptz not null default now(),
    constraint semantic_risk_result_mode check (
        evaluation_mode<>'test' or scenario_id is null
    ),
    constraint semantic_risk_result_hard_critical check (
        not hard_critical or risk_class='critical'
    )
);

create or replace function enforce_semantic_risk_result_immutability()
returns trigger language plpgsql as $$
begin
    raise exception 'semantic risk evaluation results are immutable';
end
$$;

drop trigger if exists trg_semantic_risk_result_immutability
    on semantic_risk_evaluation_results;
create trigger trg_semantic_risk_result_immutability
before update on semantic_risk_evaluation_results
for each row execute function enforce_semantic_risk_result_immutability();

create index if not exists idx_semantic_risk_subscription_source
    on semantic_risk_policy_subscriptions(source_kind,selector_value,policy_id,policy_version);
create index if not exists idx_semantic_control_health_latest
    on semantic_control_health_observations(partition_key,control_id,observed_at_utc desc,observation_id);
create index if not exists idx_semantic_risk_evaluation_claim
    on semantic_risk_evaluation_jobs(evaluation_status,available_at,lease_until,created_at);
create index if not exists idx_semantic_risk_evaluation_source
    on semantic_risk_evaluation_jobs(source_kind,source_reference,evaluation_mode,job_id);
create index if not exists idx_semantic_risk_result_metrics
    on semantic_risk_evaluation_results(evaluation_mode,created_at,risk_class,coverage_status);

revoke all on table semantic_risk_policies,
    semantic_risk_policy_subscriptions,
    semantic_control_health_observations,
    semantic_risk_evaluation_jobs,
    semantic_risk_evaluation_results from public;
grant select on table semantic_risk_policies,
    semantic_risk_policy_subscriptions,
    semantic_control_health_observations,
    semantic_risk_evaluation_jobs,
    semantic_risk_evaluation_results to adlog_user;
grant select,insert,update on table semantic_risk_policies,
    semantic_risk_policy_subscriptions,
    semantic_risk_evaluation_jobs to adlog_storage_worker;
grant delete on table semantic_risk_policy_subscriptions to adlog_storage_worker;
grant select,insert on table semantic_control_health_observations,
    semantic_risk_evaluation_results to adlog_storage_worker;

insert into schema_migrations(version,name)
values (29,'semantic_risk_runtime')
on conflict(version) do update set name=excluded.name;

commit;
