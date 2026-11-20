-- SEMANTIC-DISPATCH-1: subscriptions, bounded dispatch leases and late reopen.
-- Source-only. No worker registration, scenario/risk/finding creation or live AD.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_dispatch_v27'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 027 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=26 and name='semantic_correlation_foundation'
    ) then
        raise exception 'migration 027 requires schema migration 026';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table semantic_correlation_candidates
    add column if not exists reopen_count integer not null default 0,
    add column if not exists late_evidence_count integer not null default 0,
    add column if not exists closed_at timestamptz,
    add column if not exists last_evidence_occurred_at timestamptz;

update semantic_correlation_candidates
set last_evidence_occurred_at=window_end_utc
where last_evidence_occurred_at is null;

alter table semantic_correlation_candidate_evidence
    add column if not exists is_late boolean not null default false;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conrelid='semantic_correlation_candidates'::regclass
          and conname='semantic_correlation_candidate_reopen_counts'
    ) then
        alter table semantic_correlation_candidates
            add constraint semantic_correlation_candidate_reopen_counts
            check (reopen_count >= 0 and late_evidence_count >= 0);
    end if;
end
$$;

create table if not exists semantic_correlation_subscriptions (
    rule_id text not null,
    rule_version integer not null,
    semantic_type text not null check (length(semantic_type) between 1 and 160),
    subscription_order smallint not null check (subscription_order between 0 and 255),
    definition_sha256 bytea not null check (octet_length(definition_sha256)=32),
    created_at timestamptz not null default now(),
    primary key(rule_id,rule_version,semantic_type),
    unique(rule_id,rule_version,subscription_order),
    foreign key(rule_id,rule_version)
        references semantic_correlation_rules(rule_id,rule_version) on delete restrict
);

create or replace function enforce_semantic_subscription_draft_only()
returns trigger language plpgsql as $$
declare
    status text;
begin
    if tg_op in ('UPDATE','DELETE') then
        select lifecycle_status into status
        from semantic_correlation_rules
        where rule_id=old.rule_id and rule_version=old.rule_version;
        if status is distinct from 'draft' then
            raise exception 'semantic correlation subscriptions are immutable outside draft';
        end if;
    end if;
    if tg_op in ('INSERT','UPDATE') then
        select lifecycle_status into status
        from semantic_correlation_rules
        where rule_id=new.rule_id and rule_version=new.rule_version;
        if status is distinct from 'draft' then
            raise exception 'semantic correlation subscriptions are immutable outside draft';
        end if;
    end if;
    if tg_op='DELETE' then
        return old;
    end if;
    return new;
end
$$;

drop trigger if exists trg_semantic_subscription_draft_only
    on semantic_correlation_subscriptions;
create trigger trg_semantic_subscription_draft_only
before insert or update or delete on semantic_correlation_subscriptions
for each row execute function enforce_semantic_subscription_draft_only();

create table if not exists semantic_correlation_dispatch_jobs (
    job_id uuid primary key,
    normalized_event_id uuid not null references normalized_events(normalized_event_id) on delete restrict,
    rule_id text not null,
    rule_version integer not null,
    idempotency_key bytea not null unique check (octet_length(idempotency_key)=32),
    partition_key text not null check (length(partition_key) between 1 and 160),
    occurred_at_utc timestamptz not null,
    is_late boolean not null default false,
    dispatch_status text not null default 'queued' check (dispatch_status in (
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
    foreign key(rule_id,rule_version)
        references semantic_correlation_rules(rule_id,rule_version) on delete restrict,
    constraint semantic_correlation_dispatch_lease check (
        (dispatch_status='leased' and lease_token is not null and lease_until is not null)
        or (dispatch_status<>'leased' and lease_token is null and lease_until is null)
    ),
    constraint semantic_correlation_dispatch_terminal check (
        (dispatch_status='completed' and completed_at is not null and last_error_code is null)
        or (dispatch_status in ('failed','quarantined') and last_error_code is not null)
        or dispatch_status in ('queued','leased')
    ),
    unique(normalized_event_id,rule_id,rule_version)
);

create index if not exists idx_semantic_correlation_subscription_type
    on semantic_correlation_subscriptions(semantic_type,rule_id,rule_version);
create index if not exists idx_semantic_correlation_dispatch_claim
    on semantic_correlation_dispatch_jobs(dispatch_status,available_at,lease_until,created_at);
create index if not exists idx_semantic_correlation_dispatch_partition
    on semantic_correlation_dispatch_jobs(partition_key,occurred_at_utc,job_id);

revoke all on table semantic_correlation_subscriptions,
    semantic_correlation_dispatch_jobs from public;
grant select on semantic_correlation_subscriptions,
    semantic_correlation_dispatch_jobs to adlog_user;
grant select,insert,update,delete on semantic_correlation_subscriptions
    to adlog_storage_worker;
grant select,insert,update on semantic_correlation_dispatch_jobs
    to adlog_storage_worker;
grant select,insert,update on semantic_correlation_candidate_evidence
    to adlog_storage_worker;

insert into schema_migrations(version,name)
values (27,'semantic_dispatch_foundation')
on conflict(version) do update set name=excluded.name;

commit;
