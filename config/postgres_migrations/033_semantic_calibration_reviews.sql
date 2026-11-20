-- SEMANTIC-CALIBRATION-1: append-only analyst verdict labels.
-- Additive and local-only. It registers no worker, creates no findings and
-- performs no collection or contact with surveyed servers.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_calibration_reviews_v33'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 033 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=32 and name='runtime_worker_heartbeats'
    ) then
        raise exception 'migration 033 requires schema migration 032';
    end if;
end
$$;

set local role adlog_storage_owner;

create table if not exists semantic_scenario_reviews (
    review_id uuid primary key,
    review_request_id uuid not null unique,
    scenario_id uuid not null references semantic_security_scenarios(scenario_id) on delete restrict,
    supersedes_review_id uuid references semantic_scenario_reviews(review_id) on delete restrict,
    verdict text not null check (verdict in (
        'confirmed_security','false_positive','benign_expected','insufficient_evidence'
    )),
    review_confidence text not null check (review_confidence in ('high','medium','low')),
    rationale text not null check (length(rationale) between 5 and 2000),
    scenario_snapshot_sha256 bytea not null check (octet_length(scenario_snapshot_sha256)=32),
    reviewed_by text not null check (length(reviewed_by) between 1 and 160),
    reviewer_role text not null check (reviewer_role in ('viewer','operator','admin')),
    reviewed_at timestamptz not null default now(),
    constraint semantic_scenario_review_not_self_superseding check (
        supersedes_review_id is null or supersedes_review_id<>review_id
    )
);

create unique index if not exists uq_semantic_scenario_review_superseded_once
    on semantic_scenario_reviews(supersedes_review_id)
    where supersedes_review_id is not null;
create index if not exists idx_semantic_scenario_review_latest
    on semantic_scenario_reviews(scenario_id,reviewed_at desc,review_id desc);

create or replace function enforce_semantic_scenario_review_immutability()
returns trigger language plpgsql as $$
begin
    raise exception 'semantic scenario reviews are append-only';
end
$$;

drop trigger if exists trg_semantic_scenario_review_immutability
    on semantic_scenario_reviews;
create trigger trg_semantic_scenario_review_immutability
before update or delete on semantic_scenario_reviews
for each row execute function enforce_semantic_scenario_review_immutability();

revoke all on table semantic_scenario_reviews from public;
grant select,insert on table semantic_scenario_reviews to adlog_user;
grant select,insert on table semantic_scenario_reviews to adlog_storage_worker;

insert into schema_migrations(version,name)
values (33,'semantic_calibration_reviews')
on conflict(version) do update set name=excluded.name;

commit;
