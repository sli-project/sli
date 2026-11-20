-- SEMANTIC-3: durable AD-state evidence for an existing canonical action.
-- No collector, AD query, worker, risk engine, or finding path is enabled.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_canonical_action_state_evidence_v24'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 024 requires membership in adlog_storage_owner';
    end if;
    if to_regclass('canonical_actions') is null or to_regclass('ad_context_evidence') is null then
        raise exception 'migration 024 requires canonical actions and AD Context evidence';
    end if;
    if not exists (select 1 from schema_migrations where version=23 and name='canonical_action_confirmation_statuses') then
        raise exception 'migration 024 requires schema migration 023';
    end if;
    if not exists (select 1 from schema_migrations where version=17 and name='ad_context_foundation') then
        raise exception 'migration 024 requires schema migration 017';
    end if;
end $$;

-- Migration 017 predates the semantic owner role and creates this evidence
-- table as the maintenance session owner.  The exact REFERENCES privilege is
-- required before the least-privilege semantic owner can create its FK.
grant references on table ad_context_evidence to adlog_storage_owner;

set local role adlog_storage_owner;

create table if not exists canonical_action_state_evidence (
    canonical_action_id uuid not null references canonical_actions(canonical_action_id) on delete restrict,
    context_evidence_id bigint not null references ad_context_evidence(id) on delete restrict,
    assessment_status text not null check (assessment_status in ('observed','partially_confirmed','state_confirmed','multi_source_confirmed','contradicted')),
    change_origin text not null check (change_origin in ('baseline_import','incremental_sync','targeted_reconcile')),
    match_key bytea not null check (octet_length(match_key)=32),
    explanation text not null check (length(explanation) between 1 and 2000),
    created_at timestamptz not null default now(),
    primary key(canonical_action_id, context_evidence_id),
    unique(match_key)
);

create index if not exists idx_canonical_action_state_evidence_context
    on canonical_action_state_evidence(context_evidence_id, canonical_action_id);

revoke all on canonical_action_state_evidence from public;
grant select on canonical_action_state_evidence to adlog_user;
grant select, insert, update on canonical_action_state_evidence to adlog_storage_worker;

insert into schema_migrations(version,name)
values (24,'canonical_action_state_evidence')
on conflict(version) do update set name=excluded.name;
commit;
