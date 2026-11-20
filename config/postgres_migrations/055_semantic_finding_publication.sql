-- Stage 8 production semantic finding publication boundary.
-- Additive only: no policy activation, worker start or existing finding rewrite.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_findings_v55'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 055 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=54 and name='semantic_worker_runtime_schema_guard'
    ) then
        raise exception 'migration 055 requires schema migration 054';
    end if;
    if to_regrole('adlog_semantic_worker') is null then
        raise exception 'migration 055 requires adlog_semantic_worker';
    end if;
end
$$;

-- These legacy product tables and sequences are owned by adlog_user in the
-- production topology. The exact maintenance session grants only the bounded
-- publication surface before reducing its active role.
grant select,insert,update on table findings to adlog_semantic_worker;
grant select,insert on table
    finding_evidence,
    finding_entities,
    finding_status_history
to adlog_semantic_worker;
grant usage,select on sequence
    findings_id_seq,
    finding_evidence_id_seq,
    finding_entities_id_seq,
    finding_status_history_id_seq
to adlog_semantic_worker;
grant references on table findings to adlog_storage_owner;

do $$
begin
    if not has_table_privilege(
        'adlog_semantic_worker', 'findings', 'SELECT,INSERT,UPDATE'
    ) or not has_table_privilege(
        'adlog_semantic_worker', 'finding_evidence', 'SELECT,INSERT'
    ) or not has_table_privilege(
        'adlog_semantic_worker', 'finding_entities', 'SELECT,INSERT'
    ) or not has_table_privilege(
        'adlog_semantic_worker', 'finding_status_history', 'SELECT,INSERT'
    ) or not has_sequence_privilege(
        'adlog_semantic_worker', 'findings_id_seq', 'USAGE,SELECT'
    ) or not has_sequence_privilege(
        'adlog_semantic_worker', 'finding_evidence_id_seq', 'USAGE,SELECT'
    ) or not has_sequence_privilege(
        'adlog_semantic_worker', 'finding_entities_id_seq', 'USAGE,SELECT'
    ) or not has_sequence_privilege(
        'adlog_semantic_worker', 'finding_status_history_id_seq', 'USAGE,SELECT'
    ) then
        raise exception 'migration 055 failed exact finding publication grants';
    end if;
end
$$;

set local role adlog_storage_owner;

create table if not exists semantic_finding_publications (
    scenario_id uuid primary key
        references semantic_security_scenarios(scenario_id) on delete restrict,
    finding_id bigint not null unique
        references findings(id) on delete restrict,
    first_job_id uuid not null unique
        references semantic_risk_evaluation_results(job_id) on delete restrict,
    finding_fingerprint text not null unique
        check (finding_fingerprint ~ '^semantic:[0-9a-f]{64}$'),
    published_evidence_count integer not null
        check (published_evidence_count > 0),
    created_at timestamptz not null default now(),
    unique(scenario_id,finding_id)
);

create or replace function enforce_semantic_finding_publication_immutability()
returns trigger language plpgsql as $$
begin
    raise exception 'semantic finding publication links are immutable';
end
$$;

drop trigger if exists trg_semantic_finding_publication_immutability
    on semantic_finding_publications;
create trigger trg_semantic_finding_publication_immutability
before update or delete on semantic_finding_publications
for each row execute function enforce_semantic_finding_publication_immutability();

revoke all on table semantic_finding_publications from public;
grant select,insert on table semantic_finding_publications
to adlog_semantic_worker;

insert into schema_migrations(version,name)
values (55,'semantic_finding_publication')
on conflict(version) do update set name=excluded.name;

commit;
