-- Stage 10 immutable reconciliation audit and exact identity overlay.
-- Original observations, terminal receipts and evidence manifests stay unchanged.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_session_reconciliation_v65')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 065 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=64
          and name='vpn_session_canonical_identity_read_boundary'
    ) then
        raise exception 'migration 065 requires schema migration 064';
    end if;
    if to_regrole('adlog_radius_session_reconciliation_writer') is not null then
        raise exception 'migration 065 requires absent reconciliation writer role';
    end if;
    if to_regclass('radius_session_reconciliation_attempts') is not null
       or to_regclass('radius_session_identity_overlays') is not null then
        raise exception 'migration 065 requires absent reconciliation tables';
    end if;
end
$$;

create role adlog_radius_session_reconciliation_writer
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_radius_session_reconciliation_writer to adlog_storage_owner;

set local role adlog_storage_owner;

create table radius_session_reconciliation_attempts (
    attempt_key text primary key
        check (attempt_key ~ '^[0-9a-f]{64}$'),
    observation_id uuid not null
        references radius_accounting_session_observations,
    evidence_uid uuid not null references core_evidence_manifests,
    outcome text not null
        check (outcome in ('projected','still_unresolved')),
    evidence_corpus_sha256 text not null
        check (evidence_corpus_sha256 ~ '^[0-9a-f]{64}$'),
    resolver_contract_id text not null
        check (
            btrim(resolver_contract_id) <> ''
            and length(resolver_contract_id) <= 160
        ),
    resolution_input_sha256 text,
    writer_contract_id text not null
        check (btrim(writer_contract_id) <> ''),
    created_at timestamptz not null default now(),
    unique (
        observation_id,evidence_corpus_sha256,resolver_contract_id
    ),
    check (
        (outcome='projected'
         and resolution_input_sha256 ~ '^[0-9a-f]{64}$')
        or
        (outcome='still_unresolved'
         and resolution_input_sha256 is null)
    )
);

create table radius_session_identity_overlays (
    observation_id uuid primary key
        references radius_accounting_session_observations,
    attempt_key text not null unique
        references radius_session_reconciliation_attempts,
    evidence_uid uuid not null references core_evidence_manifests,
    session_identity_key text not null
        check (session_identity_key ~ '^radius-session:[0-9a-f]{64}$'),
    exact_principal_key text not null
        check (exact_principal_key ~ '^entity:[1-9][0-9]*$'),
    resolution_input_sha256 text not null
        check (resolution_input_sha256 ~ '^[0-9a-f]{64}$'),
    resolver_contract_id text not null
        check (
            btrim(resolver_contract_id) <> ''
            and length(resolver_contract_id) <= 160
        ),
    created_at timestamptz not null default now()
);

create index radius_session_reconciliation_attempt_observation_idx
    on radius_session_reconciliation_attempts(
        observation_id,created_at,attempt_key
    );

revoke all on table
    radius_session_reconciliation_attempts,
    radius_session_identity_overlays
from public;

grant usage on schema public
to adlog_radius_session_reconciliation_writer;
grant select(observation_id,evidence_uid,identity_state)
on radius_accounting_session_observations
to adlog_radius_session_reconciliation_writer;
grant select(observation_id,outcome)
on radius_session_projection_receipts
to adlog_radius_session_reconciliation_writer;
grant select(id) on entities_v2
to adlog_radius_session_reconciliation_writer;
grant select on table
    radius_session_reconciliation_attempts,
    radius_session_identity_overlays
to adlog_radius_session_reconciliation_writer;
grant insert(
    attempt_key,observation_id,evidence_uid,outcome,
    evidence_corpus_sha256,resolver_contract_id,
    resolution_input_sha256,writer_contract_id
) on radius_session_reconciliation_attempts
to adlog_radius_session_reconciliation_writer;
grant insert(
    observation_id,attempt_key,evidence_uid,session_identity_key,
    exact_principal_key,resolution_input_sha256,resolver_contract_id
) on radius_session_identity_overlays
to adlog_radius_session_reconciliation_writer;

insert into schema_migrations(version,name)
values (65,'radius_session_reconciliation_overlay')
on conflict(version) do update set name=excluded.name;

commit;
