-- Stage 9 disposable-first foundation for evidence-first RADIUS Accounting.
-- This migration creates no source instance, cursor, subscription or worker.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_accounting_transaction_v58')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 058 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=55 and name='semantic_finding_publication'
    ) then
        raise exception 'migration 058 requires schema migration 055';
    end if;
    if to_regrole('adlog_radius_accounting_worker') is not null then
        raise exception 'migration 058 requires absent role adlog_radius_accounting_worker';
    end if;
end
$$;

create role adlog_radius_accounting_worker
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_radius_accounting_worker to adlog_storage_owner;

set local role adlog_storage_owner;

create table if not exists acquisition_source_instances (
    source_instance_id text primary key
        check (source_instance_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    organization_scope text not null check (btrim(organization_scope) <> ''),
    source_kind text not null check (btrim(source_kind) <> ''),
    endpoint_identity text not null check (btrim(endpoint_identity) <> ''),
    adapter_binding text not null check (btrim(adapter_binding) <> ''),
    credential_handle text check (
        credential_handle is null
        or (
            credential_handle ~ '^secret:[A-Za-z0-9_.:-]+$'
            and length(credential_handle) <= 507
        )
    ),
    display_name text not null check (btrim(display_name) <> ''),
    desired_activation text not null default 'disabled'
        check (desired_activation in ('disabled','manual_enabled')),
    observed_health text not null default 'unknown'
        check (observed_health in ('unknown','ready','degraded','blocked')),
    configuration_sha256 text not null
        check (configuration_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (organization_scope, source_kind, endpoint_identity)
);

create table if not exists acquisition_stream_cursors (
    source_instance_id text not null references acquisition_source_instances,
    stream_id text not null
        check (stream_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    transport_binding text not null
        check (transport_binding ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    cursor_epoch uuid not null,
    file_generation text not null
        check (file_generation ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    byte_offset bigint not null check (byte_offset >= 0),
    last_record_sha256 text
        check (
            last_record_sha256 is null
            or last_record_sha256 ~ '^[0-9a-f]{64}$'
        ),
    previous_file_generation text,
    previous_generation_last_record_sha256 text
        check (
            previous_generation_last_record_sha256 is null
            or previous_generation_last_record_sha256 ~ '^[0-9a-f]{64}$'
        ),
    revision bigint not null default 0 check (revision >= 0),
    updated_at timestamptz not null default now(),
    primary key (source_instance_id, stream_id, transport_binding)
);

create table if not exists acquisition_consumer_subscriptions (
    subscription_id text primary key
        check (subscription_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    source_instance_id text not null,
    stream_id text not null,
    transport_binding text not null,
    consumer_id text not null check (btrim(consumer_id) <> ''),
    consumer_component_id text not null
        check (btrim(consumer_component_id) <> ''),
    consumer_component_version text not null
        check (btrim(consumer_component_version) <> ''),
    routing_contract_id text not null
        check (btrim(routing_contract_id) <> ''),
    consumer_contract_version text not null
        check (btrim(consumer_contract_version) <> ''),
    replay_policy text not null
        check (replay_policy in ('no_replay','bounded_replay')),
    resource_profile_id text not null check (btrim(resource_profile_id) <> ''),
    selector_json jsonb not null check (jsonb_typeof(selector_json)='object'),
    selector_sha256 text not null
        check (selector_sha256 ~ '^[0-9a-f]{64}$'),
    authority_mode text not null
        check (authority_mode in ('authoritative','shadow')),
    desired_activation text not null default 'disabled'
        check (desired_activation in ('disabled','manual_enabled')),
    partition_key text not null check (btrim(partition_key) <> ''),
    created_at timestamptz not null default now(),
    unique (
        source_instance_id, stream_id, transport_binding,
        consumer_id, partition_key
    ),
    foreign key (source_instance_id, stream_id, transport_binding)
        references acquisition_stream_cursors
);

create table if not exists core_evidence_manifests (
    evidence_uid uuid primary key,
    source_instance_id text not null,
    stream_id text not null,
    transport_binding text not null,
    cursor_epoch uuid not null,
    file_generation text not null,
    cursor_start_byte_offset bigint not null
        check (cursor_start_byte_offset >= 0),
    batch_record_ordinal integer not null check (batch_record_ordinal >= 0),
    canonical_record_sha256 text not null
        check (canonical_record_sha256 ~ '^[0-9a-f]{64}$'),
    object_reference text not null
        check (
            object_reference ~ '^evidence:[A-Za-z0-9_.:-]+$'
            and length(object_reference) <= 509
        ),
    object_sha256 text not null
        check (object_sha256 ~ '^[0-9a-f]{64}$'),
    object_size_bytes integer not null
        check (object_size_bytes between 1 and 65536),
    verified_at_utc timestamptz not null,
    created_at timestamptz not null default now(),
    unique (
        source_instance_id, stream_id, transport_binding,
        cursor_epoch, file_generation,
        cursor_start_byte_offset, batch_record_ordinal
    ),
    foreign key (source_instance_id, stream_id, transport_binding)
        references acquisition_stream_cursors
);

create table if not exists radius_accounting_session_observations (
    observation_id uuid primary key,
    evidence_uid uuid not null unique references core_evidence_manifests,
    lifecycle_event text not null
        check (lifecycle_event in ('start','interim_update','stop')),
    session_identity_key text,
    exact_principal_key text,
    identity_state text not null
        check (identity_state in ('exact','unresolved')),
    observed_at_utc timestamptz,
    timestamp_basis text,
    timestamp_state text not null
        check (timestamp_state in ('ready','unresolved')),
    session_confirmed_by_accounting boolean not null
        check (session_confirmed_by_accounting),
    producer_contract_id text not null,
    resource_groups text[] not null check (cardinality(resource_groups) > 0),
    row_sensitivity text not null
        check (row_sensitivity in ('internal','restricted','confidential')),
    field_categories text[] not null check (cardinality(field_categories) > 0),
    evidence_access_requirement text not null
        check (btrim(evidence_access_requirement) <> ''),
    label_policy_version text not null check (btrim(label_policy_version) <> ''),
    provenance_json jsonb not null,
    created_at timestamptz not null default now(),
    check (
        (identity_state='exact'
         and session_identity_key is not null
         and exact_principal_key is not null)
        or
        (identity_state='unresolved'
         and session_identity_key is null
         and exact_principal_key is null)
    ),
    check (
        (timestamp_state='ready'
         and observed_at_utc is not null
         and timestamp_basis is not null)
        or
        (timestamp_state='unresolved'
         and observed_at_utc is null
         and timestamp_basis is null)
    )
);

create table if not exists acquisition_delivery_outbox (
    delivery_id bigserial primary key,
    subscription_id text not null
        references acquisition_consumer_subscriptions,
    evidence_uid uuid not null references core_evidence_manifests,
    observation_id uuid not null
        references radius_accounting_session_observations,
    idempotency_key text not null unique
        check (idempotency_key ~ '^[0-9a-f]{64}$'),
    delivery_state text not null default 'queued'
        check (delivery_state in ('queued','delivered','quarantined')),
    created_at timestamptz not null default now(),
    delivered_at timestamptz,
    check (
        (delivery_state='delivered' and delivered_at is not null)
        or
        (delivery_state<>'delivered' and delivered_at is null)
    ),
    unique (subscription_id, observation_id)
);

create table if not exists radius_accounting_class_cache (
    source_instance_id text not null references acquisition_source_instances,
    class_scope_sha256 text not null
        check (class_scope_sha256 ~ '^[0-9a-f]{64}$'),
    exact_principal_key text not null
        check (btrim(exact_principal_key) <> ''),
    expires_at_utc timestamptz not null,
    updated_at timestamptz not null default now(),
    primary key (source_instance_id, class_scope_sha256)
);

create index if not exists acquisition_delivery_outbox_claim_idx
    on acquisition_delivery_outbox(delivery_state, created_at, delivery_id);
create index if not exists radius_accounting_class_cache_expiry_idx
    on radius_accounting_class_cache(source_instance_id, expires_at_utc);
create index if not exists core_evidence_manifest_hash_idx
    on core_evidence_manifests(
        source_instance_id, stream_id, canonical_record_sha256
    );

revoke all on table
    acquisition_source_instances,
    acquisition_stream_cursors,
    acquisition_consumer_subscriptions,
    core_evidence_manifests,
    radius_accounting_session_observations,
    acquisition_delivery_outbox,
    radius_accounting_class_cache
from public;
revoke all on sequence acquisition_delivery_outbox_delivery_id_seq
from public;

grant usage on schema public to adlog_radius_accounting_worker;
grant select on table
    acquisition_source_instances,
    acquisition_consumer_subscriptions
to adlog_radius_accounting_worker;
grant select,update on table acquisition_stream_cursors
to adlog_radius_accounting_worker;
grant select,insert on table
    core_evidence_manifests,
    radius_accounting_session_observations,
    acquisition_delivery_outbox
to adlog_radius_accounting_worker;
grant select,insert,update,delete on table
    radius_accounting_class_cache
to adlog_radius_accounting_worker;
grant usage,select on sequence acquisition_delivery_outbox_delivery_id_seq
to adlog_radius_accounting_worker;

insert into schema_migrations(version,name)
values (58,'radius_accounting_transaction_foundation')
on conflict(version) do update set name=excluded.name;

commit;
