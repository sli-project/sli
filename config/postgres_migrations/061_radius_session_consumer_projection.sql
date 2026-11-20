-- Stage 9 durable consumer boundary and consumer-owned VPN session projection.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_session_consumer_v61')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 061 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=60 and name='radius_identity_resolver_owner'
    ) then
        raise exception 'migration 061 requires schema migration 060';
    end if;
    if to_regrole('adlog_radius_session_consumer') is not null then
        raise exception 'migration 061 requires absent role adlog_radius_session_consumer';
    end if;
end
$$;

create role adlog_radius_session_consumer
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_radius_session_consumer to adlog_storage_owner;

set local role adlog_storage_owner;

alter table acquisition_delivery_outbox
    add column attempt_count integer not null default 0
        check (attempt_count >= 0),
    add column available_at timestamptz not null default now(),
    add column lease_token uuid,
    add column lease_until timestamptz,
    add column heartbeat_at timestamptz,
    add column last_error_code text,
    add column updated_at timestamptz not null default now();

alter table acquisition_delivery_outbox
    drop constraint acquisition_delivery_outbox_delivery_state_check;
alter table acquisition_delivery_outbox
    add constraint acquisition_delivery_outbox_delivery_state_check
        check (
            delivery_state in (
                'queued','leased','failed','delivered','quarantined'
            )
        ),
    add constraint acquisition_delivery_outbox_lease_check
        check (
            (
                delivery_state='leased'
                and lease_token is not null
                and lease_until is not null
            )
            or
            (
                delivery_state<>'leased'
                and lease_token is null
                and lease_until is null
            )
        ),
    add constraint acquisition_delivery_outbox_error_code_check
        check (
            last_error_code is null
            or last_error_code ~ '^[a-z][a-z0-9_]{0,119}$'
        );

create table radius_session_projection_receipts (
    delivery_id bigint primary key
        references acquisition_delivery_outbox,
    observation_id uuid not null
        references radius_accounting_session_observations,
    outcome text not null
        check (
            outcome in (
                'projected',
                'identity_unresolved',
                'timestamp_unresolved'
            )
        ),
    projected_row_count integer not null
        check (projected_row_count between 0 and 10000),
    consumer_contract_id text not null
        check (btrim(consumer_contract_id) <> ''),
    processed_at timestamptz not null default now()
);

create table radius_vpn_session_projection (
    session_row_id text primary key
        check (
            session_row_id ~ '^radius-session-row:[0-9a-f]{64}$'
        ),
    session_identity_key text not null
        check (
            session_identity_key ~ '^radius-session:[0-9a-f]{64}$'
        ),
    exact_principal_key text not null
        check (btrim(exact_principal_key) <> ''),
    generation integer not null check (generation > 0),
    lifecycle_state text not null
        check (
            lifecycle_state in (
                'closed','partial_closed','open_observed','partial_open'
            )
        ),
    completeness text not null
        check (
            completeness in (
                'complete','missing_start','missing_stop','middle_only'
            )
        ),
    started_at_utc timestamptz,
    last_observed_at_utc timestamptz not null,
    stopped_at_utc timestamptz,
    duration_seconds bigint check (duration_seconds >= 0),
    observation_count integer not null
        check (observation_count between 1 and 10000),
    anomalies text[] not null default '{}',
    read_model_contract_id text not null
        check (btrim(read_model_contract_id) <> ''),
    updated_at timestamptz not null default now(),
    unique (session_identity_key, generation),
    check (
        anomalies <@ array['start_before_stop']::text[]
    ),
    check (
        (completeness='complete'
         and started_at_utc is not null
         and stopped_at_utc is not null
         and duration_seconds is not null)
        or
        (completeness='missing_start'
         and started_at_utc is null
         and stopped_at_utc is not null
         and duration_seconds is null)
        or
        (completeness='missing_stop'
         and started_at_utc is not null
         and stopped_at_utc is null
         and duration_seconds is null)
        or
        (completeness='middle_only'
         and started_at_utc is null
         and stopped_at_utc is null
         and duration_seconds is null)
    ),
    check (
        (started_at_utc is null or started_at_utc<=last_observed_at_utc)
        and
        (stopped_at_utc is null or stopped_at_utc<=last_observed_at_utc)
    )
);

drop index acquisition_delivery_outbox_claim_idx;
create index acquisition_delivery_outbox_claim_idx
    on acquisition_delivery_outbox(
        delivery_state,available_at,lease_until,created_at,delivery_id
    );
create index radius_vpn_session_projection_principal_idx
    on radius_vpn_session_projection(
        exact_principal_key,last_observed_at_utc desc,session_row_id
    );
create index radius_vpn_session_projection_state_idx
    on radius_vpn_session_projection(
        lifecycle_state,last_observed_at_utc desc,session_row_id
    );

revoke all on table
    radius_session_projection_receipts,
    radius_vpn_session_projection
from public;

grant usage on schema public to adlog_radius_session_consumer;
grant select on table
    acquisition_delivery_outbox,
    radius_accounting_session_observations,
    radius_session_projection_receipts,
    radius_vpn_session_projection
to adlog_radius_session_consumer;
grant update(
    delivery_state,attempt_count,available_at,lease_token,lease_until,
    heartbeat_at,last_error_code,delivered_at,updated_at
) on acquisition_delivery_outbox
to adlog_radius_session_consumer;
grant insert on table radius_session_projection_receipts
to adlog_radius_session_consumer;
grant insert,update,delete on table radius_vpn_session_projection
to adlog_radius_session_consumer;

insert into schema_migrations(version,name)
values (61,'radius_session_consumer_projection')
on conflict(version) do update set name=excluded.name;

commit;
