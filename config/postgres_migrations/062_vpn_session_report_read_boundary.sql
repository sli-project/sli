-- Stage 9 read-only product boundary for the existing vpn.audit report.
-- No package/report assignment is created by this migration.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_vpn_session_report_read_v62')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 062 requires membership in adlog_storage_owner';
    end if;
    if not pg_has_role(session_user, 'adlog_user', 'MEMBER') then
        raise exception 'migration 062 requires membership in adlog_user';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=61 and name='radius_session_consumer_projection'
    ) then
        raise exception 'migration 062 requires schema migration 061';
    end if;
    if to_regrole('adlog_vpn_session_reader_owner') is not null then
        raise exception 'migration 062 requires absent role adlog_vpn_session_reader_owner';
    end if;
end
$$;

create role adlog_vpn_session_reader_owner
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_vpn_session_reader_owner to adlog_storage_owner;

set local role adlog_storage_owner;

grant select(
    session_row_id,exact_principal_key,generation,lifecycle_state,
    completeness,started_at_utc,last_observed_at_utc,stopped_at_utc,
    duration_seconds,observation_count,anomalies,updated_at
) on radius_vpn_session_projection
to adlog_vpn_session_reader_owner;
grant select(
    delivery_id,subscription_id,observation_id,delivery_state
) on acquisition_delivery_outbox
to adlog_vpn_session_reader_owner;
grant select(
    delivery_id,outcome
) on radius_session_projection_receipts
to adlog_vpn_session_reader_owner;
grant select(
    observation_id,evidence_uid,observed_at_utc
) on radius_accounting_session_observations
to adlog_vpn_session_reader_owner;
grant select(
    evidence_uid,source_instance_id,verified_at_utc
) on core_evidence_manifests
to adlog_vpn_session_reader_owner;
grant select(
    subscription_id,source_instance_id
) on acquisition_consumer_subscriptions
to adlog_vpn_session_reader_owner;
grant select(
    source_instance_id,organization_scope,source_kind
) on acquisition_source_instances
to adlog_vpn_session_reader_owner;

grant select(id,fqdn) on domains
to adlog_vpn_session_reader_owner;
grant select(id,domain_id) on observed_entities
to adlog_vpn_session_reader_owner;

reset role;
grant usage,create on schema public
to adlog_vpn_session_reader_owner;

set local role adlog_vpn_session_reader_owner;

create view radius_vpn_session_rows_v1
with (security_barrier=true)
as
select
    projection.session_row_id,
    entity_row.id as entity_id,
    entity_row.domain_id,
    projection.generation,
    projection.lifecycle_state,
    projection.completeness,
    projection.started_at_utc,
    projection.last_observed_at_utc,
    projection.stopped_at_utc,
    projection.duration_seconds,
    projection.observation_count,
    projection.anomalies,
    projection.updated_at
from radius_vpn_session_projection projection
join observed_entities entity_row
  on projection.exact_principal_key='entity:' || entity_row.id::text
where entity_row.domain_id is not null;

create view radius_vpn_session_coverage_v1
with (security_barrier=true)
as
with source_domains as (
    select source.source_instance_id,domain_row.id as domain_id
    from acquisition_source_instances source
    join domains domain_row
      on lower(domain_row.fqdn)=lower(source.organization_scope)
    where source.source_kind='windows.nps.radius'
),
delivery_counts as (
    select
        source_domain.domain_id,
        count(*) as total_delivery_count,
        count(*) filter (
            where delivery.delivery_state='queued'
        ) as queued_delivery_count,
        count(*) filter (
            where delivery.delivery_state='leased'
        ) as leased_delivery_count,
        count(*) filter (
            where delivery.delivery_state='failed'
        ) as failed_delivery_count,
        count(*) filter (
            where delivery.delivery_state='delivered'
        ) as delivered_delivery_count,
        count(*) filter (
            where delivery.delivery_state='quarantined'
        ) as quarantined_delivery_count,
        count(*) filter (
            where receipt.outcome='projected'
        ) as projected_receipt_count,
        count(*) filter (
            where receipt.outcome='identity_unresolved'
        ) as identity_unresolved_count,
        count(*) filter (
            where receipt.outcome='timestamp_unresolved'
        ) as timestamp_unresolved_count,
        min(
            coalesce(observation.observed_at_utc,evidence.verified_at_utc)
        ) as history_available_from_utc,
        max(
            coalesce(observation.observed_at_utc,evidence.verified_at_utc)
        ) as history_available_to_utc
    from acquisition_delivery_outbox delivery
    join acquisition_consumer_subscriptions subscription
      on subscription.subscription_id=delivery.subscription_id
    join source_domains source_domain
      on source_domain.source_instance_id=subscription.source_instance_id
    join radius_accounting_session_observations observation
      on observation.observation_id=delivery.observation_id
    join core_evidence_manifests evidence
      on evidence.evidence_uid=observation.evidence_uid
    left join radius_session_projection_receipts receipt
      on receipt.delivery_id=delivery.delivery_id
    group by source_domain.domain_id
),
projection_counts as (
    select
        entity_row.domain_id,
        count(*) as projected_session_count
    from radius_vpn_session_projection projection
    join observed_entities entity_row
      on projection.exact_principal_key='entity:' || entity_row.id::text
    where entity_row.domain_id is not null
    group by entity_row.domain_id
)
select
    source_domain.domain_id,
    coalesce(delivery.total_delivery_count,0)::bigint
        as total_delivery_count,
    coalesce(delivery.queued_delivery_count,0)::bigint
        as queued_delivery_count,
    coalesce(delivery.leased_delivery_count,0)::bigint
        as leased_delivery_count,
    coalesce(delivery.failed_delivery_count,0)::bigint
        as failed_delivery_count,
    coalesce(delivery.delivered_delivery_count,0)::bigint
        as delivered_delivery_count,
    coalesce(delivery.quarantined_delivery_count,0)::bigint
        as quarantined_delivery_count,
    coalesce(delivery.projected_receipt_count,0)::bigint
        as projected_receipt_count,
    coalesce(delivery.identity_unresolved_count,0)::bigint
        as identity_unresolved_count,
    coalesce(delivery.timestamp_unresolved_count,0)::bigint
        as timestamp_unresolved_count,
    coalesce(projection.projected_session_count,0)::bigint
        as projected_session_count,
    delivery.history_available_from_utc,
    delivery.history_available_to_utc
from (
    select distinct domain_id from source_domains
) source_domain
left join delivery_counts delivery
  on delivery.domain_id=source_domain.domain_id
left join projection_counts projection
  on projection.domain_id=source_domain.domain_id;

revoke all on
    radius_vpn_session_rows_v1,
    radius_vpn_session_coverage_v1
from public;
grant select on
    radius_vpn_session_rows_v1,
    radius_vpn_session_coverage_v1
to adlog_user;

reset role;
revoke create on schema public
from adlog_vpn_session_reader_owner;

reset role;

insert into access_capabilities(
    capability_key,label,description
) values
(
    'vpn.sessions.view',
    'VPN-сеансы',
    'Просмотр ограниченной проекции RADIUS Accounting без raw evidence'
),
(
    'vpn.session.evidence.read',
    'Evidence VPN-сеанса',
    'Чтение неизменяемого evidence только через отдельный контролируемый endpoint'
)
on conflict(capability_key) do update set
    label=excluded.label,
    description=excluded.description;

set local role adlog_storage_owner;
insert into schema_migrations(version,name)
values (62,'vpn_session_report_read_boundary')
on conflict(version) do update set name=excluded.name;

commit;
