-- Resolve canonical VPN identities by primary key instead of sorting the
-- complete entity spine. Published columns, reader ownership and grants stay
-- unchanged; malformed or overflowing keys never become an identity.
begin;
select pg_advisory_xact_lock(hashtext('sli_vpn_session_indexed_identity_v210'));

do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_vpn_session_reader_owner','MEMBER') then
        raise exception 'migration 210 requires the storage and VPN reader owners';
    end if;
    if not exists(select 1 from public.schema_migrations where version=209 and name='workstation_protection_state')
       or exists(select 1 from public.schema_migrations where version>=210)
       or to_regclass('public.radius_vpn_session_rows_v1') is null
       or to_regclass('public.radius_vpn_session_coverage_v1') is null then
        raise exception 'migration 210 requires the VPN read views and exact migration 209';
    end if;
end $$;
grant usage,create on schema public to adlog_vpn_session_reader_owner;
set local role adlog_vpn_session_reader_owner;

create or replace view radius_vpn_session_rows_v1
with (security_barrier=true)
as
select
    projection.session_row_id,
    entity_row.id::bigint as entity_id,
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
join entities_v2 entity_row
  on entity_row.id=case
       when projection.exact_principal_key ~ '^entity:[1-9][0-9]{0,18}$'
       then case when substring(projection.exact_principal_key from 8)::numeric<=9223372036854775807
                 then substring(projection.exact_principal_key from 8)::bigint
            end
     end
where entity_row.domain_id is not null;

create or replace view radius_vpn_session_coverage_v1
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
        count(*) filter (where delivery.delivery_state='queued')
            as queued_delivery_count,
        count(*) filter (where delivery.delivery_state='leased')
            as leased_delivery_count,
        count(*) filter (where delivery.delivery_state='failed')
            as failed_delivery_count,
        count(*) filter (where delivery.delivery_state='delivered')
            as delivered_delivery_count,
        count(*) filter (where delivery.delivery_state='quarantined')
            as quarantined_delivery_count,
        count(*) filter (where receipt.outcome='projected')
            as projected_receipt_count,
        count(*) filter (where receipt.outcome='identity_unresolved')
            as identity_unresolved_count,
        count(*) filter (where receipt.outcome='timestamp_unresolved')
            as timestamp_unresolved_count,
        min(coalesce(observation.observed_at_utc,evidence.verified_at_utc))
            as history_available_from_utc,
        max(coalesce(observation.observed_at_utc,evidence.verified_at_utc))
            as history_available_to_utc
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
    join entities_v2 entity_row
      on entity_row.id=case
       when projection.exact_principal_key ~ '^entity:[1-9][0-9]{0,18}$'
       then case when substring(projection.exact_principal_key from 8)::numeric<=9223372036854775807
                 then substring(projection.exact_principal_key from 8)::bigint
            end
     end
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
from (select distinct domain_id from source_domains) source_domain
left join delivery_counts delivery
  on delivery.domain_id=source_domain.domain_id
left join projection_counts projection
  on projection.domain_id=source_domain.domain_id;

reset role;
revoke create on schema public from adlog_vpn_session_reader_owner;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(210,'vpn_session_indexed_identity');
commit;