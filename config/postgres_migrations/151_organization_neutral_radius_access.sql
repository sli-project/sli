-- Installation-neutral RADIUS evidence and an explicitly assignable access package.
-- Existing direct assignments, subjects, scopes and denies are preserved.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_organization_neutral_radius_access_v151'));

do $$
begin
    if not exists (
        select 1 from public.schema_migrations
        where version=150 and name='storage_v2_event_bigint'
    ) then
        raise exception 'migration 151 requires exact migration 150 storage_v2_event_bigint';
    end if;
    if exists (
        select 1 from public.schema_migrations
        where version=151 and name is distinct from 'organization_neutral_radius_access'
    ) then
        raise exception 'migration version 151 is already owned by another contract';
    end if;
    if not exists (
        select 1 from public.access_capabilities where capability_key='vpn.session.evidence.read'
    ) then
        raise exception 'vpn_evidence_capability_not_registered';
    end if;
end
$$;

-- No role, user or group receives this package automatically. The established
-- access-management surface assigns it; existing scoped direct grants survive.
insert into public.access_packages(package_key,name,description,is_system)
values ('vpn_evidence_reader','Чтение evidence VPN-сеансов',
        'Чтение evidence в пределах разрешённого отчёта VPN',true)
on conflict(package_key) do nothing;

insert into public.access_package_capabilities(package_id,capability_id)
select package.id,capability.id
from public.access_packages package cross join public.access_capabilities capability
where package.package_key='vpn_evidence_reader'
  and capability.capability_key='vpn.session.evidence.read'
on conflict do nothing;

-- The registered subscription and the evidence source must agree. The view
-- retains its owner, security barrier, columns and existing read privileges.
grant create on schema public to adlog_vpn_session_reader_owner;
set local role adlog_vpn_session_reader_owner;

create or replace view public.radius_vpn_session_evidence_observations_v1
with (security_barrier=true)
as
select distinct
    projection.session_row_id,
    entity_row.domain_id,
    observation.observation_id,
    observation.lifecycle_event,
    observation.identity_state,
    observation.timestamp_state,
    observation.session_identity_key,
    observation.exact_principal_key,
    observation.observed_at_utc,
    evidence.evidence_uid,
    evidence.source_instance_id,
    evidence.stream_id,
    evidence.transport_binding,
    evidence.object_reference,
    evidence.canonical_record_sha256,
    evidence.object_sha256,
    evidence.object_size_bytes,
    evidence.verified_at_utc
from public.radius_vpn_session_projection projection
join public.entities_v2 entity_row
  on projection.exact_principal_key='entity:' || entity_row.id::text
join public.acquisition_delivery_outbox delivery
  on delivery.subscription_id like 'vpn-radius-session-observations-%-v1'
 and delivery.delivery_state='delivered'
join public.acquisition_consumer_subscriptions subscription
  on subscription.subscription_id=delivery.subscription_id
join public.radius_accounting_session_observations observation
  on observation.observation_id=delivery.observation_id
join public.core_evidence_manifests evidence
  on evidence.evidence_uid=observation.evidence_uid
 and evidence.source_instance_id=subscription.source_instance_id
where observation.timestamp_state='ready'
  and observation.identity_state='exact'
  and observation.session_identity_key=projection.session_identity_key
  and observation.exact_principal_key=projection.exact_principal_key;

reset role;
revoke create on schema public from adlog_vpn_session_reader_owner;

-- Update the installed preflight without changing its owner, signature or ACL.
-- CREATE OR REPLACE retains the execute-only runtime boundary and one-source gate.
grant create on schema public to adlog_radius_preflight_reader;
set local role adlog_radius_preflight_reader;

create or replace function public.sli_g11a3_preflight_state_v1()
returns table(
    source_subscription_disabled boolean,
    no_temporary_login boolean,
    no_worker_started boolean,
    cursor_revision bigint
)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
declare
    registration_count bigint;
    activation_disabled boolean;
    observed_revision bigint;
begin
    select
      count(*),
      coalesce(bool_and(
        source.desired_activation='disabled'
        and subscription.desired_activation='disabled'
        and exists(
          select 1 from public.schema_migrations
          where version=58
            and name='radius_accounting_transaction_foundation'
        )
        and exists(
          select 1 from public.schema_migrations
          where version=59
            and name='radius_identity_spine_resolver'
        )
      ),false),
      min(cursor_row.revision)::bigint
    into registration_count,activation_disabled,observed_revision
    from public.acquisition_source_instances source
    join public.acquisition_stream_cursors cursor_row
      on cursor_row.source_instance_id=source.source_instance_id
    join public.acquisition_consumer_subscriptions subscription
      on subscription.source_instance_id=cursor_row.source_instance_id
     and subscription.stream_id=cursor_row.stream_id
     and subscription.transport_binding=cursor_row.transport_binding
    where cursor_row.stream_id='radius-accounting'
      and cursor_row.transport_binding=
          'windows-rpc-smb-readonly-tail-v1'
      and subscription.subscription_id like 'vpn-radius-session-observations-%-v1';

    if registration_count<>1 or observed_revision is null then
        raise exception 'g11a3_preflight_registration_invalid'
            using errcode='P0001';
    end if;

    return query
    select
      activation_disabled,
      not exists(
        select 1 from pg_catalog.pg_roles
        where left(rolname,20)='adlog_radius_manual_'
      ),
      not exists(
        select 1 from pg_catalog.pg_stat_activity
        where application_name='sli_stage9_radius_manual_worker'
          and pid<>pg_backend_pid()
      ),
      observed_revision;
end
$$;

reset role;
revoke create on schema public from adlog_radius_preflight_reader;

insert into public.schema_migrations(version,name)
values (151,'organization_neutral_radius_access')
on conflict(version) do update set name=excluded.name;

commit;
