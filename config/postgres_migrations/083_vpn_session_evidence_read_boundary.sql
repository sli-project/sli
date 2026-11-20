-- Stage G11A6: controlled immutable Accounting evidence references for vpn.audit.
-- Source-only schema preparation: no source, worker, runtime or assignment changes.
-- Pre-Stage10 read boundary: sourced only from the already-accepted vpn.audit
-- Accounting pipeline (migration 062).  Does not read or require any Stage10
-- reconciliation object (radius_session_identity_overlays,
-- radius_session_reconciliation_attempts, migrations 065/080).  Identity is
-- published only where the source-native pipeline already marked it exact;
-- there is no correlation by time or name and no substitute identity is
-- fabricated when it is not yet exact.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_vpn_session_evidence_read_v83')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 083 requires membership in adlog_storage_owner';
    end if;
    if not pg_has_role(session_user, 'adlog_user', 'MEMBER') then
        raise exception 'migration 083 requires membership in adlog_user';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=34 and name='ad_context_entities_v2'
    ) then
        raise exception 'migration 083 requires migration 034';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=62 and name='vpn_session_report_read_boundary'
    ) then
        raise exception 'migration 083 requires migration 062';
    end if;
    if exists(select 1 from schema_migrations where version=83) then
        raise exception 'migration 083 version is already recorded';
    end if;
    if to_regrole('adlog_vpn_session_reader_owner') is null
       or to_regclass('radius_vpn_session_projection') is null
       or to_regclass('entities_v2') is null then
        raise exception 'migration 083 prerequisites are missing';
    end if;
end
$$;

grant usage,create on schema public
to adlog_vpn_session_reader_owner;

set local role adlog_storage_owner;

grant select(
    lifecycle_event,session_identity_key,exact_principal_key,
    identity_state,timestamp_state
) on radius_accounting_session_observations
to adlog_vpn_session_reader_owner;
grant select(session_identity_key)
on radius_vpn_session_projection
to adlog_vpn_session_reader_owner;
grant select(id,domain_id)
on entities_v2
to adlog_vpn_session_reader_owner;
grant select(
    stream_id,transport_binding,object_reference,
    canonical_record_sha256,object_sha256,object_size_bytes
) on core_evidence_manifests
to adlog_vpn_session_reader_owner;

set local role adlog_vpn_session_reader_owner;

create view radius_vpn_session_evidence_observations_v1
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
from radius_vpn_session_projection projection
join entities_v2 entity_row
  on projection.exact_principal_key='entity:' || entity_row.id::text
join acquisition_delivery_outbox delivery
  on delivery.subscription_id=
       'vpn-radius-session-observations-msservices-v1'
 and delivery.delivery_state='delivered'
join radius_accounting_session_observations observation
  on observation.observation_id=delivery.observation_id
join core_evidence_manifests evidence
  on evidence.evidence_uid=observation.evidence_uid
where observation.timestamp_state='ready'
  and observation.identity_state='exact'
  and observation.session_identity_key=projection.session_identity_key
  and observation.exact_principal_key=projection.exact_principal_key;

revoke all on radius_vpn_session_evidence_observations_v1
from public;
grant select on radius_vpn_session_evidence_observations_v1
to adlog_user;

reset role;
revoke create on schema public
from adlog_vpn_session_reader_owner;

set local role adlog_storage_owner;
insert into schema_migrations(version,name)
values (83,'vpn_session_evidence_read_boundary')
on conflict(version) do update set name=excluded.name;

commit;
