-- Evidence-preserving rollback for migration 062.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_vpn_session_report_read_v62')
);

do $$
begin
    if exists (
        select 1
        from access_capability_assignments assignment
        join access_capabilities capability
          on capability.id=assignment.capability_id
        where capability.capability_key in (
            'vpn.sessions.view','vpn.session.evidence.read'
        )
    ) or exists (
        select 1
        from access_package_capabilities package_capability
        join access_capabilities capability
          on capability.id=package_capability.capability_id
        where capability.capability_key in (
            'vpn.sessions.view','vpn.session.evidence.read'
        )
    ) then
        raise exception 'migration 062 rollback blocked by active capability assignments';
    end if;
end
$$;

set local role adlog_user;
revoke select on
    radius_vpn_session_rows_v1,
    radius_vpn_session_coverage_v1
from adlog_user;

set local role adlog_vpn_session_reader_owner;
drop view radius_vpn_session_coverage_v1;
drop view radius_vpn_session_rows_v1;

set local role adlog_storage_owner;
revoke all on table
    radius_vpn_session_projection,
    acquisition_delivery_outbox,
    radius_session_projection_receipts,
    radius_accounting_session_observations,
    core_evidence_manifests,
    acquisition_consumer_subscriptions,
    acquisition_source_instances
from adlog_vpn_session_reader_owner;

reset role;
revoke all on table domains,observed_entities
from adlog_vpn_session_reader_owner;
delete from access_capabilities
where capability_key in (
    'vpn.sessions.view','vpn.session.evidence.read'
);

set local role adlog_storage_owner;
delete from schema_migrations
where version=62 and name='vpn_session_report_read_boundary';

reset role;
revoke usage on schema public
from adlog_vpn_session_reader_owner;
revoke adlog_vpn_session_reader_owner from adlog_storage_owner;
drop role adlog_vpn_session_reader_owner;

commit;
