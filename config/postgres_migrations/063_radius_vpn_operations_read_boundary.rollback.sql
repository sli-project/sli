-- Aggregate-view-only rollback; acquisition/session data is preserved.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_vpn_operations_v63')
);

set local role adlog_vpn_session_reader_owner;
revoke select on radius_vpn_operations_v1 from adlog_user;

drop view radius_vpn_operations_v1;

set local role adlog_storage_owner;
revoke select(
    display_name,desired_activation,observed_health,updated_at
) on acquisition_source_instances
from adlog_vpn_session_reader_owner;
revoke select(
    stream_id,transport_binding,consumer_id,authority_mode,
    replay_policy,resource_profile_id,desired_activation
) on acquisition_consumer_subscriptions
from adlog_vpn_session_reader_owner;
revoke select(
    source_instance_id,stream_id,transport_binding,revision,updated_at
) on acquisition_stream_cursors
from adlog_vpn_session_reader_owner;

reset role;
revoke select(id,capability_key) on access_capabilities
from adlog_vpn_session_reader_owner;
revoke select(capability_id) on access_capability_assignments
from adlog_vpn_session_reader_owner;
revoke select(capability_id) on access_package_capabilities
from adlog_vpn_session_reader_owner;
revoke select(report_key,status,version) on report_registry_v4
from adlog_vpn_session_reader_owner;

set local role adlog_storage_owner;
delete from schema_migrations
where version=63 and name='radius_vpn_operations_read_boundary';

commit;
