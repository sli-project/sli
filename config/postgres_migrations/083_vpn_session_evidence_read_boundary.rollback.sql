-- Evidence-preserving rollback for migration 083.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_vpn_session_evidence_read_v83')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=83 and name='vpn_session_evidence_read_boundary'
    ) then
        raise exception 'migration 083 rollback requires its marker';
    end if;
end
$$;

set local role adlog_user;
revoke select on radius_vpn_session_evidence_observations_v1
from adlog_user;

set local role adlog_vpn_session_reader_owner;
drop view radius_vpn_session_evidence_observations_v1;

set local role adlog_storage_owner;
revoke select(
    lifecycle_event,session_identity_key,exact_principal_key,
    identity_state,timestamp_state
) on radius_accounting_session_observations
from adlog_vpn_session_reader_owner;
revoke select(session_identity_key)
on radius_vpn_session_projection
from adlog_vpn_session_reader_owner;
do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=64 and name='vpn_session_canonical_identity_read_boundary'
    ) then
        execute 'revoke select(id,domain_id) on entities_v2 from adlog_vpn_session_reader_owner';
    end if;
end
$$;
revoke select(
    stream_id,transport_binding,object_reference,
    canonical_record_sha256,object_sha256,object_size_bytes
) on core_evidence_manifests
from adlog_vpn_session_reader_owner;
delete from schema_migrations
where version=83 and name='vpn_session_evidence_read_boundary';

commit;
