-- Remove only the bounded manifest metadata grant from migration 098.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_session_consumer_manifest_hash_v98')
);

set local role adlog_storage_owner;

revoke select (evidence_uid, canonical_record_sha256)
on core_evidence_manifests
from adlog_radius_session_consumer;

delete from schema_migrations
where version=98 and name='radius_session_consumer_manifest_hash';

commit;
