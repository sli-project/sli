-- Remove the direct-ingest worker grants while preserving relations and data.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_storage_v2_direct_ingest_worker_grants_v96')
);

revoke select, insert, update on table raw_log_files
    from adlog_storage_worker;
revoke select, insert on table
    storage_v2_event_identity_allocations,
    storage_v2_entity_identity_allocations
    from adlog_storage_worker;
revoke usage, select on sequence
    raw_log_files_id_seq,
    storage_v2_event_id_seq,
    entities_v2_id_seq
    from adlog_storage_worker;

set local role adlog_storage_owner;
revoke select, insert on table
    storage_v2_event_identity_allocations,
    storage_v2_entity_identity_allocations
    from adlog_storage_worker;
reset role;

delete from schema_migrations
where version=96 and name='storage_v2_direct_ingest_worker_grants';

commit;
