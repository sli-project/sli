begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_lifecycle_runtime_maintenance_v77'));

do $$
begin
    if exists (
        select 1 from runtime_worker_heartbeats
        where worker_name='storage_lifecycle'
    ) then
        raise exception 'remove the storage_lifecycle heartbeat before rollback';
    end if;
end
$$;

alter table runtime_worker_heartbeats
    drop constraint if exists runtime_worker_heartbeats_name;

alter table runtime_worker_heartbeats
    add constraint runtime_worker_heartbeats_name check (
        worker_name in (
            'collection',
            'ad_context_snapshot',
            'storage_v2_outbox',
            'post_collection',
            'entity_state',
            'semantic'
        )
    );

alter table events_v2_core reset (
    autovacuum_vacuum_scale_factor,
    autovacuum_vacuum_threshold,
    autovacuum_analyze_scale_factor,
    autovacuum_analyze_threshold
);

delete from schema_migrations
where version=77 and name='storage_lifecycle_runtime_maintenance';

commit;
