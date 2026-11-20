begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_context_snapshot_heartbeat_v46'));

do $$
begin
    if exists (
        select 1 from runtime_worker_heartbeats
        where worker_name='ad_context_snapshot'
    ) then
        raise exception 'remove the ad_context_snapshot heartbeat before rollback';
    end if;
end
$$;

alter table runtime_worker_heartbeats
    drop constraint if exists runtime_worker_heartbeats_name;

alter table runtime_worker_heartbeats
    add constraint runtime_worker_heartbeats_name check (
        worker_name in (
            'collection',
            'storage_v2_outbox',
            'post_collection',
            'entity_state',
            'semantic'
        )
    );

delete from schema_migrations
where version=46 and name='ad_context_snapshot_heartbeat';

commit;
