-- Register the unified AD snapshot as a first-class external runtime worker.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_context_snapshot_heartbeat_v46'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=45 and name='ad_context_shared_entity_identity'
    ) then
        raise exception 'migration 046 requires migration 045';
    end if;
    if to_regclass('runtime_worker_heartbeats') is null then
        raise exception 'migration 046 requires runtime_worker_heartbeats';
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

insert into schema_migrations(version, name)
values (46, 'ad_context_snapshot_heartbeat')
on conflict(version) do update set name=excluded.name;

commit;
