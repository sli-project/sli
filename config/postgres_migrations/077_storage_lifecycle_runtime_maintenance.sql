-- Register the admitted storage lifecycle worker and tune ordinary autovacuum
-- for the seven-day hot corpus. This migration does not delete or rewrite rows.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_lifecycle_runtime_maintenance_v77'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=71 and name='semantic_source_retention_decoupling'
    ) then
        raise exception 'migration 077 requires migration 071';
    end if;
    if to_regclass('runtime_worker_heartbeats') is null then
        raise exception 'migration 077 requires runtime_worker_heartbeats';
    end if;
    if to_regclass('events_v2_core') is null then
        raise exception 'migration 077 requires events_v2_core';
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
            'storage_lifecycle',
            'post_collection',
            'entity_state',
            'semantic'
        )
    );

alter table events_v2_core set (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_threshold = 50000,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_analyze_threshold = 50000
);

insert into schema_migrations(version, name)
values (77, 'storage_lifecycle_runtime_maintenance')
on conflict(version) do update set name=excluded.name;

commit;
