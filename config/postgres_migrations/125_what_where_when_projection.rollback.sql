begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_what_where_when_projection_v125'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=125 and name='what_where_when_projection') then
    raise exception 'migration 125 is not applied';
  end if;
end $$;

delete from runtime_worker_heartbeats where worker_name='what_where_when_projection';
alter table runtime_worker_heartbeats drop constraint if exists runtime_worker_heartbeats_name;
alter table runtime_worker_heartbeats add constraint runtime_worker_heartbeats_name check (
  worker_name in (
    'collection','ad_context_snapshot','ad_snapshot_manifest_coordinator',
    'computers_v5_snapshot','computers_v6_snapshot','computers_v6_source',
    'users_v2_snapshot','storage_v2_outbox','storage_lifecycle','post_collection',
    'entity_state','semantic'
  )
);

drop table if exists what_where_when_observations;
drop table if exists what_where_when_projection_state;
delete from schema_migrations where version=125 and name='what_where_when_projection';
commit;
