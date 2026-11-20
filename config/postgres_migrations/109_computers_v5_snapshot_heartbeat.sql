begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_v5_snapshot_heartbeat'));

do $$ begin
  if not exists(select 1 from schema_migrations where version=108 and name='computers_report_v5') then
    raise exception 'computers v5 snapshot heartbeat requires migration 108';
  end if;
end $$;

alter table runtime_worker_heartbeats drop constraint if exists runtime_worker_heartbeats_name;
alter table runtime_worker_heartbeats add constraint runtime_worker_heartbeats_name check (
  worker_name in (
    'collection','ad_context_snapshot','computers_v5_snapshot','storage_v2_outbox',
    'storage_lifecycle','post_collection','entity_state','semantic'
  )
);

insert into schema_migrations(version,name) values(109,'computers_v5_snapshot_heartbeat')
on conflict(version) do update set name=excluded.name;
commit;
