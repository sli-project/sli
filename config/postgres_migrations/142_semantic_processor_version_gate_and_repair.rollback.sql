begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_processor_version_gate_and_repair_v142_rollback'));

do $$
begin
  if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
    raise exception 'migration 142 rollback requires membership in adlog_storage_owner';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version=142 and name='semantic_processor_version_gate_and_repair'
  ) then
    raise exception 'migration 142 rollback requires exact marker';
  end if;
  if not exists (
    select 1 from pg_constraint
    where conrelid='public.semantic_processing_outbox'::regclass
      and conname='semantic_processing_outbox_job_kind_check'
      and pg_get_constraintdef(oid) like '%semantic_repair%'
  ) then
    raise exception 'migration 142 rollback requires semantic repair constraint';
  end if;
  if exists (
    select 1 from public.semantic_processing_outbox
    where job_kind = 'semantic_repair'
  ) then
    raise exception 'migration 142 rollback refuses retained repair rows';
  end if;
end
$$;

set local role adlog_storage_owner;

alter table public.semantic_processing_outbox
  drop constraint semantic_processing_outbox_job_kind_check;
alter table public.semantic_processing_outbox
  add constraint semantic_processing_outbox_job_kind_check
  check (job_kind in (
    'normalize_event', 'assemble_action', 'semantic_replay', 'investigation_context'
  ));

delete from public.schema_migrations
where version=142 and name='semantic_processor_version_gate_and_repair';

commit;
