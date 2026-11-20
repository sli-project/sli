begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_processor_version_gate_and_repair_v142'));

do $$
begin
  if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
    raise exception 'migration 142 requires membership in adlog_storage_owner';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version=141 and name='semantic_dispatch_rule_lock_acl'
  ) then
    raise exception 'migration 142 requires exact migration 141 semantic_dispatch_rule_lock_acl';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version=142 and name is distinct from 'semantic_processor_version_gate_and_repair'
  ) then
    raise exception 'migration version 142 is already owned by another contract';
  end if;
  if to_regclass('public.semantic_processing_outbox') is null then
    raise exception 'migration 142 requires semantic_processing_outbox';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version=142 and name='semantic_processor_version_gate_and_repair'
  ) and not exists (
    select 1 from pg_constraint
    where conrelid='public.semantic_processing_outbox'::regclass
      and conname='semantic_processing_outbox_job_kind_check'
      and pg_get_constraintdef(oid) like '%investigation_context%'
      and pg_get_constraintdef(oid) not like '%semantic_repair%'
  ) then
    raise exception 'migration 142 requires exact pre-repair job kind constraint';
  end if;
end
$$;

set local role adlog_storage_owner;

alter table public.semantic_processing_outbox
  drop constraint if exists semantic_processing_outbox_job_kind_check;
alter table public.semantic_processing_outbox
  add constraint semantic_processing_outbox_job_kind_check
  check (job_kind in (
    'normalize_event', 'assemble_action', 'semantic_replay',
    'investigation_context', 'semantic_repair'
  ));

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid='public.semantic_processing_outbox'::regclass
      and conname='semantic_processing_outbox_job_kind_check'
      and pg_get_constraintdef(oid) like '%semantic_repair%'
  ) then
    raise exception 'migration 142 semantic repair job kind readback failed';
  end if;
end
$$;

insert into public.schema_migrations(version,name)
values (142, 'semantic_processor_version_gate_and_repair')
on conflict(version) do nothing;

commit;
