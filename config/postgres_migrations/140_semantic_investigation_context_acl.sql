begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_investigation_context_acl_v140'));

do $$
begin
  if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
    raise exception 'migration 140 requires membership in adlog_storage_owner';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version = 139 and name = 'investigation_evidence_refs_runtime_acl'
  ) then
    raise exception 'migration 140 requires exact migration 139 investigation_evidence_refs_runtime_acl';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 140 and name is distinct from 'semantic_investigation_context_acl'
  ) then
    raise exception 'migration version 140 is already owned by another contract';
  end if;
  if to_regrole('adlog_semantic_worker') is null then
    raise exception 'migration 140 requires runtime role adlog_semantic_worker';
  end if;
  if to_regclass('public.storage_v2_keywords') is null then
    raise exception 'migration 140 requires public.storage_v2_keywords';
  end if;
  if to_regclass('public.semantic_processing_outbox') is null then
    raise exception 'migration 140 requires public.semantic_processing_outbox';
  end if;
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.semantic_processing_outbox'::regclass
      and conname = 'semantic_processing_outbox_job_kind_check'
      and pg_get_constraintdef(oid) not like '%investigation_context%'
  ) and not exists (
    select 1 from public.schema_migrations
    where version = 140 and name = 'semantic_investigation_context_acl'
  ) then
    raise exception 'migration 140 requires the exact pre-140 job kind constraint';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version = 140 and name = 'semantic_investigation_context_acl'
  ) and has_table_privilege(
    'adlog_semantic_worker', 'public.storage_v2_keywords', 'SELECT'
  ) then
    raise exception 'migration 140 first apply requires absent effective select baseline';
  end if;
end
$$;

set local role adlog_storage_owner;

alter table public.semantic_processing_outbox
  drop constraint if exists semantic_processing_outbox_job_kind_check;
alter table public.semantic_processing_outbox
  add constraint semantic_processing_outbox_job_kind_check
  check (job_kind in (
    'normalize_event', 'assemble_action', 'semantic_replay', 'investigation_context'
  ));

grant select on table public.storage_v2_keywords to adlog_semantic_worker;

do $$
begin
  if not has_table_privilege(
    'adlog_semantic_worker', 'public.storage_v2_keywords', 'SELECT'
  ) then
    raise exception 'migration 140 semantic context privilege readback failed';
  end if;
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.semantic_processing_outbox'::regclass
      and conname = 'semantic_processing_outbox_job_kind_check'
      and pg_get_constraintdef(oid) like '%investigation_context%'
  ) then
    raise exception 'migration 140 context job kind readback failed';
  end if;
  if has_table_privilege('adlog_semantic_worker', 'public.storage_v2_keywords', 'INSERT')
     or has_table_privilege('adlog_semantic_worker', 'public.storage_v2_keywords', 'UPDATE')
     or has_table_privilege('adlog_semantic_worker', 'public.storage_v2_keywords', 'DELETE')
     or has_table_privilege('adlog_semantic_worker', 'public.storage_v2_keywords', 'TRUNCATE')
     or has_table_privilege('adlog_semantic_worker', 'public.storage_v2_keywords', 'REFERENCES')
     or has_table_privilege('adlog_semantic_worker', 'public.storage_v2_keywords', 'TRIGGER') then
    raise exception 'migration 140 semantic context privilege is broader than select';
  end if;
end
$$;

insert into public.schema_migrations(version,name)
values (140, 'semantic_investigation_context_acl')
on conflict(version) do nothing;

commit;
