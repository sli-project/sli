begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_investigation_context_acl_v140_rollback'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 140 and name = 'semantic_investigation_context_acl'
  ) then
    raise exception 'migration 140 rollback requires exact marker';
  end if;
  if exists (
       select 1
       from pg_attribute keyword_column
       join pg_roles runtime_role on runtime_role.rolname = 'adlog_semantic_worker'
       join lateral aclexplode(keyword_column.attacl) privilege_record on true
       where keyword_column.attrelid = 'public.storage_v2_keywords'::regclass
         and keyword_column.attnum > 0
         and not keyword_column.attisdropped
         and privilege_record.grantee = runtime_role.oid
         and privilege_record.privilege_type = 'SELECT'
     )
     or exists (
       select 1
       from pg_class relation_row
       join pg_roles runtime_role on runtime_role.rolname = 'adlog_semantic_worker'
       join lateral aclexplode(
         coalesce(relation_row.relacl, acldefault('r', relation_row.relowner))
       ) privilege_record on true
       where relation_row.oid = 'public.storage_v2_keywords'::regclass
         and privilege_record.grantee = runtime_role.oid
         and privilege_record.privilege_type = 'SELECT'
         and (
           privilege_record.is_grantable
           or privilege_record.grantor <> relation_row.relowner
         )
     ) then
    raise exception 'migration 140 rollback refuses expanded select ACL';
  end if;
  if exists (
    select 1 from public.semantic_processing_outbox
    where job_kind = 'investigation_context'
  ) then
    raise exception 'migration 140 rollback refuses retained investigation context jobs';
  end if;
end
$$;

set local role adlog_storage_owner;

revoke select on table public.storage_v2_keywords from adlog_semantic_worker;

alter table public.semantic_processing_outbox
  drop constraint semantic_processing_outbox_job_kind_check;
alter table public.semantic_processing_outbox
  add constraint semantic_processing_outbox_job_kind_check
  check (job_kind in ('normalize_event', 'assemble_action', 'semantic_replay'));

do $$
begin
  if has_table_privilege(
    'adlog_semantic_worker', 'public.storage_v2_keywords', 'SELECT'
  ) then
    raise exception 'migration 140 rollback privilege readback failed';
  end if;
end
$$;

delete from public.schema_migrations
where version = 140 and name = 'semantic_investigation_context_acl';

commit;
