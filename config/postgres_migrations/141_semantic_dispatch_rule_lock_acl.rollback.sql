begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_dispatch_rule_lock_acl_v141_rollback'));

do $$
begin
  if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
    raise exception 'migration 141 rollback requires membership in adlog_storage_owner';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version = 141 and name = 'semantic_dispatch_rule_lock_acl'
  ) then
    raise exception 'migration 141 rollback requires exact marker';
  end if;
  if (
    select count(*)
    from public.schema_migrations
    where (version, name) in (
      (134, 'security_events_chains_report'),
      (135, 'semantic_cross_dc_partitions'),
      (136, 'investigation_typed_evidence_refs'),
      (137, 'semantic_count_then_rule_kind'),
      (138, 'normalized_event_versioned_identity'),
      (139, 'investigation_evidence_refs_runtime_acl'),
      (140, 'semantic_investigation_context_acl')
    )
  ) <> 7 then
    raise exception 'migration 141 rollback requires exact markers 134 through 140';
  end if;
  if not has_column_privilege(
       'adlog_semantic_worker',
       'public.semantic_correlation_rules',
       'updated_at',
       'UPDATE'
     )
     or has_table_privilege(
       'adlog_semantic_worker',
       'public.semantic_correlation_rules',
       'UPDATE'
     )
     or has_column_privilege(
       'adlog_semantic_worker',
       'public.semantic_correlation_rules',
       'updated_at',
       'UPDATE WITH GRANT OPTION'
     )
     or exists (
       select 1
       from pg_attribute semantic_rule_column
       where semantic_rule_column.attrelid = 'public.semantic_correlation_rules'::regclass
         and semantic_rule_column.attnum > 0
         and not semantic_rule_column.attisdropped
         and semantic_rule_column.attname <> 'updated_at'
         and has_column_privilege(
           'adlog_semantic_worker',
           semantic_rule_column.attrelid,
           semantic_rule_column.attname,
           'UPDATE'
         )
     )
     or exists (
       select 1
       from pg_class relation_row
       join pg_roles runtime_role on runtime_role.rolname = 'adlog_semantic_worker'
       join lateral aclexplode(
         coalesce(relation_row.relacl, acldefault('r', relation_row.relowner))
       ) privilege_record on true
       where relation_row.oid = 'public.semantic_correlation_rules'::regclass
         and privilege_record.grantee = runtime_role.oid
         and privilege_record.privilege_type = 'UPDATE'
     )
     or exists (
       select 1
       from pg_attribute semantic_rule_column
       join pg_class relation_row on relation_row.oid = semantic_rule_column.attrelid
       join pg_roles runtime_role on runtime_role.rolname = 'adlog_semantic_worker'
       join lateral aclexplode(semantic_rule_column.attacl) privilege_record on true
       where semantic_rule_column.attrelid = 'public.semantic_correlation_rules'::regclass
         and semantic_rule_column.attnum > 0
         and not semantic_rule_column.attisdropped
         and privilege_record.grantee = runtime_role.oid
         and privilege_record.privilege_type = 'UPDATE'
         and (
           semantic_rule_column.attname <> 'updated_at'
           or privilege_record.is_grantable
           or privilege_record.grantor <> relation_row.relowner
         )
     ) then
    raise exception 'migration 141 rollback refuses expanded update ACL';
  end if;
end
$$;

set local role adlog_storage_owner;

revoke update(updated_at) on table public.semantic_correlation_rules from adlog_semantic_worker;

do $$
begin
  if has_table_privilege('adlog_semantic_worker', 'public.semantic_correlation_rules', 'UPDATE')
     or has_column_privilege(
       'adlog_semantic_worker',
       'public.semantic_correlation_rules',
       'updated_at',
       'UPDATE'
     ) then
    raise exception 'migration 141 rollback privilege readback failed';
  end if;
end
$$;

delete from public.schema_migrations
where version = 141 and name = 'semantic_dispatch_rule_lock_acl';

commit;
