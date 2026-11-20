begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_dispatch_rule_lock_acl_v141'));

do $$
begin
  if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
    raise exception 'migration 141 requires membership in adlog_storage_owner';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version = 140 and name = 'semantic_investigation_context_acl'
  ) then
    raise exception 'migration 141 requires exact migration 140 semantic_investigation_context_acl';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 141 and name is distinct from 'semantic_dispatch_rule_lock_acl'
  ) then
    raise exception 'migration version 141 is already owned by another contract';
  end if;
  if to_regrole('adlog_semantic_worker') is null then
    raise exception 'migration 141 requires runtime role adlog_semantic_worker';
  end if;
  if to_regclass('public.semantic_correlation_rules') is null then
    raise exception 'migration 141 requires public.semantic_correlation_rules';
  end if;
  if not exists (
    select 1
    from pg_attribute semantic_rule_column
    where semantic_rule_column.attrelid = 'public.semantic_correlation_rules'::regclass
      and semantic_rule_column.attname = 'updated_at'
      and semantic_rule_column.attnum > 0
      and not semantic_rule_column.attisdropped
  ) then
    raise exception 'migration 141 requires semantic_correlation_rules.updated_at';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version = 141 and name = 'semantic_dispatch_rule_lock_acl'
  ) and (
    has_table_privilege('adlog_semantic_worker', 'public.semantic_correlation_rules', 'UPDATE')
    or exists (
      select 1
      from pg_attribute semantic_rule_column
      where semantic_rule_column.attrelid = 'public.semantic_correlation_rules'::regclass
        and semantic_rule_column.attnum > 0
        and not semantic_rule_column.attisdropped
        and has_column_privilege(
          'adlog_semantic_worker',
          semantic_rule_column.attrelid,
          semantic_rule_column.attname,
          'UPDATE'
        )
    )
  ) then
    raise exception 'migration 141 first apply requires absent effective update baseline';
  end if;
end
$$;

set local role adlog_storage_owner;

grant update(updated_at) on table public.semantic_correlation_rules to adlog_semantic_worker;

do $$
begin
  if not has_column_privilege(
    'adlog_semantic_worker',
    'public.semantic_correlation_rules',
    'updated_at',
    'UPDATE'
  ) then
    raise exception 'migration 141 rule lock privilege readback failed';
  end if;
  if has_table_privilege('adlog_semantic_worker', 'public.semantic_correlation_rules', 'UPDATE')
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
     ) then
    raise exception 'migration 141 rule lock privilege is broader than updated_at';
  end if;
  if exists (
    select 1
    from pg_attribute semantic_rule_column
    join pg_class relation_row on relation_row.oid = semantic_rule_column.attrelid
    join pg_roles runtime_role on runtime_role.rolname = 'adlog_semantic_worker'
    join lateral aclexplode(semantic_rule_column.attacl) privilege_record on true
    where semantic_rule_column.attrelid = 'public.semantic_correlation_rules'::regclass
      and semantic_rule_column.attname = 'updated_at'
      and semantic_rule_column.attnum > 0
      and not semantic_rule_column.attisdropped
      and privilege_record.grantee = runtime_role.oid
      and privilege_record.privilege_type = 'UPDATE'
      and (
        privilege_record.is_grantable
        or privilege_record.grantor <> relation_row.relowner
      )
  ) then
    raise exception 'migration 141 rule lock privilege ACL readback failed';
  end if;
end
$$;

insert into public.schema_migrations(version,name)
values (141, 'semantic_dispatch_rule_lock_acl')
on conflict(version) do nothing;

commit;
