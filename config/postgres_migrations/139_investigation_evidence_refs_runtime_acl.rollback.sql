begin;

select pg_advisory_xact_lock(hashtext('ad_log_investigation_evidence_refs_runtime_acl_v139_rollback'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 139 and name = 'investigation_evidence_refs_runtime_acl'
  ) then
    raise exception 'migration 139 rollback requires exact marker';
  end if;
  if has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'SELECT WITH GRANT OPTION')
     or has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'INSERT WITH GRANT OPTION')
     or exists (
       select 1
       from pg_attribute evidence_column
       where evidence_column.attrelid = 'public.investigation_evidence_refs'::regclass
         and evidence_column.attnum > 0
         and not evidence_column.attisdropped
         and (
           has_column_privilege('adlog_user', evidence_column.attrelid, evidence_column.attname, 'SELECT WITH GRANT OPTION')
           or has_column_privilege('adlog_user', evidence_column.attrelid, evidence_column.attname, 'INSERT WITH GRANT OPTION')
         )
     )
     or exists (
       select 1
       from pg_class relation_row
       join pg_roles runtime_role on runtime_role.rolname = 'adlog_user'
       join lateral aclexplode(coalesce(relation_row.relacl, acldefault('r', relation_row.relowner))) privilege_record on true
       where relation_row.oid = 'public.investigation_evidence_refs'::regclass
         and privilege_record.grantee = runtime_role.oid
         and privilege_record.privilege_type in ('SELECT', 'INSERT')
         and (
           privilege_record.is_grantable
           or privilege_record.grantor <> relation_row.relowner
         )
     )
     or exists (
       select 1
       from pg_attribute evidence_column
       join pg_roles runtime_role on runtime_role.rolname = 'adlog_user'
       join lateral aclexplode(coalesce(evidence_column.attacl, '{}'::aclitem[])) privilege_record on true
       where evidence_column.attrelid = 'public.investigation_evidence_refs'::regclass
         and evidence_column.attnum > 0
         and not evidence_column.attisdropped
         and privilege_record.grantee = runtime_role.oid
         and privilege_record.privilege_type in ('SELECT', 'INSERT')
     ) then
    raise exception 'migration 139 rollback refuses expanded select/insert ACL';
  end if;
end
$$;

revoke select, insert on table public.investigation_evidence_refs from adlog_user;

do $$
begin
  if has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'SELECT')
     or has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'INSERT') then
    raise exception 'migration 139 rollback runtime privilege readback failed';
  end if;
end
$$;

delete from public.schema_migrations
where version = 139 and name = 'investigation_evidence_refs_runtime_acl';

commit;
