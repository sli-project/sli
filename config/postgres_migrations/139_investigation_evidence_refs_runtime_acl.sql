begin;

select pg_advisory_xact_lock(hashtext('ad_log_investigation_evidence_refs_runtime_acl_v139'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 138 and name = 'normalized_event_versioned_identity'
  ) then
    raise exception 'migration 139 requires exact migration 138 normalized_event_versioned_identity';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 139 and name is distinct from 'investigation_evidence_refs_runtime_acl'
  ) then
    raise exception 'migration version 139 is already owned by another contract';
  end if;
  if not exists (select 1 from pg_roles where rolname = 'adlog_user') then
    raise exception 'migration 139 requires runtime role adlog_user';
  end if;
  if to_regclass('public.investigation_evidence_refs') is null then
    raise exception 'migration 139 requires public.investigation_evidence_refs';
  end if;
  if not exists (
    select 1 from public.schema_migrations
    where version = 139 and name = 'investigation_evidence_refs_runtime_acl'
  ) then
    if has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'SELECT')
       or has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'INSERT')
       or exists (
         select 1
         from pg_attribute evidence_column
         where evidence_column.attrelid = 'public.investigation_evidence_refs'::regclass
           and evidence_column.attnum > 0
           and not evidence_column.attisdropped
           and (
             has_column_privilege('adlog_user', evidence_column.attrelid, evidence_column.attname, 'SELECT')
             or has_column_privilege('adlog_user', evidence_column.attrelid, evidence_column.attname, 'INSERT')
           )
       ) then
      raise exception 'migration 139 first apply requires absent effective select/insert baseline';
    end if;
  end if;
end
$$;

grant select, insert on table public.investigation_evidence_refs to adlog_user;

do $$
begin
  if not has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'SELECT')
     or not has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'INSERT') then
    raise exception 'migration 139 required runtime privilege readback failed';
  end if;
  if has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'UPDATE')
     or has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'DELETE')
     or has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'TRUNCATE')
     or has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'REFERENCES')
     or has_table_privilege('adlog_user', 'public.investigation_evidence_refs', 'TRIGGER') then
    raise exception 'migration 139 forbidden runtime privilege readback failed';
  end if;
  if exists (
    select 1
    from pg_attribute evidence_column
    where evidence_column.attrelid = 'public.investigation_evidence_refs'::regclass
      and evidence_column.attnum > 0
      and not evidence_column.attisdropped
      and (
        not has_column_privilege('adlog_user', evidence_column.attrelid, evidence_column.attname, 'SELECT')
        or not has_column_privilege('adlog_user', evidence_column.attrelid, evidence_column.attname, 'INSERT')
        or has_column_privilege('adlog_user', evidence_column.attrelid, evidence_column.attname, 'UPDATE')
        or has_column_privilege('adlog_user', evidence_column.attrelid, evidence_column.attname, 'REFERENCES')
      )
  ) then
    raise exception 'migration 139 column runtime privilege readback failed';
  end if;
end
$$;

insert into public.schema_migrations(version,name)
values (139, 'investigation_evidence_refs_runtime_acl')
on conflict(version) do nothing;

commit;
