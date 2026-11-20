select pg_advisory_xact_lock(
  hashtext('ad_log_reports_runtime_collection_history_restoration_v133')
);

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 132
      and name = 'ad_snapshot_delete_authorization'
  ) then
    raise exception 'migration 133 requires exact migration 132 ad_snapshot_delete_authorization';
  end if;

  if exists (
    select 1 from public.schema_migrations
    where version = 133
      and name is distinct from 'runtime_collection_history_restoration'
  ) then
    raise exception 'migration version 133 is already owned by another contract';
  end if;

  if to_regclass('public.runtime_collection_runs') is not null
     and not exists (
       select 1 from public.schema_migrations
       where version = 133
         and name = 'runtime_collection_history_restoration'
     ) then
    raise exception 'migration 133 refuses an existing runtime_collection_runs relation without its exact marker';
  end if;

  if to_regclass('public.runtime_collection_runs') is null
     and exists (
       select 1 from public.schema_migrations
       where version = 133
         and name = 'runtime_collection_history_restoration'
     ) then
    raise exception 'migration 133 exact marker requires runtime_collection_runs relation';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'adlog_user') then
    raise exception 'migration 133 requires runtime role adlog_user';
  end if;
end
$$;

do $$
begin
  if to_regclass('public.runtime_collection_runs') is null then
    execute $ddl$
      create table public.runtime_collection_runs (
        run_id text primary key,
        worker_id text not null,
        job_id integer null,
        status text not null,
        phase text not null,
        servers_json jsonb not null default '[]'::jsonb,
        hours integer not null,
        max_events_per_channel integer not null,
        created_at timestamptz not null default now(),
        started_at timestamptz null,
        finished_at timestamptz null,
        duration_ms integer null,
        errors_json jsonb null,
        updated_at timestamptz not null default now()
      )
    $ddl$;
    execute 'create index idx_runtime_collection_runs_created on public.runtime_collection_runs(created_at desc)';
    execute 'create index idx_runtime_collection_runs_status on public.runtime_collection_runs(status, updated_at desc)';
    execute 'revoke all on table public.runtime_collection_runs from public';
    execute 'grant select, insert, update on table public.runtime_collection_runs to adlog_user';
  end if;
end
$$;

do $$
begin
  if not exists (
    select 1
    from pg_class relation_row
    join pg_namespace namespace_row on namespace_row.oid = relation_row.relnamespace
    where namespace_row.nspname = 'public'
      and relation_row.relname = 'runtime_collection_runs'
      and relation_row.relkind = 'r'
  ) then
    raise exception 'migration 133 runtime_collection_runs table readback failed';
  end if;

  if (select count(*) from information_schema.columns
      where table_schema = 'public' and table_name = 'runtime_collection_runs') <> 14
     or exists (
       select 1
       from (
         values
           ('run_id', 'text', false),
           ('worker_id', 'text', false),
           ('job_id', 'integer', true),
           ('status', 'text', false),
           ('phase', 'text', false),
           ('servers_json', 'jsonb', false),
           ('hours', 'integer', false),
           ('max_events_per_channel', 'integer', false),
           ('created_at', 'timestamp with time zone', false),
           ('started_at', 'timestamp with time zone', true),
           ('finished_at', 'timestamp with time zone', true),
           ('duration_ms', 'integer', true),
           ('errors_json', 'jsonb', true),
           ('updated_at', 'timestamp with time zone', false)
       ) as expected(column_name, data_type, is_nullable)
       where not exists (
         select 1
         from information_schema.columns actual
         where actual.table_schema = 'public'
           and actual.table_name = 'runtime_collection_runs'
           and actual.column_name = expected.column_name
           and actual.data_type = expected.data_type
           and (actual.is_nullable = 'YES') = expected.is_nullable
       )
     ) then
    raise exception 'migration 133 runtime_collection_runs column contract readback failed';
  end if;

  if not exists (
       select 1
       from pg_attrdef default_row
       join pg_attribute attribute_row
         on attribute_row.attrelid = default_row.adrelid
        and attribute_row.attnum = default_row.adnum
       where default_row.adrelid = 'public.runtime_collection_runs'::regclass
         and attribute_row.attname = 'servers_json'
         and pg_get_expr(default_row.adbin, default_row.adrelid) = '''[]''::jsonb'
     ) or not exists (
       select 1
       from pg_attrdef default_row
       join pg_attribute attribute_row
         on attribute_row.attrelid = default_row.adrelid
        and attribute_row.attnum = default_row.adnum
       where default_row.adrelid = 'public.runtime_collection_runs'::regclass
         and attribute_row.attname = 'created_at'
         and pg_get_expr(default_row.adbin, default_row.adrelid) = 'now()'
     ) or not exists (
       select 1
       from pg_attrdef default_row
       join pg_attribute attribute_row
         on attribute_row.attrelid = default_row.adrelid
        and attribute_row.attnum = default_row.adnum
       where default_row.adrelid = 'public.runtime_collection_runs'::regclass
         and attribute_row.attname = 'updated_at'
         and pg_get_expr(default_row.adbin, default_row.adrelid) = 'now()'
     ) then
    raise exception 'migration 133 runtime_collection_runs default contract readback failed';
  end if;

  if not exists (
    select 1
    from pg_constraint constraint_row
    where constraint_row.conrelid = 'public.runtime_collection_runs'::regclass
      and constraint_row.contype = 'p'
      and constraint_row.conkey = array[
        (select attnum from pg_attribute
         where attrelid = 'public.runtime_collection_runs'::regclass
           and attname = 'run_id'
           and not attisdropped)
      ]
  ) then
    raise exception 'migration 133 runtime_collection_runs primary key readback failed';
  end if;

  if not exists (
    select 1 from pg_indexes
    where schemaname = 'public'
      and tablename = 'runtime_collection_runs'
      and indexname = 'idx_runtime_collection_runs_created'
      and indexdef = 'CREATE INDEX idx_runtime_collection_runs_created ON public.runtime_collection_runs USING btree (created_at DESC)'
  ) or not exists (
    select 1 from pg_indexes
    where schemaname = 'public'
      and tablename = 'runtime_collection_runs'
      and indexname = 'idx_runtime_collection_runs_status'
      and indexdef = 'CREATE INDEX idx_runtime_collection_runs_status ON public.runtime_collection_runs USING btree (status, updated_at DESC)'
  ) then
    raise exception 'migration 133 runtime_collection_runs index contract readback failed';
  end if;

  if exists (
       select 1
       from pg_class relation_row,
            lateral aclexplode(coalesce(
              relation_row.relacl,
              acldefault('r', relation_row.relowner)
            )) privilege_row
       where relation_row.oid = 'public.runtime_collection_runs'::regclass
         and privilege_row.grantee = 0
     )
     or not has_table_privilege('adlog_user', 'public.runtime_collection_runs', 'select')
     or not has_table_privilege('adlog_user', 'public.runtime_collection_runs', 'insert')
     or not has_table_privilege('adlog_user', 'public.runtime_collection_runs', 'update')
     or has_table_privilege('adlog_user', 'public.runtime_collection_runs', 'delete,truncate,references,trigger') then
    raise exception 'migration 133 runtime_collection_runs ACL readback failed';
  end if;
end
$$;

insert into public.schema_migrations(version, name) values (133, 'runtime_collection_history_restoration')
on conflict (version) do nothing;
