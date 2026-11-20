-- Migration 150 — widen the internal Storage V2 event identity to bigint.
-- Windows Event ID (events_v2_core.event_id), entity IDs and role IDs stay unchanged.
--
-- OFFLINE maintenance: stop collectors, semantic/projector workers and readers.
-- ALTER TYPE integer -> bigint rewrites each heap and rebuilds its indexes;
-- ACCESS EXCLUSIVE locks block even SELECT until COMMIT. FK revalidation also
-- scans referencing tables. Multiple columns of one table are altered together.
-- Budget minutes for small installations, potentially hours for large ones.
-- Estimate with sum(pg_total_relation_size(...)) for the listed relations,
-- divided by measured rewrite throughput, plus index rebuild/FK validation time.
-- For example, 100 GiB at 50 MiB/s is ~34 minutes for ONE sequential pass;
-- several passes, WAL, checkpoints and replicas can multiply this substantially.
-- Allow space for replacement heaps/indexes AND WAL (at least the relation size,
-- preferably 2-3x with a measured margin). This is an estimate, not a runtime SLA.
-- Rehearse on a restored copy; ANALYZE affected tables after COMMIT.
-- lock_timeout bounds acquisition only; statement_timeout=0 allows the rewrite.
-- https://www.postgresql.org/docs/18/sql-altertable.html
--
-- Existing bigint evidence/cursors are included as checked no-ops. Catalog FK
-- discovery also covers additional FK columns, without relying on column names.
-- Transactional DDL: any missing relation, unexpected type or view dependency
-- aborts the whole upgrade. No CASCADE and no sequence restart/setval.

begin;
set local search_path = pg_catalog, public;
set local lock_timeout = '5s';
set local statement_timeout = 0;
select pg_advisory_xact_lock(hashtext('ad_log_storage_v2_event_bigint_v150'));

do $$
declare
    item record;
    changes text;
    view_definition text;
    view_owner text;
    view_options text[];
    view_comment text;
    sequence_position bigint;
    greatest_event_id bigint;
    added integer;
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'member')
       or not pg_has_role(session_user, 'adlog_user', 'member') then
        raise exception 'migration 150 requires storage and runtime owner membership';
    end if;
    if not exists (
        select 1 from public.schema_migrations
        where version = 149 and name = 'investigation_finding_links'
    ) then
        raise exception 'migration 150 requires exact migration 149 investigation_finding_links';
    end if;
    if exists (
        select 1 from public.schema_migrations where version = 150
        and name is distinct from 'storage_v2_event_bigint'
    ) then
        raise exception 'migration version 150 is already owned by another contract';
    end if;

    create temporary table event_bigint_columns (
        schema_name text not null default 'public',
        table_name text not null,
        column_name text not null,
        target_type text not null,
        primary key (schema_name, table_name, column_name)
    ) on commit drop;
    insert into event_bigint_columns(table_name, column_name, target_type) values
        ('events_v2_core', 'id', 'bigint'),
        ('storage_v2_event_identity_allocations', 'id', 'bigint'),
        ('event_facts_v2', 'event_id', 'bigint'),
        ('event_entity_link_blocks_v2', 'first_event_id', 'bigint'),
        ('event_entity_link_blocks_v2', 'last_event_id', 'bigint'),
        ('event_entity_link_blocks_v2', 'event_ids', 'bigint[]'),
        ('entity_state_current', 'source_event_db_id', 'bigint'),
        ('entity_state_projection_jobs', 'source_event_db_id', 'bigint'),
        ('normalized_events', 'source_event_id', 'bigint'),
        ('semantic_processing_outbox', 'source_event_id', 'bigint'),
        ('entity_identity_merge_events_v2', 'source_event_id', 'bigint'),
        ('entity_identity_semantic_replays_v2', 'source_event_id', 'bigint'),
        ('detections', 'primary_event_id', 'bigint'),
        ('entity_states', 'evidence_event_id', 'bigint'),
        ('event_links', 'source_event_id', 'bigint'),
        ('event_links', 'target_event_id', 'bigint'),
        ('finding_evidence', 'event_id', 'bigint'),
        ('findings', 'last_evidence_event_id', 'bigint'),
        ('ad_context_event_links', 'event_db_id', 'bigint'),
        ('investigation_events', 'event_db_id', 'bigint'),
        ('process_episode_evidence', 'source_event_id', 'bigint'),
        ('process_episode_revisions', 'boot_event_id', 'bigint'),
        ('process_episode_revisions', 'start_event_id', 'bigint'),
        ('process_episode_revisions', 'end_event_id', 'bigint'),
        ('what_where_when_observations', 'source_event_id', 'bigint'),
        ('what_where_when_projection_state', 'high_water_event_id', 'bigint'),
        ('findings_refresh_state', 'last_event_id', 'bigint'),
        ('findings_refresh_state', 'bootstrap_event_id', 'bigint'),
        ('storage_lifecycle_snapshots', 'events_max_id', 'bigint'),
        ('storage_v2_archive_blocks', 'first_event_id', 'bigint'),
        ('storage_v2_archive_blocks', 'last_event_id', 'bigint'),
        ('storage_v2_archive_sets', 'source_min_event_id', 'bigint'),
        ('storage_v2_archive_sets', 'source_max_event_id', 'bigint'),
        ('storage_v2_backfill_checkpoints', 'high_watermark_event_id', 'bigint'),
        ('storage_v2_backfill_checkpoints', 'last_verified_event_id', 'bigint'),
        ('storage_v2_backfill_chunks', 'chunk_start_event_id', 'bigint'),
        ('storage_v2_backfill_chunks', 'chunk_end_event_id', 'bigint'),
        ('storage_v2_outbox', 'first_event_id', 'bigint'),
        ('storage_v2_outbox', 'last_event_id', 'bigint'),
        ('storage_v2_outbox', 'event_ids', 'bigint[]');

    -- Follow FK column pairs, including transitive references to widened keys.
    loop
        insert into event_bigint_columns(schema_name, table_name, column_name, target_type)
        select ns.nspname, rel.relname, child.attname, target.target_type
        from pg_constraint fk
        cross join lateral unnest(fk.conkey, fk.confkey) pair(child_num, parent_num)
        join pg_class rel on rel.oid = fk.conrelid
        join pg_namespace ns on ns.oid = rel.relnamespace
        join pg_attribute child on child.attrelid = fk.conrelid and child.attnum = pair.child_num
        join pg_attribute parent on parent.attrelid = fk.confrelid and parent.attnum = pair.parent_num
        join event_bigint_columns target
          on fk.confrelid = to_regclass(format('%I.%I', target.schema_name, target.table_name))
         and parent.attname = target.column_name
        where fk.contype = 'f'
        on conflict do nothing;
        get diagnostics added = row_count;
        exit when added = 0;
    end loop;

    for item in select * from event_bigint_columns loop
        if not exists (
            select 1 from pg_attribute
            where attrelid = to_regclass(format('%I.%I', item.schema_name, item.table_name))
              and attname = item.column_name and not attisdropped
              and atttypid in (
                  item.target_type::regtype,
                  case when item.target_type = 'bigint[]' then 'integer[]'::regtype
                       else 'integer'::regtype end
              )
        ) then
            raise exception 'migration 150 missing or unexpected identity column %.%.%',
                item.schema_name, item.table_name, item.column_name;
        end if;
    end loop;

    -- Migration 090 remains immutable: its int32 preflight belongs to the
    -- historical integer schema. The widened schema uses this bigint gate,
    -- including reservations not yet published to the core. Never rewind the
    -- sequence, even when retention has removed the highest published IDs.
    select last_value into sequence_position from public.storage_v2_event_id_seq;
    select greatest(
        sequence_position,
        coalesce((select max(id) from public.events_v2_core), 0),
        coalesce((select max(id) from public.storage_v2_event_identity_allocations), 0)
    ) into greatest_event_id;
    if greatest_event_id >= 9223372036854775807 then
        raise exception 'migration 150 event bigint identity capacity is exhausted at %', greatest_event_id;
    end if;

    -- A verified retry must not repeat heap rewrites or FK validation scans.
    if exists (select 1 from public.schema_migrations where version = 150)
       and not exists (
           select 1 from event_bigint_columns target
           join pg_attribute col
             on col.attrelid = to_regclass(format('%I.%I', target.schema_name, target.table_name))
            and col.attname = target.column_name
           where col.atttypid <> target.target_type::regtype
       )
       and exists (
           select 1 from pg_sequence where seqrelid = 'public.storage_v2_event_id_seq'::regclass
             and seqtypid = 'bigint'::regtype and seqmax = 9223372036854775807
       )
       and exists (
           select 1 from pg_attribute where attrelid = 'public.event_entity_links_v2'::regclass
             and attname = 'event_id' and atttypid = 'bigint'::regtype
       )
       and position('(item.value->>''source_event_id'')::integer' in
           pg_get_functiondef('public.write_process_episode_revision_v89(jsonb)'::regprocedure)) = 0 then
        return;
    end if;

    -- Lock in deterministic order before inspecting/dropping FK dependencies.
    for item in select distinct schema_name, table_name from event_bigint_columns
                order by schema_name, table_name loop
        execute format('lock table %I.%I in access exclusive mode', item.schema_name, item.table_name);
    end loop;

    create temporary table event_bigint_fks on commit drop as
    select fk.conrelid, fk.conname, fk.convalidated, pg_get_constraintdef(fk.oid) as definition
    from pg_constraint fk
    where fk.contype = 'f' and exists (
        select 1 from event_bigint_columns target
        join pg_attribute col
          on col.attrelid = to_regclass(format('%I.%I', target.schema_name, target.table_name))
         and col.attname = target.column_name
        where (fk.confrelid = col.attrelid and col.attnum = any(fk.confkey))
           or (fk.conrelid = col.attrelid and col.attnum = any(fk.conkey))
    );

    -- ALTER TYPE cannot change a column used by a view. Save the definition,
    -- owner, reloptions, table/column ACLs and comment; downstream dependencies
    -- fail closed on DROP (no CASCADE). FK definitions retain NOT VALID state.
    select pg_get_viewdef(oid), pg_get_userbyid(relowner), reloptions, obj_description(oid)
      into strict view_definition, view_owner, view_options, view_comment
    from pg_class where oid = 'public.event_entity_links_v2'::regclass and relkind = 'v';
    create temporary table event_bigint_view_acl on commit drop as
    select null::text as column_name, acl.*
    from pg_class rel cross join lateral aclexplode(coalesce(rel.relacl, acldefault('r', rel.relowner))) acl
    where rel.oid = 'public.event_entity_links_v2'::regclass
    union all
    select col.attname::text, acl.*
    from pg_attribute col cross join lateral aclexplode(col.attacl) acl
    where col.attrelid = 'public.event_entity_links_v2'::regclass;

    for item in select * from event_bigint_fks loop
        execute format('alter table %s drop constraint %I', item.conrelid::regclass, item.conname);
    end loop;
    drop view public.event_entity_links_v2;

    for item in select distinct schema_name, table_name from event_bigint_columns
                order by schema_name, table_name loop
        select string_agg(format('alter column %I type %s using %I::%s',
                                target.column_name, target.target_type,
                                target.column_name, target.target_type), ', ' order by target.column_name)
          into changes
        from event_bigint_columns target
        join pg_attribute col
          on col.attrelid = to_regclass(format('%I.%I', target.schema_name, target.table_name))
         and col.attname = target.column_name
        where target.schema_name = item.schema_name and target.table_name = item.table_name
          and col.atttypid <> target.target_type::regtype;
        if changes is not null then
            execute format('alter table %I.%I %s', item.schema_name, item.table_name, changes);
        end if;
    end loop;

    alter sequence public.storage_v2_event_id_seq as bigint no maxvalue;
    select last_value into sequence_position from public.storage_v2_event_id_seq;
    if sequence_position >= 9223372036854775807 then
        raise exception 'migration 150 event bigint identity capacity is exhausted';
    end if;

    for item in select * from event_bigint_fks loop
        execute format('alter table %s add constraint %I %s',
                       item.conrelid::regclass, item.conname, item.definition);
    end loop;
    execute 'create view public.event_entity_links_v2 as ' || view_definition;
    execute format('alter view public.event_entity_links_v2 owner to %I', view_owner);
    if view_options is not null then
        execute 'alter view public.event_entity_links_v2 set (' || array_to_string(view_options, ',') || ')';
    end if;
    execute format('comment on view public.event_entity_links_v2 is %L', view_comment);
    -- Remove grants introduced by the applying role's default privileges.
    for item in
        select distinct acl.grantee from pg_class rel
        cross join lateral aclexplode(rel.relacl) acl
        where rel.oid = 'public.event_entity_links_v2'::regclass
    loop
        execute 'revoke all on public.event_entity_links_v2 from ' ||
            case when item.grantee = 0 then 'public' else quote_ident(pg_get_userbyid(item.grantee)) end;
    end loop;
    for item in select * from event_bigint_view_acl order by is_grantable desc loop
        execute format('grant %s%s on public.event_entity_links_v2 to %s%s',
            item.privilege_type,
            case when item.column_name is null then '' else format(' (%I)', item.column_name) end,
            case when item.grantee = 0 then 'public' else quote_ident(pg_get_userbyid(item.grantee)) end,
            case when item.is_grantable then ' with grant option' else '' end);
    end loop;

    -- Replace only the old internal event cast, preserving function owner,
    -- SECURITY DEFINER/search_path and ACLs through CREATE OR REPLACE.
    -- Old expression: (item.value->>'source_event_id')::integer
    -- New expression: (item.value->>'source_event_id')::bigint
    select pg_get_functiondef('public.write_process_episode_revision_v89(jsonb)'::regprocedure)
      into view_definition;
    view_definition := replace(view_definition,
        '(item.value->>''source_event_id'')::integer', '(item.value->>''source_event_id'')::bigint');
    execute view_definition;
end
$$;

insert into schema_migrations(version, name)
values (150, 'storage_v2_event_bigint')
on conflict(version) do update set name=excluded.name;

commit;
