-- Complete the least-privilege Storage V2 direct-ingest worker boundary.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_storage_v2_direct_ingest_worker_grants_v96')
);

do $$
declare
    relation_name text;
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'member') then
        raise exception 'migration 096 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=94 and name='storage_v2_runtime_authorization_owner'
    ) then
        raise exception 'migration 096 requires migration 094';
    end if;
    if exists(select 1 from schema_migrations where version=96) then
        raise exception 'migration 096 version is already recorded';
    end if;
    if not exists(select 1 from pg_roles where rolname='adlog_storage_worker') then
        raise exception 'migration 096 requires role adlog_storage_worker';
    end if;

    foreach relation_name in array array[
        'raw_log_files',
        'storage_v2_event_identity_allocations',
        'storage_v2_entity_identity_allocations',
        'storage_v2_provider',
        'storage_v2_channel',
        'storage_v2_computer',
        'storage_v2_keywords',
        'storage_v2_domain_name',
        'storage_v2_role',
        'storage_v2_extracted_from',
        'storage_v2_entity_type',
        'events_v2_core',
        'event_facts_v2',
        'entities_v2'
    ] loop
        if to_regclass('public.' || relation_name) is null then
            raise exception 'migration 096 requires relation %', relation_name;
        end if;
    end loop;

    foreach relation_name in array array[
        'raw_log_files_id_seq',
        'storage_v2_event_id_seq',
        'entities_v2_id_seq'
    ] loop
        if to_regclass('public.' || relation_name) is null then
            raise exception 'migration 096 requires sequence %', relation_name;
        end if;
    end loop;

    foreach relation_name in array array[
        'storage_v2_provider',
        'storage_v2_channel',
        'storage_v2_computer',
        'storage_v2_keywords',
        'storage_v2_domain_name',
        'storage_v2_role',
        'storage_v2_extracted_from',
        'storage_v2_entity_type',
        'events_v2_core',
        'event_facts_v2',
        'entities_v2'
    ] loop
        if not has_table_privilege(
            'adlog_storage_worker', relation_name, 'SELECT,INSERT,UPDATE'
        ) then
            raise exception 'migration 096 found incomplete existing worker grant on %', relation_name;
        end if;
    end loop;
end
$$;

alter table storage_v2_event_identity_allocations owner to adlog_storage_owner;
alter table storage_v2_entity_identity_allocations owner to adlog_storage_owner;

grant select, insert, update on table raw_log_files
    to adlog_storage_worker;
grant select, insert on table
    storage_v2_event_identity_allocations,
    storage_v2_entity_identity_allocations
    to adlog_storage_worker;
grant usage, select on sequence
    raw_log_files_id_seq,
    storage_v2_event_id_seq,
    entities_v2_id_seq
    to adlog_storage_worker;

do $$
begin
    if not has_table_privilege(
        'adlog_storage_worker', 'raw_log_files', 'SELECT,INSERT,UPDATE'
    ) or not has_table_privilege(
        'adlog_storage_worker', 'storage_v2_event_identity_allocations', 'SELECT,INSERT'
    ) or not has_table_privilege(
        'adlog_storage_worker', 'storage_v2_entity_identity_allocations', 'SELECT,INSERT'
    ) or not has_sequence_privilege(
        'adlog_storage_worker', 'raw_log_files_id_seq', 'USAGE,SELECT'
    ) or not has_sequence_privilege(
        'adlog_storage_worker', 'storage_v2_event_id_seq', 'USAGE,SELECT'
    ) or not has_sequence_privilege(
        'adlog_storage_worker', 'entities_v2_id_seq', 'USAGE,SELECT'
    ) then
        raise exception 'migration 096 worker privilege readback failed';
    end if;
end
$$;

insert into schema_migrations(version, name)
values (96, 'storage_v2_direct_ingest_worker_grants')
on conflict(version) do update set name=excluded.name;

commit;
