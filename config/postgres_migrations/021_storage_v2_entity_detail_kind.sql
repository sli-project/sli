begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_entity_detail_kind_v21'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 021 requires membership in adlog_storage_owner';
    end if;
    if to_regclass('storage_v2_archive_sets') is null
       or to_regclass('storage_v2_archive_blocks') is null then
        raise exception 'migration 021 requires Storage V2 archive tables';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=20 and name='casefold_search_indexes'
    ) then
        raise exception 'migration 021 requires schema migration 020';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table storage_v2_archive_sets
    drop constraint if exists storage_v2_archive_sets_archive_kind_check;
alter table storage_v2_archive_sets
    add constraint storage_v2_archive_sets_archive_kind_check
    check (archive_kind in ('event', 'link_detail', 'entity_detail')) not valid;
alter table storage_v2_archive_sets
    validate constraint storage_v2_archive_sets_archive_kind_check;

alter table storage_v2_archive_blocks
    drop constraint if exists storage_v2_archive_blocks_archive_kind_check;
alter table storage_v2_archive_blocks
    add constraint storage_v2_archive_blocks_archive_kind_check
    check (archive_kind in ('event', 'link_detail', 'entity_detail')) not valid;
alter table storage_v2_archive_blocks
    validate constraint storage_v2_archive_blocks_archive_kind_check;

insert into schema_migrations(version, name)
values (21, 'storage_v2_entity_detail_kind')
on conflict(version) do update set name=excluded.name;

commit;
