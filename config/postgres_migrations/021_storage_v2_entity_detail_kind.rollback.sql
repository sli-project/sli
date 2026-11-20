begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_entity_detail_kind_v21_rollback'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 021 requires membership in adlog_storage_owner';
    end if;
    if exists (
        select 1 from storage_v2_archive_sets where archive_kind='entity_detail'
    ) or exists (
        select 1 from storage_v2_archive_blocks where archive_kind='entity_detail'
    ) then
        raise exception 'rollback 021 refused: entity_detail archive rows exist';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table storage_v2_archive_sets
    drop constraint if exists storage_v2_archive_sets_archive_kind_check;
alter table storage_v2_archive_sets
    add constraint storage_v2_archive_sets_archive_kind_check
    check (archive_kind in ('event', 'link_detail')) not valid;
alter table storage_v2_archive_sets
    validate constraint storage_v2_archive_sets_archive_kind_check;

alter table storage_v2_archive_blocks
    drop constraint if exists storage_v2_archive_blocks_archive_kind_check;
alter table storage_v2_archive_blocks
    add constraint storage_v2_archive_blocks_archive_kind_check
    check (archive_kind in ('event', 'link_detail')) not valid;
alter table storage_v2_archive_blocks
    validate constraint storage_v2_archive_blocks_archive_kind_check;

delete from schema_migrations
where version=21 and name='storage_v2_entity_detail_kind';

commit;
