begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_event_catalog_revision_reference_v51')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 051 rollback requires membership in adlog_storage_owner';
    end if;
    if exists (
        select 1 from schema_migrations where version>51
    ) then
        raise exception 'migration 051 rollback refuses later migrations';
    end if;
end
$$;

set local role adlog_storage_owner;

drop trigger if exists events_v2_core_catalog_revision on events_v2_core;
drop function if exists set_event_noise_catalog_revision();

alter table events_v2_core
    drop constraint if exists events_v2_core_noise_catalog_revision_required,
    drop constraint if exists events_v2_core_noise_catalog_revision_fk,
    drop column if exists noise_catalog_revision_id;

drop table if exists event_catalog_revisions;

delete from schema_migrations
where version=51 and name='event_catalog_revision_reference';

commit;
