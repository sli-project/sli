-- Evidence-preserving rollback for migration 088.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_source_capture_continuity_declarations_v88')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=88 and name='source_capture_continuity_declarations'
    ) then
        raise exception 'migration 088 rollback requires its marker';
    end if;
    if exists(select 1 from source_capture_continuity_declarations) then
        raise exception 'migration 088 rollback would discard immutable continuity evidence';
    end if;
end
$$;

set local role adlog_storage_owner;

drop trigger source_capture_continuity_declarations_immutable
    on source_capture_continuity_declarations;
drop function source_capture_continuity_declarations_reject_mutation();
drop table source_capture_continuity_declarations;

delete from schema_migrations
where version=88 and name='source_capture_continuity_declarations';

commit;
