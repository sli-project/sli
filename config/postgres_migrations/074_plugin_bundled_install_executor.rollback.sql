-- Clean rollback only before any bundled install operation was committed.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_install_v74'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 074 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=74 and name='plugin_bundled_install_executor'
    ) then
        raise exception 'rollback 074 requires exact migration marker';
    end if;
    if exists (
        select 1 from plugin_lifecycle_operations_v1
        where requested_action='install'
    ) then
        raise exception 'rollback 074 forbidden after bundled install';
    end if;
end
$$;

delete from schema_migrations
where version=74 and name='plugin_bundled_install_executor';
drop function execute_bundled_plugin_install_v1(
    uuid,text,bigint,text,text,text,text
);
revoke execute on function append_administrative_activity_v1(
    uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,inet,uuid
) from adlog_plugin_lifecycle_owner;

commit;
