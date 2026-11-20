-- Rollback is safe only while the new capability has no direct assignments.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_administrative_activity_reader_v72')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 072 requires membership in adlog_storage_owner';
    end if;
    if exists (
        select 1
        from access_capability_assignments assignment
        join access_capabilities capability
          on capability.id=assignment.capability_id
        where capability.capability_key='administrative.activity.view'
    ) then
        raise exception 'rollback 072 forbidden after capability assignment';
    end if;
end
$$;

delete from access_package_capabilities mapping
using access_packages package,access_capabilities capability
where mapping.package_id=package.id
  and mapping.capability_id=capability.id
  and package.package_key='access_admin'
  and capability.capability_key='administrative.activity.view';

delete from access_capabilities
where capability_key='administrative.activity.view';

revoke execute on function read_administrative_activity_v1(bigint,integer,text)
    from adlog_user;
drop function read_administrative_activity_v1(bigint,integer,text);

delete from schema_migrations
where version=72 and name='administrative_activity_reader';

commit;
