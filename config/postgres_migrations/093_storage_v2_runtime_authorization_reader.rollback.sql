-- Remove the runtime read grant without dropping the authorization table.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_storage_v2_runtime_authorization_reader_v93')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 093 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=93 and name='storage_v2_runtime_authorization_reader'
    ) then
        raise exception 'rollback 093 requires migration 093';
    end if;
end
$$;

set local role adlog_storage_owner;

revoke select on table storage_v2_runtime_authorizations from adlog_user;

delete from schema_migrations where version=93;

commit;
