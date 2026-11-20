-- Revoke runtime read access; retain canonical table ownership and data.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_storage_v2_runtime_authorization_owner_v94')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 094 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=94 and name='storage_v2_runtime_authorization_owner'
    ) then
        raise exception 'rollback 094 requires migration 094';
    end if;
end
$$;

set local role adlog_storage_owner;

revoke select on table storage_v2_runtime_authorizations from adlog_user;

delete from schema_migrations where version=94;

commit;
