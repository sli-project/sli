-- Correct migration-091 table ownership, then grant runtime read-only access.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_storage_v2_runtime_authorization_owner_v94')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 094 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=93 and name='storage_v2_runtime_authorization_reader'
    ) then
        raise exception 'migration 094 requires migration 093';
    end if;
    if to_regclass('storage_v2_runtime_authorizations') is null then
        raise exception 'migration 094 requires storage_v2_runtime_authorizations';
    end if;
    if exists(select 1 from schema_migrations where version=94) then
        raise exception 'migration 094 version is already recorded';
    end if;
end
$$;

alter table storage_v2_runtime_authorizations owner to adlog_storage_owner;

set local role adlog_storage_owner;

grant select on table storage_v2_runtime_authorizations to adlog_user;

insert into schema_migrations(version,name)
values(94,'storage_v2_runtime_authorization_owner')
on conflict(version) do update set name=excluded.name;

commit;
