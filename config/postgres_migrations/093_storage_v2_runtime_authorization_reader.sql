-- Allow the application runtime to verify sealed Storage V2 route authority.
-- Runtime remains read-only; only the migration role can mutate authorization.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_storage_v2_runtime_authorization_reader_v93')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 093 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=92 and name='current_event_catalog_revision'
    ) then
        raise exception 'migration 093 requires migration 092';
    end if;
    if to_regclass('storage_v2_runtime_authorizations') is null then
        raise exception 'migration 093 requires storage_v2_runtime_authorizations';
    end if;
    if not exists(select 1 from pg_roles where rolname='adlog_user') then
        raise exception 'migration 093 requires adlog_user';
    end if;
    if exists(select 1 from schema_migrations where version=93) then
        raise exception 'migration 093 version is already recorded';
    end if;
end
$$;

set local role adlog_storage_owner;

grant select on table storage_v2_runtime_authorizations to adlog_user;

insert into schema_migrations(version,name)
values(93,'storage_v2_runtime_authorization_reader')
on conflict(version) do update set name=excluded.name;

commit;
