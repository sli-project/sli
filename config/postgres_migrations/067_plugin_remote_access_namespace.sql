-- Stage 10 prepared-only PostgreSQL namespace for plugin sli.remote-access.
-- Existing Stage 9 tables and production read paths remain unchanged.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_plugin_remote_access_namespace_v67')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 067 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=66 and name='administrative_activity_journal'
    ) then
        raise exception 'migration 067 requires schema migration 066';
    end if;
    if to_regrole('adlog_plugin_remote_access_owner') is not null
       or to_regrole('adlog_plugin_remote_access_runtime') is not null then
        raise exception 'migration 067 requires absent plugin roles';
    end if;
    if exists (
        select 1 from pg_namespace where nspname='sli_plugin_remote_access'
    ) then
        raise exception 'migration 067 requires absent plugin namespace';
    end if;
end
$$;

create role adlog_plugin_remote_access_owner
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
create role adlog_plugin_remote_access_runtime
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_plugin_remote_access_owner to adlog_storage_owner;
grant adlog_plugin_remote_access_runtime to adlog_storage_owner;

create schema sli_plugin_remote_access
    authorization adlog_plugin_remote_access_owner;
revoke all on schema sli_plugin_remote_access from public;
grant usage on schema sli_plugin_remote_access
    to adlog_plugin_remote_access_runtime;

set local role adlog_plugin_remote_access_owner;
create table sli_plugin_remote_access.plugin_namespace_contract_v1 (
    plugin_id text primary key
        check (plugin_id='sli.remote-access'),
    contract_id text not null
        check (contract_id='sli.plugin-postgresql-isolation.v1'),
    contract_version integer not null check (contract_version=1),
    created_at_utc timestamptz not null default now()
);
insert into sli_plugin_remote_access.plugin_namespace_contract_v1(
    plugin_id,contract_id,contract_version
) values (
    'sli.remote-access','sli.plugin-postgresql-isolation.v1',1
);
revoke all on table
    sli_plugin_remote_access.plugin_namespace_contract_v1
from public;
grant select on table
    sli_plugin_remote_access.plugin_namespace_contract_v1
to adlog_plugin_remote_access_runtime;

reset role;
insert into schema_migrations(version,name)
values (67,'plugin_remote_access_namespace')
on conflict(version) do update set name=excluded.name;

commit;
