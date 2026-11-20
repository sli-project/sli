-- Host updater authority; readiness, access and plugin activation remain separate.
begin;
select pg_advisory_xact_lock(hashtext('sli_installed_release_v179'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 179 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=178 and name='agent_onboarding')
       or exists(select 1 from public.schema_migrations where version>=179) then
        raise exception 'migration 179 requires exact migration 178 and unused version 179';
    end if;
end $$;
alter table public.schema_migrations add column sha256 text
    check(sha256 is null or sha256 ~ '^[a-f0-9]{64}$');
-- Existing hashes are attested by the trusted migrator after exact ID/name readback.
-- SQL cannot attest its own file hash. Never manufacture checksums in the migration.
create table public.installed_release_v1 (
    singleton boolean primary key default true check(singleton),
    installation_key text not null check(installation_key ~ '^[a-f0-9]{64}$'),
    operation text not null check(operation ~ '^[a-f0-9]{32}$'),
    inventory jsonb not null check(jsonb_typeof(inventory)='object'),
    updated_at_utc timestamptz not null default now()
);
alter table public.installed_release_v1 owner to adlog_storage_owner;
revoke all on public.installed_release_v1 from public,adlog_user;
-- Only the host-owned updater's existing administrative connection writes here.
insert into public.schema_migrations(version,name) values(179,'installed_release');
commit;
