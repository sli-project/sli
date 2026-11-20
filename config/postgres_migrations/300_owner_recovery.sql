begin;
select pg_advisory_xact_lock(hashtext('ad_log_owner_recovery_v300'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 300 requires adlog_storage_owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=299 and name='login_account_throttle') then
        raise exception 'migration 300 requires exact migration 299 login_account_throttle';
    end if;
    if exists(select 1 from public.schema_migrations where version>=300) then
        raise exception 'migration 300 already applied, occupied or superseded';
    end if;
end $$;

set local role adlog_storage_owner;
create table public.auth_owner_recovery (
    user_id bigint primary key references public.auth_users(id) on delete cascade,
    code_hash text not null check (code_hash ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz not null
);
revoke all on public.auth_owner_recovery from public, adlog_user;
grant select, insert, update, delete on public.auth_owner_recovery to adlog_user;
insert into public.schema_migrations(version,name) values(300,'owner_recovery');
reset role;
commit;
