begin;
select pg_advisory_xact_lock(hashtext('ad_log_login_account_throttle_v299'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 299 requires adlog_storage_owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=280 and name='service_account_origin') then
        raise exception 'migration 299 requires exact migration 280 service_account_origin';
    end if;
    -- Intervening migrations belong to independent changes; preserve their markers.
    if exists(select 1 from public.schema_migrations where version>=299) then
        raise exception 'migration 299 already applied, occupied or superseded';
    end if;
end $$;

set local role adlog_storage_owner;
create table public.auth_login_throttle (
    account_key text primary key check (account_key ~ '^[0-9a-f]{64}$'),
    failures integer not null check (failures between 1 and 9),
    window_started_at timestamptz not null,
    blocked_until timestamptz
);
create index auth_login_throttle_expiry on public.auth_login_throttle(window_started_at);
revoke all on public.auth_login_throttle from public, adlog_user;
grant select, insert, update, delete on public.auth_login_throttle to adlog_user;
insert into public.schema_migrations(version,name) values(299,'login_account_throttle');
reset role;
commit;
