begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_platform_owner_access'));

create table if not exists access_platform_owners (
    user_id bigint primary key references auth_users(id) on delete restrict,
    owner_key text not null unique,
    business_reason text not null,
    created_at timestamptz not null default now()
);

insert into access_platform_owners(user_id,owner_key,business_reason)
select id,'primary','Единственный владелец, администратор и тестировщик проекта SLI'
from auth_users
where lower(username)='platform-owner' and is_active=true
on conflict(user_id) do update set
    owner_key=excluded.owner_key,
    business_reason=excluded.business_reason;

do $$
begin
    if not exists(
        select 1 from access_platform_owners owner_row
        join auth_users auth_user on auth_user.id=owner_row.user_id
        where owner_row.owner_key='primary' and lower(auth_user.username)='platform-owner' and auth_user.is_active=true
    ) then
        raise exception 'active platform owner platform-owner was not found';
    end if;
    if exists(select 1 from pg_roles where rolname='adlog_user') then
        execute 'grant select on access_platform_owners to adlog_user';
    end if;
end $$;

insert into schema_migrations(version,name) values(37,'platform_owner_access')
on conflict(version) do update set name=excluded.name;

commit;
