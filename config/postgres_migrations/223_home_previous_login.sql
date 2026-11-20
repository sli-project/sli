-- Preserve the previous successful user login for the home queue baseline.
begin;
select pg_advisory_xact_lock(hashtext('sli_home_previous_login_v223'));
do $$ begin
    if not exists(select 1 from public.schema_migrations where version=222 and name='sigma_attack_coverage')
       or exists(select 1 from public.schema_migrations where version>=223) then
        raise exception 'migration 223 prerequisites failed';
    end if;
end $$;
alter table public.auth_users add column previous_login_at timestamptz;
insert into public.schema_migrations(version,name) values(223,'home_previous_login');
commit;
