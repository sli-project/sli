begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_account_check_cleanup461'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=460 and name='account_check_rows')
       or exists(select 1 from public.schema_migrations where version>=461) then
        raise exception 'account_check_cleanup461_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.account_check_cleanup460 add column vacuumed boolean not null default false;

-- Read the legacy count once at the start of a drain. The 460 constraints
-- prevent new negative rows, so committed deletions can update it in memory.
create function public.account_check_cleanup_status461(p_family text,p_count boolean)
returns table(complete boolean,vacuumed boolean,remaining bigint)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    select c.complete,c.vacuumed into strict complete,vacuumed
    from public.account_check_cleanup460 c where c.family=p_family;
    if complete then
        remaining:=0;
    elsif p_count then
        if p_family='decoy' then
            select count(*) into remaining from public.semantic_account_decoy_checks where result_code<>'observed';
        else
            select count(*) into remaining from public.semantic_account_watch_checks where result_code<>'observed';
        end if;
    end if;
    return next;
end $$;
revoke all on function public.account_check_cleanup_status461(text,boolean) from public;
grant execute on function public.account_check_cleanup_status461(text,boolean) to adlog_storage_lifecycle_delete;

create function public.mark_account_check_vacuumed461(p_family text) returns void
language sql security definer set search_path=pg_catalog,pg_temp as $$
    update public.account_check_cleanup460 set vacuumed=true where family=p_family and complete
$$;
revoke all on function public.mark_account_check_vacuumed461(text) from public;
grant execute on function public.mark_account_check_vacuumed461(text) to adlog_storage_lifecycle_delete;

-- VACUUM must run outside a transaction, with table-local maintenance rights.
grant maintain on public.semantic_account_decoy_checks,public.semantic_account_watch_checks
    to adlog_storage_lifecycle_delete;

reset role;
insert into public.schema_migrations(version,name) values(461,'account_check_cleanup');
commit;
