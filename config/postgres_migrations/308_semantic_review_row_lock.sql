-- Preserve semantic_reviews.py's FOR KEY SHARE without granting API UPDATE.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_review_row_lock_v308'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=307 and name='security_candidate_sid_lookup')
       or exists(select 1 from public.schema_migrations where version>=308)
       or to_regprocedure('public.lock_semantic_review_scenario_v308(uuid)') is not null then
        raise exception 'semantic_review_308_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create function public.lock_semantic_review_scenario_v308(p_id uuid)
returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    perform 1 from public.semantic_security_scenarios where scenario_id=p_id for key share;
end
$$;
revoke all on function public.lock_semantic_review_scenario_v308(uuid) from public,adlog_user;
grant execute on function public.lock_semantic_review_scenario_v308(uuid) to adlog_user;
insert into public.schema_migrations(version,name) values(308,'semantic_review_row_lock');
reset role;
commit;
