begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_sigma_history_test412'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=412 and name='sigma_history_test')
       or exists(select 1 from public.schema_migrations where version>412) then
        raise exception 'sigma_history_test412_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.sigma_test_payload411(jsonb,bigint,timestamptz,integer,text,text,integer);
drop function public.sigma_test_next411(jsonb,timestamptz,timestamptz,integer[],bigint,bigint);
drop function public.sigma_test_ceiling411(jsonb,timestamptz,timestamptz,integer[]);
drop function public.sigma_test_candidates411(jsonb,timestamptz,timestamptz,integer[]);
drop function public.sigma_test_scope_allowed411(jsonb,integer[]);
delete from public.schema_migrations where version=412 and name='sigma_history_test';
reset role;
commit;
