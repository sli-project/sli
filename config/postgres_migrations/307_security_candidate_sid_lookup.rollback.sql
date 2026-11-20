begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_security_candidate_sid_lookup_v307'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=307 and name='security_candidate_sid_lookup')
       or exists(select 1 from public.schema_migrations where version>307)
       or (select proowner from pg_catalog.pg_proc where oid='public.security_candidate_sid_matches_v307(bigint,integer,text)'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'security_candidate_307_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.security_candidate_sid_matches_v307(bigint,integer,text);
delete from public.schema_migrations where version=307 and name='security_candidate_sid_lookup';
reset role;
commit;
