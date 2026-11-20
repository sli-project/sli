-- Refuse destructive rollback once the ledger contains work/history.
begin;
select pg_advisory_xact_lock(hashtext('sli_core_job_queue_v154'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=154 and name='core_job_queue')
       or exists(select 1 from public.schema_migrations where version>154) then
        raise exception 'rollback 154 prerequisites failed';
    end if;
    if exists(select 1 from sli_jobs.jobs) or exists(select 1 from sli_jobs.audit) then
        raise exception 'rollback 154 refuses job history';
    end if;
end $$;
do $$
declare f record;
begin
    for f in select oid::regprocedure as signature from pg_proc
        where pronamespace='public'::regnamespace and proowner='sli_job_owner'::regrole loop
        execute format('drop function %s',f.signature);
    end loop;
end $$;
drop table sli_jobs.audit;
drop table sli_jobs.jobs;
drop schema sli_jobs;
do $$
declare profile text; purpose text;
begin
    foreach profile in array array['light','heavy','long'] loop
        foreach purpose in array array['dispatcher','executor','publisher'] loop
            execute format('drop owned by %I','sli_job_'||purpose||'_'||profile);
            execute format('drop role %I','sli_job_'||purpose||'_'||profile);
        end loop;
    end loop;
end $$;
drop owned by sli_job_owner;
drop role sli_job_owner;
delete from public.schema_migrations where version=154 and name='core_job_queue';
commit;
