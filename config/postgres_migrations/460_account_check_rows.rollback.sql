begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_account_check_rows460'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=460 and name='account_check_rows')
       or exists(select 1 from public.schema_migrations where version>460) then
        raise exception 'account_check_rows460_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    for saved in select * from public.account_detection_restore460 loop
        execute saved.definition;
    end loop;
end $$;
drop function public.prune_account_check_rows460(text,integer);
drop function public.complete_account_batch460(text,text,jsonb,jsonb);
drop function public.prepare_account_checkpoint460(text,text,jsonb,boolean);
drop function public.seed_account_checkpoint460(bigint);
drop table public.account_detection_restore460,public.account_check_cleanup460;

-- Hits and live pending work remain intact. Manual runs can rediscover the
-- rows whose negative acknowledgments were already compacted.
delete from public.account_detection_checkpoints451 where all_event_kinds;
alter table public.account_detection_checkpoints451 drop column all_event_kinds,drop column last_evaluated_event_id;
alter table public.semantic_account_decoy_checks drop constraint account_decoy_hits460;
alter table public.semantic_account_watch_checks drop constraint account_watch_hits460;
reset role;
delete from public.schema_migrations where version=460 and name='account_check_rows';
commit;
