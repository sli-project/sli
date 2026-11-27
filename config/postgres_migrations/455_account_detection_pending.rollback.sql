begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_account_detection_pending455'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=455 and name='account_detection_pending')
       or exists(select 1 from public.schema_migrations where version>455) then
        raise exception 'account_detection_pending455_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare saved record; begin
    for saved in select * from public.account_detection_restore455 loop
        execute saved.definition;
    end loop;
end $$;

-- Rebuild on demand under the 451 reader using the retained exact checks.
truncate public.account_detection_pending451,public.account_detection_checkpoints451;
drop function public.prune_account_detection_pending455(timestamptz,integer);
drop function public.subscribe_account_checkpoint455(text,text,jsonb);
drop function public.account_detection_event_kind455(text,integer);
drop table public.account_detection_restore455;
alter table public.account_detection_checkpoints451
    drop column seed_complete,drop column seed_normalized,drop column seed_at;
reset role;
delete from public.schema_migrations where version=455 and name='account_detection_pending';
commit;
