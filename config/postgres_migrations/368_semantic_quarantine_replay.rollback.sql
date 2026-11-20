begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_quarantine_replay368'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=368 and name='semantic_quarantine_replay')
       or exists(select 1 from public.schema_migrations where version>368) then
        raise exception 'semantic_quarantine_replay368_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
revoke select(action,target,details) on public.semantic_control_audit from adlog_semantic_worker;
drop function public.record_semantic_quarantine_resolution368(text,jsonb);
drop index public.semantic_quarantine_receipts368;
-- Keep original jobs, normalized facts, canonical actions and all audit receipts.
delete from public.schema_migrations where version=368 and name='semantic_quarantine_replay';
reset role;
commit;
