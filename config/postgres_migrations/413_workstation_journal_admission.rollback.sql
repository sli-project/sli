begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_journal_admission413'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=413 and name='workstation_journal_admission')
       or exists(select 1 from public.schema_migrations where version>413) then
        raise exception 'workstation_journal_admission413_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare saved record; begin
    select * into strict saved from public.workstation_journal_restore412;
    if pg_get_functiondef('public.attest_short_event337()'::regprocedure) is distinct from saved.installed then
        raise exception 'workstation_journal_admission413_rollback_trigger_shape' using errcode='55000';
    end if;
    execute saved.original;
end $$;
drop function public.write_workstation_journal412(uuid,jsonb);
drop function public.workstation_journal_proof412(uuid,integer,bigint,timestamptz,integer,bigint,text,jsonb);
drop function public.workstation_journal_packet_allowed412(jsonb);
drop function public.workstation_journal_scope412(uuid,text,text);
drop function public.set_workstation_journal_grant412(uuid,boolean);
drop table public.workstation_journal_restore412;
drop table public.workstation_journal_grants412;
-- Retain acknowledged packets and all published events and summaries.
delete from public.schema_migrations where version=413 and name='workstation_journal_admission';
reset role;
commit;
