begin;
select pg_advisory_xact_lock(hashtext('sli_problem_notification_transitions423'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=423 and name='problem_notification_transitions')
       or exists(select 1 from public.schema_migrations where version>423) then
        raise exception 'problem_notification_transitions423_rollback_preflight' using errcode='55000';
    end if;
end $$;

drop trigger notify_manual_problem_reopen423 on public.finding_status_history;
set local role adlog_storage_owner;
drop function public.notify_manual_problem_reopen423();
drop function public.enqueue_problem_notification423(uuid,uuid);
drop function public.insert_problem_notification423(uuid,text,text,text,timestamptz);

create or replace function public.notification_telegram_severity_gate() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$
begin
    if new.channel='telegram' and new.object_kind='semantic_finding'
       and new.object_severity is distinct from 'high' and new.object_severity is distinct from 'critical' then
        return null;
    end if;
    return new;
end $$;

-- Keep the expanded check so prior delivery rows and their attempts survive
-- rollback and can still be updated by the previous workers.
reset role;
delete from public.schema_migrations where version=423 and name='problem_notification_transitions';
commit;
