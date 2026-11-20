begin;
select pg_advisory_xact_lock(hashtext('sli_detection_event_clock362'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=362 and name='detection_event_clock')
       or exists(select 1 from public.schema_migrations where version>362) then
        raise exception 'detection_event_clock362_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare definition text; begin
    select d.definition into strict definition from public.detection_event_clock_definitions362 d;
    execute definition;
end $$;
drop function public.read_password_event_window362(jsonb,jsonb);
drop function public.password_event_clock362(jsonb,jsonb);
drop table public.detection_event_clock_definitions362;
-- Event decisions, evidence and checkpoint progress survive rollback.
delete from public.schema_migrations where version=362 and name='detection_event_clock';
reset role;
commit;
