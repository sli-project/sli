begin;
select pg_advisory_xact_lock(hashtext('sli_file_action_intake389'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=389 and name='file_action_intake')
       or exists(select 1 from public.schema_migrations where version>389) then
        raise exception 'file_action_intake389_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $patch389$ declare definition text; patched text; begin
    select pg_get_functiondef('public.attest_short_event337()'::regprocedure) into strict definition;
    patched:=replace(definition,$old$    if new.method ? '$file_packet' then return public.attest_file_action389(new); end if;
$old$,'');
    if patched=definition then raise exception 'file_action_intake389_rollback_trigger_shape' using errcode='55000'; end if;
    execute patched;
end $patch389$;
-- Existing accepted data survives rollback and remains subject to the ordinary
-- hot/cold partition retention. Only the new importer capability is removed.
drop function public.write_file_actions389(uuid,jsonb);
drop function public.attest_file_action389(public.event_hot);
drop function public.file_action_row389(uuid,integer);
drop function public.file_action_path389(text,text);
drop function public.verify_file_action_packet389(public.sli_agent_packet_inbox);
drop function public.file_action_canonical389(jsonb,integer);
drop table public.file_action_projection389;
delete from public.schema_migrations where version=389 and name='file_action_intake';
reset role;
commit;
