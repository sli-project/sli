begin;
select pg_advisory_xact_lock(hashtext('sli_disabled_module_intake380'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'disabled_module_intake380_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
alter table public.sli_agent_packet_inbox drop constraint sli_agent_inbox_disabled363;
-- Restore pending status for modules unsupported by the old marker constraint.
update public.sli_agent_packet_inbox set module_disabled_at=null
where envelope->>'module_id' is distinct from 'sli.file-audit' and module_disabled_at is not null;
alter table public.sli_agent_packet_inbox add constraint sli_agent_inbox_disabled363 check (
    module_disabled_at is null or
    (envelope->>'module_id' is not distinct from 'sli.file-audit' and imported_at is null));
drop function public.agent_module_enabled_v380(text);
delete from public.schema_migrations where version=380 and name='disabled_module_intake';
reset role;
commit;
