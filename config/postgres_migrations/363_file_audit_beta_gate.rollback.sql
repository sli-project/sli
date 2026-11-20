begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_beta_gate363'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'file_audit_beta_gate363_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
revoke update(module_disabled_at) on public.sli_agent_packet_inbox from adlog_user;
alter table public.sli_agent_packet_inbox drop constraint sli_agent_inbox_disabled363;
alter table public.sli_agent_packet_inbox drop column module_disabled_at;
delete from public.schema_migrations where version=363 and name='file_audit_beta_gate';
reset role;
commit;
