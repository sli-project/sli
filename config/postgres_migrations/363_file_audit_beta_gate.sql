begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_beta_gate363'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=362 and name='detection_event_clock')
       or exists(select 1 from public.schema_migrations where version>=363) then
        raise exception 'file_audit_beta_gate363_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Terminal refusal is separate from successful import. Existing evidence holds
-- and queue retention still apply; no module payload write privilege is added.
alter table public.sli_agent_packet_inbox add column module_disabled_at timestamptz;
alter table public.sli_agent_packet_inbox add constraint sli_agent_inbox_disabled363 check (
    module_disabled_at is null or
    (envelope->>'module_id' is not distinct from 'sli.file-audit' and imported_at is null));
grant update(module_disabled_at) on public.sli_agent_packet_inbox to adlog_user;

insert into public.schema_migrations(version,name) values(363,'file_audit_beta_gate');
reset role;
commit;
