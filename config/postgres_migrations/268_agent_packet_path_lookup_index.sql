-- Add the exact core-verifier packet path access path; preserve native authority.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_packet_path_lookup_index_v268'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
           where version=267 and name='file_audit_discovery_join')
       or exists(select 1 from public.schema_migrations where version>=268) then
        raise exception 'migration 268 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
create index sli_agent_inbox_packet_path_index
    on public.sli_agent_packet_inbox (('agent-packet:'::text || packet_id::text));
insert into public.schema_migrations(version,name) values(268,'agent_packet_path_lookup_index');
commit;
