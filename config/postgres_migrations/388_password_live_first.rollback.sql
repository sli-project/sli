begin;
select pg_advisory_xact_lock(hashtext('sli_password_live_first388'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=388 and name='password_live_first')
       or exists(select 1 from public.schema_migrations where version>388) then
        raise exception 'password_live_first388_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
lock table public.event_hot,public.event_cold_facts,public.event_cold_daily in share mode;
-- Keep durable generic evidence when the restored importer cannot interpret it.
do $$ begin
    if exists(select 1 from public.event_hot where method#>>'{$origin,plugin_id}'='sli.windows-eventlog')
       or exists(select 1 from public.event_cold_facts where method#>>'{$origin,plugin_id}'='sli.windows-eventlog')
       or exists(select 1 from public.event_cold_daily where method#>>'{$origin,plugin_id}'='sli.windows-eventlog') then
        raise exception 'generic_short_events388_rollback_has_history' using errcode='55000';
    end if;
end $$;
-- Do not discard a fork, audit record, checkpoint or proof to roll back code
-- unable to interpret it. Before first use rollback is exact and reversible.
do $$ declare r record; begin
    if exists(select 1 from public.password_passes388)
       or exists(select 1 from public.semantic_password_checkpoints where execution_json->'rule_version'>'2'::jsonb)
       or exists(select 1 from public.semantic_finding_publications group by finding_id having count(*)>1) then
        raise exception 'password_live_first388_rollback_has_history' using errcode='55000'; end if;
    for r in select * from public.password_restore388 loop
        if pg_get_functiondef(r.signature::regprocedure) is distinct from r.installed_definition
           or exists(select 1 from pg_proc where oid=r.signature::regprocedure
                and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_live_first388_rollback_changed' using errcode='55000'; end if;
        execute r.definition;
    end loop;
end $$;
drop function public.write_generic_short_events388(jsonb);
drop function public.generic_short_event_proof388(uuid,integer,bigint,timestamptz,integer,bigint,jsonb);
alter table public.semantic_finding_publications add constraint semantic_finding_publications_finding_id_key unique(finding_id);
alter table public.semantic_finding_publications add constraint semantic_finding_publications_finding_fingerprint_key unique(finding_fingerprint);
drop index public.password_publication_finding388;
drop index public.password_finding_entity388;
drop function public.password_catchup_status388();
drop function public.password_is_catchup388(jsonb);
drop function public.password_plan388(jsonb,text);
drop function public.password_execution388(jsonb,text,integer);
drop table public.password_passes388;
drop function public.password_pass_immutable388();
drop table public.password_restore388;
delete from public.schema_migrations where version=388 and name='password_live_first';
reset role;
commit;
