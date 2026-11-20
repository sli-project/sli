begin;
select pg_advisory_xact_lock(hashtext('sli_short_entity_reads_v339'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=339 and name='short_entity_reads')
       or exists(select 1 from public.schema_migrations where version>339) then
        raise exception 'short_entity_reads_339_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop index public.event_hot_entity339;
drop index public.event_cold_facts_entity339;
drop index public.event_cold_daily_entity339;
drop function public.entity_event_keys339(integer);
drop function public.short_event_entity_keys339(integer,text,text,text,text,jsonb,jsonb);
drop function public.short_event_entity_links339(integer,text,text,text,text,jsonb,jsonb);
drop function public.short_entity_principal339(text,text,text,text);
delete from public.schema_migrations where version=339;
reset role;
commit;
