begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_detection_read_checkpoints447'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=447 and name='detection_read_checkpoints')
       or exists(select 1 from public.schema_migrations where version>447) then
        raise exception 'detection_read_checkpoints447_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    for saved in select * from public.detection_reader_restore447 loop
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
            and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
            raise exception 'detection_read_checkpoints447_rollback_metadata' using errcode='55000';
        end if;
        execute saved.definition;
    end loop;
end $$;

drop trigger complete_account_watch447 on public.semantic_account_watch_checks;
drop trigger complete_account_decoy447 on public.semantic_account_decoy_checks;
drop trigger catalog_detection_cold447 on public.event_cold_daily;
drop trigger catalog_detection_hot447 on public.event_hot;
drop function public.complete_account_checkpoint_event447();
drop function public.register_account_checkpoint447(text,text,jsonb);
drop function public.catalog_detection_event447();
drop function public.detection_catalog_witness447(regclass,jsonb,jsonb,boolean);
drop index public.event_cold_detection_witness447;
drop index public.event_hot_detection_witness447;
drop index public.event_hot_detection_normalized447;
drop index public.event_hot_detection_scope447;
drop table public.detection_reader_restore447,public.account_detection_pending447,
    public.account_detection_checkpoints447,public.detection_source_catalog447;
reset role;
delete from public.schema_migrations where version=447 and name='detection_read_checkpoints';
commit;
