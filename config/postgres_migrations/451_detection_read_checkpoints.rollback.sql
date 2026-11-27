begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_detection_read_checkpoints451'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=451 and name='detection_read_checkpoints')
       or exists(select 1 from public.schema_migrations where version>451) then
        raise exception 'detection_read_checkpoints451_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    for saved in select * from public.detection_reader_restore451 loop
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
            and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
            raise exception 'detection_read_checkpoints451_rollback_metadata' using errcode='55000';
        end if;
        execute saved.definition;
    end loop;
end $$;

drop trigger complete_account_watch451 on public.semantic_account_watch_checks;
drop trigger complete_account_decoy451 on public.semantic_account_decoy_checks;
drop trigger catalog_detection_cold451 on public.event_cold_daily;
drop trigger catalog_detection_hot451 on public.event_hot;
drop function public.complete_account_checkpoint_event451();
drop function public.register_account_checkpoint451(text,text,jsonb);
drop function public.catalog_detection_event451();
drop function public.detection_catalog_witness451(regclass,jsonb,jsonb,boolean);
drop index public.event_cold_detection_witness451;
drop index public.event_hot_detection_witness451;
drop index public.event_hot_detection_normalized451;
drop index public.event_hot_detection_scope451;
drop table public.detection_reader_restore451,public.account_detection_pending451,
    public.account_detection_checkpoints451,public.detection_source_catalog451;
reset role;
delete from public.schema_migrations where version=451 and name='detection_read_checkpoints';
commit;
