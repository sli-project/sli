begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_detection_read_checkpoints449'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=449 and name='detection_read_checkpoints')
       or exists(select 1 from public.schema_migrations where version>449) then
        raise exception 'detection_read_checkpoints449_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    for saved in select * from public.detection_reader_restore449 loop
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
            and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
            raise exception 'detection_read_checkpoints449_rollback_metadata' using errcode='55000';
        end if;
        execute saved.definition;
    end loop;
end $$;

drop trigger complete_account_watch449 on public.semantic_account_watch_checks;
drop trigger complete_account_decoy449 on public.semantic_account_decoy_checks;
drop trigger catalog_detection_cold449 on public.event_cold_daily;
drop trigger catalog_detection_hot449 on public.event_hot;
drop function public.complete_account_checkpoint_event449();
drop function public.register_account_checkpoint449(text,text,jsonb);
drop function public.catalog_detection_event449();
drop function public.detection_catalog_witness449(regclass,jsonb,jsonb,boolean);
drop index public.event_cold_detection_witness449;
drop index public.event_hot_detection_witness449;
drop index public.event_hot_detection_normalized449;
drop index public.event_hot_detection_scope449;
drop table public.detection_reader_restore449,public.account_detection_pending449,
    public.account_detection_checkpoints449,public.detection_source_catalog449;
reset role;
delete from public.schema_migrations where version=449 and name='detection_read_checkpoints';
commit;
