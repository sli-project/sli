begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_short_cursor355'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'semantic_short_cursor355_rollback_role' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $patch355$ declare definition text; begin
    select pg_get_functiondef('public.semantic_import_notify320()'::regprocedure) into strict definition;
    execute replace(definition,$branch355$
    if tg_table_name='normalized_events' then -- semantic_short_cursor355
        insert into public.semantic_default_dirty320(agent_id,module_id)
        select distinct (e.source_origin->>'agent_id')::uuid,'sli.windows.ad-dc'
        from changed n join public.semantic_event_source355 e on e.id=n.source_event_id
        order by 1,2;
        return null;
    end if;
$branch355$,'');
end $patch355$;
drop view public.semantic_event_source355;
-- Existing decisions and jobs are data, and survive rollback.
delete from public.schema_migrations where version=355 and name='semantic_short_cursor';
reset role;
commit;
