begin;
select pg_advisory_xact_lock(hashtext('sli_password_queue_projection399'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=399 and name='password_queue_projection')
       or exists(select 1 from public.schema_migrations where version>399) then
        raise exception 'password_queue_projection399_rollback_preflight' using errcode='55000';
    end if;
end $$;

drop trigger invalidate_password_queue_insert399 on public.finding_event_copies337;
drop trigger invalidate_password_queue_update399 on public.finding_event_copies337;
drop trigger invalidate_password_queue_delete399 on public.finding_event_copies337;
drop trigger truncate_password_queue_evidence399 on public.finding_event_copies337;
do $$ declare relation_name text; begin
    foreach relation_name in array array['domains','ad_context_runs','ad_context_entity_aliases','ad_context_entity_versions','ad_context_sections'] loop
        execute format('drop trigger invalidate_password_queue_context399 on public.%I',relation_name);
        execute format('drop trigger truncate_password_queue_context399 on public.%I',relation_name);
    end loop;
end $$;

set local role adlog_storage_owner;
do $$ declare previous public.password_queue_scope_restore399%rowtype; begin
    select * into strict previous from public.password_queue_scope_restore399;
    if not exists(select 1 from pg_proc p where p.oid='public.semantic_finding_in_domains_v265(bigint,bigint[])'::regprocedure
        and pg_get_functiondef(p.oid)=previous.installed_definition and p.proowner=previous.owner_oid
        and p.proacl is not distinct from previous.acl) then
        raise exception 'password_queue_projection399_rollback_scope_changed';
    end if;
    execute previous.definition;
end $$;

drop function public.password_queue_presentation399(bigint,text);
drop function public.refresh_stale_password_queue399();
drop function public.refresh_password_queue_presentation399(bigint);
drop function public.password_queue_projection_current399(public.password_queue_projection399,uuid,uuid[]);
drop function public.password_queue_context_current399(jsonb);
drop function public.password_queue_source_resets399();
drop function public.record_password_queue_source_reset399();
drop function public.invalidate_password_queue_context399();
drop function public.invalidate_password_queue_evidence399();
drop table public.password_queue_projection399;
drop table public.password_queue_evidence_versions399;
drop table public.password_queue_source_resets399;
drop table public.password_queue_context399;
drop table public.password_queue_scope_restore399;
drop index public.finding_event_copy_scope399;
delete from public.schema_migrations where version=399 and name='password_queue_projection';
reset role;
commit;
