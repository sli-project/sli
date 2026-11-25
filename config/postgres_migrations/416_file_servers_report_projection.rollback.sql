begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_file_servers_report416'));
do $$ begin
    if exists(select 1 from public.schema_migrations where version>416)
       or not exists(select 1 from public.schema_migrations where version=416 and name='file_servers_report_projection') then
        raise exception 'file_servers_report416_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.read_file_audit_snapshot416(jsonb,uuid,timestamptz,text);
drop function public.read_file_audit_objects416(jsonb,uuid,timestamptz,text,boolean,text,text,jsonb,integer);
reset role;
set local role adlog_file_audit_owner;
do $$ declare saved record; begin
    for saved in select * from sli_plugin_file_audit.report_restore416 loop
        if pg_get_functiondef(saved.signature) is distinct from saved.installed_definition then
            raise exception 'file_servers_report416_rollback_reader_changed' using errcode='55000';
        end if;
        execute saved.definition;
    end loop;
end $$;
drop table sli_plugin_file_audit.report_restore416;
reset role;
delete from public.schema_migrations where version=416 and name='file_servers_report_projection';
commit;
