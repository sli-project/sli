begin;
select pg_advisory_xact_lock(hashtext('sli_file_permissions_opt_in405'));
set local role adlog_storage_owner;
do $$ declare rec record; begin
    if exists(select 1 from public.schema_migrations where version>405) then
        raise exception 'file_permissions_opt_in405_rollback_preflight' using errcode='55000';
    end if;
    for rec in select * from public.file_permissions_restore405 loop
        if pg_get_functiondef(rec.signature) is distinct from rec.installed_definition then
            raise exception 'file_permissions_opt_in405_rollback_definition_changed' using errcode='55000';
        end if;
        execute rec.definition;
    end loop;
end $$;
drop table public.file_permissions_restore405;
drop function public.file_permissions_allowed405(uuid,text,text,boolean);
delete from public.schema_migrations where version=405 and name='file_permissions_opt_in';
reset role;
commit;
