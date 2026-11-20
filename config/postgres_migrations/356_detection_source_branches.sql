-- Keep the existing File Audit provenance branch reachable on short storage.
-- AD discovery still uses only importer-attested short events; do not consult
-- the retired-core fallback or summary when short storage is selected.
begin;
select pg_advisory_xact_lock(hashtext('sli_detection_source_branches356'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=351 and name='inbox_payload_retention')
       or exists(select 1 from public.schema_migrations where version>=356)
       or (select proowner from pg_proc where oid='public.default_detection_sources_before_v301()'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'detection_source_branches356_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.detection_source_definitions356(signature text primary key,definition text not null);
revoke all on public.detection_source_definitions356 from public,adlog_user,adlog_semantic_worker;
insert into public.detection_source_definitions356
select oid::regprocedure::text,pg_get_functiondef(oid) from pg_proc
where oid='public.default_detection_sources_before_v301()'::regprocedure;
do $patch356$
declare definition text; old_sql text; new_sql text;
begin
    select d.definition into strict definition from public.detection_source_definitions356 d;
    old_sql:=$old$    if public.detections_use_short337() then return query select * from public.short_detection_sources337(); return; end if;$old$;
    new_sql:=$new$    if public.detections_use_short337() then return query select * from public.short_detection_sources337(); end if;$new$;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'detection_source_branches356_shape' using errcode='55000';
    end if;
    definition:=replace(definition,old_sql,new_sql);
    old_sql:=$old$if not (select bootstrap_done from public.semantic_import_state320 where singleton) then$old$;
    new_sql:=$new$if not public.detections_use_short337() and not (select bootstrap_done from public.semantic_import_state320 where singleton) then$new$;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'detection_source_branches356_shape' using errcode='55000';
    end if;
    definition:=replace(definition,old_sql,new_sql);
    old_sql:=$old$where module.module_id in ('sli.windows.ad-dc','sli.vpn-nps') and t.source_instance_id=module.source_instance_id$old$;
    new_sql:=$new$where not public.detections_use_short337() and module.module_id in ('sli.windows.ad-dc','sli.vpn-nps') and t.source_instance_id=module.source_instance_id$new$;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'detection_source_branches356_shape' using errcode='55000';
    end if;
    definition:=replace(definition,old_sql,new_sql);
    execute definition;
end $patch356$;
insert into public.schema_migrations(version,name) values(356,'detection_source_branches');
reset role;
commit;
