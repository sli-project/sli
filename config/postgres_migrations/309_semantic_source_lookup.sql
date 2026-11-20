-- Same source authority and bounded batches; avoid ordered scans of the core.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_source_lookup_v309'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=308 and name='semantic_review_row_lock')
       or exists(select 1 from public.schema_migrations where version>=309)
       or (select proowner from pg_catalog.pg_proc where oid='public.default_detection_sources_before_v301()'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_lookup_309_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- file_path is UNIQUE. A scalar lookup makes raw_log_file_id an index condition
-- before ORDER BY/LIMIT, including for packets without any retained core row.
-- CREATE OR REPLACE preserves owner, ACL, definer and fixed search_path.
do $patch$
declare definition text;
    old_sql text := $old$select e.log_source_id from public.raw_log_files raw
                join public.events_v2_core e on e.raw_log_file_id=raw.id
                where raw.file_path='agent-packet:'||witness.packet_id::text
                  and e.log_source_id is not null$old$;
    new_sql text := $new$select e.log_source_id from public.events_v2_core e
                where e.raw_log_file_id=(select raw.id from public.raw_log_files raw
                    where raw.file_path='agent-packet:'||witness.packet_id::text)
                  and e.log_source_id is not null$new$;
begin
    definition:=pg_get_functiondef('public.default_detection_sources_before_v301()'::regprocedure);
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_lookup_309_definition_mismatch' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
end $patch$;
-- Storage owner inherits the file-audit owner (migration183). Index ownership
-- stays with the table owner; no schema, role or data permissions are changed.
create index file_audit_discovery_stream_v309 on sli_plugin_file_audit.observations
    (agent_id,collection_scope_id,policy_revision,source_instance_id,generation);
create index file_audit_decoy_stream_v309 on sli_plugin_file_audit.observations
    (agent_id,source_instance_id,generation,observed_at,evidence_key)
    where event_id in (4656,5145,4663,4660,4670);
create index file_audit_context_window_v309 on sli_plugin_file_audit.observations
    (agent_id,source_instance_id,generation,policy_revision,observed_at,record_id);
insert into public.schema_migrations(version,name) values(309,'semantic_source_lookup');
reset role;
commit;
