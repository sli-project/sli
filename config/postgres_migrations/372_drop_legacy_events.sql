-- Retire the former event store. Rollback restores DDL only, NEVER event data.
begin;
select pg_advisory_xact_lock(hashtext('sli_drop_legacy_events372'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=371)
       or exists(select 1 from public.schema_migrations where version>=372) then
        raise exception 'drop_legacy_events372_preflight' using errcode='55000';
    end if;
end $$;
-- Freeze relation DDL while collecting rollback definitions and dependencies.
-- Waiting for an active writer has no new time limit.
lock table public.events_v2_core,public.event_facts_v2,public.event_entity_link_blocks_v2 in access exclusive mode;
-- raw_log_files and its sequence belong to the migration login (sli_migration) on
-- installed systems, not to adlog_storage_owner: lock them as the installer session.
reset role;
lock table public.raw_log_files in access exclusive mode;
set local role adlog_storage_owner;
create table public.legacy_event_rollback372(
    ordinal bigint generated always as identity primary key,phase integer not null,statement text not null);
revoke all on public.legacy_event_rollback372 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker,
    adlog_storage_lifecycle_worker,adlog_storage_lifecycle_delete,adlog_storage_lifecycle_guard;

-- Explicit reviewed functions are populated below. Unknown dependencies abort
-- this transaction; no DROP CASCADE can silently remove a neighboring feature.
create table public.legacy_functions372(signature text primary key,remove boolean not null);
insert into legacy_functions372 values
    ('public.write_process_episode_revision_v89(jsonb)',true),
    ('public.semantic_finding_review_v160(bigint)',false),
    ('public.semantic_finding_suppressed_v160(bigint,text)',false),
    ('public.read_agent_semantic_source_v190(bigint)',true),
    ('public.resolve_finding_evidence_ref_before_v301(uuid,text,text,text,text,text,text,text)',false),
    ('public.link_finding_evidence_ref(bigint,uuid,text,text,text,text,text,text,text)',false),
    ('public.read_nps_threshold_events(uuid,text,text,text,timestamp with time zone,timestamp with time zone)',true),
    ('public.nps_threshold_window_quality(uuid,text,text,text,timestamp with time zone,timestamp with time zone,timestamp with time zone)',true),
    ('public.read_account_decoy_events(uuid,text,text,text,text,uuid)',false),
    ('public.read_account_watch_events(uuid,text,text,text,text,uuid)',false),
    ('public.default_detection_sources_before_v301()',false),
    ('public.read_default_password_events(jsonb)',false),
    ('public.read_admitted_sigma_events(jsonb,bigint)',true),
    ('public.semantic_finding_in_domains_v262(bigint,bigint[])',false),
    ('public.semantic_finding_in_domains_v265(bigint,bigint[])',false),
    ('public.read_default_password_window_v2(jsonb)',false),
    ('public.read_password_retained_proof_v2(jsonb,jsonb)',false),
    ('public.password_v2_native_cost(jsonb,jsonb)',false),
    ('public.event_source_packet_v284(bigint)',true),
    ('public.report_security_candidate_counts(jsonb,text,timestamp with time zone,timestamp with time zone)',false),
    ('public.read_identity_attack_events_v301(jsonb,bigint[])',false),
    ('public.t109_detection_sources()',false),
    ('public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)',false),
    ('public.read_t109_native(jsonb,timestamp with time zone,timestamp with time zone)',false),
    ('public.lock_storage_lifecycle_tables_v319(text)',false),
    ('public.lock_storage_lifecycle_events_v319(bigint[])',true),
    ('public.lock_storage_lifecycle_facts_v319(bigint[])',true),
    ('public.semantic_import_notify320()',true),
    ('public.semantic_import_refresh320()',true),
    ('public.semantic_default_refresh320()',true),
    ('public.semantic_default_full320()',true),
    ('public.semantic_t109_full320()',true),
    ('public.semantic_import_progress320()',true),
    ('public.semantic_source_candidates320(uuid,jsonb,text,text,timestamp with time zone,timestamp with time zone,uuid)',true),
    ('public.storage_lifecycle_evidence_v321(bigint,bigint,integer[],text,text)',true),
    ('public.semantic_backfill_window_v332(bigint,integer,text,text)',true),
    ('public.detections_use_short337()',true),
    ('public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)',false),
    ('public.copy_linked_finding_event337()',false);

create table public.legacy_tables372(oid oid primary key,depth integer not null);
insert into legacy_tables372
with recursive tables(oid,depth) as (
    select name::regclass::oid,0 from unnest(array['public.events_v2_core','public.event_facts_v2',
        'public.event_entity_link_blocks_v2','public.raw_log_files']) name
    union all select i.inhrelid,t.depth+1 from tables t join pg_inherits i on i.inhparent=t.oid
) select oid,max(depth) from tables group by oid;

-- prosrc is necessary for PL/pgSQL and string-bodied SQL: PostgreSQL does not
-- record all of their relation references in pg_depend. Include row-type and
-- view dependencies, and recheck after replacing the public entry points.
do $$ declare unexpected text; begin
    select string_agg(p.oid::regprocedure::text,', ' order by p.oid::regprocedure::text) into unexpected
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname not in ('pg_catalog','information_schema') and n.nspname !~ '^pg_(temp|toast)'
      and (p.prosrc ~* '\m(events_v2_core|event_facts_v2|event_entity_link_blocks_v2|raw_log_files|event_entity_links_v2|detections_use_short337)\M'
        or exists(select 1 from pg_depend d where d.classid='pg_proc'::regclass and d.objid=p.oid
          and ((d.refclassid='pg_class'::regclass and d.refobjid in(select oid from legacy_tables372))
            or (d.refclassid='pg_type'::regclass and d.refobjid in(
                select reltype from pg_class where oid in(select oid from legacy_tables372))))))
      and not exists(select 1 from legacy_functions372 f where to_regprocedure(f.signature)=p.oid);
    if unexpected is not null then
        raise exception 'drop_legacy_events372_unreviewed_function: %',unexpected using errcode='55000';
    end if;
    if exists(select 1 from legacy_functions372 where to_regprocedure(signature) is null) then
        raise exception 'drop_legacy_events372_missing_function' using errcode='55000';
    end if;
    if exists(select 1 from pg_depend d join pg_rewrite r on d.classid='pg_rewrite'::regclass and d.objid=r.oid
        where d.refclassid='pg_class'::regclass and d.refobjid in(select oid from legacy_tables372)
          and r.ev_class<>'public.event_entity_links_v2'::regclass) then
        raise exception 'drop_legacy_events372_unreviewed_view' using errcode='55000';
    end if;
    if exists(select 1 from pg_constraint c where c.contype='f' and c.conparentid=0
        and c.confrelid in(select oid from legacy_tables372) and c.conrelid not in(select oid from legacy_tables372)
        and (c.conrelid::regclass::text,c.conname) not in (
            ('detections','detections_primary_event_id_v2_fkey'),
            ('event_links','event_links_source_event_id_v2_fkey'),('event_links','event_links_target_event_id_v2_fkey'),
            ('finding_evidence','finding_evidence_event_id_v2_fkey'),
            ('source_capture_continuity_declarations','source_capture_continuity_declarations_raw_log_file_id_fkey'))) then
        raise exception 'drop_legacy_events372_unreviewed_foreign_key' using errcode='55000';
    end if;
end $$;

-- The private journal contains catalog DDL only. It preserves installed
-- function definitions/owners/ACLs, including changes on upgraded databases.
insert into public.legacy_event_rollback372(phase,statement)
select 50,pg_get_functiondef(p.oid) from legacy_functions372 f join pg_proc p on p.oid=f.signature::regprocedure;
insert into public.legacy_event_rollback372(phase,statement)
select 51,format('alter function %s owner to %I',p.oid::regprocedure,pg_get_userbyid(p.proowner))
from legacy_functions372 f join pg_proc p on p.oid=f.signature::regprocedure;
insert into public.legacy_event_rollback372(phase,statement)
select 52,format($ddl$do $clear$ declare a record; begin
    for a in select distinct grantee from pg_proc p cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner)))
        where p.oid=%L::regprocedure loop
        execute format('revoke all on function %%s from %%s',%L,
            case when a.grantee=0 then 'public' else quote_ident(pg_get_userbyid(a.grantee)) end);
    end loop;
end $clear$$ddl$,p.oid::regprocedure::text,p.oid::regprocedure::text)
from legacy_functions372 f join pg_proc p on p.oid=f.signature::regprocedure;
insert into public.legacy_event_rollback372(phase,statement)
select 53,format('grant %s on function %s to %s%s',a.privilege_type,p.oid::regprocedure,
    case when a.grantee=0 then 'public' else quote_ident(pg_get_userbyid(a.grantee)) end,
    case when a.is_grantable then ' with grant option' else '' end)
from legacy_functions372 f join pg_proc p on p.oid=f.signature::regprocedure
cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a;

-- Snapshot empty table DDL, not table rows. Include any installed partitions,
-- their indexes, column grants and triggers, without retaining event payloads.
insert into public.legacy_event_rollback372(phase,statement)
select 10,format('create sequence %s as %s increment by %s minvalue %s maxvalue %s start with %s cache %s %s',
    c.oid::regclass,format_type(s.seqtypid,null),s.seqincrement,s.seqmin,s.seqmax,s.seqstart,s.seqcache,
    case when s.seqcycle then 'cycle' else 'no cycle' end)
from pg_class c join pg_sequence s on s.seqrelid=c.oid
where exists(select 1 from pg_depend d where d.classid='pg_class'::regclass and d.objid=c.oid
    and d.refclassid='pg_class'::regclass and d.refobjid in(select oid from legacy_tables372) and d.deptype in ('a','i'));
reset role;
do $$ declare item record; value bigint; called boolean; begin
    for item in select c.oid from pg_class c where c.relkind='S' and exists(
        select 1 from pg_depend d where d.classid='pg_class'::regclass and d.objid=c.oid
          and d.refclassid='pg_class'::regclass and d.refobjid in(select oid from legacy_tables372) and d.deptype in ('a','i')) loop
        execute format('select last_value,is_called from %s',item.oid::regclass) into value,called;
        insert into public.legacy_event_rollback372(phase,statement)
            values(11,format('select pg_catalog.setval(%L,%s,%L)',item.oid::regclass::text,value,called));
    end loop;
end $$;
set local role adlog_storage_owner;
insert into public.legacy_event_rollback372(phase,statement)
select 20+t.depth,case when c.relispartition then
    format('create table %s partition of %s %s%s',c.oid::regclass,
        (select inhparent::regclass from pg_inherits where inhrelid=c.oid),pg_get_expr(c.relpartbound,c.oid),
        case when c.relkind='p' then ' partition by '||pg_get_partkeydef(c.oid) else '' end)
    else format('create table %s (%s)%s',c.oid::regclass,
        (select string_agg(format('%I %s%s%s',a.attname,format_type(a.atttypid,a.atttypmod),
            case when d.adbin is null then '' else ' default '||pg_get_expr(d.adbin,d.adrelid) end,
            case when a.attnotnull then ' not null' else '' end),',' order by a.attnum)
         from pg_attribute a left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum
         where a.attrelid=c.oid and a.attnum>0 and not a.attisdropped),
        case when c.relkind='p' then ' partition by '||pg_get_partkeydef(c.oid) else '' end) end
from legacy_tables372 t join pg_class c on c.oid=t.oid order by t.depth,c.oid;
insert into public.legacy_event_rollback372(phase,statement)
select 30,format('alter table %s owner to %I',c.oid::regclass,pg_get_userbyid(c.relowner))
from legacy_tables372 t join pg_class c on c.oid=t.oid;
insert into public.legacy_event_rollback372(phase,statement)
select 32,format('alter table %s set (%s)',c.oid::regclass,array_to_string(c.reloptions,','))
from legacy_tables372 t join pg_class c on c.oid=t.oid where c.reloptions is not null;
insert into public.legacy_event_rollback372(phase,statement)
select 31,format('alter sequence %s owner to %I; alter sequence %s owned by %s.%I',
    c.oid::regclass,pg_get_userbyid(c.relowner),c.oid::regclass,d.refobjid::regclass,a.attname)
from pg_class c join pg_depend d on d.classid='pg_class'::regclass and d.objid=c.oid and d.deptype in ('a','i')
join pg_attribute a on a.attrelid=d.refobjid and a.attnum=d.refobjsubid
where c.relkind='S' and d.refclassid='pg_class'::regclass and d.refobjid in(select oid from legacy_tables372);
insert into public.legacy_event_rollback372(phase,statement)
select case when c.contype='f' then 41 else 40 end,
    format('alter table %s add constraint %I %s%s',c.conrelid::regclass,c.conname,pg_get_constraintdef(c.oid),
        -- The referenced old rows are deliberately gone. Retained references
        -- remain intact; NOT VALID still enforces every future write.
        case when c.contype='f' and c.convalidated and c.conrelid not in(select oid from legacy_tables372)
             then ' not valid' else '' end)
from pg_constraint c where c.contype in ('p','u','c','f','x') and c.conparentid=0 and c.conislocal
    and (c.conrelid in(select oid from legacy_tables372)
        or c.contype='f' and c.confrelid in(select oid from legacy_tables372));
insert into public.legacy_event_rollback372(phase,statement)
select 42,pg_get_indexdef(i.indexrelid) from pg_index i where i.indrelid in(select oid from legacy_tables372)
    and not exists(select 1 from pg_constraint c where c.conindid=i.indexrelid);
insert into public.legacy_event_rollback372(phase,statement)
select 43,format('alter index %s attach partition %s',h.inhparent::regclass,h.inhrelid::regclass)
from pg_inherits h join pg_index i on i.indexrelid=h.inhrelid where i.indrelid in(select oid from legacy_tables372);
insert into public.legacy_event_rollback372(phase,statement)
select 60,format('create view %s%s as %s',c.oid::regclass,
    case when c.reloptions is null then '' else ' with ('||array_to_string(c.reloptions,',')||')' end,pg_get_viewdef(c.oid))
from pg_class c where c.oid='public.event_entity_links_v2'::regclass;
insert into public.legacy_event_rollback372(phase,statement)
select 61,format('alter view %s owner to %I',c.oid::regclass,pg_get_userbyid(c.relowner))
from pg_class c where c.oid='public.event_entity_links_v2'::regclass;
insert into public.legacy_event_rollback372(phase,statement)
select 70,pg_get_triggerdef(t.oid) from pg_trigger t where not t.tgisinternal
    and (t.tgrelid in(select oid from legacy_tables372)
        or t.tgfoid in(select signature::regprocedure from legacy_functions372 where remove));
insert into public.legacy_event_rollback372(phase,statement)
select 71,format('alter table %s %s trigger %I',t.tgrelid::regclass,
    case t.tgenabled when 'D' then 'disable' when 'R' then 'enable replica' when 'A' then 'enable always' else 'enable' end,t.tgname)
from pg_trigger t where not t.tgisinternal and (t.tgrelid in(select oid from legacy_tables372)
    or t.tgfoid in(select signature::regprocedure from legacy_functions372 where remove));
-- Clear any current default grants before replaying exact installed ACLs.
-- A role added to ALTER DEFAULT PRIVILEGES after 371 must not gain old data
-- access merely because an administrator rolls back this migration.
insert into public.legacy_event_rollback372(phase,statement)
select 79,format($ddl$do $clear$ declare a record; begin
    for a in select distinct grantee from pg_class c cross join lateral aclexplode(c.relacl)
        where c.oid=%L::regclass loop
        execute format('revoke all on %s %%s from %%s',%L,
            case when a.grantee=0 then 'public' else quote_ident(pg_get_userbyid(a.grantee)) end);
    end loop;
end $clear$$ddl$,c.oid::regclass::text,case when c.relkind='S' then 'sequence' else 'table' end,c.oid::regclass::text)
from pg_class c where c.oid in(select oid from legacy_tables372) or c.oid='public.event_entity_links_v2'::regclass
    or c.relkind='S' and exists(select 1 from pg_depend d where d.classid='pg_class'::regclass and d.objid=c.oid
        and d.refclassid='pg_class'::regclass and d.refobjid in(select oid from legacy_tables372) and d.deptype in ('a','i'));
insert into public.legacy_event_rollback372(phase,statement)
select 80,format('grant %s on %s %s to %s%s',a.privilege_type,
    case when c.relkind='S' then 'sequence' else 'table' end,c.oid::regclass,
    case when a.grantee=0 then 'public' else quote_ident(pg_get_userbyid(a.grantee)) end,
    case when a.is_grantable then ' with grant option' else '' end)
from pg_class c cross join lateral aclexplode(coalesce(c.relacl,acldefault(case when c.relkind='S' then 'S'::"char" else 'r'::"char" end,c.relowner))) a
where c.oid in(select oid from legacy_tables372) or c.oid='public.event_entity_links_v2'::regclass
    or c.oid in(select objid from pg_depend where classid='pg_class'::regclass and refclassid='pg_class'::regclass
        and refobjid in(select oid from legacy_tables372) and deptype in ('a','i')) and c.relkind='S';
insert into public.legacy_event_rollback372(phase,statement)
select 81,format('grant %s (%I) on table %s to %s%s',acl.privilege_type,a.attname,a.attrelid::regclass,
    case when acl.grantee=0 then 'public' else quote_ident(pg_get_userbyid(acl.grantee)) end,
    case when acl.is_grantable then ' with grant option' else '' end)
from pg_attribute a cross join lateral aclexplode(a.attacl) acl where a.attrelid in(select oid from legacy_tables372);

-- The 362 password finalizer branched on detections_use_short337(). Event time
-- is now the only clock, so recreate it without that call before the drop. The
-- journal above already holds the 362 definition for rollback.
do $$ declare definition text; begin
    select pg_get_functiondef('public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure) into strict definition;
    definition:=regexp_replace(definition,'\(case when public\.detections_use_short337\(\) and t<c\.last_attempt_at then t is distinct from public\.password_event_clock362\(s,execution\)\s+else t<c\.last_attempt_at end\)',
        '(t<c.last_attempt_at and t is distinct from public.password_event_clock362(s,execution))');
    if strpos(definition,'detections_use_short337')>0 then
        raise exception 'drop_legacy_events372_finalizer_shape' using errcode='55000'; end if;
    execute definition;
end $$;

CREATE OR REPLACE FUNCTION public.read_identity_attack_events_v301(s jsonb, p_refs bigint[] DEFAULT NULL::bigint[])
 RETURNS TABLE(source_event_id bigint, event_id integer, occurred_at_utc timestamp with time zone, sha256 text, source_xml text)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return query select * from public.read_identity_attack_events_v301_short337(s,p_refs);
end $function$;

CREATE OR REPLACE FUNCTION public.read_default_password_events(s jsonb)
 RETURNS TABLE(source_event_id bigint, event_id integer, occurred_at_utc timestamp with time zone, sha256 text, source_xml text)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return query select * from public.read_default_password_events_short337(s);
end $function$;

CREATE OR REPLACE FUNCTION public.read_default_password_window_v2(s jsonb)
 RETURNS TABLE(record_kind text, metadata jsonb, source_event_id bigint, event_id integer, occurred_at_utc timestamp with time zone, sha256 text, source_xml text)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return query select * from public.read_default_password_window_v2_short337(s);
end $function$;

CREATE OR REPLACE FUNCTION public.read_password_retained_proof_v2(s jsonb, occurrences jsonb)
 RETURNS TABLE(occurrence_index integer, source_event_id bigint, event_id integer, occurred_at_utc timestamp with time zone, sha256 text, source_xml text, xml_bytes integer, xml_sha256 text)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return query select * from public.read_password_retained_proof_v2_short337(s,occurrences);
end $function$;

CREATE OR REPLACE FUNCTION public.password_v2_native_cost(s jsonb, occurrences jsonb)
 RETURNS bigint
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return public.password_v2_native_cost_short337(s,occurrences);
end $function$;

CREATE OR REPLACE FUNCTION public.read_account_decoy_events(p_installation uuid, p_plugin text, p_source text, p_generation text, p_checkpoint text, p_normalized uuid)
 RETURNS TABLE(normalized_event_id uuid, source_event_id bigint, event_id integer, semantic_type text, occurred_at_utc timestamp with time zone, roles_json jsonb, quality_json jsonb, sha256 text, labels jsonb, identities jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return query select * from public.read_account_decoy_events_short337(p_installation,p_plugin,p_source,p_generation,p_checkpoint,p_normalized);
end $function$;

CREATE OR REPLACE FUNCTION public.read_account_watch_events(p_installation uuid, p_plugin text, p_source text, p_generation text, p_checkpoint text, p_normalized uuid)
 RETURNS TABLE(normalized_event_id uuid, source_event_id bigint, event_id integer, semantic_type text, occurred_at_utc timestamp with time zone, roles_json jsonb, quality_json jsonb, sha256 text, entries jsonb, identities jsonb, event_item jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return query select * from public.read_account_watch_events_short337(p_installation,p_plugin,p_source,p_generation,p_checkpoint,p_normalized);
end $function$;

CREATE OR REPLACE FUNCTION public.t109_detection_sources()
 RETURNS TABLE(source jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return query select * from public.short_detection_sources337();
end $function$;

CREATE OR REPLACE FUNCTION public.read_t109_native(s jsonb, p_start timestamp with time zone DEFAULT NULL::timestamp with time zone, p_end timestamp with time zone DEFAULT NULL::timestamp with time zone)
 RETURNS TABLE(native_id text, event_id integer, occurred_at_utc timestamp with time zone, sha256 text, source_xml text, collection_scope_id text, document jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    return query select * from public.short_t109_events337(s,p_start,p_end);
end $function$;

CREATE OR REPLACE FUNCTION public.default_detection_sources_before_v301()
 RETURNS TABLE(source jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
declare login oid; installation uuid;
begin
    return query select * from public.short_detection_sources337();
    select oid into strict login from pg_catalog.pg_roles where rolname=session_user;
    select installation_id into strict installation from public.semantic_default_installation;
    insert into public.finding_evidence_source_bindings
        (principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
         collection_scope_id,storage_kind,agent_id)
    select distinct login,session_user,installation,'sli.file-audit',o.source_instance_id,o.generation,
           root->>'collection_scope_id','file_audit_observation',agent.id
    from public.sli_agents agent
    cross join lateral jsonb_array_elements(agent.assigned_modules) m
    cross join lateral jsonb_array_elements(m#>'{config,roots}') root
    cross join lateral public.file_audit_discovery_witness_v267(
        agent.id,root->>'collection_scope_id',coalesce(m#>>'{config,policy_revision}','1')::bigint) o
    where agent.status='active' and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb
      and not exists(select 1 from public.finding_evidence_source_bindings b
          where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.file-audit'
            and b.source_instance_id=o.source_instance_id and b.source_generation=o.generation
            and b.collection_scope_id=root->>'collection_scope_id' and b.storage_kind='file_audit_observation')
    on conflict do nothing;

    return query
    select jsonb_build_object('scope',jsonb_build_object('installation_id',b.installation_id::text,
        'plugin_id',b.plugin_id,'source_instance_id',b.source_instance_id,
        'source_generation',b.source_generation,'collection_scope_id',b.collection_scope_id),
        'agent_id',b.agent_id::text,'config',coalesce(m->'config','{}'::jsonb))
        || case when b.storage_kind='file_audit_observation' then
            jsonb_build_object('ransom_policy',jsonb_build_object('state',case when exists(
                select 1 from sli_plugin_file_audit.policy_revisions policy
                where policy.agent_id=b.agent_id
                  and policy.source_instance_id=b.source_instance_id
                  and policy.revision::text=coalesce(m#>>'{config,policy_revision}','1')
                  -- Legacy retained JSON is object-shaped but its fields may be malformed.
                  -- Never cast it in global discovery: one bad policy cannot hide
                  -- unrelated sources. Only bounded canonical assigned values parse.
                  and case when coalesce(m#>>'{config,mass_operation_files}','100') ~ '^[1-9][0-9]{0,6}$'
                      then coalesce(m#>>'{config,mass_operation_files}','100')::integer between 1 and 1000000
                      else false end
                  and case when coalesce(m#>>'{config,mass_operation_seconds}','300') ~ '^[1-9][0-9]{0,4}$'
                      then coalesce(m#>>'{config,mass_operation_seconds}','300')::integer between 1 and 86400
                      else false end
                  and coalesce(policy.policy->>'mass_operation_files','100')
                      =coalesce(m#>>'{config,mass_operation_files}','100')
                  and coalesce(policy.policy->>'mass_operation_seconds','300')
                      =coalesce(m#>>'{config,mass_operation_seconds}','300')
            ) then 'ready' else 'waiting' end)) else '{}'::jsonb end
    from public.finding_evidence_source_bindings b
    join public.sli_agents agent on agent.id=b.agent_id and agent.status='active'
    cross join lateral jsonb_array_elements(agent.assigned_modules) m
    where b.principal_oid=login and b.principal_name=session_user
      and m->>'module_id'=b.plugin_id and m->'enabled'='true'::jsonb
      and b.storage_kind='file_audit_observation'
      and exists(select 1 from jsonb_array_elements(m#>'{config,roots}') root
          where root->>'collection_scope_id'=b.collection_scope_id)
    order by b.plugin_id,b.source_instance_id,b.source_generation,b.collection_scope_id limit 128;
end $function$
;

CREATE OR REPLACE FUNCTION public.resolve_finding_evidence_ref_before_v301(p_installation uuid, p_plugin text, p_source text, p_generation text, p_collection text, p_kind text, p_native text, p_sha256 text)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
declare b public.finding_evidence_source_bindings%rowtype;
begin
    if p_sha256 is null or p_sha256 !~ '^[a-f0-9]{64}$' or p_native is null then return false; end if;
    select a.* into b from public.finding_evidence_source_bindings a join pg_catalog.pg_roles r
        on r.oid=a.principal_oid and r.rolname=a.principal_name
        where r.rolname=session_user and a.installation_id=p_installation and a.plugin_id=p_plugin
          and a.source_instance_id=p_source and a.source_generation=p_generation
          and a.collection_scope_id=p_collection and a.storage_kind=p_kind;
    if not found then return false; end if;
    if p_kind='file_audit_snapshot' then
        if p_native !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
           or p_plugin<>'sli.file-audit' or p_collection='' then return false; end if;
        return exists(select 1 from public.file_audit_snapshot_provenance_v264(b.agent_id,p_native::uuid) provenance
            where provenance->>'command_id'=substring(p_generation from 15)
              and provenance->>'snapshot_sha256'=p_sha256
              and provenance->>'source_instance_id'=p_source
              and provenance->>'collection_scope_id'=p_collection);
    elsif p_kind='workstation_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_workstations.observations o
            where o.id=p_native and o.agent_key=b.agent_key and o.observation_sha256=p_sha256
              and o.observation->>'generation'=p_generation and o.observation->>'agent_key'=b.agent_key
              and encode(sha256(convert_to(o.source_xml,'UTF8')),'hex')=o.observation->>'source_sha256');
    elsif p_kind='file_audit_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_file_audit.observations o
            where o.evidence_key=p_native and public.agent_source_identity_v296(o.agent_id)=b.agent_id and o.source_instance_id=p_source
              and o.generation=p_generation and o.payload_sha256=p_sha256
              and o.normalized->>'payload_sha256'=p_sha256 and o.normalized->>'evidence_key'=p_native
              and (o.collection_scope_id=p_collection
                   or public.file_ransom_evidence_in_root(o.agent_id,p_source,p_collection,p_native)
                   or public.file_decoy_evidence_in_root(o.agent_id,p_source,p_generation,p_collection,p_native)));
    end if;
    return false;
end $function$
;

CREATE OR REPLACE FUNCTION public.resolve_finding_evidence_ref(p_installation uuid, p_plugin text, p_source text, p_generation text, p_collection text, p_kind text, p_native text, p_sha256 text)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    if p_kind='core_event' then
        return public.short_ref_allowed337(jsonb_build_object('installation_id',p_installation::text,'plugin_id',p_plugin,
            'source_instance_id',p_source,'source_generation',p_generation,'collection_scope_id',p_collection),p_native,p_sha256);
    end if;
    return public.resolve_finding_evidence_ref_before_t109(p_installation,p_plugin,p_source,p_generation,
        p_collection,p_kind,p_native,p_sha256);
end $function$;

CREATE OR REPLACE FUNCTION public.link_finding_evidence_ref(p_finding bigint, p_installation uuid, p_plugin text, p_source text, p_generation text, p_collection text, p_kind text, p_native text, p_sha256 text)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
declare v_added boolean; v_count bigint; v_existing text;
begin
    if public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,p_collection,
            p_kind,p_native,p_sha256) is not true then
        raise exception 'evidence_unavailable_or_denied' using errcode='42501';
    end if;
    insert into public.finding_evidence_refs(finding_id,installation_id,plugin_id,source_instance_id,
        source_generation,collection_scope_id,storage_kind,native_id,sha256)
    values(p_finding,p_installation,p_plugin,p_source,p_generation,p_collection,p_kind,p_native,p_sha256)
    on conflict do nothing;
    get diagnostics v_count = row_count;
    v_added := v_count>0;
    select sha256 into strict v_existing from public.finding_evidence_refs
        where finding_id=p_finding and installation_id=p_installation and plugin_id=p_plugin
          and source_instance_id=p_source and source_generation=p_generation and collection_scope_id=p_collection
          and storage_kind=p_kind and native_id=p_native and evidence_role='semantic_scenario';
    if v_existing is distinct from p_sha256 then
        raise exception 'evidence_hash_conflict';
    end if;
    if p_kind='core_event' then
            v_added:=public.copy_finding_event337(p_finding,p_native,p_sha256,'semantic_scenario','enabled semantic scenario evidence');
            return v_added;
        end if;
    return v_added;
end $function$
;

CREATE OR REPLACE FUNCTION public.semantic_finding_in_domains_v265(p_finding bigint, p_domains bigint[])
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
declare allowed boolean;
begin
    with native_domains as materialized (
      select scopes.*,case when count(distinct b.agent_id)=1 then min(b.agent_id::text)::uuid end as agent_id,
        case when count(distinct server.domain_id)=1 and bool_and(server.domain_id is not null) then min(server.domain_id) end as domain_id
      from (select distinct installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind
        from public.finding_evidence_refs where finding_id=p_finding and storage_kind not in ('core_event','file_audit_snapshot','ad_directory_observation')) scopes
      left join public.finding_evidence_source_bindings b on b.installation_id=scopes.installation_id and b.plugin_id=scopes.plugin_id
        and b.source_instance_id=scopes.source_instance_id and b.source_generation=scopes.source_generation
        and b.collection_scope_id=scopes.collection_scope_id and b.storage_kind=scopes.storage_kind
      left join (public.sli_agent_receipts receipt join public.sli_agent_packet_inbox inbox on inbox.packet_id=receipt.packet_id
        and inbox.imported_at is not null and inbox.envelope=receipt.envelope and receipt.receipt->>'status'='committed')
        on receipt.agent_id=b.agent_id and receipt.module_id='sli.file-audit'
          and receipt.envelope->>'generation'=b.source_generation and receipt.envelope->>'source_instance_id'=b.source_instance_id
      left join public.servers server on server.hostname=inbox.packet#>>'{header,source}'
      group by scopes.installation_id,scopes.plugin_id,scopes.source_instance_id,scopes.source_generation,scopes.collection_scope_id,scopes.storage_kind
    ), evidence_domains as (
      select c.domain_id from public.finding_event_copies337 c where c.finding_id=p_finding
      union all
      select case when o.evidence_key is not null then domains.domain_id end
      from public.finding_evidence_refs ref left join native_domains domains on domains.installation_id=ref.installation_id
        and domains.plugin_id=ref.plugin_id and domains.source_instance_id=ref.source_instance_id and domains.source_generation=ref.source_generation
        and domains.collection_scope_id=ref.collection_scope_id and domains.storage_kind=ref.storage_kind
      left join sli_plugin_file_audit.observations o on o.evidence_key=ref.native_id and o.agent_id=domains.agent_id
        and o.source_instance_id=ref.source_instance_id and o.generation=ref.source_generation and o.payload_sha256=ref.sha256
      where ref.finding_id=p_finding and ref.storage_kind not in ('core_event','file_audit_snapshot','ad_directory_observation')
      union all
      select (public.file_acl_link_binding_v265(p_finding,ref.installation_id,ref.source_instance_id,ref.source_generation,
        ref.collection_scope_id,ref.native_id,ref.sha256)->>'domain_id')::bigint
      from public.finding_evidence_refs ref where ref.finding_id=p_finding and ref.storage_kind='file_audit_snapshot'
    union all select case when proof.sha256=ref.sha256 then run.domain_id end
         from public.finding_evidence_refs ref
         left join public.ad_context_evidence evidence on evidence.id=case when ref.storage_kind='ad_directory_observation' then ref.native_id::bigint end
         left join public.ad_context_runs run on run.run_id=evidence.source_run_id
         left join lateral public.identity_snapshot_rows_v301(jsonb_build_object('plugin_id',ref.plugin_id,
             'source_instance_id',ref.source_instance_id,'source_generation',ref.source_generation,
             'collection_scope_id',ref.collection_scope_id),array[case when ref.storage_kind='ad_directory_observation' then ref.native_id::bigint end]) proof on true
         where ref.finding_id=p_finding and ref.storage_kind='ad_directory_observation'
         ) select count(*)>0 and coalesce(bool_and(domain_id is not null and (p_domains is null or domain_id=any(p_domains))),false)
      into allowed from evidence_domains;
    return allowed;
end $function$
;

CREATE OR REPLACE FUNCTION public.semantic_finding_in_domains_v262(p_finding bigint, p_domains bigint[])
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
    with native_domains as materialized (
        -- Resolve the receipt source once per scope, not once per file in a
        -- mass-operation episode. Pending packets are not evidence witnesses.
        select scopes.*,case when count(distinct b.agent_id)=1 then min(b.agent_id::text)::uuid end as agent_id,
            case when count(distinct server.domain_id)=1 and bool_and(server.domain_id is not null)
                 then min(server.domain_id) end as domain_id
        from (select distinct installation_id,plugin_id,source_instance_id,source_generation,
                    collection_scope_id,storage_kind from public.finding_evidence_refs
              where finding_id=p_finding and storage_kind<>'core_event') scopes
        left join public.finding_evidence_source_bindings b
          on b.installation_id=scopes.installation_id and b.plugin_id=scopes.plugin_id
         and b.source_instance_id=scopes.source_instance_id and b.source_generation=scopes.source_generation
         and b.collection_scope_id=scopes.collection_scope_id and b.storage_kind=scopes.storage_kind
        left join (public.sli_agent_receipts receipt join public.sli_agent_packet_inbox inbox
            on inbox.packet_id=receipt.packet_id and inbox.imported_at is not null
           and inbox.envelope=receipt.envelope and receipt.receipt->>'status'='committed')
          on receipt.agent_id=b.agent_id and receipt.module_id='sli.file-audit'
         and receipt.envelope->>'generation'=b.source_generation
         and receipt.envelope->>'source_instance_id'=b.source_instance_id
        left join public.servers server on server.hostname=inbox.packet#>>'{header,source}'
        group by scopes.installation_id,scopes.plugin_id,scopes.source_instance_id,scopes.source_generation,
                 scopes.collection_scope_id,scopes.storage_kind
    ), evidence_domains as (
        select c.domain_id from public.finding_event_copies337 c where c.finding_id=p_finding
        union all
        select case when o.evidence_key is not null then domains.domain_id end
        from public.finding_evidence_refs ref
        left join native_domains domains
          on domains.installation_id=ref.installation_id and domains.plugin_id=ref.plugin_id
         and domains.source_instance_id=ref.source_instance_id and domains.source_generation=ref.source_generation
         and domains.collection_scope_id=ref.collection_scope_id and domains.storage_kind=ref.storage_kind
        left join sli_plugin_file_audit.observations o on o.evidence_key=ref.native_id
          and o.agent_id=domains.agent_id and o.source_instance_id=ref.source_instance_id
          and o.generation=ref.source_generation and o.payload_sha256=ref.sha256
        where ref.finding_id=p_finding and ref.storage_kind<>'core_event'
    )
    select count(*)>0 and coalesce(bool_and(domain_id is not null and domain_id=any(p_domains)),false)
    from evidence_domains
$function$
;

CREATE OR REPLACE FUNCTION public.copy_linked_finding_event337()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
        perform public.copy_finding_event337(new.finding_id,new.event_id::text,encode(h.source_sha256,'hex'),new.evidence_role,new.note)
        from public.event_hot h where h.event_id=new.event_id and h.source_sha256 is not null;
    return new;
end $function$
;

reset role;
CREATE OR REPLACE FUNCTION public.lock_storage_lifecycle_tables_v319(p_scope text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
begin
    case p_scope
    when 'file_actions' then lock table sli_plugin_file_audit.rule_actions in share mode;
    when 'file' then
        lock table sli_plugin_file_audit.retention_holds in share mode;
        lock table public.investigation_events in share mode;
        lock table sli_plugin_file_audit.rule_snapshots in share mode;
        lock table sli_plugin_file_audit.rule_actions in share mode;
    else raise exception 'storage_lifecycle_lock_scope_invalid' using errcode='22023';
    end case;
end $function$
;

set local role adlog_storage_owner;
CREATE OR REPLACE FUNCTION public.semantic_finding_review_v160(p_id bigint)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public'
AS $function$
    with context_events as not materialized (
        select h.event_id as id,h.event_kind as event_id,h.domain_id,(h.method->>'$server_id')::bigint as server_id,
            h.method#>>'{$principals,SubjectUserSid}' as subject_user_sid,
            h.method#>>'{$principals,SubjectUserName}' as subject_user_name,
            h.method#>>'{$principals,TargetUserSid}' as target_user_sid,
            coalesce(h.fields->>'ProcessName',h.method->>'ProcessName') as process_name,
            coalesce(h.fields->>'LogonType',h.method->>'LogonType') as logon_type,
            coalesce(h.fields->>'SubjectLogonId',h.method->>'SubjectLogonId',h.fields->>'TargetLogonId',h.method->>'TargetLogonId') as logon_id,
            h.method->>'$correlation_id' as correlation_id,h.method->>'$provider' as provider,h.time_created_utc from public.event_hot h where h.source_sha256 is not null
    ), samples as materialized (
        select h.event_id as id,h.event_kind as event_id,h.domain_id,(h.method->>'$server_id')::bigint as server_id,
            h.method#>>'{$principals,SubjectUserSid}' as subject_user_sid,
            h.method#>>'{$principals,SubjectUserName}' as subject_user_name,
            h.method#>>'{$principals,TargetUserSid}' as target_user_sid,
            coalesce(h.fields->>'ProcessName',h.method->>'ProcessName') as process_name,
            coalesce(h.fields->>'LogonType',h.method->>'LogonType') as logon_type,
            coalesce(h.fields->>'SubjectLogonId',h.method->>'SubjectLogonId',h.fields->>'TargetLogonId',h.method->>'TargetLogonId') as logon_id,
            h.method->>'$correlation_id' as correlation_id,h.method->>'$provider' as provider,h.time_created_utc from public.finding_event_copies337 h
        where h.finding_id=p_id
        order by h.time_created_utc desc,h.event_id desc limit 21
    ), review_samples as materialized (
        select * from samples order by time_created_utc desc,id desc limit 20
    ), classified as (
        select s.*,
            case
            when s.event_id <> 4719 then 'unknown'
            when (s.process_name is null or lower(s.process_name) ~ '(^|[\\/])(gpupdate|svchost|gpscript)[.]exe$')
                and exists(select 1 from context_events g
                where g.server_id=s.server_id and g.domain_id=s.domain_id
                and s.correlation_id is not null and s.correlation_id <> ''
                and g.correlation_id=s.correlation_id
                and g.provider='Microsoft-Windows-GroupPolicy'
                and g.event_id in (4000,4004,8000,8004)
                and g.time_created_utc between s.time_created_utc-interval '5 minutes'
                    and s.time_created_utc+interval '5 minutes' limit 1) then 'known_gpo_refresh'
            when s.subject_user_sid in ('S-1-5-18','S-1-5-19','S-1-5-20') then 'system_account'
            when s.subject_user_sid is not null and right(s.subject_user_name,1)='$' then 'machine_account'
            when exists(select 1 from context_events l
                where l.server_id=s.server_id and l.domain_id=s.domain_id
                and s.logon_id is not null and s.logon_id <> '' and l.logon_id=s.logon_id
                and l.event_id=4624 and l.target_user_sid=s.subject_user_sid
                and l.logon_type in ('2','10')
                and l.time_created_utc between s.time_created_utc-interval '12 hours' and s.time_created_utc
                and exists(select 1 from context_events privilege
                    where privilege.server_id=s.server_id and privilege.domain_id=s.domain_id
                    and privilege.logon_id=s.logon_id and privilege.event_id=4672
                    and privilege.subject_user_sid=s.subject_user_sid
                    and privilege.time_created_utc between l.time_created_utc and s.time_created_utc limit 1)
                limit 1) then 'interactive_admin'
            else 'unknown' end as bucket
        from review_samples s
    )
    select jsonb_build_object('kind','hint','verdict',false,
        'bucket',case when count(distinct bucket)=1 then min(bucket) else 'unknown' end,
        'sample_count',count(*),'truncated',(select count(*)>20 from samples),
        'process_observed',coalesce(bool_or(process_name is not null),false),
        'has_audit_change',coalesce(bool_or(event_id=4719),false),
        'mixed',count(distinct bucket)>1,
        'gpo_correlated',coalesce(bool_and(bucket='known_gpo_refresh'),false),
        'machine_account',coalesce(bool_and(bucket='machine_account'),false),
        'interactive_session',coalesce(bool_and(bucket='interactive_admin'),false),
        'privileged_session',coalesce(bool_and(bucket='interactive_admin'),false),
        'domain_id',case when count(distinct domain_id)=1 then min(domain_id) else null end,
        'subject_sid',case when count(subject_user_sid)=count(*) and count(distinct subject_user_sid)=1
            then min(subject_user_sid) else null end)
    from classified
$function$
;

CREATE OR REPLACE FUNCTION public.semantic_finding_suppressed_v160(p_id bigint, p_type text)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public'
AS $function$
    select exists(select 1 from public.semantic_suppressions rule,
        lateral (select public.semantic_finding_review_v160(p_id) as hint) review
        where rule.state='active' and rule.expires_at > statement_timestamp()
        and rule.semantic_type=p_type and rule.domain_id=(hint->>'domain_id')::bigint
        and ((rule.scope_kind='bucket' and rule.scope_value=hint->>'bucket'
                and (hint->>'has_audit_change')::boolean is true
                and (hint->>'truncated')::boolean is false)
            or (rule.scope_kind='subject_sid' and rule.scope_value=hint->>'subject_sid'))
        -- A subject-scoped rule cannot spill into another domain/subject,
        -- even when a finding contains more evidence than the hint sample.
        and not exists(select 1 from public.finding_event_details337 e
            where e.finding_id=p_id
            and (e.domain_id <> rule.domain_id or e.subject_user_sid is distinct from hint->>'subject_sid')))
$function$
;

CREATE OR REPLACE FUNCTION public.report_security_candidate_counts(p_filters jsonb, p_zone text, p_start timestamp with time zone, p_end timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
declare v_result jsonb; v_heartbeat jsonb; v_refresh boolean := false; v_coverage boolean := false;
    v_domains bigint[]; v_page jsonb; v_generated timestamptz;
begin
    if p_filters is null or jsonb_typeof(p_filters)<>'object'
       or exists(select 1 from jsonb_object_keys(p_filters) k where k not in ('severity','status','population'))
       or exists(select 1 from jsonb_each(p_filters) e where jsonb_typeof(e.value)<>'string')
       or (p_filters ? 'severity' and p_filters->>'severity' not in ('critical','high','medium','low'))
       or (p_filters ? 'status' and p_filters->>'status' not in ('new','repeated','confirmed','active','review','false_positive','closed'))
       or (p_filters ? 'population' and p_filters->>'population' not in ('open','attention','all'))
       or p_start is null or p_end is null or p_end<=p_start or p_end-p_start>interval '32 days' then
        raise exception 'report_candidate_parameters_invalid';
    end if;
    with queue_population as materialized (
        select findings.id,cohort.key as problem_cohort,findings.severity,
               (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) as status,(coalesce(risk.state='active' and risk.expires_at > statement_timestamp(),false)) as risk_accepted,
               count(*) over(partition by cohort.key) as occurrence_count,
               max(findings.id) over(partition by cohort.key) as queue_cursor_id,
               row_number() over(partition by cohort.key order by
                   case (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) when 'new' then 1 when 'repeated' then 2
                       when 'confirmed' then 3 when 'active' then 4 when 'review' then 5
                       when 'false_positive' then 6 when 'closed' then 7 else 8 end,
                   case findings.severity when 'critical' then 1 when 'high' then 2
                       when 'medium' then 3 when 'low' then 4 else 5 end,
                   findings.id desc) as representative_rank
        from public.findings_active findings
        left join lateral (select s.* from public.semantic_suppressions s
            join public.auth_users u on u.id=s.responsible_user_id
            where s.finding_id=findings.id and s.kind='risk_acceptance'
            order by s.id desc limit 1) risk on true
    cross join (select p_zone::text as time_zone) cohort_config
    left join lateral (
        select count(*) as retained_count,
               count(*) filter(where e.event_id in (4728,4732,4756)) as membership_count,
               bool_and(coalesce(e.channel='Security' and e.identity_provider='Microsoft-Windows-Security-Auditing',false)) as membership_source,
               count(distinct (e.domain_id,e.server_id,
                   timezone(cohort_config.time_zone,e.time_created_utc)::date,
                   e.target_user_sid,e.membership_member_sid)) as membership_identities,
               count(distinct (e.domain_id,e.server_id,
                   timezone(cohort_config.time_zone,e.time_created_utc)::date)) as source_days,
               bool_and(e.domain_id is not null and e.server_id is not null
                   and e.time_created_utc is not null) as source_complete,
               bool_and(e.target_user_sid ~ '^S-1-([0-9]+-)*[0-9]+$'
                   and e.membership_member_sid ~ '^S-1-([0-9]+-)*[0-9]+$'
                   and e.target_user_sid is not null and e.membership_member_sid is not null) as identities_complete,
               min(e.domain_id) as domain_id,min(e.server_id) as server_id,
               min(timezone(cohort_config.time_zone,e.time_created_utc)::date)::text as day,
               min(e.target_user_sid) as group_sid,min(e.membership_member_sid) as member_sid,
               case when count(distinct e.domain_id)=1 then min(d.fqdn) end as domain_name
        from public.finding_event_details337 e
        left join public.domains d on d.id=e.domain_id
        where e.finding_id=findings.id
    ) witness on true
    cross join lateral (
        select case
            when witness.retained_count=findings.evidence_count and witness.retained_count>0
                and witness.source_complete and witness.identities_complete and witness.membership_source
                and witness.membership_count=witness.retained_count and witness.membership_identities=1
            then jsonb_build_array('membership',findings.rule_code,witness.domain_id,witness.server_id,
                witness.member_sid,witness.group_sid,witness.day)
            when witness.retained_count=findings.evidence_count and witness.retained_count>0
                and witness.source_complete and witness.membership_count=0 and witness.source_days=1
                and nullif(btrim(findings.target),'') is not null and length(findings.target)<=2048
            then jsonb_build_array('object',findings.rule_code,witness.domain_id,witness.server_id,
                findings.target,witness.day)
            else jsonb_build_array('finding',findings.id)
        end as key
    ) raw_cohort
    cross join lateral (
        select case when length(raw_cohort.key::text)<=4096 then raw_cohort.key
                    else jsonb_build_array('finding',findings.id) end as key
    ) cohort
 where public.is_semantic_finding_published_v1(findings.id) and (findings.rule_code<>'semantic.qw.file-acl-broad-write' or public.semantic_finding_in_domains_v265(findings.id,null)) and not coalesce(risk.state='active' and risk.expires_at > statement_timestamp(),false) and not public.semantic_finding_suppressed_v160(findings.id,findings.rule_code) and ((p_filters->>'severity') is null or findings.severity=p_filters->>'severity') and ((p_filters->>'status') is null or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end)=p_filters->>'status') and (coalesce(p_filters->>'population','open')<>'attention' or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) in ('new','confirmed','repeated')) and (coalesce(p_filters->>'population','open')<>'open' or p_filters->>'status' is not null or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) in ('new','confirmed','repeated','active','review')) and findings.last_seen_utc::timestamptz >= p_start and findings.last_seen_utc::timestamptz < p_end
    ), queue_groups as (
        select * from queue_population where representative_rank=1
    ) , individual_counts as (
        select count(*) as total from public.findings_active findings
        left join lateral (select s.* from public.semantic_suppressions s
            join public.auth_users u on u.id=s.responsible_user_id
            where s.finding_id=findings.id and s.kind='risk_acceptance'
            order by s.id desc limit 1) risk on true where public.is_semantic_finding_published_v1(findings.id) and (findings.rule_code<>'semantic.qw.file-acl-broad-write' or public.semantic_finding_in_domains_v265(findings.id,null)) and not coalesce(risk.state='active' and risk.expires_at > statement_timestamp(),false) and not public.semantic_finding_suppressed_v160(findings.id,findings.rule_code) and ((p_filters->>'severity') is null or findings.severity=p_filters->>'severity') and ((p_filters->>'status') is null or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end)=p_filters->>'status') and (coalesce(p_filters->>'population','open')<>'attention' or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) in ('new','confirmed','repeated')) and (coalesce(p_filters->>'population','open')<>'open' or p_filters->>'status' is not null or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) in ('new','confirmed','repeated','active','review')) and findings.last_seen_utc::timestamptz >= p_start and findings.last_seen_utc::timestamptz < p_end
    ), cohort_counts as (select count(*) as total from queue_groups)
    select jsonb_build_object('counts',jsonb_build_object(
        'individual',(select jsonb_build_object('total',total,'has_more',total>50) from individual_counts),
        'cohorts',(select jsonb_build_object('total',total,'has_more',total>50) from cohort_counts))) into v_result;
    
    v_generated:=clock_timestamp();
    select jsonb_build_object('status',case when status in ('running','idle') then status else 'other' end,
        'heartbeat_at',heartbeat_at,'expected_interval_seconds',expected_interval_seconds,
        'details_json',jsonb_build_object('runtime_mode',case when btrim(details_json->>'runtime_mode')
            in ('facts-v1','investigation-v1','findings-v1') then btrim(details_json->>'runtime_mode') end,
            'manual_runtime',case when details_json->'manual_runtime'='false'::jsonb then false else true end))
    into v_heartbeat from public.runtime_worker_heartbeats where worker_name='semantic' limit 1;
    begin
        select coalesce(last_status='failed',false) into v_refresh from public.findings_refresh_state
            where pipeline_name='events_to_findings_v1';
        perform max(event_id) from public.event_hot;
    exception when others then v_refresh:=true;
    end;
    begin
        select coalesce(array_agg(id order by id),'{}'::bigint[]) into v_domains from public.domains;
        if cardinality(v_domains)>0 then
            v_page:=public.read_password_detection_coverage(v_domains);
            v_coverage:=jsonb_typeof(v_page) is distinct from 'object'
                or jsonb_typeof(v_page->'rows') is distinct from 'array'
                or jsonb_typeof(v_page->'has_more') is distinct from 'boolean'
                or (v_page->>'has_more')::boolean or jsonb_array_length(v_page->'rows')=0
                or exists(select 1 from jsonb_array_elements(v_page->'rows') r
                    where r->>'policy_state' in ('unknown','disabled_last_known')
                       or r->>'frozen_episode_count'<>'0'
                       or r->>'policy_state'='enabled' and r->>'status'<>'healthy');
        end if;
    exception when others then v_coverage:=true;
    end;
    return v_result || jsonb_build_object('quality_inputs',jsonb_build_object(
        'heartbeat',coalesce(v_heartbeat,'{}'::jsonb),'refresh_limited',coalesce(v_refresh,false),
        'coverage_incomplete',coalesce(v_coverage,false)), 'generated_at',v_generated);
end $function$
;


-- Tables/triggers can have pre-baseline owners. Only DDL on those existing
-- objects uses the migration session; all new objects above use storage_owner.
reset role;
do $$ declare item record; begin
    for item in select t.tgrelid,t.tgname from pg_trigger t where not t.tgisinternal
        and t.tgfoid in(select signature::regprocedure from legacy_functions372 where remove) loop
        execute format('drop trigger %I on %s',item.tgname,item.tgrelid::regclass);
    end loop;
    for item in select c.conrelid,c.conname from pg_constraint c where c.contype='f' and c.conparentid=0
        and c.confrelid in(select oid from legacy_tables372) and c.conrelid not in(select oid from legacy_tables372) loop
        execute format('alter table %s drop constraint %I',item.conrelid::regclass,item.conname);
    end loop;
    for item in select signature from legacy_functions372 where remove loop
        execute format('drop function %s',item.signature);
    end loop;
end $$;
drop view public.event_entity_links_v2;

-- Refuse remaining callers, including triggers calling a removed function by
-- name through dynamic SQL. RESTRICT below independently checks pg_depend.
do $$ declare unexpected text; begin
    select string_agg(p.oid::regprocedure::text,', ') into unexpected from pg_proc p
    join pg_namespace n on n.oid=p.pronamespace
    where n.nspname not in ('pg_catalog','information_schema') and n.nspname !~ '^pg_(temp|toast)'
      and (p.prosrc ~* '\m(events_v2_core|event_facts_v2|event_entity_link_blocks_v2|raw_log_files|event_entity_links_v2|detections_use_short337)\M'
        or exists(select 1 from legacy_functions372 f where f.remove
            and p.prosrc ~ ('\m'||split_part(split_part(f.signature,'(',1),'.',2)||'\M')));
    if unexpected is not null then
        raise exception 'drop_legacy_events372_remaining_function: %',unexpected using errcode='55000';
    end if;
end $$;
-- Dropping each root removes only its own partitions, indexes, triggers and
-- grants. Other tables, including source representations and finding copies,
-- remain in place. External reference rows have not been deleted or rewritten.
drop table public.event_facts_v2,public.event_entity_link_blocks_v2,public.events_v2_core,public.raw_log_files restrict;
drop table public.legacy_functions372,public.legacy_tables372;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(372,'drop_legacy_events');
reset role;
commit;
