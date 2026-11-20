-- Online narrow index: no XML, JSON, generation or INCLUDE payloads.
-- As in 324, run through psql -f / atomic=False. An interrupted invalid
-- concurrent index must be dropped CONCURRENTLY before retry; never attest it.
begin;
select pg_advisory_xact_lock(hashtext('sli_t109_workstation_path_v325'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=324 and name='detector_query_paths')
       or exists(select 1 from public.schema_migrations where version>=325)
       or (select proowner from pg_proc where oid='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure)
            is distinct from 'adlog_storage_owner'::regrole then
        raise exception 't109_workstation_325_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table if not exists public.t109_definitions325(signature text primary key,definition text not null,catalog jsonb not null);
revoke all on public.t109_definitions325 from public,adlog_user,adlog_semantic_worker;
insert into public.t109_definitions325
select oid::regprocedure::text,pg_get_functiondef(oid),to_jsonb(p)-'prosrc'
from pg_proc p where oid='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure
on conflict do nothing;
reset role;
commit;

-- Session identity has historical table-owner authority (same as 324).
create index concurrently if not exists t109_workstation_candidates325
    on sli_plugin_workstations.observations(agent_key,event_id,observed_at desc,id desc)
    where event_id in (4688,4104,1102,4719,7036,7040,7045);

begin;
select pg_advisory_xact_lock(hashtext('sli_t109_workstation_path_v325'));
set local role adlog_storage_owner;
do $$ begin
    if not exists(select 1 from pg_index where indexrelid=to_regclass('sli_plugin_workstations.t109_workstation_candidates325')
        and indrelid='sli_plugin_workstations.observations'::regclass and indisvalid and indisready) then
        raise exception 't109_workstation_325_index_invalid' using errcode='55000';
    end if;
end $$;
do $patch$
declare target oid:='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure;
    definition text; original_catalog jsonb; first_pos integer; last_pos integer; file_sql text;
    old_sql text:=$old$    elsif b.storage_kind='workstation_observation' then
        return query select o.id,o.event_id,o.observed_at,o.observation_sha256,o.source_xml,''::text,null::jsonb
        from sli_plugin_workstations.observations o
        where o.agent_key=b.agent_key and o.observation->>'generation'=b.source_generation
          and o.event_id in (4688,4104,1102,4719,7036,7040,7045)
          and o.observed_at<=statement_timestamp()
          and (p_start is not null and o.observed_at between p_start and p_end
            or p_start is null and not exists(select 1 from public.semantic_t109_seen seen
                where md5(seen.scope_json::text)=md5(s::text) and seen.scope_json=s and seen.native_id=o.id))
          and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
            b.source_generation,'','workstation_observation',o.id,o.observation_sha256)
        order by o.observed_at desc,o.id desc limit 1000;
$old$;
    new_sql text:=$new$    elsif b.storage_kind='workstation_observation' then
        -- Seven ordered index seeks, bounded BEFORE any native proof/payload
        -- fetch. Per-code top K contains the global top K. Keyset pagination
        -- keeps timestamp ties and skips rejected evidence without starvation.
        loop
            ws_count:=0;
            for candidate in execute $candidates$
                select page.id,page.event_id,page.observed_at
                from unnest(array[4688,4104,1102,4719,7036,7040,7045]) code(event_id)
                cross join lateral (
                    select o.id,o.event_id,o.observed_at
                    from sli_plugin_workstations.observations o
                    where o.agent_key=$1 and o.event_id=code.event_id
                      and o.event_id in (4688,4104,1102,4719,7036,7040,7045)
                      and o.observed_at<=statement_timestamp()
                      and ($4 is null or o.observed_at between $4 and $5)
                      and ($6 is null or (o.observed_at,o.id)<($6,$7))
                      and o.observation->>'generation'=$2
                      and ($4 is not null or not exists(
                          -- Existing (native_id,scope_json) index; neither
                          -- scope hashing nor a full seen scan per candidate.
                          select 1 from public.semantic_t109_seen seen
                          where seen.native_id=o.id and seen.scope_json=$3 offset 0))
                    order by o.observed_at desc,o.id desc limit 256
                ) page
                order by page.observed_at desc,page.id desc limit 256
            $candidates$ using b.agent_key,b.source_generation,s,p_start,p_end,ws_after_at,ws_after_id
            loop
                ws_count:=ws_count+1;
                ws_after_at:=candidate.observed_at;ws_after_id:=candidate.id;
                -- Only this bounded portion reaches wide/toasted payloads and
                -- the unchanged resolver. Every emitted row is still attested.
                select o.observation_sha256,o.source_xml into ws_payload
                    from sli_plugin_workstations.observations o where o.id=candidate.id;
                if found and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
                    b.source_generation,'','workstation_observation',candidate.id,ws_payload.observation_sha256) then
                    native_id:=candidate.id;event_id:=candidate.event_id;occurred_at_utc:=candidate.observed_at;
                    sha256:=ws_payload.observation_sha256;source_xml:=ws_payload.source_xml;
                    collection_scope_id:='';document:=null;return next;
                    emitted:=emitted+1;if emitted>=1000 then return;end if;
                end if;
            end loop;
            exit when ws_count<256;
        end loop;
$new$;
begin
    select d.definition,d.catalog into strict definition,original_catalog from public.t109_definitions325 d;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1
       or strpos(definition,'emitted integer:=0;')=0
       or pg_get_functiondef(target) is distinct from definition then
        raise exception 't109_workstation_325_definition_mismatch' using errcode='55000';
    end if;
    definition:=replace(definition,old_sql,new_sql);
    definition:=replace(definition,'emitted integer:=0;',
        'emitted integer:=0; ws_after_at timestamptz; ws_after_id text; ws_count integer; ws_payload record;');

    -- File-audit has the same resolver-before-LIMIT bug. Retain every root,
    -- receipt, action and policy predicate and its 1000/10001 accepted-row cap.
    -- Core-event already attests inside a loop and is left byte-for-byte intact.
    first_pos:=strpos(definition,'        return query select o.evidence_key,o.event_id,a.observed_at,o.payload_sha256,null::text,');
    last_pos:=strpos(definition,'        order by a.observed_at desc,a.action_id desc limit case when p_start is null then 1000 else 10001 end;');
    if first_pos=0 or last_pos<=first_pos then raise exception 't109_workstation_325_file_shape';end if;
    last_pos:=last_pos+length('        order by a.observed_at desc,a.action_id desc limit case when p_start is null then 1000 else 10001 end;');
    file_sql:=substr(definition,first_pos,last_pos-first_pos);
    if strpos(file_sql,$old$          and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
            b.source_generation,a.collection_scope_id,'file_audit_observation',o.evidence_key,o.payload_sha256)
$old$)=0 then raise exception 't109_workstation_325_file_proof_shape';end if;
    file_sql:=replace(file_sql,$old$        return query select o.evidence_key,o.event_id,a.observed_at,o.payload_sha256,null::text,
            a.collection_scope_id,to_jsonb(a)||$old$,$new$        for candidate in
        select o.evidence_key as candidate_id,o.event_id as candidate_event_id,a.observed_at as candidate_at,
            o.payload_sha256 as candidate_sha256,a.collection_scope_id as candidate_collection,to_jsonb(a)||$new$);
    file_sql:=replace(file_sql,'else a.operation end)','else a.operation end) as candidate_document');
    file_sql:=replace(file_sql,$old$          and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
            b.source_generation,a.collection_scope_id,'file_audit_observation',o.evidence_key,o.payload_sha256)
$old$,'');
    file_sql:=replace(file_sql,'md5(seen.scope_json::text)=md5(s::text) and seen.scope_json=s','seen.scope_json=s');
    file_sql:=replace(file_sql,
        'order by a.observed_at desc,a.action_id desc limit case when p_start is null then 1000 else 10001 end;',
        $sql$order by a.observed_at desc,a.action_id desc
        loop
            if public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
                b.source_generation,candidate.candidate_collection,'file_audit_observation',
                candidate.candidate_id,candidate.candidate_sha256) then
                native_id:=candidate.candidate_id;event_id:=candidate.candidate_event_id;occurred_at_utc:=candidate.candidate_at;
                sha256:=candidate.candidate_sha256;source_xml:=null;collection_scope_id:=candidate.candidate_collection;
                document:=candidate.candidate_document;return next;
                emitted:=emitted+1;if emitted>=(case when p_start is null then 1000 else 10001 end) then exit;end if;
            end if;
        end loop;$sql$);
    definition:=substr(definition,1,first_pos-1)||file_sql||substr(definition,last_pos);
    execute definition;
    if (select to_jsonb(p)-'prosrc' from pg_proc p where oid=target) is distinct from original_catalog then
        raise exception 't109_workstation_325_catalog_changed' using errcode='55000';
    end if;
end $patch$;
insert into public.schema_migrations(version,name) values(325,'t109_workstation_path');
reset role;
commit;
