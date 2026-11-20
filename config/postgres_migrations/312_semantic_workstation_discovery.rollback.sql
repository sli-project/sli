begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_workstation_discovery_v312'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=311 and name='semantic_inbox_admission')
       or not exists(select 1 from public.schema_migrations where version=312 and name='semantic_workstation_discovery')
       or exists(select 1 from public.schema_migrations where version>312)
       or (select proowner from pg_proc where oid='public.t109_detection_sources()'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_workstation_312_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- CREATE OR REPLACE retains OID, owner, ACL, SECURITY DEFINER and search_path.
do $patch$
declare definition text;
    old_sql text := $old$    -- WS XML: admission runs once per assigned agent, never per observation.
    -- The ordered receipt PK probe stops at its first envelope-matched import;
    -- LIMIT is after every predicate and has no history tail restriction.
    with workstation_agents as materialized (
        select a.id,a.host_id
        from public.sli_agents a cross join lateral (
            select 1 from public.sli_agent_receipts r cross join lateral (
                select 1 from public.sli_agent_packet_inbox i
                where i.packet_id=r.packet_id and i.imported_at is not null and i.envelope=r.envelope
                offset 0
            ) imported
            where r.agent_id=a.id and r.module_id='sli.workstations'
              and r.receipt->>'status'='committed' and r.envelope->>'source_instance_id'=a.host_id::text
            order by r.sequence desc limit 1 offset 0
        ) receipt
        where a.status='active' and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
            where m->>'module_id'='sli.workstations' and m->'enabled'='true'::jsonb)
    )
    insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,
        plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,agent_key)
    select login,session_user,installation,'sli.workstations',a.host_id::text,
        g.generation,'','workstation_observation',a.id::text
    from workstation_agents a cross join lateral (
        -- Loose index traversal: one seek per distinct observation generation,
        -- including generations absent from receipts. All families and ages count.
        with recursive generations(generation) as (
            (select o.observation->>'generation' from sli_plugin_workstations.observations o
             where o.agent_key=a.id::text and o.observation->>'generation' is not null
             order by o.observation->>'generation' limit 1)
            union all
            select next_generation.generation from generations previous cross join lateral (
                select o.observation->>'generation' as generation from sli_plugin_workstations.observations o
                where o.agent_key=a.id::text and o.observation->>'generation'>previous.generation
                order by o.observation->>'generation' limit 1
            ) next_generation
        )
        select generation from generations
        union all
        -- DISTINCT also includes NULL. Preserve the original NOT NULL failure
        -- for malformed observations rather than silently dropping that input.
        (select o.observation->>'generation' from sli_plugin_workstations.observations o
         where o.agent_key=a.id::text and o.observation->>'generation' is null limit 1)
    ) g
    on conflict do nothing;
$old$;
    new_sql text := $new$    -- WS XML is already admitted by the native importer; discovery additionally
    -- requires an active assignment and a committed, imported matching stream.
    insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,
        plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,agent_key)
    select distinct login,session_user,installation,'sli.workstations',a.host_id::text,
        o.observation->>'generation','','workstation_observation',a.id::text
    from public.sli_agents a join sli_plugin_workstations.observations o on o.agent_key=a.id::text
    where a.status='active' and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
        where m->>'module_id'='sli.workstations' and m->'enabled'='true'::jsonb)
      and exists(select 1 from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
        where r.agent_id=a.id and r.module_id='sli.workstations' and r.receipt->>'status'='committed'
          and i.imported_at is not null and i.envelope=r.envelope
          and r.envelope->>'source_instance_id'=a.host_id::text)
    on conflict do nothing;
$new$;
begin
    definition:=pg_get_functiondef('public.t109_detection_sources()'::regprocedure);
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_workstation_312_definition_mismatch' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
end $patch$;
-- DROP INDEX takes ACCESS EXCLUSIVE on observations; do it last.
drop index sli_plugin_workstations.workstation_discovery_generation_v312;
delete from public.schema_migrations where version=312 and name='semantic_workstation_discovery';
reset role;
commit;
