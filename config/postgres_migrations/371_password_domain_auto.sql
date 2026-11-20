begin;
select pg_advisory_xact_lock(hashtext('sli_password_domain_auto371'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=370 and name='password_producer_failures')
       or exists(select 1 from public.schema_migrations where version>=371)
       or (select relowner from pg_class where oid='public.sli_agent_module_bindings'::regclass)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'password_domain_auto371_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- This fills ownership metadata only. Source admission, native proof and the
-- policy-history issuer remain the authority for producing password signals.
create function public.reconcile_password_detection_domain371(p_agent uuid) returns bigint
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare a public.sli_agents%rowtype; m public.sli_agent_module_bindings%rowtype;
    assignment jsonb; domain bigint; installation uuid; s jsonb; digest bytea;
    pin_value text; adopted bigint;
begin
    select * into a from public.sli_agents where id=p_agent for update;
    if not found or a.status<>'active' or a.rights_probe ? 'identity_conflict' then return null; end if;
    if (select count(*) from jsonb_array_elements(a.assigned_modules) v where v->>'module_id'='sli.windows.ad-dc')<>1 then
        return null;
    end if;
    select v into assignment from jsonb_array_elements(a.assigned_modules) v where v->>'module_id'='sli.windows.ad-dc';
    if assignment->'enabled' is distinct from 'true'::jsonb then return null; end if;
    select * into m from public.sli_agent_module_bindings where agent_id=p_agent and module_id='sli.windows.ad-dc';
    if not found or m.source_instance_id is distinct from coalesce(a.source_host_id,a.host_id)::text
       or m.source_name is distinct from assignment#>>'{config,source_name}'
       or m.policy_revision is distinct from assignment#>>'{config,policy_revision}'
       or m.channel<>'ad-dc' or m.module_version<>'1.0.0' then return null; end if;
    if m.password_detection_domain_id is not null then return m.password_detection_domain_id; end if;

    -- Prefer the persisted registration decision. Without it, use the same
    -- canonical/short DC-name matching as registration, never the first domain.
    select min(dc.domain_id) into domain from public.servers dc
    where dc.role='domain_controller' and dc.is_active and coalesce(
        dc.id::text=(select details->>'server_id' from public.sli_agent_audit
            where target=p_agent::text and action='issue' order by id desc limit 1),
        lower(m.source_name) in (lower(dc.hostname),lower(dc.fqdn))
        or strpos(m.source_name,'.')=0
            and lower(m.source_name)=split_part(lower(coalesce(nullif(dc.fqdn,''),dc.hostname)),'.',1)
        or strpos(coalesce(nullif(dc.fqdn,''),dc.hostname),'.')=0
            and lower(dc.hostname)=split_part(lower(m.source_name),'.',1))
    having count(distinct dc.domain_id)=1;
    if domain is null then return null; end if;
    if (select count(*) from public.semantic_default_installation)<>1 then return null; end if;
    select installation_id into installation from public.semantic_default_installation;
    if installation is null then return null; end if;
    s:=jsonb_build_object('installation_id',installation::text,'plugin_id',m.module_id,
        'source_instance_id',m.source_instance_id,'source_generation',m.source_instance_id,'collection_scope_id','');
    digest:=public.password_v2_scope_key(s);
    -- Keep the existing source -> checkpoint lock order and immutable owners.
    perform pg_advisory_xact_lock(hashtextextended(encode(digest,'hex'),0));
    select * into m from public.sli_agent_module_bindings where agent_id=p_agent and module_id='sli.windows.ad-dc' for update;
    if m.password_detection_domain_id is not null then return m.password_detection_domain_id; end if;
    for pin_value in select encode(sha256(convert_to(public.password_v2_json_compact(public.password_v2_coverage_execution(s,r)),'UTF8')),'hex')
        from unnest(array['qw.password-brute-force','qw.password-spray']) r order by 1 loop
        perform 1 from public.semantic_password_checkpoints c where c.scope_digest=digest and c.pin=pin_value for update;
    end loop;
    if exists(select 1 from public.semantic_password_checkpoints c where c.scope_digest=digest
        and c.scope_json=s and c.execution_json=public.password_v2_coverage_execution(s,c.execution_json->>'rule_id')
        and c.owner_domain_id is not null and c.owner_domain_id<>domain) then return null; end if;
    update public.semantic_password_checkpoints c set owner_domain_id=domain where c.scope_digest=digest
        and c.scope_json=s and c.execution_json=public.password_v2_coverage_execution(s,c.execution_json->>'rule_id')
        and c.execution_json->>'rule_id' in ('qw.password-brute-force','qw.password-spray')
        and c.pin=encode(sha256(convert_to(public.password_v2_json_compact(c.execution_json),'UTF8')),'hex') and c.owner_domain_id is null;
    get diagnostics adopted=row_count;
    update public.sli_agent_module_bindings set password_detection_domain_id=domain
        where agent_id=p_agent and module_id='sli.windows.ad-dc';
    insert into public.sli_agent_audit(action,actor,target,details)
    values('password_domain_bind','system:password-domain-auto',p_agent::text,
        jsonb_build_object('old_domain_id',null,'new_domain_id',domain,'scope',s,
            'expected_revision',a.policy_revision,'issued_revision',m.policy_revision,'adopted_checkpoints',adopted));
    return domain;
end $$;
revoke all on function public.reconcile_password_detection_domain371(uuid) from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
grant execute on function public.reconcile_password_detection_domain371(uuid) to adlog_user;

-- Package upgrade repairs already issued bindings through the same path used
-- by enrollment, module assignment and API startup.
do $$ declare agent uuid; begin
    for agent in select b.agent_id from public.sli_agent_module_bindings b
        join public.sli_agents a on a.id=b.agent_id
        where a.status='active' and b.module_id='sli.windows.ad-dc' and b.password_detection_domain_id is null
        order by b.agent_id loop
        perform public.reconcile_password_detection_domain371(agent);
    end loop;
end $$;
insert into public.schema_migrations(version,name) values(371,'password_domain_auto');
reset role;
commit;
