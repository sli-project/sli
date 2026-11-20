-- Prospective normal assignment retention; no commands, activation or backfill.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_file_audit_assignment_policy_v272'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=271 and name='account_watch_source_prefilter')
       or exists(select 1 from public.schema_migrations where version>=272)
       or to_regprocedure('sli_plugin_file_audit.retain_assignment_policy(uuid,text,bigint)') is not null
       or not exists(select 1 from pg_class where oid='sli_plugin_file_audit.policy_revisions'::regclass
           and relowner='adlog_file_audit_owner'::regrole)
       or not exists(select 1 from pg_class where oid='public.sli_agents'::regclass
           and relowner='adlog_storage_owner'::regrole) then
        raise exception 'migration 272 prerequisites failed' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Existing185 grants id/host_id/status/policy_revision; add only this column.
grant select(assigned_modules) on public.sli_agents to adlog_file_audit_owner;
reset role;
set local role adlog_file_audit_owner;

create function sli_plugin_file_audit.retain_assignment_policy(
    p_agent uuid,p_actor_kind text,p_actor_id bigint
) returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare host uuid; v_revision bigint; modules jsonb; matches bigint; assignment jsonb; config jsonb;
    item jsonb; root jsonb; setting record; pin text;
begin
    -- Called after ordinary locked CAS/update and before its mandatory audit.
    -- This retains that exact app-issued config; it is not a worker repair API.
    if p_actor_kind is null or p_actor_kind not in ('session','api_key')
       or p_actor_id is null or p_actor_id<=0 then
        raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    select a.host_id,a.policy_revision,a.assigned_modules into host,v_revision,modules
      from public.sli_agents a where a.id=p_agent and a.status='active';
    if not found or host is null or jsonb_typeof(modules) is distinct from 'array' then
        raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    select count(*) into matches from jsonb_array_elements(modules) m
      where m->>'module_id'='sli.file-audit';
    if matches<>1 then raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    select m into assignment from jsonb_array_elements(modules) m where m->>'module_id'='sli.file-audit';
    config:=assignment->'config';
    if jsonb_typeof(assignment) is distinct from 'object'
       or jsonb_typeof(assignment->'enabled') is distinct from 'boolean'
       or jsonb_typeof(config) is distinct from 'object' then
        raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    if octet_length(config::text)>262144
       or config-array['policy_revision','source_name','source_kind','roots','max_events','max_bytes','wall_seconds',
           'spool_bytes','inventory_depth','inventory_objects','optional_events','service_account_exclusions',
           'mass_operation_files','mass_operation_seconds','initial_read_hours']<>'{}'::jsonb
       or not(config ?& array['policy_revision','roots','max_events','max_bytes','wall_seconds','spool_bytes',
           'inventory_depth','inventory_objects','optional_events','service_account_exclusions',
           'mass_operation_files','mass_operation_seconds'])
       or config->'policy_revision' is distinct from to_jsonb(v_revision::text)
       or jsonb_typeof(config->'optional_events') is distinct from 'boolean'
       or jsonb_typeof(config->'roots') is distinct from 'array'
       or jsonb_typeof(config->'service_account_exclusions') is distinct from 'array'
       or (config ? 'source_kind' and (jsonb_typeof(config->'source_kind') is distinct from 'string'
           or config->>'source_kind' not in ('server','workstation')))
       or (config ? 'source_name' and (jsonb_typeof(config->'source_name') is distinct from 'string'
           or length(config->>'source_name') not between 1 and 255)) then
        raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    for setting in select * from (values
        ('max_events',1,10000),('max_bytes',1024,8388608),('wall_seconds',1,120),
        ('spool_bytes',1048576,1073741824),('inventory_depth',0,64),('inventory_objects',1,100000),
        ('mass_operation_files',1,1000000),('mass_operation_seconds',1,86400)
    ) limits(key,low,high) loop
        if jsonb_typeof(config->setting.key) is distinct from 'number'
           or config->>setting.key !~ '^(0|[1-9][0-9]{0,9})$' then
            raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
        if (config->>setting.key)::numeric not between setting.low and setting.high then
            raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    end loop;
    if config ? 'initial_read_hours' and config->'initial_read_hours'<>'"all"'::jsonb then
        if jsonb_typeof(config->'initial_read_hours') is distinct from 'number'
           or config->>'initial_read_hours' !~ '^(0|[1-9][0-9]{0,5})$' then
            raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
        if (config->>'initial_read_hours')::integer>876000 then
            raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    end if;
    if jsonb_array_length(config->'roots') not between 1 and 100
       or jsonb_array_length(config->'service_account_exclusions')>100
       or (select count(*)<>count(distinct value) from jsonb_array_elements(config->'service_account_exclusions')) then
        raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    for item in select value from jsonb_array_elements(config->'service_account_exclusions') loop
        if jsonb_typeof(item) is distinct from 'string' or length(item#>>'{}')>184
           or item#>>'{}' !~ '^S-1-([0-9]+-)*[0-9]+$' then
            raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    end loop;
    for root in select value from jsonb_array_elements(config->'roots') loop
        if jsonb_typeof(root) is distinct from 'object'
           or not(root ?& array['collection_scope_id','share_name','path','important','sacl'])
           or root-array['collection_scope_id','share_name','path','important','sacl']<>'{}'::jsonb
           or jsonb_typeof(root->'collection_scope_id') is distinct from 'string'
           or length(root->>'collection_scope_id') not between 1 and 256
           or root->>'collection_scope_id' !~ '^[a-zA-Z0-9_.:-]+$'
           or jsonb_typeof(root->'path') is distinct from 'string' or length(root->>'path') not between 3 and 4096
           or jsonb_typeof(root->'share_name') is distinct from 'string'
           or length(root->>'share_name')>80
           or jsonb_typeof(root->'important') is distinct from 'boolean'
           or jsonb_typeof(root->'sacl') is distinct from 'object' then
            raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
        if (root->'sacl')-array['trustee_sids','inherit_files','inherit_directories']<>'{}'::jsonb
           or jsonb_typeof(root#>'{sacl,inherit_files}') is distinct from 'boolean'
           or jsonb_typeof(root#>'{sacl,inherit_directories}') is distinct from 'boolean'
           or jsonb_typeof(root#>'{sacl,trustee_sids}') is distinct from 'array' then
            raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
        if jsonb_array_length(root#>'{sacl,trustee_sids}') not between 1 and 100
           or (select count(*)<>count(distinct value) from jsonb_array_elements(root#>'{sacl,trustee_sids}')) then
            raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
        for item in select value from jsonb_array_elements(root#>'{sacl,trustee_sids}') loop
            if jsonb_typeof(item) is distinct from 'string' or length(item#>>'{}')>184
               or item#>>'{}' !~ '^S-1-([0-9]+-)*[0-9]+$' then
                raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
        end loop;
    end loop;
    if (select count(*)<>count(distinct value->>'collection_scope_id') from jsonb_array_elements(config->'roots')) then
        raise exception 'file_audit_assignment_policy_denied' using errcode='42501'; end if;
    pin:=encode(sha256(convert_to(config::text,'UTF8')),'hex');
    insert into sli_plugin_file_audit.policy_revisions
        (agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
    values(p_agent,host::text,v_revision,clock_timestamp(),p_actor_kind,p_actor_id,config,pin)
    on conflict(agent_id,source_instance_id,revision) do nothing;
    if not exists(select 1 from sli_plugin_file_audit.policy_revisions p
        where p.agent_id=p_agent and p.source_instance_id=host::text and p.revision=v_revision
          and p.policy=config and p.policy_sha256=pin) then
        raise exception 'file_audit_assignment_policy_conflict' using errcode='55000'; end if;
end $$;
revoke all on function sli_plugin_file_audit.retain_assignment_policy(uuid,text,bigint)
    from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
grant execute on function sli_plugin_file_audit.retain_assignment_policy(uuid,text,bigint) to adlog_user;
do $$ begin
    if exists(select 1 from pg_proc p cross join lateral aclexplode(p.proacl) a
        where p.oid='sli_plugin_file_audit.retain_assignment_policy(uuid,text,bigint)'::regprocedure
          and (a.grantee not in ('adlog_file_audit_owner'::regrole,'adlog_user'::regrole)
               or a.privilege_type<>'EXECUTE' or a.is_grantable)) then
        raise exception 'file_audit_assignment_policy_private_acl' using errcode='42501'; end if;
end $$;
reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(272,'file_audit_assignment_policy');
commit;
