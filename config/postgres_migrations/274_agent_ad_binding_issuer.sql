-- Prospective audited live-AD issuance; no source reads, activation or backfill.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_ad_binding_issuer_v274'));
do $$
declare owner_id oid; runtime record;
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=273 and name='password_attacks_v2')
       or exists(select 1 from public.schema_migrations where version>=274) then
        raise exception 'agent_ad_issuer_preflight' using errcode='55000'; end if;
    select oid into strict owner_id from pg_roles where rolname='adlog_storage_owner';
    if exists(select 1 from pg_class where oid in('public.sli_agents'::regclass,
        'public.sli_agent_policy_history'::regclass,'public.sli_agent_module_bindings'::regclass)
        and relowner<>owner_id)
       or exists(select 1 from pg_trigger where tgrelid in('public.sli_agents'::regclass,
          'public.sli_agent_policy_history'::regclass) and not tgisinternal)
       or exists(select 1 from pg_attribute where attrelid='public.sli_agent_policy_history'::regclass
          and attname='staged_xact_id' and not attisdropped)
       or to_regprocedure('public.password_v2_scope_key(jsonb)') is null then
        raise exception 'agent_ad_issuer_preflight' using errcode='55000'; end if;
    -- Append-only history is the existing runtime ACL contract, not an owner bypass claim.
    if exists(select 1 from pg_class c cross join lateral aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        where c.oid='public.sli_agent_policy_history'::regclass and a.grantee<>owner_id
          and not(a.grantee='adlog_user'::regrole and a.privilege_type in('SELECT','INSERT') and not a.is_grantable))
       or exists(select 1 from pg_attribute c cross join lateral aclexplode(c.attacl) a
           where c.attrelid='public.sli_agent_policy_history'::regclass and a.grantee<>owner_id)
       or exists(select 1 from pg_proc where prosecdef and prosrc ~* '(insert\s+into|update|delete\s+from|truncate)\s+(public\.)?sli_agent_policy_history') then
        raise exception 'agent_ad_issuer_preflight' using errcode='55000'; end if;
    for runtime in select oid,rolname,rolsuper,rolcreaterole,rolreplication,rolbypassrls from pg_roles
        where rolname in('adlog_user','adlog_semantic_worker','adlog_storage_worker') loop
        if runtime.rolsuper or runtime.rolcreaterole or runtime.rolreplication or runtime.rolbypassrls
           or pg_has_role(runtime.oid,owner_id,'MEMBER')
           or has_table_privilege(runtime.oid,'public.sli_agent_policy_history','UPDATE,DELETE,TRUNCATE,TRIGGER')
           or has_any_column_privilege(runtime.oid,'public.sli_agent_policy_history','UPDATE')
           or has_table_privilege(runtime.oid,'public.sli_agents','TRIGGER')
           or has_column_privilege(runtime.oid,'public.sli_agents','id','UPDATE')
           or has_column_privilege(runtime.oid,'public.sli_agents','host_id','UPDATE')
           or has_parameter_privilege(runtime.oid,'session_replication_role','SET') then
            raise exception 'agent_ad_issuer_preflight' using errcode='55000'; end if;
    end loop;
    if (select count(*) from pg_roles where rolname in('adlog_user','adlog_semantic_worker','adlog_storage_worker'))<>3 then
        raise exception 'agent_ad_issuer_preflight' using errcode='55000'; end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
alter table public.sli_agent_policy_history add column staged_xact_id xid8;
create function public.agent_ad_stamp_history() returns trigger
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
begin
    new.staged_xact_id:=pg_current_xact_id();
    return new;
end $$;
revoke all on function public.agent_ad_stamp_history() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
create trigger agent_ad_history_stamp before insert on public.sli_agent_policy_history
    for each row execute function public.agent_ad_stamp_history();
alter table public.sli_agent_policy_history enable always trigger agent_ad_history_stamp;

create function public.agent_ad_issue_binding() returns trigger
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare a jsonb; c jsonb; modules jsonb; o jsonb; n jsonb; prior jsonb; history_row record;
    m public.sli_agent_module_bindings%rowtype; installation uuid; scope jsonb; count_live bigint;
    metadata_keys text[]:=array['allow_event_ids','batch_size','channel_generations','channels',
        'connect_address','initial_read_hours','policy_revision','source_name'];
begin
    -- OLD/NEW are actual locked rows; caller flags and post-state inference are not authority.
    for modules in select old.assigned_modules union all select new.assigned_modules loop
        if jsonb_typeof(modules) is distinct from 'array'
           or exists(select 1 from jsonb_array_elements(modules) v where v='"sli.windows.ad-dc"'::jsonb) then
            raise exception 'agent_ad_issuer_shape' using errcode='55000'; end if;
        select count(*) into count_live from jsonb_array_elements(modules) v where v->>'module_id'='sli.windows.ad-dc';
        if count_live>1 then raise exception 'agent_ad_issuer_shape' using errcode='55000'; end if;
    end loop;
    select v into o from jsonb_array_elements(old.assigned_modules) v where v->>'module_id'='sli.windows.ad-dc';
    select v into n from jsonb_array_elements(new.assigned_modules) v where v->>'module_id'='sli.windows.ad-dc';
    -- Full normalized object shape is preserved; Python retains pack/event allowlist validation.
    for a in select o where o is not null union all select n where n is not null loop
        c:=a->'config';
        if (select array_agg(key order by key) from jsonb_object_keys(a) key) is distinct from array['config','enabled','module_id']
           or jsonb_typeof(a->'enabled') is distinct from 'boolean' or jsonb_typeof(c) is distinct from 'object' then
            raise exception 'agent_ad_issuer_shape' using errcode='55000'; end if;
        if (select array_agg(key order by key) from jsonb_object_keys(c) key) is distinct from metadata_keys
           or jsonb_typeof(c->'source_name') is distinct from 'string' or length(c->>'source_name') not between 1 and 128
           or length(btrim(c->>'source_name'))=0
           or jsonb_typeof(c->'connect_address') is distinct from 'string' or length(c->>'connect_address') not between 1 and 128
           or length(btrim(c->>'connect_address'))=0
           or jsonb_typeof(c->'policy_revision') is distinct from 'string' or c->>'policy_revision' !~ '^[1-9][0-9]{0,15}$'
           or (c->>'policy_revision')::numeric>9007199254740991
           or jsonb_typeof(c->'batch_size') is distinct from 'number' or c->>'batch_size' !~ '^[1-9][0-9]*$'
           or (c->>'batch_size')::numeric>128
           or jsonb_typeof(c->'channels') is distinct from 'object'
           or jsonb_typeof(c->'channel_generations') is distinct from 'object'
           or not(c->'allow_event_ids'='null'::jsonb or jsonb_typeof(c->'allow_event_ids')='array')
           or not(c->'initial_read_hours'='"all"'::jsonb or jsonb_typeof(c->'initial_read_hours')='number'
               and c->>'initial_read_hours' ~ '^(0|[1-9][0-9]*)$' and (c->>'initial_read_hours')::numeric<=876000) then
            raise exception 'agent_ad_issuer_shape' using errcode='55000'; end if;
        if (select array_agg(key order by key) from jsonb_object_keys(c->'channels') key)
               is distinct from array['Directory Service','Security','System']
           or exists(select 1 from jsonb_each(c->'channels') v where jsonb_typeof(v.value)<>'boolean')
           or exists(select 1 from jsonb_each(c->'channel_generations') v where v.key not in('Security','System','Directory Service')
               or jsonb_typeof(v.value)<>'string' or length(v.value#>>'{}') not between 1 and 128)
           or (jsonb_typeof(c->'allow_event_ids')='array' and (jsonb_array_length(c->'allow_event_ids')>512
               or exists(select 1 from jsonb_array_elements(c->'allow_event_ids') v where jsonb_typeof(v)<>'number' or v::text !~ '^[0-9]+$'))) then
            raise exception 'agent_ad_issuer_shape' using errcode='55000'; end if;
    end loop;
    if (o is not null and (o#>>'{config,policy_revision}')::numeric>old.policy_revision)
       or (n is not null and (n#>>'{config,policy_revision}')::numeric>new.policy_revision) then
        raise exception 'agent_ad_issuer_transition' using errcode='55000'; end if;
    select * into m from public.sli_agent_module_bindings where agent_id=new.id and module_id='sli.windows.ad-dc';
    if m.agent_id is not null then
        if n is null or o is null or m.source_instance_id is distinct from new.host_id::text
           or m.channel<>'ad-dc' or m.module_version<>'1.0.0'
           or m.source_name is distinct from n#>>'{config,source_name}'
           or m.source_name is distinct from o#>>'{config,source_name}' then
            raise exception 'agent_ad_issuer_identity' using errcode='55000'; end if;
    end if;
    if o is not distinct from n then return new; end if;
    if n is null or old.id is distinct from new.id or old.host_id is distinct from new.host_id
       or old.status<>'active' or new.status<>'active' or new.policy_revision<>old.policy_revision+1
       or new.policy_revision not between 1 and 9007199254740991
       or n#>>'{config,policy_revision}' is distinct from new.policy_revision::text then
        raise exception 'agent_ad_issuer_transition' using errcode='55000'; end if;
    if current_setting('transaction_isolation')<>'read committed' then
        raise exception 'agent_ad_issuer_isolation' using errcode='55000'; end if;
    if m.agent_id is null and o->'enabled'='true'::jsonb then
        raise exception 'agent_ad_issuer_legacy_unavailable' using errcode='55000'; end if;
    if m.agent_id is not null and o->'enabled'='true'::jsonb and m.policy_revision is distinct from o#>>'{config,policy_revision}' then
        raise exception 'agent_ad_issuer_identity' using errcode='55000'; end if;
    if n->'enabled'<>'true'::jsonb then return new; end if;
    if not exists(select 1 from public.sli_agent_policy_history h where h.agent_id=new.id and h.revision=new.policy_revision
        and h.assigned_modules=new.assigned_modules and h.staged_xact_id=pg_current_xact_id()) then
        raise exception 'agent_ad_issuer_staging' using errcode='55000'; end if;
    if exists(select 1 from public.sli_agent_policy_history h where h.agent_id=new.id and
        (h.revision=old.policy_revision and h.assigned_modules is distinct from old.assigned_modules
         or h.revision>old.policy_revision and not(h.revision=new.policy_revision and h.assigned_modules=new.assigned_modules
             and h.staged_xact_id is not null and h.staged_xact_id=pg_current_xact_id()))) then
        raise exception 'agent_ad_issuer_staging' using errcode='55000'; end if;
    if m.agent_id is null then
        for history_row in select * from public.sli_agent_policy_history h where h.agent_id=new.id
            and not(h.revision=new.policy_revision and h.assigned_modules=new.assigned_modules
                and h.staged_xact_id is not null and h.staged_xact_id=pg_current_xact_id()) loop
            if exists(select 1 from jsonb_array_elements(history_row.assigned_modules) v where v='"sli.windows.ad-dc"'::jsonb)
               or (select count(*) from jsonb_array_elements(history_row.assigned_modules) v where v->>'module_id'='sli.windows.ad-dc')>1 then
                raise exception 'agent_ad_issuer_legacy_unavailable' using errcode='55000'; end if;
            select v into prior from jsonb_array_elements(history_row.assigned_modules) v where v->>'module_id'='sli.windows.ad-dc';
            -- Retained disabled metadata must meet the same complete standard as OLD/NEW.
            if prior is not null then
                c:=prior->'config';
                if (select array_agg(key order by key) from jsonb_object_keys(prior) key) is distinct from array['config','enabled','module_id']
                   or prior->'enabled' is distinct from 'false'::jsonb or jsonb_typeof(c) is distinct from 'object' then
                    raise exception 'agent_ad_issuer_legacy_unavailable' using errcode='55000'; end if;
                if (select array_agg(key order by key) from jsonb_object_keys(c) key) is distinct from metadata_keys
                   or jsonb_typeof(c->'source_name') is distinct from 'string' or length(c->>'source_name') not between 1 and 128
                   or length(btrim(c->>'source_name'))=0
                   or jsonb_typeof(c->'connect_address') is distinct from 'string' or length(c->>'connect_address') not between 1 and 128
                   or length(btrim(c->>'connect_address'))=0
                   or jsonb_typeof(c->'policy_revision') is distinct from 'string' or c->>'policy_revision' !~ '^[1-9][0-9]{0,15}$'
                   or (c->>'policy_revision')::numeric>9007199254740991
                   or jsonb_typeof(c->'batch_size') is distinct from 'number' or c->>'batch_size' !~ '^[1-9][0-9]*$'
                   or (c->>'batch_size')::numeric>128
                   or jsonb_typeof(c->'channels') is distinct from 'object'
                   or jsonb_typeof(c->'channel_generations') is distinct from 'object'
                   or not(c->'allow_event_ids'='null'::jsonb or jsonb_typeof(c->'allow_event_ids')='array')
                   or not(c->'initial_read_hours'='"all"'::jsonb or jsonb_typeof(c->'initial_read_hours')='number'
                       and c->>'initial_read_hours' ~ '^(0|[1-9][0-9]*)$' and (c->>'initial_read_hours')::numeric<=876000) then
                    raise exception 'agent_ad_issuer_legacy_unavailable' using errcode='55000'; end if;
                if (select array_agg(key order by key) from jsonb_object_keys(c->'channels') key)
                       is distinct from array['Directory Service','Security','System']
                   or exists(select 1 from jsonb_each(c->'channels') v where jsonb_typeof(v.value)<>'boolean')
                   or exists(select 1 from jsonb_each(c->'channel_generations') v where v.key not in('Security','System','Directory Service')
                       or jsonb_typeof(v.value)<>'string' or length(v.value#>>'{}') not between 1 and 128)
                   or (jsonb_typeof(c->'allow_event_ids')='array' and (jsonb_array_length(c->'allow_event_ids')>512
                       or exists(select 1 from jsonb_array_elements(c->'allow_event_ids') v where jsonb_typeof(v)<>'number' or v::text !~ '^[0-9]+$'))) then
                    raise exception 'agent_ad_issuer_legacy_unavailable' using errcode='55000'; end if;
                if (prior#>>'{config,policy_revision}')::numeric>history_row.revision then
                    raise exception 'agent_ad_issuer_legacy_unavailable' using errcode='55000'; end if;
            end if;
        end loop;
    end if;
    select count(*) into count_live from public.semantic_default_installation;
    if count_live<>1 then raise exception 'agent_ad_issuer_installation' using errcode='55000'; end if;
    select installation_id into strict installation from public.semantic_default_installation;
    if installation is null then raise exception 'agent_ad_issuer_installation' using errcode='55000'; end if;
    scope:=jsonb_build_object('installation_id',installation::text,'plugin_id','sli.windows.ad-dc',
        'source_instance_id',new.host_id::text,'source_generation',new.host_id::text,'collection_scope_id','');
    perform pg_advisory_xact_lock(hashtextextended(encode(public.password_v2_scope_key(scope),'hex'),0));
    -- Separate post-lock query: READ COMMITTED sees a competing committed issuer.
    if exists(select 1 from public.sli_agent_module_bindings where module_id='sli.windows.ad-dc'
        and source_instance_id=new.host_id::text and agent_id<>new.id) then
        raise exception 'agent_ad_issuer_claim' using errcode='55000'; end if;
    select * into m from public.sli_agent_module_bindings where agent_id=new.id and module_id='sli.windows.ad-dc' for update;
    if m.agent_id is null then
        insert into public.sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
        values(new.id,'sli.windows.ad-dc',new.host_id::text,n#>>'{config,source_name}','ad-dc','1.0.0',n#>>'{config,policy_revision}');
    else
        update public.sli_agent_module_bindings set policy_revision=n#>>'{config,policy_revision}'
            where agent_id=new.id and module_id='sli.windows.ad-dc';
    end if;
    return new;
end $$;
revoke all on function public.agent_ad_issue_binding() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
create trigger agent_ad_binding_issuer before update of assigned_modules on public.sli_agents
    for each row execute function public.agent_ad_issue_binding();
alter table public.sli_agents enable always trigger agent_ad_binding_issuer;
do $$ begin
    if exists(select 1 from pg_proc p cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        where p.oid in('public.agent_ad_stamp_history()'::regprocedure,'public.agent_ad_issue_binding()'::regprocedure)
        and a.grantee<>p.proowner) then
        raise exception 'agent_ad_issuer_private_acl' using errcode='42501'; end if;
end $$;
insert into public.schema_migrations(version,name) values(274,'agent_ad_binding_issuer');
commit;
