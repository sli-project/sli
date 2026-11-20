-- Same-machine, drain-fenced runtime replacement. No collection or backfill.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_agent_runtime_switch_v296'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role('adlog_storage_owner','adlog_file_audit_owner','MEMBER') then
        raise exception 'agent_runtime_switch_preflight' using errcode='55000';
    end if;
    if not exists(select 1 from public.schema_migrations where version=274 and name='agent_ad_binding_issuer')
       or not exists(select 1 from public.schema_migrations where version=281 and name='agent_registration_hostname')
       or not exists(select 1 from public.schema_migrations where version=287 and name='workstation_inventory_job')
       or exists(select 1 from public.schema_migrations where version>=296) then
        raise exception 'agent_runtime_switch_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Retain the exact pre-migration capabilities for an explicit, lossless rollback.
create table public.sli_agent_runtime_switch_restore_v296 (
    object_key text primary key,
    definition text not null,
    owner_name name not null,
    schema_name name not null
);
revoke all on public.sli_agent_runtime_switch_restore_v296
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker,adlog_file_audit_owner;
insert into public.sli_agent_runtime_switch_restore_v296
    select 'audit_constraint',pg_get_expr(conbin,conrelid),'adlog_storage_owner','public'
    from pg_constraint where conrelid='public.sli_agent_audit'::regclass
      and conname='sli_agent_audit_action_check';
insert into public.sli_agent_runtime_switch_restore_v296
    select 'issuer',pg_get_functiondef(p.oid),p.proowner::regrole::text,n.nspname
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where p.oid='public.agent_ad_issue_binding()'::regprocedure;
alter table public.sli_agents drop constraint sli_agents_status_check;
alter table public.sli_agents add constraint sli_agents_status_check check(status in ('active','disabled','replaced'));
-- Replacement authority is durable token metadata, never parsed from audit text.
-- Legacy enrollments remain unproven and cannot inherit another agent's source.
alter table public.sli_agent_enrollment_tokens
    add column replacement_for uuid references public.sli_agents(id),
    add column enrolled_agent_id uuid unique references public.sli_agents(id),
    add constraint sli_agent_enrollment_link_v296 check(enrolled_agent_id is null or used_at is not null);
grant update(enrolled_agent_id) on public.sli_agent_enrollment_tokens to adlog_user;
-- Transport identity is immutable. These fields are issued ONLY by replacement.
alter table public.sli_agents
    add column source_host_id uuid,
    add column source_agent_id uuid references public.sli_agents(id),
    add column runtime_resume jsonb not null default '{}'::jsonb check(jsonb_typeof(runtime_resume)='object');
grant select(source_host_id,source_agent_id) on public.sli_agents to adlog_file_audit_owner;
grant select(source_host_id,source_agent_id,status) on public.sli_agents to sli_workstation_inventory_owner;
create unique index sli_agents_active_source_v296 on public.sli_agents(coalesce(source_agent_id,id)) where status='active';

-- Private canonical/current lookups for existing native evidence capabilities.
-- Retired transport IDs remain valid provenance, never valid authentication.
create function public.agent_source_identity_v296(p_agent uuid) returns uuid
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select coalesce(source_agent_id,id) from public.sli_agents where id=p_agent
$$;
create function public.agent_current_runtime_v296(p_agent uuid) returns uuid
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select case when count(*)=1 then (array_agg(id))[1] end from public.sli_agents
      where coalesce(source_agent_id,id)=public.agent_source_identity_v296(p_agent) and status='active'
$$;
revoke all on function public.agent_source_identity_v296(uuid),public.agent_current_runtime_v296(uuid)
    from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
grant execute on function public.agent_source_identity_v296(uuid),public.agent_current_runtime_v296(uuid) to adlog_file_audit_owner;
create table public.sli_agent_runtime_switches (
    old_agent_id uuid primary key references public.sli_agents(id),
    new_agent_id uuid not null unique references public.sli_agents(id),
    state text not null check(state in ('draining','completed')),
    old_revision bigint not null,
    new_revision bigint not null,
    old_control jsonb not null,
    actor text not null check(length(actor) between 1 and 128 and actor !~ '[[:cntrl:]]'),
    requested_at timestamptz not null default clock_timestamp(),
    completed_at timestamptz,
    staged_xact_id xid8,
    staged_modules jsonb,
    staged_revision bigint,
    check(old_agent_id<>new_agent_id),
    check((state='completed')=(completed_at is not null))
);
revoke all on public.sli_agent_runtime_switches from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant select on public.sli_agent_runtime_switches to adlog_user;
do $$ declare prior text; begin
    select pg_get_expr(conbin,conrelid) into strict prior from pg_constraint
      where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action in (''runtime_switch_prepare'',''runtime_switch_complete''))',prior);
end $$;

-- INSERT permission on agents must not allow a caller to mint source authority.
create function public.agent_runtime_source_guard_v296() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if tg_op='INSERT' then
        if new.source_host_id is not null or new.source_agent_id is not null or new.runtime_resume<>'{}'::jsonb then
            raise exception 'agent_runtime_source_private' using errcode='42501';
        end if;
    elsif (new.source_host_id,new.source_agent_id,new.runtime_resume)
        is distinct from (old.source_host_id,old.source_agent_id,old.runtime_resume) then
        if not exists(select 1 from public.sli_agent_runtime_switches s
            join public.sli_agents a on a.id=s.old_agent_id
            where s.new_agent_id=new.id and s.state='draining' and s.staged_xact_id=pg_current_xact_id()
              and new.source_host_id=coalesce(a.source_host_id,a.host_id)
              and new.source_agent_id=coalesce(a.source_agent_id,a.id)) then
            raise exception 'agent_runtime_source_private' using errcode='42501';
        end if;
    end if;
    return new;
end $$;
revoke all on function public.agent_runtime_source_guard_v296() from public,adlog_user;
create trigger agent_runtime_source_guard before insert or update on public.sli_agents
    for each row execute function public.agent_runtime_source_guard_v296();
alter table public.sli_agents enable always trigger agent_runtime_source_guard;

-- Extend the exact existing issuer, retaining its shape, staging and ACL fences.
-- The exceptional transition can only be staged by the definer below, in this xact.
-- The storage owner has no database TEMP privilege on a clean installation.
-- Keep this helper private in its owned schema and drop it before commit.
create function public.agent_runtime_replace_definition_v296(definition text,needle text,replacement text) returns text
language plpgsql set search_path=pg_catalog,pg_temp as $$
declare changed text;
begin
    changed:=replace(definition,needle,replacement);
    if changed is not distinct from definition then
        raise exception 'migration_296_definition_drift' using errcode='55000';
    end if;
    return changed;
end $$;
revoke all on function public.agent_runtime_replace_definition_v296(text,text,text)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
do $$ declare definition text; begin
    select pg_get_functiondef('public.agent_ad_issue_binding()'::regprocedure) into definition;
    if position('-- OLD/NEW are actual locked rows' in definition)=0 then
        raise exception 'migration_296_definition_drift' using errcode='55000'; end if;
    definition:=public.agent_runtime_replace_definition_v296(definition,'new.host_id::text','coalesce(new.source_host_id,new.host_id)::text');
    definition:=public.agent_runtime_replace_definition_v296(definition,'    -- OLD/NEW are actual locked rows', $branch$
    if exists(select 1 from public.sli_agent_runtime_switches s
        where s.new_agent_id=new.id and s.state='draining' and s.staged_xact_id=pg_current_xact_id()
          and new.assigned_modules=s.staged_modules and new.policy_revision=s.staged_revision) then
        return new;
    end if;
    -- OLD/NEW are actual locked rows$branch$);
    -- Retired bindings stay as history. They no longer compete for live ownership.
    definition:=public.agent_runtime_replace_definition_v296(definition,'and source_instance_id=coalesce(new.source_host_id,new.host_id)::text and agent_id<>new.id)',
        'and source_instance_id=coalesce(new.source_host_id,new.host_id)::text and agent_id<>new.id
         and exists(select 1 from public.sli_agents a where a.id=agent_id and a.status=''active''))');
    execute definition;
end $$;


-- Cross-owner writes are confined to this private capability; no new table ACL.
set local role adlog_storage_owner;
grant select(old_agent_id,new_agent_id,state,staged_xact_id) on public.sli_agent_runtime_switches to adlog_file_audit_owner;
reset role;
set local role adlog_file_audit_owner;
grant usage on schema sli_plugin_file_audit to adlog_storage_owner;
create function sli_plugin_file_audit.copy_runtime_v296(p_old uuid,p_new uuid,p_revision bigint)
returns jsonb language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare a record; file_state jsonb; command jsonb; config jsonb;
begin
    if not exists(select 1 from public.sli_agent_runtime_switches where old_agent_id=p_old and new_agent_id=p_new
        and state='draining' and staged_xact_id=pg_current_xact_id()) then
        raise exception 'agent_runtime_source_private' using errcode='42501'; end if;
    select host_id,source_host_id,file_audit into strict a from public.sli_agents where id=p_old;
    file_state:=a.file_audit;
    if file_state ? 'request' then
        command:=file_state#>'{request,command}';
        command:=command||jsonb_build_object('command_id',gen_random_uuid()::text,'policy_revision',p_revision::text);
        config:=(file_state#>'{request,config}')||jsonb_build_object('policy_revision',p_revision::text);
        file_state:=jsonb_build_object('request',jsonb_build_object('config',config,'command',command),
            'state','pending','scopes','{}'::jsonb,'may_own_audit',coalesce((a.file_audit->>'may_own_audit')::boolean,false));
        insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            select p_new,source_instance_id,p.revision,authored_at,actor_kind,actor_id,policy,policy_sha256
            from sli_plugin_file_audit.policy_revisions p where agent_id=p_old;
        insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            select p_new,coalesce(a.source_host_id,a.host_id)::text,p_revision,clock_timestamp(),actor_kind,actor_id,config,
                encode(sha256(convert_to(config::text,'UTF8')),'hex')
            from sli_plugin_file_audit.policy_revisions where agent_id=p_old order by authored_at desc limit 1;
        insert into sli_plugin_file_audit.audit_commands(command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_ids,
            requested_at,actor_kind,actor_id,command_sha256)
            select command->>'command_id',p_new,coalesce(a.source_host_id,a.host_id)::text,p_revision,command->>'action',
                array(select jsonb_array_elements_text(command->'collection_scope_ids')),clock_timestamp(),actor_kind,actor_id,
                encode(sha256(convert_to(command::text,'UTF8')),'hex')
            from sli_plugin_file_audit.audit_commands where agent_id=p_old and command_id=a.file_audit#>>'{request,command,command_id}';
    else
        insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            select p_new,source_instance_id,p.revision,authored_at,actor_kind,actor_id,policy,policy_sha256
            from sli_plugin_file_audit.policy_revisions p where agent_id=p_old;
    end if;

    insert into sli_plugin_file_audit.settings
        select p_new,source_instance_id,enabled,source_payload_days,acl_history_days,facts_retention,file_event_cleanup_enabled,
            mass_operation_files,mass_operation_seconds,working_time_source
        from sli_plugin_file_audit.settings where agent_id=p_old;
    return file_state;
end $$;
revoke all on function sli_plugin_file_audit.copy_runtime_v296(uuid,uuid,bigint) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function sli_plugin_file_audit.copy_runtime_v296(uuid,uuid,bigint) to adlog_storage_owner;
reset role;
set local role adlog_storage_owner;

create function public.replace_agent_runtime_v296(p_old uuid,p_new uuid,p_phase text,p_actor text)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare a public.sli_agents%rowtype; b public.sli_agents%rowtype;
    s public.sli_agent_runtime_switches%rowtype; revision bigint; resumes jsonb; modules jsonb;
    file_state jsonb; cert record;
begin
    if p_old is null or p_new is null or p_old=p_new or p_phase not in ('prepare','complete')
       or p_phase is null or p_actor is null or length(p_actor) not between 1 and 128 or p_actor ~ '[[:cntrl:]]'
       or current_setting('transaction_isolation')<>'read committed' then
        raise exception 'agent_replacement_conflict' using errcode='55000'; end if;
    -- Shared with all mTLS/policy/import writers. Deterministic order avoids AB/BA.
    perform id from public.sli_agents where id in(p_old,p_new) order by id for update;
    select * into a from public.sli_agents where id=p_old;
    select * into b from public.sli_agents where id=p_new;
    select * into s from public.sli_agent_runtime_switches where old_agent_id=p_old;
    if s.old_agent_id is not null and s.new_agent_id=p_new and s.state='completed' then
        return jsonb_build_object('state','completed','old_agent_id',p_old,'new_agent_id',p_new);
    end if;
    if a.id is null or b.id is null or a.status<>'active' or b.status<>'active'
       or exists(select 1 from public.sli_agent_runtime_switches where
            (old_agent_id in(p_old,p_new) or new_agent_id in(p_old,p_new))
            and not(old_agent_id=p_old and new_agent_id=p_new)
            and not(state='completed' and new_agent_id=p_old)) then
        raise exception 'agent_replacement_conflict' using errcode='55000'; end if;
    -- The exact old runtime must have been authorized by the consumed,
    -- key-bound enrollment token. Group/ordinary tokens grant no source rights.
    if not exists(select 1 from public.sli_agent_enrollment_tokens t
        where t.enrolled_agent_id=p_new and t.replacement_for=p_old and t.used_at is not null
          and t.host_id=b.host_id
          and not exists(select 1 from public.sli_agent_group_approval_links g where g.enrollment_token_id=t.id)) then
        raise exception 'agent_replacement_token_mismatch' using errcode='55000'; end if;
    -- Display claims are an additional machine consistency check, never an ACL.
    if a.registration_host_name is null or b.registration_host_name is null
       or lower(a.registration_host_name)<>lower(b.registration_host_name) then
        raise exception 'agent_replacement_hostname_mismatch' using errcode='55000'; end if;
    if exists(select 1 from public.sli_agent_receipts where agent_id=p_new and module_id<>'sli.heartbeat')
       or exists(select 1 from public.sli_agent_snapshot_cycles where agent_id=p_new)
       or exists(select 1 from public.sli_agent_snapshot_bindings where agent_id=p_new)
       or exists(select 1 from public.sli_agent_module_bindings where agent_id=p_new and password_detection_domain_id is not null)
       or b.source_host_id is not null or b.file_audit<>'{}'::jsonb then
        raise exception 'agent_replacement_target_used' using errcode='55000'; end if;
    if not exists(select 1 from public.sli_agent_certificates where agent_id=p_new
        and revoked_at is null and not_after>clock_timestamp()) then
        raise exception 'agent_replacement_not_ready' using errcode='55000'; end if;
    if exists(select 1 from jsonb_array_elements(a.assigned_modules) m
        where jsonb_typeof(m)<>'object' or m->>'module_id' not in
            ('sli.windows.ad-dc','sli.workstations','sli.file-audit','sli.vpn-nps','sli.radius-accounting','sli.ad-snapshot','sli.gpo-snapshot','sli.heartbeat')
            and m->'enabled'='true'::jsonb) then
        raise exception 'agent_replacement_module_unsupported' using errcode='55000'; end if;
    if p_phase='prepare' then
        if s.old_agent_id is not null then
            if s.new_agent_id<>p_new then raise exception 'agent_replacement_conflict' using errcode='55000'; end if;
            return jsonb_build_object('state',s.state,'old_agent_id',p_old,'new_agent_id',p_new);
        end if;
        if greatest(a.policy_revision,b.policy_revision)>=9007199254740990 then
            raise exception 'agent_replacement_conflict' using errcode='55000'; end if;
        insert into public.sli_agent_runtime_switches(old_agent_id,new_agent_id,state,old_revision,new_revision,old_control,actor)
            values(p_old,p_new,'draining',a.policy_revision+1,b.policy_revision+1,a.collection_policy,p_actor);
        insert into public.sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
            select id,policy_revision,assigned_modules,collection_policy from public.sli_agents where id in(p_old,p_new)
            on conflict do nothing;
        insert into public.sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
            select id,policy_revision+1,assigned_modules,jsonb_set(collection_policy,'{state}','"drain"')
            from public.sli_agents where id in(p_old,p_new);
        update public.sli_agents set collection_policy=jsonb_set(collection_policy,'{state}','"drain"'),
            policy_revision=policy_revision+1,applied_collection_state='unknown' where id in(p_old,p_new);
        insert into public.sli_agent_audit(action,actor,target,details) values('runtime_switch_prepare',p_actor,p_old::text,
            jsonb_build_object('new_agent_id',p_new));
        return jsonb_build_object('state','draining','old_agent_id',p_old,'new_agent_id',p_new);
    end if;
    if s.old_agent_id is null or s.new_agent_id<>p_new then
        raise exception 'agent_replacement_conflict' using errcode='55000'; end if;
    if a.policy_revision<>s.old_revision or b.policy_revision<>s.new_revision
       or a.collection_policy->>'state'<>'drain' or b.collection_policy->>'state'<>'drain' then
        raise exception 'agent_replacement_policy_changed' using errcode='55000'; end if;
    if a.applied_policy_revision<>a.policy_revision or b.applied_policy_revision<>b.policy_revision
       or a.applied_collection_state<>'paused' or b.applied_collection_state<>'paused' then
        raise exception 'agent_replacement_not_ready' using errcode='55000'; end if;
    if b.rights_probe->'runtime_handoff_supported' is distinct from 'true'::jsonb then
        raise exception 'agent_replacement_client_unsupported' using errcode='55000'; end if;
    if exists(select 1 from public.sli_agent_packet_inbox where envelope->>'agent_id' in(p_old::text,p_new::text) and imported_at is null)
       or exists(select 1 from public.sli_agent_snapshot_cycles where agent_id=p_old and publication_state='pending') then
        raise exception 'agent_replacement_pending_import' using errcode='55000'; end if;
    revision:=greatest(a.policy_revision,b.policy_revision)+1;
    select coalesce(jsonb_object_agg(module_id,jsonb_build_object('sequence',0,
        'source_instance_id',envelope->'source_instance_id','channel',envelope->'channel',
        'generation',envelope->'generation','cursor_after',envelope->'cursor_after')),'{}'::jsonb) into resumes
        from (select distinct on(module_id) module_id,envelope from public.sli_agent_receipts
              where agent_id=p_old and module_id in('sli.windows.ad-dc','sli.workstations','sli.file-audit','sli.vpn-nps','sli.radius-accounting')
              order by module_id,sequence desc) latest;
    -- A runtime can itself be replaced before every transferred module sends.
    resumes:=a.runtime_resume||resumes;
    -- Immutable capture policies/cursors keep their original module revisions.
    modules:=a.assigned_modules;
    update public.sli_agent_runtime_switches set staged_xact_id=pg_current_xact_id(),staged_modules=modules,staged_revision=revision
        where old_agent_id=p_old;
    file_state:=sli_plugin_file_audit.copy_runtime_v296(p_old,p_new,revision);
    if octet_length(modules::text)+octet_length(resumes::text)+octet_length(file_state::text)>56000 then
        raise exception 'agent_replacement_policy_size' using errcode='55000'; end if;
    -- Copy authority, retaining old bindings for immutable evidence resolution.
    delete from public.sli_agent_module_bindings where agent_id=p_new;
    insert into public.sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision,password_detection_domain_id)
        select p_new,module_id,source_instance_id,source_name,channel,module_version,policy_revision,password_detection_domain_id
        from public.sli_agent_module_bindings where agent_id=p_old;
    perform pg_advisory_xact_lock(170,1);
    update public.sli_agent_snapshot_bindings set enabled=false where agent_id=p_old;
    insert into public.sli_agent_snapshot_bindings(agent_id,module_id,config,enabled)
        select p_new,module_id,config,exists(select 1 from jsonb_array_elements(modules) m where m->>'module_id'=sb.module_id and m->'enabled'='true'::jsonb)
        from public.sli_agent_snapshot_bindings sb where agent_id=p_old;
    insert into public.sli_agent_snapshot_policies(agent_id,module_id,config,enabled,superseded_at)
        select p_new,module_id,config,enabled,superseded_at from public.sli_agent_snapshot_policies where agent_id=p_old;
    insert into public.sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
        values(p_new,revision,modules,s.old_control);
    update public.sli_agents set status='replaced',collection_policy=jsonb_set(collection_policy,'{state}','"paused"') where id=p_old;
    update public.sli_agents set source_host_id=coalesce(a.source_host_id,a.host_id),source_agent_id=coalesce(a.source_agent_id,a.id),
        runtime_resume=resumes,assigned_modules=modules,policy_revision=revision,collection_policy=s.old_control,
        applied_policy_revision=0,applied_collection_state='unknown',file_audit=file_state,windows_audit='{}'::jsonb where id=p_new;
    perform pg_advisory_xact_lock(hashtext('sli-agent-revocations'));
    for cert in update public.sli_agent_certificates set revoked_at=clock_timestamp()
        where agent_id=p_old and revoked_at is null returning serial loop
        insert into public.sli_agent_audit(action,actor,target,details) values('revoke',p_actor,p_old::text,jsonb_build_object('serial',cert.serial));
    end loop;
    update public.sli_agent_runtime_switches set state='completed',completed_at=clock_timestamp(),staged_xact_id=null
        where old_agent_id=p_old;
    insert into public.sli_agent_audit(action,actor,target,details) values('runtime_switch_complete',p_actor,p_old::text,
        jsonb_build_object('new_agent_id',p_new,'source_host_id',coalesce(a.source_host_id,a.host_id),'revision',revision));
    return jsonb_build_object('state','completed','old_agent_id',p_old,'new_agent_id',p_new,'policy_revision',revision);
end $$;
revoke all on function public.replace_agent_runtime_v296(uuid,uuid,text,text) from public,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.replace_agent_runtime_v296(uuid,uuid,text,text) to adlog_user;

-- Existing definer capabilities must compare data identity, never transport SAN.
-- Recreate ONLY functions that use host_id, preserving their owners and ACLs.
do $$ declare f record; definition text; changed text; begin
    for f in select p.oid,p.proname,p.proowner::regrole::text as owner_name,n.nspname,
        has_schema_privilege(p.proowner,n.oid,'CREATE') as had_create
        from pg_proc p join pg_namespace n on n.oid=p.pronamespace
        where (n.nspname='sli_plugin_file_audit' and p.proname in
            ('enqueue_audit','retain_assignment_policy','collection_context','collection_context_for_packet',
             'store_collection','collection_replay','rule_context','publish_rules'))
        or (n.nspname='public' and p.proname in
            ('file_audit_snapshot_provenance_v264','file_acl_resource_allowed_v265','read_default_file_acl_resources','file_acl_link_binding_v265',
             'password_v2_configured_identity','resolve_finding_evidence_ref','resolve_agent_workstation_v160'))
        or (n.nspname='sli_plugin_workstations' and p.proname='inventory_inputs_v1') loop
        definition:=pg_get_functiondef(f.oid);
        changed:=definition;
        if f.proname='enqueue_audit' then
            changed:=public.agent_runtime_replace_definition_v296(changed,'and host_id::text=p_source','and coalesce(source_host_id,host_id)::text=p_source');
        elsif f.proname='file_audit_snapshot_provenance_v264' then
            if position('declare snap ' in definition)>0 then
                changed:=public.agent_runtime_replace_definition_v296(changed,'agent.host_id','coalesce(agent.source_host_id,agent.host_id)');
            end if;
        elsif f.proname<>'resolve_finding_evidence_ref' then
            changed:=public.agent_runtime_replace_definition_v296(changed,'a.host_id','coalesce(a.source_host_id,a.host_id)');
        end if;
        if position('password_v2_configured_identity' in definition)>0 then
            changed:=public.agent_runtime_replace_definition_v296(changed,'where id=p_agent;', 'where id=public.agent_current_runtime_v296(p_agent);');
            changed:=public.agent_runtime_replace_definition_v296(changed,'where agent_id=p_agent and module_id=', 'where agent_id=a.id and module_id=');
            changed:=public.agent_runtime_replace_definition_v296(changed,'f.agent_id=p_agent', 'f.agent_id=public.agent_source_identity_v296(p_agent)');
        end if;
        if position('resolve_finding_evidence_ref' in definition)>0 then
            changed:=public.agent_runtime_replace_definition_v296(changed,'inbox.envelope->>''agent_id''=b.agent_id::text',
                'public.agent_source_identity_v296(receipt.agent_id)=b.agent_id');
            changed:=public.agent_runtime_replace_definition_v296(changed,'o.agent_id=b.agent_id', 'public.agent_source_identity_v296(o.agent_id)=b.agent_id');
            changed:=public.agent_runtime_replace_definition_v296(changed,'file_ransom_evidence_in_root(b.agent_id,', 'file_ransom_evidence_in_root(o.agent_id,');
            changed:=public.agent_runtime_replace_definition_v296(changed,'file_decoy_evidence_in_root(b.agent_id,', 'file_decoy_evidence_in_root(o.agent_id,');
        end if;
        if position('file_audit_snapshot_provenance_v264' in definition)>0 and position('declare snap ' in definition)>0 then
            changed:=public.agent_runtime_replace_definition_v296(changed,'snapshot_id=p_snapshot and agent_id=p_agent',
                'snapshot_id=p_snapshot and public.agent_source_identity_v296(agent_id)=public.agent_source_identity_v296(p_agent)');
            changed:=public.agent_runtime_replace_definition_v296(changed,'agent.id=p_agent', 'agent.id=public.agent_current_runtime_v296(p_agent)');
            changed:=public.agent_runtime_replace_definition_v296(changed,'c.agent_id=p_agent', 'c.agent_id=snap.agent_id');
            changed:=public.agent_runtime_replace_definition_v296(changed,'p.agent_id=p_agent', 'p.agent_id=snap.agent_id');
            changed:=public.agent_runtime_replace_definition_v296(changed,'receipt.agent_id=p_agent', 'receipt.agent_id=snap.agent_id');
        end if;
        if position('inventory_inputs_v1' in definition)>0 then
            changed:=public.agent_runtime_replace_definition_v296(changed,'a.id::text','coalesce(a.source_agent_id,a.id)::text');
            changed:=public.agent_runtime_replace_definition_v296(changed,'from public.sli_agents a where exists(', 'from public.sli_agents a where a.status<>''replaced'' and exists(');
        end if;
        if position('resolve_agent_workstation_v160' in definition)>0 then
            changed:=public.agent_runtime_replace_definition_v296(changed,'v_host uuid;','v_host uuid; v_source_agent uuid;');
            changed:=public.agent_runtime_replace_definition_v296(changed,'select coalesce(a.source_host_id,a.host_id) into v_host',
                'select coalesce(a.source_host_id,a.host_id),coalesce(a.source_agent_id,a.id) into v_host,v_source_agent');
            changed:=public.agent_runtime_replace_definition_v296(changed,'p_agent::text','v_source_agent::text');
        end if;
        if changed<>definition then
            if not pg_has_role(session_user,f.owner_name,'MEMBER') then
                raise exception 'agent_runtime_switch_owner_membership' using errcode='42501';
            end if;
            insert into public.sli_agent_runtime_switch_restore_v296
                values(f.oid::text,definition,f.owner_name,f.nspname);
            if not f.had_create then
                reset role;
                execute format('grant create on schema %I to %I',f.nspname,f.owner_name);
            end if;
            execute format('set local role %I',f.owner_name);
            execute changed;
            if not f.had_create then
                reset role;
                execute format('revoke create on schema %I from %I',f.nspname,f.owner_name);
            end if;
            set local role adlog_storage_owner;
        end if;
    end loop;
end $$;
drop function public.agent_runtime_replace_definition_v296(text,text,text);
insert into public.schema_migrations(version,name) values(296,'agent_runtime_switch');
commit;
