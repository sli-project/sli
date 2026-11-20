-- Extend the guarded UI transition to registered, registry-managed importers.
-- VPN keeps its component admission/drain executor; no existing migration changes.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_plugin_state_v166'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 166 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=152 and name='plugin_state')
       or not exists(select 1 from public.schema_migrations where version=160 and name='agent_workstation_dispatch')
       or exists(select 1 from public.schema_migrations where version>=166) then
        raise exception 'migration 166 requires migrations 152 and 160 and an unused version 166';
    end if;
end $$;

grant usage,create on schema public to adlog_plugin_lifecycle_owner;
set local role adlog_plugin_lifecycle_owner;
create or replace function public.set_plugin_enabled_v1(p_plugin_id text,p_enabled boolean,
    p_revision bigint,p_actor_kind text,p_actor_id bigint,p_configured boolean)
returns table(plugin_id text,package_version text,installed boolean,configured boolean,
    enabled boolean,receiving_data boolean,component_runtime text,queue_state text,
    revision bigint,last_data_at_utc text)
language plpgsql security definer set search_path=pg_catalog,public
as $$
declare
    v_current public.plugin_installations_v1%rowtype;
    v_authorized boolean := false;
    v_configured boolean;
    v_action text;
    v_digest text;
    v_confirmation text;
    v_operation_uid uuid;
begin
    if p_actor_kind='session' then
        select exists(select 1 from public.auth_users u where u.id=p_actor_id
            and u.is_active and (u.role='admin' or exists(
                select 1 from public.access_platform_owners o where o.user_id=u.id))) into v_authorized;
    elsif p_actor_kind='api_key' then
        select exists(select 1 from public.auth_api_keys k where k.id=p_actor_id
            and k.role='admin' and k.is_active and k.revoked_at is null
            and (k.expires_at is null or k.expires_at>now())) into v_authorized;
    end if;
    if not v_authorized then
        raise insufficient_privilege using message='plugin_management_owner_or_admin_required';
    end if;
    if p_plugin_id is null or p_enabled is null or p_revision is null or p_revision<1 then
        raise exception 'plugin_state_request_invalid';
    end if;

    -- Shared with VPN admission and the agent packet publication transaction.
    perform pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));
    select i.* into v_current from public.plugin_installations_v1 i
        where i.plugin_id=p_plugin_id for update;
    if not found then raise exception 'plugin_not_found'; end if;
    if v_current.revision<>p_revision then raise exception 'plugin_revision_conflict'; end if;
    if v_current.package_lifecycle<>'registered' then raise exception 'plugin_not_installed'; end if;

    if p_plugin_id='sli.remote-access' then
        if p_configured is null then raise exception 'plugin_state_request_invalid'; end if;
        v_configured := p_configured;
    else
        -- Generic callers cannot override the persisted configuration readiness.
        select coalesce(s.configured,false) into v_configured
            from public.plugin_state_v1 s where s.plugin_id=p_plugin_id;
        v_configured := coalesce(v_configured,false);
    end if;
    if p_enabled and not v_configured then raise exception 'plugin_not_configured'; end if;

    if (v_current.desired_activation='enabled_manual')<>p_enabled then
        if p_enabled and v_current.component_runtime<>'stopped' then
            raise exception 'plugin_runtime_not_stopped';
        elsif not p_enabled and v_current.component_runtime not in ('running','failed') then
            raise exception 'plugin_runtime_not_running';
        end if;
        v_operation_uid := gen_random_uuid();
        if p_plugin_id='sli.remote-access' then
            if p_enabled and v_current.queue_state<>'drained' then
                raise exception 'plugin_queue_not_drained';
            end if;
            if p_enabled and exists(select 1 from public.plugin_component_leases_v1 l
                where l.plugin_id=p_plugin_id and l.released_at_utc is null
                  and l.expires_at_utc>clock_timestamp()) then
                raise exception 'plugin_active_leases';
            end if;
            v_action := case when p_enabled then 'enable' else 'drain' end;
            v_digest := encode(sha256(convert_to(p_plugin_id||':'||v_action||':'||p_revision,'UTF8')),'hex');
            perform * from public.execute_plugin_runtime_transition_v1(
                v_operation_uid,v_action,p_revision,v_digest,
                format('PLUGIN-%s-SLI-REMOTE-ACCESS-R%s-%s',upper(v_action),p_revision,upper(substr(v_digest,1,12))),
                p_actor_kind,p_actor_id::text);
        else
            -- Registry-managed importers have no component drain protocol. The
            -- shared lock finishes any admitted import before disable commits;
            -- waiting inbox packets are retained for the next explicit enable.
            -- Never bypass a future plugin's component admission/queue protocol.
            if exists(select 1 from public.plugin_component_admission_v1 a where a.plugin_id=p_plugin_id) then
                raise exception 'plugin_runtime_transition_unsupported';
            end if;
            if v_current.queue_state<>'drained' then raise exception 'plugin_queue_not_drained'; end if;
            if exists(select 1 from public.plugin_component_leases_v1 l
                where l.plugin_id=p_plugin_id and l.released_at_utc is null
                  and l.expires_at_utc>clock_timestamp()) then
                raise exception 'plugin_active_leases';
            end if;
            v_action := case when p_enabled then 'enable' else 'disable' end;
            v_digest := encode(sha256(convert_to(p_plugin_id||':'||v_action||':'||p_revision,'UTF8')),'hex');
            v_confirmation := format('PLUGIN-%s-%s-R%s-%s',upper(v_action),
                upper(replace(p_plugin_id,'.','-')),p_revision,upper(substr(v_digest,1,12)));
            update public.plugin_installations_v1 i
                set desired_activation=case when p_enabled then 'enabled_manual' else 'disabled' end,
                    observed_health='unknown',
                    component_runtime=case when p_enabled then 'running' else 'stopped' end,
                    queue_state='drained',revision=i.revision+1,updated_at_utc=now()
                where i.plugin_id=p_plugin_id and i.revision=p_revision;
            if not found then raise exception 'plugin_revision_conflict'; end if;
            insert into public.plugin_lifecycle_operations_v1(
                operation_uid,plugin_id,requested_action,expected_revision,committed_revision,
                plan_sha256,confirmation_sha256,actor_kind,actor_key,outcome,reason_code)
            values(v_operation_uid,p_plugin_id,v_action,p_revision,p_revision+1,
                v_digest,encode(sha256(convert_to(v_confirmation,'UTF8')),'hex'),
                p_actor_kind,p_actor_id::text,'succeeded',null);
            perform * from public.append_administrative_activity_v1(
                v_operation_uid,clock_timestamp(),p_actor_kind,p_actor_id::text,
                'plugin_lifecycle','plugin.'||v_action,'plugin',p_plugin_id,'succeeded',null,
                jsonb_build_object('expected_revision',p_revision,'committed_revision',p_revision+1,
                    'plan_sha256',v_digest,'active_leases',0,'nonterminal_deliveries',0),null,v_operation_uid);
        end if;
    end if;
    insert into public.plugin_state_v1(plugin_id,configured) values(p_plugin_id,v_configured)
        on conflict on constraint plugin_state_v1_pkey do update
            set configured=excluded.configured,updated_at_utc=now();
    return query select * from public.read_plugin_states_v1() s where s.plugin_id=p_plugin_id;
end $$;
revoke all on function public.set_plugin_enabled_v1(text,boolean,bigint,text,bigint,boolean) from public;
grant execute on function public.set_plugin_enabled_v1(text,boolean,bigint,text,bigint,boolean) to adlog_user;
reset role;
revoke create on schema public from adlog_plugin_lifecycle_owner;
insert into public.schema_migrations(version,name) values(166,'registered_plugin_activation');
commit;
