-- Unified observed axes supplement, rather than duplicate, installation state.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_plugin_state_v152'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 152 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from schema_migrations where version=151 and name='organization_neutral_radius_access')
       or not exists(select 1 from schema_migrations where version=76 and name='plugin_runtime_activation_executor')
       or not exists(select 1 from schema_migrations where version=78 and name='plugin_runtime_guard_read_boundary') then
        raise exception 'migration 152 requires exact migrations 151, 076 and 078';
    end if;
    if exists(select 1 from schema_migrations where version=152) then
        raise exception 'migration 152 already applied';
    end if;
end
$$;

grant usage,create on schema public to adlog_plugin_lifecycle_owner;
create table plugin_state_v1 (
    plugin_id text primary key references plugin_installations_v1(plugin_id),
    configured boolean not null default false,
    last_data_at_utc timestamptz,
    updated_at_utc timestamptz not null default now()
);
insert into plugin_state_v1(plugin_id) select plugin_id from plugin_installations_v1;
revoke all on plugin_state_v1 from public,adlog_user;
alter table plugin_state_v1 owner to adlog_plugin_lifecycle_owner;

-- A future plugin's queue must not prevent the VPN plugin from draining.
create or replace function read_plugin_runtime_queue_nonterminal_v1()
returns bigint language sql stable security definer set search_path=pg_catalog,public
as $$
    select count(*)::bigint from public.acquisition_delivery_outbox delivery
    join public.acquisition_consumer_subscriptions subscription
      on subscription.subscription_id=delivery.subscription_id
    where subscription.consumer_id='sli.windows.vpn-radius'
      and subscription.consumer_component_id='radius-session-observation'
      and delivery.delivery_state in ('queued','leased','failed','quarantined')
$$;

-- Only safe state, without endpoint identities, credentials or event payloads.
create function read_plugin_states_v1()
returns table(plugin_id text,package_version text,installed boolean,configured boolean,
    enabled boolean,receiving_data boolean,component_runtime text,queue_state text,
    revision bigint,last_data_at_utc text)
language sql stable security definer set search_path=pg_catalog,public
as $$
    select i.plugin_id,i.package_version,i.package_lifecycle='registered',
           coalesce(s.configured,false),i.desired_activation='enabled_manual',
           coalesce(i.desired_activation='enabled_manual'
               and s.last_data_at_utc>now()-interval '10 minutes',false),
           i.component_runtime,i.queue_state,i.revision,s.last_data_at_utc::text
    from public.plugin_installations_v1 i
    left join public.plugin_state_v1 s using(plugin_id)
    order by i.plugin_id limit 20
$$;

-- The API passes an authenticated numeric actor id, never client-supplied roles.
grant select(id,role,is_active) on auth_users to adlog_plugin_lifecycle_owner;
grant select(user_id) on access_platform_owners to adlog_plugin_lifecycle_owner;
grant select(id,role,is_active,revoked_at,expires_at) on auth_api_keys to adlog_plugin_lifecycle_owner;

create function set_plugin_enabled_v1(p_plugin_id text,p_enabled boolean,
    p_revision bigint,p_actor_kind text,p_actor_id bigint,p_configured boolean)
returns table(plugin_id text,package_version text,installed boolean,configured boolean,
    enabled boolean,receiving_data boolean,component_runtime text,queue_state text,
    revision bigint,last_data_at_utc text)
language plpgsql security definer set search_path=pg_catalog,public
as $$
declare
    v_current plugin_installations_v1%rowtype;
    v_action text;
    v_digest text;
    v_authorized boolean := false;
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
    if p_plugin_id is distinct from 'sli.remote-access' or p_enabled is null
       or p_revision is null or p_configured is null then
        raise exception 'plugin_state_request_invalid';
    end if;
    -- Serialize with acquisition admission and the existing runtime executor.
    perform pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));
    select * into v_current from public.plugin_installations_v1
        where plugin_installations_v1.plugin_id=p_plugin_id for update;
    if not found or v_current.revision<>p_revision or v_current.package_lifecycle<>'registered'
       or (p_enabled and (not p_configured or (
           v_current.desired_activation='disabled' and v_current.component_runtime<>'stopped'))) then
        return;
    end if;
    if (v_current.desired_activation='enabled_manual')<>p_enabled then
        v_action := case when p_enabled then 'enable' else 'drain' end;
        v_digest := encode(sha256(convert_to(p_plugin_id||':'||v_action||':'||p_revision,'UTF8')),'hex');
        perform * from public.execute_plugin_runtime_transition_v1(
            gen_random_uuid(),v_action,p_revision,v_digest,
            format('PLUGIN-%s-SLI-REMOTE-ACCESS-R%s-%s',upper(v_action),p_revision,upper(substr(v_digest,1,12))),
            p_actor_kind,p_actor_id::text);
    end if;
    insert into public.plugin_state_v1(plugin_id,configured) values(p_plugin_id,p_configured)
        on conflict on constraint plugin_state_v1_pkey do update
            set configured=excluded.configured,updated_at_utc=now();
    return query select * from public.read_plugin_states_v1() s where s.plugin_id=p_plugin_id;
end
$$;

-- Host observations: a successful idle poll is not proof of incoming data.
create function observe_remote_access_plugin_v1(p_configured boolean,p_received boolean)
returns void language sql security definer set search_path=pg_catalog,public
as $$
    insert into public.plugin_state_v1(plugin_id,configured,last_data_at_utc)
    values('sli.remote-access',p_configured,case when p_received then now() end)
    on conflict(plugin_id) do update set configured=excluded.configured,
        last_data_at_utc=coalesce(excluded.last_data_at_utc,plugin_state_v1.last_data_at_utc),
        updated_at_utc=now()
$$;

create function finish_remote_access_plugin_drain_v1()
returns boolean language plpgsql security definer set search_path=pg_catalog,public
as $$
declare
    v_current plugin_installations_v1%rowtype;
    v_digest text;
begin
    perform pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));
    select * into v_current from public.plugin_installations_v1
        where plugin_id='sli.remote-access' for update;
    if not found or v_current.desired_activation<>'disabled'
       or v_current.component_runtime<>'draining' then return false; end if;
    if exists(select 1 from public.plugin_component_leases_v1
        where plugin_id='sli.remote-access' and released_at_utc is null
          and expires_at_utc>clock_timestamp())
       or public.read_plugin_runtime_queue_nonterminal_v1()<>0 then return false; end if;
    v_digest := encode(sha256(convert_to('sli.remote-access:disable:'||v_current.revision,'UTF8')),'hex');
    perform * from public.execute_plugin_runtime_transition_v1(
        gen_random_uuid(),'disable',v_current.revision,v_digest,
        format('PLUGIN-DISABLE-SLI-REMOTE-ACCESS-R%s-%s',v_current.revision,upper(substr(v_digest,1,12))),
        'system','plugin_drain');
    return true;
end
$$;

revoke all on function read_plugin_states_v1() from public;
revoke all on function set_plugin_enabled_v1(text,boolean,bigint,text,bigint,boolean) from public;
revoke all on function observe_remote_access_plugin_v1(boolean,boolean) from public;
revoke all on function finish_remote_access_plugin_drain_v1() from public;
grant execute on function read_plugin_states_v1(),
    set_plugin_enabled_v1(text,boolean,bigint,text,bigint,boolean),
    observe_remote_access_plugin_v1(boolean,boolean),
    finish_remote_access_plugin_drain_v1() to adlog_user;
alter function read_plugin_states_v1() owner to adlog_plugin_lifecycle_owner;
alter function set_plugin_enabled_v1(text,boolean,bigint,text,bigint,boolean) owner to adlog_plugin_lifecycle_owner;
alter function observe_remote_access_plugin_v1(boolean,boolean) owner to adlog_plugin_lifecycle_owner;
alter function finish_remote_access_plugin_drain_v1() owner to adlog_plugin_lifecycle_owner;
revoke create on schema public from adlog_plugin_lifecycle_owner;

insert into schema_migrations(version,name) values(152,'plugin_state');
commit;
