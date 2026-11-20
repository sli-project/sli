-- Exact bundled install executor for the disabled Stage 10 plugin lifecycle.
-- This migration does not start processes, contact sources, or enable runtime.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_install_v74'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 074 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=73 and name='plugin_lifecycle_registry'
    ) then
        raise exception 'migration 074 requires migration 073';
    end if;
    if to_regprocedure(
        'public.execute_bundled_plugin_install_v1(uuid,text,bigint,text,text,text,text)'
    ) is not null then
        raise exception 'migration 074 requires absent install executor';
    end if;
end
$$;

grant execute on function append_administrative_activity_v1(
    uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,inet,uuid
) to adlog_plugin_lifecycle_owner;

create function execute_bundled_plugin_install_v1(
    p_operation_uid uuid,
    p_plugin_id text,
    p_expected_revision bigint,
    p_plan_sha256 text,
    p_confirmation text,
    p_actor_kind text,
    p_actor_key text
)
returns table(
    operation_id bigint,
    committed_revision bigint,
    package_lifecycle text,
    desired_activation text
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_current plugin_installations_v1%rowtype;
    v_existing plugin_lifecycle_operations_v1%rowtype;
    v_confirmation_sha256 text;
    v_required_confirmation text;
    v_committed_revision bigint;
begin
    if p_operation_uid is null
       or p_plugin_id <> 'sli.remote-access'
       or p_expected_revision < 1
       or p_plan_sha256 !~ '^[0-9a-f]{64}$'
       or p_actor_kind not in ('session','api_key','windows','system','local_operator')
       or btrim(coalesce(p_actor_key,''))=''
       or length(p_actor_key)>200 then
        raise exception 'plugin install request is invalid';
    end if;
    v_required_confirmation := format(
        'PLUGIN-INSTALL-SLI-REMOTE-ACCESS-R%s-%s',
        p_expected_revision,
        upper(substr(p_plan_sha256,1,12))
    );
    if p_confirmation is distinct from v_required_confirmation then
        raise exception 'plugin install confirmation is invalid';
    end if;
    v_confirmation_sha256 := encode(
        sha256(convert_to(p_confirmation,'UTF8')),
        'hex'
    );

    perform pg_advisory_xact_lock(
        hashtext('ad_log_reports_plugin_install_v74')
    );
    select current.* into v_existing
    from plugin_lifecycle_operations_v1 current
    where current.operation_uid=p_operation_uid;
    if found then
        if v_existing.plugin_id<>p_plugin_id
           or v_existing.requested_action<>'install'
           or v_existing.expected_revision<>p_expected_revision
           or v_existing.plan_sha256<>p_plan_sha256
           or v_existing.confirmation_sha256<>v_confirmation_sha256
           or v_existing.actor_kind<>p_actor_kind
           or v_existing.actor_key<>p_actor_key
           or v_existing.outcome<>'succeeded'
           or v_existing.committed_revision is null then
            raise exception 'plugin install idempotency conflict';
        end if;
        return query
        select v_existing.operation_id,v_existing.committed_revision,
               current.package_lifecycle,current.desired_activation
        from plugin_installations_v1 current
        where current.plugin_id=p_plugin_id
          and current.revision=v_existing.committed_revision;
        if not found then
            raise exception 'plugin install replay state mismatch';
        end if;
        return;
    end if;

    select current.* into v_current
    from plugin_installations_v1 current
    where current.plugin_id=p_plugin_id
    for update;
    if not found
       or v_current.revision<>p_expected_revision
       or v_current.manifest_id<>'sli.remote-access.package.v1'
       or v_current.manifest_sha256<>
          '78ae9bcc2e65f54c8469dd0494f5c951df0cfa53ae33cff84478bc70eaa958bf'
       or v_current.package_version<>'0.1.0'
       or v_current.package_lifecycle<>'validated'
       or v_current.desired_activation<>'disabled'
       or v_current.component_runtime<>'stopped'
       or v_current.queue_state<>'drained' then
        raise exception 'plugin install state or revision is invalid';
    end if;

    v_committed_revision := v_current.revision+1;
    update plugin_installations_v1 current
    set package_lifecycle='registered',
        revision=v_committed_revision,
        updated_at_utc=now()
    where current.plugin_id=p_plugin_id
      and current.revision=p_expected_revision;
    if not found then
        raise exception 'plugin install optimistic update failed';
    end if;

    insert into plugin_lifecycle_operations_v1(
        operation_uid,plugin_id,requested_action,expected_revision,
        committed_revision,plan_sha256,confirmation_sha256,actor_kind,
        actor_key,outcome,reason_code
    ) values (
        p_operation_uid,p_plugin_id,'install',p_expected_revision,
        v_committed_revision,p_plan_sha256,v_confirmation_sha256,p_actor_kind,
        p_actor_key,'succeeded',null
    ) returning plugin_lifecycle_operations_v1.operation_id
      into operation_id;

    perform * from append_administrative_activity_v1(
        p_operation_uid,clock_timestamp(),p_actor_kind,p_actor_key,
        'plugin_lifecycle','plugin.install','plugin',p_plugin_id,'succeeded',null,
        jsonb_build_object(
            'expected_revision',p_expected_revision,
            'committed_revision',v_committed_revision,
            'plan_sha256',p_plan_sha256
        ),null,p_operation_uid
    );

    committed_revision := v_committed_revision;
    package_lifecycle := 'registered';
    desired_activation := 'disabled';
    return next;
end
$$;

revoke all on function execute_bundled_plugin_install_v1(
    uuid,text,bigint,text,text,text,text
) from public,adlog_user;
grant execute on function execute_bundled_plugin_install_v1(
    uuid,text,bigint,text,text,text,text
) to adlog_plugin_lifecycle_executor;
alter function execute_bundled_plugin_install_v1(
    uuid,text,bigint,text,text,text,text
) owner to adlog_plugin_lifecycle_owner;

insert into schema_migrations(version,name)
values(74,'plugin_bundled_install_executor')
on conflict(version) do update set name=excluded.name;

commit;
