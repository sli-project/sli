-- Exact lifecycle executor for the bundled remote-access runtime.
-- It changes only durable plugin/admission state and append-only audit rows.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));

do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 076 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=75 and name='plugin_component_admission'
    ) then
        raise exception 'migration 076 requires migration 075';
    end if;
    if to_regprocedure(
      'public.execute_plugin_runtime_transition_v1(uuid,text,bigint,text,text,text,text)'
    ) is not null or to_regprocedure(
      'public.read_plugin_runtime_queue_nonterminal_v1()'
    ) is not null then
        raise exception 'migration 076 requires absent runtime transition executor';
    end if;
end
$$;

grant execute on function append_administrative_activity_v1(
    uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,inet,uuid
) to adlog_plugin_lifecycle_owner;

create function read_plugin_runtime_queue_nonterminal_v1()
returns bigint
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
    select count(*)::bigint
    from public.acquisition_delivery_outbox current
    where current.delivery_state in ('queued','leased','failed','quarantined')
$$;
revoke all on function read_plugin_runtime_queue_nonterminal_v1()
from public,adlog_user;
grant execute on function read_plugin_runtime_queue_nonterminal_v1()
to adlog_plugin_lifecycle_owner;
alter function read_plugin_runtime_queue_nonterminal_v1()
owner to adlog_storage_owner;

create function execute_plugin_runtime_transition_v1(
    p_operation_uid uuid,
    p_action text,
    p_expected_revision bigint,
    p_plan_sha256 text,
    p_confirmation text,
    p_actor_kind text,
    p_actor_key text
)
returns table(
    operation_id bigint,
    committed_revision bigint,
    desired_activation text,
    component_runtime text,
    queue_state text
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
    v_nonterminal bigint;
    v_active_leases bigint;
begin
    if p_operation_uid is null
       or p_action not in ('enable','drain','disable')
       or p_expected_revision < 1
       or p_plan_sha256 !~ '^[0-9a-f]{64}$'
       or p_actor_kind not in ('session','api_key','windows','system','local_operator')
       or btrim(coalesce(p_actor_key,''))=''
       or length(p_actor_key)>200 then
        raise exception 'plugin runtime transition request is invalid';
    end if;
    v_required_confirmation := format(
        'PLUGIN-%s-SLI-REMOTE-ACCESS-R%s-%s',
        upper(p_action),p_expected_revision,
        upper(substr(p_plan_sha256,1,12))
    );
    if p_confirmation is distinct from v_required_confirmation then
        raise exception 'plugin runtime transition confirmation is invalid';
    end if;
    v_confirmation_sha256 := encode(
        sha256(convert_to(p_confirmation,'UTF8')),'hex'
    );

    perform pg_advisory_xact_lock(
        hashtext('ad_log_reports_plugin_runtime_v76')
    );
    select current.* into v_existing
    from plugin_lifecycle_operations_v1 current
    where current.operation_uid=p_operation_uid;
    if found then
        if v_existing.plugin_id<>'sli.remote-access'
           or v_existing.requested_action<>p_action
           or v_existing.expected_revision<>p_expected_revision
           or v_existing.plan_sha256<>p_plan_sha256
           or v_existing.confirmation_sha256<>v_confirmation_sha256
           or v_existing.actor_kind<>p_actor_kind
           or v_existing.actor_key<>p_actor_key
           or v_existing.outcome<>'succeeded'
           or v_existing.committed_revision is null then
            raise exception 'plugin runtime transition idempotency conflict';
        end if;
        return query
        select v_existing.operation_id,v_existing.committed_revision,
               current.desired_activation,current.component_runtime,
               current.queue_state
        from plugin_installations_v1 current
        where current.plugin_id='sli.remote-access'
          and current.revision=v_existing.committed_revision;
        if not found then
            raise exception 'plugin runtime transition replay state mismatch';
        end if;
        return;
    end if;

    select current.* into v_current
    from plugin_installations_v1 current
    where current.plugin_id='sli.remote-access'
    for update;
    if not found
       or v_current.package_lifecycle<>'registered'
       or v_current.revision<>p_expected_revision then
        raise exception 'plugin runtime transition state or revision is invalid';
    end if;

    update plugin_component_leases_v1 current
    set released_at_utc=current.expires_at_utc,release_outcome='expired'
    where current.plugin_id='sli.remote-access'
      and current.released_at_utc is null
      and current.expires_at_utc<=clock_timestamp();
    select count(*) into v_active_leases
    from plugin_component_leases_v1 current
    where current.plugin_id='sli.remote-access'
      and current.released_at_utc is null;
    select read_plugin_runtime_queue_nonterminal_v1() into v_nonterminal;

    if p_action='enable' then
        if v_current.desired_activation<>'disabled'
           or v_current.component_runtime<>'stopped'
           or v_current.queue_state<>'drained'
           or v_active_leases<>0
           or 2<>(select count(*) from plugin_component_admission_v1 current
                 where current.plugin_id='sli.remote-access'
                   and current.admission_mode='closed') then
            raise exception 'plugin enable precondition failed';
        end if;
        update plugin_installations_v1 current
        set desired_activation='enabled_manual',observed_health='unknown',
            component_runtime='running',
            queue_state=case when v_nonterminal=0 then 'drained' else 'backlog' end,
            revision=current.revision+1,updated_at_utc=now()
        where current.plugin_id='sli.remote-access'
          and current.revision=p_expected_revision;
        update plugin_component_admission_v1 current
        set admission_mode='open',revision=current.revision+1,
            updated_at_utc=now()
        where current.plugin_id='sli.remote-access';
    elsif p_action='drain' then
        if v_current.desired_activation<>'enabled_manual'
           or v_current.component_runtime not in ('running','failed')
           or 2<>(select count(*) from plugin_component_admission_v1 current
                 where current.plugin_id='sli.remote-access'
                   and current.admission_mode='open') then
            raise exception 'plugin drain precondition failed';
        end if;
        update plugin_installations_v1 current
        set desired_activation='disabled',component_runtime='draining',
            queue_state=case when v_nonterminal=0 then 'drained' else 'backlog' end,
            revision=current.revision+1,updated_at_utc=now()
        where current.plugin_id='sli.remote-access'
          and current.revision=p_expected_revision;
        update plugin_component_admission_v1 current
        set admission_mode=case current.component_id
              when 'radius-acquisition' then 'closed' else 'drain_only' end,
            revision=current.revision+1,updated_at_utc=now()
        where current.plugin_id='sli.remote-access';
    else
        if v_current.desired_activation<>'disabled'
           or v_current.component_runtime<>'draining'
           or v_active_leases<>0
           or v_nonterminal<>0
           or not exists(
               select 1 from plugin_component_admission_v1 current
               where current.plugin_id='sli.remote-access'
                 and current.component_id='radius-acquisition'
                 and current.admission_mode='closed'
           )
           or not exists(
               select 1 from plugin_component_admission_v1 current
               where current.plugin_id='sli.remote-access'
                 and current.component_id='radius-session-observation'
                 and current.admission_mode='drain_only'
           ) then
            raise exception 'plugin disable precondition failed';
        end if;
        update plugin_installations_v1 current
        set observed_health='unknown',component_runtime='stopped',
            queue_state='drained',revision=current.revision+1,
            updated_at_utc=now()
        where current.plugin_id='sli.remote-access'
          and current.revision=p_expected_revision;
        update plugin_component_admission_v1 current
        set admission_mode='closed',revision=current.revision+1,
            updated_at_utc=now()
        where current.plugin_id='sli.remote-access';
    end if;
    if not found then
        raise exception 'plugin runtime transition optimistic update failed';
    end if;

    v_committed_revision := p_expected_revision+1;
    insert into plugin_lifecycle_operations_v1(
        operation_uid,plugin_id,requested_action,expected_revision,
        committed_revision,plan_sha256,confirmation_sha256,actor_kind,
        actor_key,outcome,reason_code
    ) values (
        p_operation_uid,'sli.remote-access',p_action,p_expected_revision,
        v_committed_revision,p_plan_sha256,v_confirmation_sha256,p_actor_kind,
        p_actor_key,'succeeded',null
    ) returning plugin_lifecycle_operations_v1.operation_id into operation_id;

    perform * from append_administrative_activity_v1(
        p_operation_uid,clock_timestamp(),p_actor_kind,p_actor_key,
        'plugin_lifecycle','plugin.'||p_action,'plugin','sli.remote-access',
        'succeeded',null,jsonb_build_object(
            'expected_revision',p_expected_revision,
            'committed_revision',v_committed_revision,
            'plan_sha256',p_plan_sha256,
            'active_leases',v_active_leases,
            'nonterminal_deliveries',v_nonterminal
        ),null,p_operation_uid
    );
    committed_revision := v_committed_revision;
    select current.desired_activation,current.component_runtime,current.queue_state
    into desired_activation,component_runtime,queue_state
    from plugin_installations_v1 current
    where current.plugin_id='sli.remote-access';
    return next;
end
$$;

revoke all on function execute_plugin_runtime_transition_v1(
    uuid,text,bigint,text,text,text,text
) from public,adlog_user;
grant execute on function execute_plugin_runtime_transition_v1(
    uuid,text,bigint,text,text,text,text
) to adlog_plugin_lifecycle_executor;
alter function execute_plugin_runtime_transition_v1(
    uuid,text,bigint,text,text,text,text
) owner to adlog_plugin_lifecycle_owner;

insert into schema_migrations(version,name)
values(76,'plugin_runtime_activation_executor')
on conflict(version) do update set name=excluded.name;

commit;
