--
-- PostgreSQL database dump
--



SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: sli_plugin_remote_access; Type: SCHEMA; Schema: -; Owner: adlog_plugin_remote_access_owner
--

CREATE SCHEMA sli_plugin_remote_access;


ALTER SCHEMA sli_plugin_remote_access OWNER TO adlog_plugin_remote_access_owner;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: acquire_plugin_component_lease_v1(uuid, text, text, text, text); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.acquire_plugin_component_lease_v1(p_lease_uid uuid, p_plugin_id text, p_component_id text, p_lease_kind text, p_holder_key text) RETURNS TABLE(lease_uid uuid, component_id text, admission_mode text, expires_at_utc timestamp with time zone)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
declare
    v_plugin plugin_installations_v1%rowtype;
    v_component plugin_component_admission_v1%rowtype;
    v_existing plugin_component_leases_v1%rowtype;
    v_now timestamptz := clock_timestamp();
begin
    if p_lease_uid is null
       or p_plugin_id<>'sli.remote-access'
       or p_component_id not in (
         'radius-acquisition','radius-session-observation'
       )
       or p_lease_kind not in ('source_contact','delivery_claim')
       or btrim(coalesce(p_holder_key,''))=''
       or length(p_holder_key)>200 then
        raise exception 'plugin component lease request is invalid';
    end if;
    if p_component_id='radius-acquisition' then
        if p_lease_kind<>'source_contact'
           or not pg_has_role(
             session_user,'adlog_radius_accounting_worker','MEMBER'
           ) then
            raise exception 'plugin acquisition lease caller is invalid';
        end if;
    elsif p_lease_kind<>'delivery_claim'
       or not pg_has_role(
         session_user,'adlog_radius_session_consumer','MEMBER'
       ) then
        raise exception 'plugin consumer lease caller is invalid';
    end if;

    select current.* into v_existing
    from plugin_component_leases_v1 current
    where current.lease_uid=p_lease_uid;
    if found then
        if v_existing.plugin_id<>p_plugin_id
           or v_existing.component_id<>p_component_id
           or v_existing.lease_kind<>p_lease_kind
           or v_existing.holder_key<>p_holder_key then
            raise exception 'plugin component lease idempotency conflict';
        end if;
        return query select v_existing.lease_uid,v_existing.component_id,
            v_existing.admission_mode_at_acquire,
            v_existing.expires_at_utc;
        return;
    end if;

    select current.* into v_plugin
    from plugin_installations_v1 current
    where current.plugin_id=p_plugin_id
    for key share;
    select current.* into v_component
    from plugin_component_admission_v1 current
    where current.plugin_id=p_plugin_id
      and current.component_id=p_component_id
    for update;
    if not found or v_plugin.package_lifecycle<>'registered' then
        raise exception 'plugin component admission state is unavailable';
    end if;

    update plugin_component_leases_v1 current
    set released_at_utc=current.expires_at_utc,
        release_outcome='expired'
    where current.plugin_id=p_plugin_id
      and current.component_id=p_component_id
      and current.released_at_utc is null
      and current.expires_at_utc<=v_now;

    if p_component_id='radius-acquisition' then
        if v_plugin.desired_activation<>'enabled_manual'
           or v_plugin.component_runtime<>'running'
           or v_component.admission_mode<>'open' then
            raise exception 'plugin acquisition admission is closed';
        end if;
    elsif not (
        (
          v_plugin.desired_activation='enabled_manual'
          and v_plugin.component_runtime='running'
          and v_component.admission_mode='open'
        )
        or
        (
          v_plugin.desired_activation='disabled'
          and v_plugin.component_runtime='draining'
          and v_component.admission_mode='drain_only'
        )
    ) then
        raise exception 'plugin consumer admission is closed';
    end if;

    insert into plugin_component_leases_v1(
        lease_uid,plugin_id,component_id,lease_kind,holder_key,
        admission_mode_at_acquire,acquired_at_utc,expires_at_utc
    ) values (
        p_lease_uid,p_plugin_id,p_component_id,p_lease_kind,p_holder_key,
        v_component.admission_mode,v_now,v_now+interval '120 seconds'
    );
    return query select p_lease_uid,p_component_id,
        v_component.admission_mode,v_now+interval '120 seconds';
end
$$;


ALTER FUNCTION public.acquire_plugin_component_lease_v1(p_lease_uid uuid, p_plugin_id text, p_component_id text, p_lease_kind text, p_holder_key text) OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: ad_snapshot_manifest_apply_v2_schedule_header(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ad_snapshot_manifest_apply_v2_schedule_header() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
declare
  expected_local_at timestamp without time zone;
begin
  if new.contract_version = 'sli.ad-snapshot-manifest/2.0' then
    expected_local_at := new.slot_start_utc at time zone 'Asia/Novosibirsk';
    if new.schedule_timezone is null then
      new.schedule_timezone := 'Asia/Novosibirsk';
    elsif new.schedule_timezone <> 'Asia/Novosibirsk' then
      raise exception 'v2 AD snapshot manifests require Asia/Novosibirsk schedule_timezone';
    end if;
    if new.scheduled_local_at is null then
      new.scheduled_local_at := expected_local_at;
    elsif new.scheduled_local_at is distinct from expected_local_at then
      raise exception 'v2 AD snapshot scheduled_local_at must match slot_start_utc';
    end if;
  elsif new.contract_version = 'sli.ad-snapshot-manifest/1.0' then
    if new.schedule_timezone is not null or new.scheduled_local_at is not null then
      raise exception 'v1 AD snapshot manifests cannot declare a schedule header';
    end if;
  end if;
  return new;
end
$$;


ALTER FUNCTION public.ad_snapshot_manifest_apply_v2_schedule_header() OWNER TO postgres;

--
-- Name: ad_snapshot_manifest_reject_mutation(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ad_snapshot_manifest_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
begin
  if tg_op = 'DELETE'
     and current_user = 'postgres'
     and session_user = 'adlog_user' then
    return null;
  end if;

  raise exception 'AD snapshot manifests are immutable';
end
$$;


ALTER FUNCTION public.ad_snapshot_manifest_reject_mutation() OWNER TO postgres;

--
-- Name: ad_snapshot_projection_output_reject_mutation(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ad_snapshot_projection_output_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
begin
  if tg_op = 'DELETE'
     and current_user = 'postgres'
     and session_user = 'adlog_user' then
    return null;
  end if;

  raise exception 'AD snapshot projection outputs are immutable';
end
$$;


ALTER FUNCTION public.ad_snapshot_projection_output_reject_mutation() OWNER TO postgres;

--
-- Name: append_administrative_activity_v1(uuid, timestamp with time zone, text, text, text, text, text, text, text, text, jsonb, inet, uuid); Type: FUNCTION; Schema: public; Owner: adlog_administrative_activity_owner
--

CREATE FUNCTION public.append_administrative_activity_v1(p_event_uid uuid, p_occurred_at_utc timestamp with time zone, p_actor_kind text, p_actor_key text, p_category text, p_action_key text, p_target_kind text, p_target_key text, p_outcome text, p_reason_code text, p_details_json jsonb, p_remote_address inet, p_correlation_id uuid) RETURNS TABLE(activity_id bigint, record_hash bytea)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $_$
declare
    v_content jsonb;
    v_content_hash bytea;
    v_previous_hash bytea;
    v_existing_content_hash bytea;
    v_existing_record_hash bytea;
    v_existing_activity_id bigint;
    v_record_hash bytea;
begin
    if p_event_uid is null or p_occurred_at_utc is null then
        raise exception 'administrative activity identity and time are required';
    end if;
    if p_actor_kind not in ('session','api_key','windows','system','local_operator','plugin')
       or btrim(coalesce(p_actor_key,''))=''
       or length(p_actor_key)>200 then
        raise exception 'administrative activity actor is invalid';
    end if;
    if p_category not in (
        'authentication','plugin_lifecycle','source_configuration',
        'access_management','report_publication','manual_operation'
    ) or p_action_key !~ '^[a-z][a-z0-9_.-]{0,119}$' then
        raise exception 'administrative activity category or action is invalid';
    end if;
    if p_outcome not in ('started','succeeded','failed','denied','stopped','cancelled') then
        raise exception 'administrative activity outcome is invalid';
    end if;
    if jsonb_typeof(coalesce(p_details_json,'{}'::jsonb)) <> 'object'
       or octet_length(coalesce(p_details_json,'{}'::jsonb)::text) > 8192
       or exists (
           select 1
           from jsonb_each(coalesce(p_details_json,'{}'::jsonb)) as detail(key,value)
           where jsonb_typeof(detail.value) not in ('string','number','boolean','null')
              or detail.key ~* '(password|secret|token|dsn|credential|payload|raw)'
       ) then
        raise exception 'administrative activity details are unsafe';
    end if;

    v_content := jsonb_build_object(
        'event_uid',p_event_uid::text,
        'occurred_at_utc',to_char(p_occurred_at_utc at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),
        'actor_kind',p_actor_kind,
        'actor_key',p_actor_key,
        'category',p_category,
        'action_key',p_action_key,
        'target_kind',p_target_kind,
        'target_key',p_target_key,
        'outcome',p_outcome,
        'reason_code',p_reason_code,
        'details_json',coalesce(p_details_json,'{}'::jsonb),
        'remote_address',p_remote_address::text,
        'correlation_id',p_correlation_id::text
    );
    v_content_hash := sha256(convert_to(v_content::text,'UTF8'));

    perform pg_advisory_xact_lock(
        hashtext('ad_log_reports_administrative_activity_append_v1')
    );

    select current.content_hash,current.record_hash,current.activity_id
    into v_existing_content_hash,v_existing_record_hash,v_existing_activity_id
    from public.administrative_activity_v1 as current
    where current.event_uid=p_event_uid;
    if found then
        if v_existing_content_hash<>v_content_hash then
            raise exception 'administrative activity idempotency conflict';
        end if;
        return query select v_existing_activity_id,v_existing_record_hash;
        return;
    end if;

    select current.record_hash
    into v_previous_hash
    from public.administrative_activity_v1 as current
    order by current.activity_id desc
    limit 1;
    v_previous_hash := coalesce(v_previous_hash,decode(repeat('00',32),'hex'));
    v_record_hash := sha256(v_previous_hash || v_content_hash);

    insert into public.administrative_activity_v1(
        event_uid,occurred_at_utc,actor_kind,actor_key,category,action_key,
        target_kind,target_key,outcome,reason_code,details_json,remote_address,
        correlation_id,content_hash,previous_record_hash,record_hash
    ) values (
        p_event_uid,p_occurred_at_utc,p_actor_kind,p_actor_key,p_category,p_action_key,
        p_target_kind,p_target_key,p_outcome,p_reason_code,
        coalesce(p_details_json,'{}'::jsonb),p_remote_address,p_correlation_id,
        v_content_hash,v_previous_hash,v_record_hash
    ) returning administrative_activity_v1.activity_id
    into v_existing_activity_id;
    return query select v_existing_activity_id,v_record_hash;
end
$_$;


ALTER FUNCTION public.append_administrative_activity_v1(p_event_uid uuid, p_occurred_at_utc timestamp with time zone, p_actor_kind text, p_actor_key text, p_category text, p_action_key text, p_target_kind text, p_target_key text, p_outcome text, p_reason_code text, p_details_json jsonb, p_remote_address inet, p_correlation_id uuid) OWNER TO adlog_administrative_activity_owner;

--
-- Name: audit_account_risk_acceptance_change(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.audit_account_risk_acceptance_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    insert into account_risk_acceptance_audit(acceptance_id,action,actor,snapshot_json)
    values(
        new.id,
        case when tg_op='INSERT' then 'created'
             when new.status='revoked' and old.status is distinct from 'revoked' then 'revoked'
             else 'updated' end,
        case when tg_op='INSERT' then new.created_by else coalesce(new.revoked_by,new.created_by) end,
        to_jsonb(new)
    );
    return new;
end;
$$;


ALTER FUNCTION public.audit_account_risk_acceptance_change() OWNER TO postgres;

--
-- Name: enforce_entity_identity_merge_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_entity_identity_merge_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'entity identity merge evidence is immutable';
end
$$;


ALTER FUNCTION public.enforce_entity_identity_merge_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_control_health_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_control_health_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'semantic control health observations are immutable';
end
$$;


ALTER FUNCTION public.enforce_semantic_control_health_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_correlation_rule_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_correlation_rule_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if old.lifecycle_status <> 'draft' and (
        new.rule_kind is distinct from old.rule_kind
        or new.definition_json is distinct from old.definition_json
        or new.definition_sha256 is distinct from old.definition_sha256
    ) then
        raise exception 'non-draft semantic correlation rule definition is immutable';
    end if;
    new.updated_at = now();
    return new;
end
$$;


ALTER FUNCTION public.enforce_semantic_correlation_rule_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_finding_publication_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_finding_publication_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'semantic finding publication links are immutable';
end
$$;


ALTER FUNCTION public.enforce_semantic_finding_publication_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_risk_contribution_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_risk_contribution_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'semantic risk contributions are immutable';
end
$$;


ALTER FUNCTION public.enforce_semantic_risk_contribution_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_risk_policy_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_risk_policy_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if old.lifecycle_status <> 'draft' and (
        new.source_kind is distinct from old.source_kind
        or new.definition_json is distinct from old.definition_json
        or new.definition_sha256 is distinct from old.definition_sha256
    ) then
        raise exception 'non-draft semantic risk policy definition is immutable';
    end if;
    new.updated_at=now();
    return new;
end
$$;


ALTER FUNCTION public.enforce_semantic_risk_policy_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_risk_result_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_risk_result_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'semantic risk evaluation results are immutable';
end
$$;


ALTER FUNCTION public.enforce_semantic_risk_result_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_risk_subscription_draft_only(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_risk_subscription_draft_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
declare
    status text;
begin
    if tg_op in ('UPDATE','DELETE') then
        select lifecycle_status into status from semantic_risk_policies
        where policy_id=old.policy_id and policy_version=old.policy_version;
        if status is distinct from 'draft' then
            raise exception 'semantic risk policy subscription is immutable outside draft';
        end if;
    end if;
    if tg_op in ('INSERT','UPDATE') then
        select lifecycle_status into status from semantic_risk_policies
        where policy_id=new.policy_id and policy_version=new.policy_version;
        if status is distinct from 'draft' then
            raise exception 'semantic risk policy subscription is immutable outside draft';
        end if;
    end if;
    if tg_op='DELETE' then return old; end if;
    return new;
end
$$;


ALTER FUNCTION public.enforce_semantic_risk_subscription_draft_only() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_scenario_review_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_scenario_review_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'semantic scenario reviews are append-only';
end
$$;


ALTER FUNCTION public.enforce_semantic_scenario_review_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_source_identity_immutability(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_source_identity_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if new.source_event_id is distinct from old.source_event_id
       or new.source_identity_json is distinct from old.source_identity_json then
        raise exception 'semantic source identity is immutable';
    end if;
    return new;
end
$$;


ALTER FUNCTION public.enforce_semantic_source_identity_immutability() OWNER TO adlog_storage_owner;

--
-- Name: enforce_semantic_subscription_draft_only(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.enforce_semantic_subscription_draft_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
declare
    status text;
begin
    if tg_op in ('UPDATE','DELETE') then
        select lifecycle_status into status
        from semantic_correlation_rules
        where rule_id=old.rule_id and rule_version=old.rule_version;
        if status is distinct from 'draft' then
            raise exception 'semantic correlation subscriptions are immutable outside draft';
        end if;
    end if;
    if tg_op in ('INSERT','UPDATE') then
        select lifecycle_status into status
        from semantic_correlation_rules
        where rule_id=new.rule_id and rule_version=new.rule_version;
        if status is distinct from 'draft' then
            raise exception 'semantic correlation subscriptions are immutable outside draft';
        end if;
    end if;
    if tg_op='DELETE' then
        return old;
    end if;
    return new;
end
$$;


ALTER FUNCTION public.enforce_semantic_subscription_draft_only() OWNER TO adlog_storage_owner;

--
-- Name: entity_v2_is_active(bigint); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.entity_v2_is_active(p_entity_id bigint) RETURNS boolean
    LANGUAGE sql STABLE STRICT SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    select not exists (
        select 1
        from public.entity_identity_merges_v2 merged
        where merged.source_entity_id=p_entity_id
    )
$$;


ALTER FUNCTION public.entity_v2_is_active(p_entity_id bigint) OWNER TO adlog_storage_owner;

--
-- Name: execute_bundled_plugin_install_v1(uuid, text, bigint, text, text, text, text); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.execute_bundled_plugin_install_v1(p_operation_uid uuid, p_plugin_id text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text) RETURNS TABLE(operation_id bigint, committed_revision bigint, package_lifecycle text, desired_activation text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $_$
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
$_$;


ALTER FUNCTION public.execute_bundled_plugin_install_v1(p_operation_uid uuid, p_plugin_id text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text) OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: execute_plugin_runtime_transition_v1(uuid, text, bigint, text, text, text, text); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.execute_plugin_runtime_transition_v1(p_operation_uid uuid, p_action text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text) RETURNS TABLE(operation_id bigint, committed_revision bigint, desired_activation text, component_runtime text, queue_state text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $_$
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
$_$;


ALTER FUNCTION public.execute_plugin_runtime_transition_v1(p_operation_uid uuid, p_action text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text) OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: expire_ad_snapshot_seven_day_ring(uuid); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE public.expire_ad_snapshot_seven_day_ring(IN p_published_manifest_id uuid)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
declare
  anchor_domain_id bigint;
  anchor_scheduled_local_at timestamp without time zone;
  cutoff_local_at timestamp without time zone;
  cutoff_at_utc timestamptz;
  source_family_count integer;
  source_count integer;
begin
  if session_user <> 'adlog_user' then
    raise exception 'AD snapshot expiry may be called only by adlog_user'
      using errcode = '42501';
  end if;

  if p_published_manifest_id is null then
    raise exception 'AD snapshot expiry requires a published manifest id';
  end if;

  perform pg_advisory_xact_lock(
    hashtext('ad_log_reports_ad_snapshot_seven_day_ring_expiry')
  );

  select manifest.domain_id, manifest.scheduled_local_at
  into anchor_domain_id, anchor_scheduled_local_at
  from public.ad_snapshot_manifests manifest
  where manifest.manifest_id = p_published_manifest_id
    and manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and manifest.schedule_timezone = 'Asia/Novosibirsk'
    and manifest.scheduled_local_at is not null;

  if not found then
    raise exception 'AD snapshot expiry requires a published scheduled v2 manifest';
  end if;

  select count(*) filter (
           where source.family in ('users_v2', 'computers_v6', 'gpo_v2')
         ),
         count(*)
  into source_family_count, source_count
  from public.ad_snapshot_manifest_sources source
  where source.manifest_id = p_published_manifest_id;

  if source_family_count <> 3 or source_count <> 9 then
    raise exception 'AD snapshot expiry requires the complete published source family set';
  end if;

  if exists (
    select 1
    from public.ad_snapshot_manifests later_manifest
    where later_manifest.domain_id = anchor_domain_id
      and later_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
      and later_manifest.schedule_timezone = 'Asia/Novosibirsk'
      and later_manifest.scheduled_local_at > anchor_scheduled_local_at
  ) then
    raise exception 'AD snapshot expiry refuses a non-latest published scheduled manifest';
  end if;

  cutoff_local_at := anchor_scheduled_local_at - interval '7 days';
  cutoff_at_utc := cutoff_local_at at time zone 'Asia/Novosibirsk';
  perform set_config('ad_snapshot_retention.expiry_active', 'on', true);

  delete from public.users_report_v2_snapshots snapshot
  where snapshot.domain_id = anchor_domain_id
    and snapshot.captured_at_utc <= cutoff_at_utc
    and not exists (
      select 1
      from public.ad_snapshot_manifest_sources retained_source
      join public.ad_snapshot_manifests retained_manifest
        on retained_manifest.manifest_id = retained_source.manifest_id
      where retained_source.family = 'users_v2'
        and retained_source.source_id = snapshot.snapshot_id::text
        and retained_manifest.domain_id = anchor_domain_id
        and retained_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
        and retained_manifest.schedule_timezone = 'Asia/Novosibirsk'
        and retained_manifest.scheduled_local_at > cutoff_local_at
    );

  delete from public.computers_v6_source_snapshots snapshot
  where snapshot.domain_id = anchor_domain_id
    and snapshot.captured_at_utc <= cutoff_at_utc
    and not exists (
      select 1
      from public.ad_snapshot_manifest_sources retained_source
      join public.ad_snapshot_manifests retained_manifest
        on retained_manifest.manifest_id = retained_source.manifest_id
      where retained_source.family = 'computers_v6'
        and retained_source.source_id = snapshot.snapshot_uuid::text
        and retained_manifest.domain_id = anchor_domain_id
        and retained_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
        and retained_manifest.schedule_timezone = 'Asia/Novosibirsk'
        and retained_manifest.scheduled_local_at > cutoff_local_at
    );

  -- GPO snapshots have no captured_at_utc; migration 116 indexes created_at for retention.
  delete from public.gpo_report_v2_source_snapshots snapshot
  where snapshot.domain_id = anchor_domain_id
    and snapshot.created_at <= cutoff_at_utc
    and not exists (
      select 1
      from public.ad_snapshot_manifest_sources retained_source
      join public.ad_snapshot_manifests retained_manifest
        on retained_manifest.manifest_id = retained_source.manifest_id
      where retained_source.family = 'gpo_v2'
        and retained_source.source_id = snapshot.source_run_id::text
        and retained_manifest.domain_id = anchor_domain_id
        and retained_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
        and retained_manifest.schedule_timezone = 'Asia/Novosibirsk'
        and retained_manifest.scheduled_local_at > cutoff_local_at
    );

  delete from public.ad_snapshot_projection_outputs output
  using public.ad_snapshot_manifests expired_manifest
  where output.manifest_id = expired_manifest.manifest_id
    and expired_manifest.domain_id = anchor_domain_id
    and expired_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and expired_manifest.schedule_timezone = 'Asia/Novosibirsk'
    and expired_manifest.scheduled_local_at <= cutoff_local_at;

  delete from public.ad_snapshot_projection_receipts receipt
  using public.ad_snapshot_manifests expired_manifest
  where receipt.manifest_id = expired_manifest.manifest_id
    and expired_manifest.domain_id = anchor_domain_id
    and expired_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and expired_manifest.schedule_timezone = 'Asia/Novosibirsk'
    and expired_manifest.scheduled_local_at <= cutoff_local_at;

  delete from public.ad_snapshot_manifest_sources source
  using public.ad_snapshot_manifests expired_manifest
  where source.manifest_id = expired_manifest.manifest_id
    and expired_manifest.domain_id = anchor_domain_id
    and expired_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and expired_manifest.schedule_timezone = 'Asia/Novosibirsk'
    and expired_manifest.scheduled_local_at <= cutoff_local_at;

  delete from public.ad_snapshot_manifests manifest
  where manifest.domain_id = anchor_domain_id
    and manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and manifest.schedule_timezone = 'Asia/Novosibirsk'
    and manifest.scheduled_local_at <= cutoff_local_at;

  perform set_config('ad_snapshot_retention.expiry_active', 'off', true);
end
$$;


ALTER PROCEDURE public.expire_ad_snapshot_seven_day_ring(IN p_published_manifest_id uuid) OWNER TO postgres;

--
-- Name: finish_remote_access_plugin_drain_v1(); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.finish_remote_access_plugin_drain_v1() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
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


ALTER FUNCTION public.finish_remote_access_plugin_drain_v1() OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: is_semantic_finding_published_v1(bigint); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.is_semantic_finding_published_v1(p_finding_id bigint) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    select exists(
        select 1
        from public.semantic_finding_publications publication
        where publication.finding_id=p_finding_id
    )
$$;


ALTER FUNCTION public.is_semantic_finding_published_v1(p_finding_id bigint) OWNER TO adlog_storage_owner;

--
-- Name: observe_remote_access_plugin_v1(boolean, boolean); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.observe_remote_access_plugin_v1(p_configured boolean, p_received boolean) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    insert into public.plugin_state_v1(plugin_id,configured,last_data_at_utc)
    values('sli.remote-access',p_configured,case when p_received then now() end)
    on conflict(plugin_id) do update set configured=excluded.configured,
        last_data_at_utc=coalesce(excluded.last_data_at_utc,plugin_state_v1.last_data_at_utc),
        updated_at_utc=now()
$$;


ALTER FUNCTION public.observe_remote_access_plugin_v1(p_configured boolean, p_received boolean) OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: process_episode_evidence_reject_mutation(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.process_episode_evidence_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
begin
    raise exception 'process episode revisions and evidence are append-only';
end
$$;


ALTER FUNCTION public.process_episode_evidence_reject_mutation() OWNER TO adlog_storage_owner;

--
-- Name: read_administrative_activity_v1(bigint, integer, text); Type: FUNCTION; Schema: public; Owner: adlog_administrative_activity_owner
--

CREATE FUNCTION public.read_administrative_activity_v1(p_before_activity_id bigint, p_limit integer, p_category text) RETURNS TABLE(activity_id bigint, event_uid uuid, occurred_at_utc timestamp with time zone, recorded_at_utc timestamp with time zone, actor_kind text, actor_key text, category text, action_key text, target_kind text, target_key text, outcome text, reason_code text, details_json jsonb, remote_address inet, correlation_id uuid, content_hash_hex text, previous_record_hash_hex text, record_hash_hex text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
    if p_limit is null or p_limit < 1 or p_limit > 201 then
        raise exception 'administrative activity reader limit is invalid';
    end if;
    if p_before_activity_id is not null and p_before_activity_id < 1 then
        raise exception 'administrative activity reader cursor is invalid';
    end if;
    if p_category is not null and p_category not in (
        'authentication','plugin_lifecycle','source_configuration',
        'access_management','report_publication','manual_operation'
    ) then
        raise exception 'administrative activity reader category is invalid';
    end if;

    return query
    select current.activity_id,current.event_uid,current.occurred_at_utc,
           current.recorded_at_utc,current.actor_kind,current.actor_key,
           current.category,current.action_key,current.target_kind,
           current.target_key,current.outcome,current.reason_code,
           current.details_json,current.remote_address,current.correlation_id,
           encode(current.content_hash,'hex'),
           encode(current.previous_record_hash,'hex'),
           encode(current.record_hash,'hex')
    from public.administrative_activity_v1 as current
    where (p_before_activity_id is null
           or current.activity_id < p_before_activity_id)
      and (p_category is null or current.category = p_category)
    order by current.activity_id desc
    limit p_limit;
end
$$;


ALTER FUNCTION public.read_administrative_activity_v1(p_before_activity_id bigint, p_limit integer, p_category text) OWNER TO adlog_administrative_activity_owner;

--
-- Name: read_plugin_component_runtime_guard_v1(text, text); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.read_plugin_component_runtime_guard_v1(p_plugin_id text, p_component_id text) RETURNS TABLE(desired_activation text, component_runtime text, admission_mode text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
    if p_plugin_id<>'sli.remote-access'
       or p_component_id not in (
         'radius-acquisition','radius-session-observation'
       ) then
        raise exception 'plugin runtime guard scope is invalid';
    end if;
    return query
    select installation.desired_activation,
           installation.component_runtime,
           admission.admission_mode
    from public.plugin_installations_v1 installation
    join public.plugin_component_admission_v1 admission
      on admission.plugin_id=installation.plugin_id
    where installation.plugin_id=p_plugin_id
      and admission.component_id=p_component_id;
    if not found then
        raise exception 'plugin runtime guard state is unavailable';
    end if;
end
$$;


ALTER FUNCTION public.read_plugin_component_runtime_guard_v1(p_plugin_id text, p_component_id text) OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: read_plugin_installations_v1(integer); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.read_plugin_installations_v1(p_limit integer) RETURNS TABLE(plugin_id text, manifest_id text, manifest_sha256 text, package_version text, rollback_version text, package_lifecycle text, desired_activation text, observed_health text, component_runtime text, queue_state text, revision bigint, immutable_evidence_count bigint, detach_reader_ready boolean, read_report_parity boolean, updated_at_utc timestamp with time zone)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
    if p_limit is null or p_limit < 1 or p_limit > 20 then
        raise exception 'plugin lifecycle reader limit is invalid';
    end if;
    return query
    select current.plugin_id,current.manifest_id,current.manifest_sha256,
           current.package_version,current.rollback_version,
           current.package_lifecycle,current.desired_activation,
           current.observed_health,current.component_runtime,current.queue_state,
           current.revision,current.immutable_evidence_count,
           current.detach_reader_ready,current.read_report_parity,
           current.updated_at_utc
    from public.plugin_installations_v1 current
    order by current.plugin_id
    limit p_limit;
end
$$;


ALTER FUNCTION public.read_plugin_installations_v1(p_limit integer) OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: read_plugin_runtime_queue_nonterminal_v1(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.read_plugin_runtime_queue_nonterminal_v1() RETURNS bigint
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    select count(*)::bigint from public.acquisition_delivery_outbox delivery
    join public.acquisition_consumer_subscriptions subscription
      on subscription.subscription_id=delivery.subscription_id
    where subscription.consumer_id='sli.windows.vpn-radius'
      and subscription.consumer_component_id='radius-session-observation'
      and delivery.delivery_state in ('queued','leased','failed','quarantined')
$$;


ALTER FUNCTION public.read_plugin_runtime_queue_nonterminal_v1() OWNER TO adlog_storage_owner;

--
-- Name: read_plugin_states_v1(); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.read_plugin_states_v1() RETURNS TABLE(plugin_id text, package_version text, installed boolean, configured boolean, enabled boolean, receiving_data boolean, component_runtime text, queue_state text, revision bigint, last_data_at_utc text)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    select i.plugin_id,i.package_version,i.package_lifecycle='registered',
           coalesce(s.configured,false),i.desired_activation='enabled_manual',
           coalesce(i.desired_activation='enabled_manual'
               and s.last_data_at_utc>now()-interval '10 minutes',false),
           i.component_runtime,i.queue_state,i.revision,s.last_data_at_utc::text
    from public.plugin_installations_v1 i
    left join public.plugin_state_v1 s using(plugin_id)
    order by i.plugin_id limit 20
$$;


ALTER FUNCTION public.read_plugin_states_v1() OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: reject_administrative_activity_mutation_v1(); Type: FUNCTION; Schema: public; Owner: adlog_administrative_activity_owner
--

CREATE FUNCTION public.reject_administrative_activity_mutation_v1() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
    raise exception 'administrative activity journal is append-only';
end
$$;


ALTER FUNCTION public.reject_administrative_activity_mutation_v1() OWNER TO adlog_administrative_activity_owner;

--
-- Name: reject_merged_entity_link_block(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.reject_merged_entity_link_block() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
    if exists (
        select 1 from public.entity_identity_merges_v2
        where source_entity_id=new.entity_id
    ) then
        raise exception 'link block targets a merged provisional entity %',
            new.entity_id;
    end if;
    return new;
end
$$;


ALTER FUNCTION public.reject_merged_entity_link_block() OWNER TO adlog_storage_owner;

--
-- Name: reject_plugin_lifecycle_operation_mutation_v1(); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.reject_plugin_lifecycle_operation_mutation_v1() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
    raise exception 'plugin lifecycle operation history is append-only';
end
$$;


ALTER FUNCTION public.reject_plugin_lifecycle_operation_mutation_v1() OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: release_plugin_component_lease_v1(uuid, text, text); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.release_plugin_component_lease_v1(p_lease_uid uuid, p_holder_key text, p_outcome text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
declare
    v_lease plugin_component_leases_v1%rowtype;
begin
    if p_lease_uid is null
       or btrim(coalesce(p_holder_key,''))=''
       or length(p_holder_key)>200
       or p_outcome not in ('completed','failed','cancelled') then
        raise exception 'plugin component lease release is invalid';
    end if;
    select current.* into v_lease
    from plugin_component_leases_v1 current
    where current.lease_uid=p_lease_uid
    for update;
    if not found or v_lease.holder_key<>p_holder_key then
        raise exception 'plugin component lease release mismatch';
    end if;
    if v_lease.component_id='radius-acquisition' then
        if not pg_has_role(
          session_user,'adlog_radius_accounting_worker','MEMBER'
        ) then
            raise exception 'plugin acquisition release caller is invalid';
        end if;
    elsif not pg_has_role(
      session_user,'adlog_radius_session_consumer','MEMBER'
    ) then
        raise exception 'plugin consumer release caller is invalid';
    end if;
    if v_lease.released_at_utc is not null then
        if v_lease.release_outcome<>p_outcome then
            raise exception 'plugin component lease release conflict';
        end if;
        return false;
    end if;
    update plugin_component_leases_v1 current
    set released_at_utc=clock_timestamp(),release_outcome=p_outcome
    where current.lease_uid=p_lease_uid
      and current.released_at_utc is null;
    return true;
end
$$;


ALTER FUNCTION public.release_plugin_component_lease_v1(p_lease_uid uuid, p_holder_key text, p_outcome text) OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: resolve_entity_identity_v2(integer); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.resolve_entity_identity_v2(candidate integer) RETURNS integer
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    select coalesce(
        (select target_entity_id from public.entity_identity_merges_v2
         where source_entity_id=candidate),
        candidate
    )
$$;


ALTER FUNCTION public.resolve_entity_identity_v2(candidate integer) OWNER TO adlog_storage_owner;

--
-- Name: set_event_noise_catalog_revision(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.set_event_noise_catalog_revision() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
    select revision.id
      into new.noise_catalog_revision_id
      from public.event_catalog_revisions revision
     where revision.version=new.noise_catalog_version;
    if new.noise_catalog_revision_id is null then
        raise exception 'unregistered event catalogue revision: %',
            new.noise_catalog_version;
    end if;
    return new;
end
$$;


ALTER FUNCTION public.set_event_noise_catalog_revision() OWNER TO adlog_storage_owner;

--
-- Name: set_plugin_enabled_v1(text, boolean, bigint, text, bigint, boolean); Type: FUNCTION; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE FUNCTION public.set_plugin_enabled_v1(p_plugin_id text, p_enabled boolean, p_revision bigint, p_actor_kind text, p_actor_id bigint, p_configured boolean) RETURNS TABLE(plugin_id text, package_version text, installed boolean, configured boolean, enabled boolean, receiving_data boolean, component_runtime text, queue_state text, revision bigint, last_data_at_utc text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
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


ALTER FUNCTION public.set_plugin_enabled_v1(p_plugin_id text, p_enabled boolean, p_revision bigint, p_actor_kind text, p_actor_id bigint, p_configured boolean) OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: sli_g11a3_preflight_state_v1(); Type: FUNCTION; Schema: public; Owner: adlog_radius_preflight_reader
--

CREATE FUNCTION public.sli_g11a3_preflight_state_v1() RETURNS TABLE(source_subscription_disabled boolean, no_temporary_login boolean, no_worker_started boolean, cursor_revision bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
declare
    registration_count bigint;
    activation_disabled boolean;
    observed_revision bigint;
begin
    select
      count(*),
      coalesce(bool_and(
        source.desired_activation='disabled'
        and subscription.desired_activation='disabled'
        and exists(
          select 1 from public.schema_migrations
          where version=58
            and name='radius_accounting_transaction_foundation'
        )
        and exists(
          select 1 from public.schema_migrations
          where version=59
            and name='radius_identity_spine_resolver'
        )
      ),false),
      min(cursor_row.revision)::bigint
    into registration_count,activation_disabled,observed_revision
    from public.acquisition_source_instances source
    join public.acquisition_stream_cursors cursor_row
      on cursor_row.source_instance_id=source.source_instance_id
    join public.acquisition_consumer_subscriptions subscription
      on subscription.source_instance_id=cursor_row.source_instance_id
     and subscription.stream_id=cursor_row.stream_id
     and subscription.transport_binding=cursor_row.transport_binding
    where cursor_row.stream_id='radius-accounting'
      and cursor_row.transport_binding=
          'windows-rpc-smb-readonly-tail-v1'
      and subscription.subscription_id like 'vpn-radius-session-observations-%-v1';

    if registration_count<>1 or observed_revision is null then
        raise exception 'g11a3_preflight_registration_invalid'
            using errcode='P0001';
    end if;

    return query
    select
      activation_disabled,
      not exists(
        select 1 from pg_catalog.pg_roles
        where left(rolname,20)='adlog_radius_manual_'
      ),
      not exists(
        select 1 from pg_catalog.pg_stat_activity
        where application_name='sli_stage9_radius_manual_worker'
          and pid<>pg_backend_pid()
      ),
      observed_revision;
end
$$;


ALTER FUNCTION public.sli_g11a3_preflight_state_v1() OWNER TO adlog_radius_preflight_reader;

--
-- Name: sli_radius_resolve_principal_key(text, text); Type: FUNCTION; Schema: public; Owner: adlog_radius_identity_resolver
--

CREATE FUNCTION public.sli_radius_resolve_principal_key(organization_fqdn text, distinguished_name text) RETURNS text
    LANGUAGE sql STABLE STRICT SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    select case
        when count(*) = 1 then 'entity:' || min(alias.entity_id)::text
        else null
    end
    from public.ad_context_entity_aliases alias
    join public.domains domain_row on domain_row.id=alias.domain_id
    where char_length(btrim(organization_fqdn)) between 1 and 255
      and char_length(btrim(distinguished_name)) between 1 and 2048
      and lower(domain_row.fqdn)=lower(btrim(organization_fqdn))
      and alias.alias_type='distinguished_name'
      and alias.normalized_value=lower(btrim(distinguished_name))
$$;


ALTER FUNCTION public.sli_radius_resolve_principal_key(organization_fqdn text, distinguished_name text) OWNER TO adlog_radius_identity_resolver;

--
-- Name: source_capture_continuity_declarations_reject_mutation(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.source_capture_continuity_declarations_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'source capture continuity declarations are immutable';
end
$$;


ALTER FUNCTION public.source_capture_continuity_declarations_reject_mutation() OWNER TO adlog_storage_owner;

--
-- Name: validate_entity_identity_merge_flat_graph(); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.validate_entity_identity_merge_flat_graph() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if exists (
        select 1 from entity_identity_merges_v2
        where target_entity_id=new.source_entity_id
           or source_entity_id=new.target_entity_id
    ) then
        raise exception 'entity identity merge chains and cycles are forbidden';
    end if;
    if exists (
        select 1 from entities_v2 source_row
        join entities_v2 target_row on target_row.id=new.target_entity_id
        where source_row.id=new.source_entity_id
          and source_row.entity_type_id <> target_row.entity_type_id
    ) then
        raise exception 'entity identity merge types differ';
    end if;
    return new;
end
$$;


ALTER FUNCTION public.validate_entity_identity_merge_flat_graph() OWNER TO adlog_storage_owner;

--
-- Name: write_process_episode_revision_v89(jsonb); Type: FUNCTION; Schema: public; Owner: adlog_storage_owner
--

CREATE FUNCTION public.write_process_episode_revision_v89(p jsonb) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
declare
    v_revision_id uuid;
    v_expected_revision_id uuid;
    v_expected_episode_id text;
    v_revision_hex text;
    v_derived_ordering_state text;
    v_existing public.process_episode_revisions%rowtype;
    v_state jsonb;
    v_manifest jsonb;
    v_revision_payload text;
    v_manifest_payload text;
    v_revision_sha bytea;
    v_manifest_sha bytea;
    v_idempotency bytea;
    v_evidence_count integer;
    v_next_revision integer;
    v_item jsonb;
    v_expected_manifest jsonb;
begin
    if jsonb_typeof(p)<>'object' then
        raise exception 'process episode writer payload must be an object';
    end if;
    if octet_length(p::text)>524288
       or octet_length(coalesce(p->>'revision_payload',''))>32768
       or octet_length(coalesce(p->>'evidence_manifest_payload',''))>131072 then
        raise exception 'process episode writer payload exceeds byte contract';
    end if;
    if not p ?& array[
        'episode_id','process_id','domain_id','source_host_id','display_host',
        'boot_event_id','start_event_id','started_at_utc','end_event_id',
        'confirmed_end_at_utc','process_name','command_line','user_sid',
        'user_name','user_domain','logon_id','parent_process_id',
        'parent_episode_id','completeness_state','confirmation_state',
        'ordering_state','evidence_count','evidence_manifest_sha256',
        'assembler_id','assembler_version','revision_id','idempotency_key',
        'revision_sha256','revision_payload','evidence_manifest',
        'evidence_manifest_payload'
    ] or (select count(*) from jsonb_object_keys(p))<>31 then
        raise exception 'process episode writer payload shape mismatch';
    end if;
    v_revision_id := (p->>'revision_id')::uuid;
    v_revision_payload := p->>'revision_payload';
    v_manifest_payload := p->>'evidence_manifest_payload';
    v_state := v_revision_payload::jsonb;
    v_manifest := v_manifest_payload::jsonb;
    if jsonb_typeof(v_state)<>'object' or jsonb_typeof(v_manifest)<>'array'
       or v_manifest <> p->'evidence_manifest' then
        raise exception 'process episode revision/evidence payload mismatch';
    end if;
    if p - array[
        'revision_id','idempotency_key','revision_sha256','revision_payload',
        'evidence_manifest','evidence_manifest_payload'
    ] <> v_state then
        raise exception 'process episode writer top-level state mismatch';
    end if;
    if exists (
        select 1 from jsonb_array_elements(v_manifest) item(value)
        where jsonb_typeof(value)<>'object'
           or not value ?& array[
                'evidence_order','source_event_id','evidence_role','semantic_type',
                'observed_at_utc','source_channel','event_record_id',
                'source_event_sha256','source_facts_sha256','domain_id','source_host_id',
                'semantic_contract_version','normalizer_id','normalizer_version',
                'semantic_sha256'
           ]
           or (select count(*) from jsonb_object_keys(value))<>15
    ) then
        raise exception 'process episode evidence object shape mismatch';
    end if;
    v_revision_sha := decode(p->>'revision_sha256','hex');
    v_manifest_sha := decode(v_state->>'evidence_manifest_sha256','hex');
    v_idempotency := decode(p->>'idempotency_key','hex');
    if octet_length(v_revision_sha)<>32 or octet_length(v_manifest_sha)<>32
       or octet_length(v_idempotency)<>32
       or v_revision_sha<>public.digest(convert_to(v_revision_payload,'UTF8'),'sha256')
       or v_manifest_sha<>public.digest(convert_to(v_manifest_payload,'UTF8'),'sha256')
       or v_idempotency<>public.digest(
            convert_to((v_state->>'episode_id') || ':' || (v_state->>'assembler_id') || ':' || (v_state->>'assembler_version') || ':','UTF8') || v_revision_sha,
            'sha256'
       ) then
        raise exception 'process episode revision/evidence digest mismatch';
    end if;
    v_expected_episode_id := encode(public.digest(convert_to(
        '{"boot_event_id":' || (v_state->>'boot_event_id') ||
        ',"domain_id":' || to_jsonb(v_state->>'domain_id')::text ||
        ',"process_id":' || (v_state->>'process_id') ||
        ',"source_host_id":' || to_jsonb(v_state->>'source_host_id')::text ||
        ',"start_event_id":' || (v_state->>'start_event_id') ||
        ',"started_at_utc":' || to_jsonb(v_state->>'started_at_utc')::text || '}',
        'UTF8'
    ),'sha256'),'hex');
    v_revision_hex := encode(public.digest(
        decode('6ba7b8119dad11d180b400c04fd430c8','hex') ||
        convert_to('adlog:process-revision:' || encode(v_idempotency,'hex'),'UTF8'),
        'sha1'
    ),'hex');
    v_revision_hex := substr(v_revision_hex,1,12) || '5' ||
        substr(v_revision_hex,14,3) ||
        to_hex((get_byte(decode(substr(v_revision_hex,17,2),'hex'),0)&63)|128) ||
        substr(v_revision_hex,19,14);
    v_expected_revision_id := (
        substr(v_revision_hex,1,8) || '-' || substr(v_revision_hex,9,4) || '-' ||
        substr(v_revision_hex,13,4) || '-' || substr(v_revision_hex,17,4) || '-' ||
        substr(v_revision_hex,21,12)
    )::uuid;
    if v_state->>'episode_id'<>v_expected_episode_id
       or v_revision_id<>v_expected_revision_id then
        raise exception 'process episode derived identity mismatch';
    end if;
    v_evidence_count := jsonb_array_length(v_manifest);
    if v_evidence_count<>coalesce((v_state->>'evidence_count')::integer,-1)
       or v_evidence_count not between 1 and 256 then
        raise exception 'process episode evidence count mismatch';
    end if;
    if exists (
        select 1 from jsonb_array_elements(v_manifest) with ordinality item(value,ord)
        where (value->>'evidence_order')::integer<>ord-1
           or (value->>'domain_id')::bigint<>(v_state->>'domain_id')::bigint
           or (value->>'source_host_id')::bigint<>(v_state->>'source_host_id')::bigint
    ) or (
        select count(distinct (value->>'source_event_id')::bigint)
        from jsonb_array_elements(v_manifest) item(value)
    )<>v_evidence_count then
        raise exception 'process episode evidence membership/provenance mismatch';
    end if;
    if (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='boot_scope'
    )<>1 or (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='boot_scope'
          and value->>'semantic_type'='system.boot.boundary'
          and (value->>'source_event_id')::bigint=(v_state->>'boot_event_id')::bigint
    )<>1 then
        raise exception 'process episode boot evidence mismatch';
    end if;
    select case when count(distinct lower(value->>'source_channel'))>1
        then 'cross_channel_uncertain' else 'source_native' end
    into v_derived_ordering_state
    from jsonb_array_elements(v_manifest) item(value);
    if v_state->>'ordering_state'<>v_derived_ordering_state then
        raise exception 'process episode derived ordering mismatch';
    end if;
    if (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='start'
    )<>1 or (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='start'
          and (value->>'source_event_id')::bigint=(v_state->>'start_event_id')::bigint
          and (value->>'observed_at_utc')::timestamptz=(v_state->>'started_at_utc')::timestamptz
    )<>1 then
        raise exception 'process episode start evidence mismatch';
    end if;
    if (v_state->>'end_event_id') is null then
        if exists(select 1 from jsonb_array_elements(v_manifest) item(value) where value->>'evidence_role'='confirmed_end') then
            raise exception 'process episode end evidence mismatch';
        end if;
    elsif (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='confirmed_end'
    )<>1 or (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='confirmed_end'
          and (value->>'source_event_id')::bigint=(v_state->>'end_event_id')::bigint
          and (value->>'observed_at_utc')::timestamptz=(v_state->>'confirmed_end_at_utc')::timestamptz
    )<>1 then
        raise exception 'process episode end evidence mismatch';
    end if;

    -- An exact replay remains verifiable from the immutable durable manifest
    -- after the seven-day hot source window has expired.  New revisions still
    -- require the authoritative hot-source validation below.
    perform pg_advisory_xact_lock(hashtextextended(v_state->>'episode_id',0));
    select * into v_existing from public.process_episode_revisions where idempotency_key=v_idempotency;
    if found then
        select jsonb_agg(jsonb_build_object(
            'evidence_order',e.evidence_order,
            'source_event_id',e.source_event_id,
            'evidence_role',e.evidence_role,
            'semantic_type',e.semantic_type,
            'semantic_contract_version',e.semantic_contract_version,
            'normalizer_id',e.normalizer_id,
            'normalizer_version',e.normalizer_version,
            'semantic_sha256',encode(e.semantic_sha256,'hex'),
            'observed_at_utc',m.value->>'observed_at_utc',
            'source_channel',e.source_channel,
            'event_record_id',e.event_record_id,
            'source_event_sha256',encode(e.source_event_sha256,'hex'),
            'source_facts_sha256',encode(e.source_facts_sha256,'hex'),
            'domain_id',e.domain_id,
            'source_host_id',e.source_host_id
        ) order by e.evidence_order) into v_expected_manifest
        from public.process_episode_evidence e
        join jsonb_array_elements(v_manifest) m(value)
          on (m.value->>'evidence_order')::integer=e.evidence_order
        where e.revision_id=v_existing.revision_id
          and (m.value->>'observed_at_utc')::timestamptz=e.observed_at_utc;
        if v_existing.revision_id<>v_revision_id
           or v_existing.revision_sha256<>v_revision_sha
           or v_existing.revision_payload<>v_revision_payload
           or v_existing.evidence_manifest_payload<>v_manifest_payload
           or (select count(*) from public.process_episode_evidence where revision_id=v_existing.revision_id)<>v_evidence_count
           or coalesce(v_expected_manifest,'[]'::jsonb)<>v_manifest then
            raise exception 'process episode evidence replay conflict';
        end if;
        return v_existing.revision_id;
    end if;

    -- Validate caller-supplied identity/provenance only.  This deliberately
    -- does not infer process membership: the single semantic worker remains
    -- the only component that assembles an episode.
    if exists (
        select 1
        from jsonb_array_elements(v_manifest) item(value)
        left join public.events_v2_core source
          on source.id=(item.value->>'source_event_id')::bigint
        left join public.event_facts_v2 facts on facts.event_id=source.id
        left join public.storage_v2_channel channel on channel.id=source.channel_id
        where item.value->>'source_event_id' is null
           or item.value->>'semantic_type' is null
           or item.value->>'observed_at_utc' is null
           or item.value->>'domain_id' is null
           or item.value->>'source_host_id' is null
           or item.value->>'source_channel' is null
           or item.value->>'event_record_id' is null
           or item.value->>'source_event_sha256' is null
           or item.value->>'source_facts_sha256' is null
           or source.id is null
           or facts.event_id is null
           or channel.id is null
           or source.domain_id<>(item.value->>'domain_id')::bigint
           or source.server_id<>(item.value->>'source_host_id')::bigint
           or source.time_created_utc<>(item.value->>'observed_at_utc')::timestamptz
           or channel.value<>(item.value->>'source_channel')
           or source.event_record_id is null
           or source.event_record_id<>(item.value->>'event_record_id')::bigint
           or source.normalized_hash<>decode(item.value->>'source_event_sha256','hex')
           or facts.source_facts_sha256<>decode(item.value->>'source_facts_sha256','hex')
           or (
                select count(*) from public.normalized_events normalized
                where normalized.source_event_id=source.id
                  and normalized.processing_status='normalized'
                  and normalized.semantic_type=item.value->>'semantic_type'
                  and normalized.semantic_contract_version=(item.value->>'semantic_contract_version')::integer
                  and normalized.normalizer_id=item.value->>'normalizer_id'
                  and normalized.normalizer_version=item.value->>'normalizer_version'
                  and normalized.semantic_sha256=decode(item.value->>'semantic_sha256','hex')
                  and normalized.occurred_at_utc=source.time_created_utc
                  and normalized.source_event_sha256=source.normalized_hash
           )<>1
    ) then
        raise exception 'process episode evidence does not match authoritative hot source';
    end if;

    select coalesce(max(revision_no),0)+1 into v_next_revision
    from public.process_episode_revisions where episode_id=v_state->>'episode_id';
    insert into public.process_episode_revisions(
        revision_id,episode_id,revision_no,assembler_id,assembler_version,
        idempotency_key,revision_sha256,revision_payload,evidence_manifest_sha256,
        evidence_manifest_payload,completeness_state,confirmation_state,
        ordering_state,domain_id,source_host_id,display_host,boot_event_id,
        process_id,start_event_id,started_at_utc,end_event_id,confirmed_end_at_utc,
        process_name,parent_process_id,parent_episode_id,command_line,user_sid,
        user_name,user_domain,logon_id,evidence_count
    ) values(
        v_revision_id,v_state->>'episode_id',v_next_revision,v_state->>'assembler_id',
        v_state->>'assembler_version',v_idempotency,v_revision_sha,v_revision_payload,
        v_manifest_sha,v_manifest_payload,v_state->>'completeness_state',
        v_state->>'confirmation_state',v_state->>'ordering_state',
        (v_state->>'domain_id')::bigint,(v_state->>'source_host_id')::bigint,
        v_state->>'display_host',(v_state->>'boot_event_id')::bigint,
        (v_state->>'process_id')::bigint,(v_state->>'start_event_id')::bigint,
        (v_state->>'started_at_utc')::timestamptz,
        (v_state->>'end_event_id')::bigint,
        (v_state->>'confirmed_end_at_utc')::timestamptz,
        v_state->>'process_name',(v_state->>'parent_process_id')::bigint,
        v_state->>'parent_episode_id',v_state->>'command_line',v_state->>'user_sid',
        v_state->>'user_name',v_state->>'user_domain',v_state->>'logon_id',
        v_evidence_count
    );
    for v_item in select value from jsonb_array_elements(v_manifest) item(value) loop
        insert into public.process_episode_evidence(
            revision_id,evidence_order,source_event_id,evidence_role,semantic_type,
            semantic_contract_version,normalizer_id,normalizer_version,semantic_sha256,
            observed_at_utc,domain_id,source_host_id,source_channel,event_record_id,
            source_event_sha256,source_facts_sha256
        ) values(
            v_revision_id,(v_item->>'evidence_order')::smallint,
            (v_item->>'source_event_id')::bigint,v_item->>'evidence_role',
            v_item->>'semantic_type',(v_item->>'semantic_contract_version')::integer,
            v_item->>'normalizer_id',v_item->>'normalizer_version',
            decode(v_item->>'semantic_sha256','hex'),
            (v_item->>'observed_at_utc')::timestamptz,
            (v_item->>'domain_id')::bigint,(v_item->>'source_host_id')::bigint,
            v_item->>'source_channel',(v_item->>'event_record_id')::bigint,
            decode(v_item->>'source_event_sha256','hex'),
            decode(v_item->>'source_facts_sha256','hex')
        );
    end loop;
    return v_revision_id;
end
$$;


ALTER FUNCTION public.write_process_episode_revision_v89(p jsonb) OWNER TO adlog_storage_owner;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_audit_v4; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_audit_v4 (
    id bigint NOT NULL,
    actor_type text NOT NULL,
    actor_id bigint,
    action text NOT NULL,
    subject_type text,
    subject_id bigint,
    target_type text,
    target_key text,
    reason text,
    outcome text DEFAULT 'ok'::text NOT NULL,
    details_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    remote_address text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.access_audit_v4 OWNER TO adlog_user;

--
-- Name: access_audit_v4_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.access_audit_v4_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_audit_v4_id_seq OWNER TO adlog_user;

--
-- Name: access_audit_v4_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.access_audit_v4_id_seq OWNED BY public.access_audit_v4.id;


--
-- Name: access_capabilities; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_capabilities (
    id bigint NOT NULL,
    capability_key text NOT NULL,
    label text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.access_capabilities OWNER TO adlog_user;

--
-- Name: access_capabilities_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.access_capabilities_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_capabilities_id_seq OWNER TO adlog_user;

--
-- Name: access_capabilities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.access_capabilities_id_seq OWNED BY public.access_capabilities.id;


--
-- Name: access_capability_assignments; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_capability_assignments (
    id bigint NOT NULL,
    subject_type text NOT NULL,
    subject_id bigint NOT NULL,
    capability_id bigint NOT NULL,
    effect text NOT NULL,
    scope_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    business_reason text NOT NULL,
    approved_by text,
    source_type text DEFAULT 'direct'::text NOT NULL,
    created_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT access_capability_assignments_effect_check CHECK ((effect = ANY (ARRAY['allow'::text, 'deny'::text]))),
    CONSTRAINT access_capability_assignments_source_type_check CHECK ((source_type = ANY (ARRAY['group'::text, 'direct'::text, 'temporary'::text, 'system'::text]))),
    CONSTRAINT access_capability_assignments_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'group'::text])))
);


ALTER TABLE public.access_capability_assignments OWNER TO adlog_user;

--
-- Name: access_capability_assignments_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.access_capability_assignments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_capability_assignments_id_seq OWNER TO adlog_user;

--
-- Name: access_capability_assignments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.access_capability_assignments_id_seq OWNED BY public.access_capability_assignments.id;


--
-- Name: access_group_members; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_group_members (
    group_id bigint NOT NULL,
    user_id bigint NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    source text DEFAULT 'direct'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.access_group_members OWNER TO adlog_user;

--
-- Name: access_groups; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_groups (
    id bigint NOT NULL,
    group_key text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.access_groups OWNER TO adlog_user;

--
-- Name: access_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.access_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_groups_id_seq OWNER TO adlog_user;

--
-- Name: access_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.access_groups_id_seq OWNED BY public.access_groups.id;


--
-- Name: access_package_capabilities; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_package_capabilities (
    package_id bigint NOT NULL,
    capability_id bigint NOT NULL
);


ALTER TABLE public.access_package_capabilities OWNER TO adlog_user;

--
-- Name: access_package_reports; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_package_reports (
    package_id bigint NOT NULL,
    report_key text NOT NULL,
    field_categories text[] DEFAULT ARRAY[]::text[] NOT NULL,
    allowed_actions text[] DEFAULT ARRAY['view'::text] NOT NULL,
    scope_json jsonb DEFAULT '{"kind": "all"}'::jsonb NOT NULL
);


ALTER TABLE public.access_package_reports OWNER TO adlog_user;

--
-- Name: access_packages; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_packages (
    id bigint NOT NULL,
    package_key text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    is_system boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.access_packages OWNER TO adlog_user;

--
-- Name: access_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.access_packages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_packages_id_seq OWNER TO adlog_user;

--
-- Name: access_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.access_packages_id_seq OWNED BY public.access_packages.id;


--
-- Name: access_platform_owners; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_platform_owners (
    user_id bigint NOT NULL,
    owner_key text NOT NULL,
    business_reason text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.access_platform_owners OWNER TO adlog_user;

--
-- Name: access_report_assignments; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_report_assignments (
    id bigint NOT NULL,
    subject_type text NOT NULL,
    subject_id bigint NOT NULL,
    report_key text NOT NULL,
    access_level text DEFAULT 'view'::text NOT NULL,
    effect text DEFAULT 'allow'::text NOT NULL,
    scope_json jsonb DEFAULT '{"kind": "all"}'::jsonb NOT NULL,
    field_categories text[] DEFAULT ARRAY[]::text[] NOT NULL,
    allowed_actions text[] DEFAULT ARRAY['view'::text] NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    source_type text DEFAULT 'direct'::text NOT NULL,
    business_reason text NOT NULL,
    approved_by text,
    created_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT access_report_assignments_access_level_check CHECK ((access_level = ANY (ARRAY['view'::text, 'manage'::text]))),
    CONSTRAINT access_report_assignments_effect_check CHECK ((effect = ANY (ARRAY['allow'::text, 'deny'::text]))),
    CONSTRAINT access_report_assignments_source_type_check CHECK ((source_type = ANY (ARRAY['group'::text, 'direct'::text, 'temporary'::text, 'system'::text]))),
    CONSTRAINT access_report_assignments_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'group'::text])))
);


ALTER TABLE public.access_report_assignments OWNER TO adlog_user;

--
-- Name: access_report_assignments_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.access_report_assignments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_report_assignments_id_seq OWNER TO adlog_user;

--
-- Name: access_report_assignments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.access_report_assignments_id_seq OWNED BY public.access_report_assignments.id;


--
-- Name: access_role_packages; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_role_packages (
    coarse_role text NOT NULL,
    package_id bigint NOT NULL,
    CONSTRAINT access_role_packages_coarse_role_check CHECK ((coarse_role = ANY (ARRAY['viewer'::text, 'operator'::text, 'admin'::text])))
);


ALTER TABLE public.access_role_packages OWNER TO adlog_user;

--
-- Name: access_subject_packages; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.access_subject_packages (
    id bigint NOT NULL,
    subject_type text NOT NULL,
    subject_id bigint NOT NULL,
    package_id bigint NOT NULL,
    effect text DEFAULT 'allow'::text NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    business_reason text NOT NULL,
    approved_by text,
    source_type text DEFAULT 'direct'::text NOT NULL,
    created_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT access_subject_packages_effect_check CHECK ((effect = ANY (ARRAY['allow'::text, 'deny'::text]))),
    CONSTRAINT access_subject_packages_source_type_check CHECK ((source_type = ANY (ARRAY['group'::text, 'direct'::text, 'temporary'::text, 'system'::text]))),
    CONSTRAINT access_subject_packages_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'group'::text])))
);


ALTER TABLE public.access_subject_packages OWNER TO adlog_user;

--
-- Name: access_subject_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.access_subject_packages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_subject_packages_id_seq OWNER TO adlog_user;

--
-- Name: access_subject_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.access_subject_packages_id_seq OWNED BY public.access_subject_packages.id;


--
-- Name: account_risk_acceptance_audit; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.account_risk_acceptance_audit (
    id bigint NOT NULL,
    acceptance_id bigint NOT NULL,
    action text NOT NULL,
    actor text NOT NULL,
    snapshot_json jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_risk_acceptance_audit_action_check CHECK ((action = ANY (ARRAY['created'::text, 'updated'::text, 'revoked'::text])))
);


ALTER TABLE public.account_risk_acceptance_audit OWNER TO postgres;

--
-- Name: account_risk_acceptance_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.account_risk_acceptance_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.account_risk_acceptance_audit_id_seq OWNER TO postgres;

--
-- Name: account_risk_acceptance_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.account_risk_acceptance_audit_id_seq OWNED BY public.account_risk_acceptance_audit.id;


--
-- Name: account_risk_acceptances; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.account_risk_acceptances (
    id bigint NOT NULL,
    public_id uuid NOT NULL,
    entity_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    risk_key text NOT NULL,
    rule_version integer NOT NULL,
    reason text NOT NULL,
    responsible text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_by text,
    revoked_at timestamp with time zone,
    revoke_reason text,
    CONSTRAINT account_risk_acceptances_check CHECK ((valid_until > valid_from)),
    CONSTRAINT account_risk_acceptances_check1 CHECK (((status = 'revoked'::text) = (revoked_at IS NOT NULL))),
    CONSTRAINT account_risk_acceptances_reason_check CHECK (((length(TRIM(BOTH FROM reason)) >= 3) AND (length(TRIM(BOTH FROM reason)) <= 2000))),
    CONSTRAINT account_risk_acceptances_responsible_check CHECK (((length(TRIM(BOTH FROM responsible)) >= 1) AND (length(TRIM(BOTH FROM responsible)) <= 256))),
    CONSTRAINT account_risk_acceptances_rule_version_check CHECK ((rule_version > 0)),
    CONSTRAINT account_risk_acceptances_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'revoked'::text, 'superseded'::text])))
);


ALTER TABLE public.account_risk_acceptances OWNER TO postgres;

--
-- Name: account_risk_acceptances_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.account_risk_acceptances_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.account_risk_acceptances_id_seq OWNER TO postgres;

--
-- Name: account_risk_acceptances_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.account_risk_acceptances_id_seq OWNED BY public.account_risk_acceptances.id;


--
-- Name: account_risk_investigation_links; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.account_risk_investigation_links (
    id bigint NOT NULL,
    investigation_id bigint NOT NULL,
    entity_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    risk_key text NOT NULL,
    rule_version integer NOT NULL,
    qualification_snapshot jsonb CONSTRAINT account_risk_investigation_link_qualification_snapshot_not_null NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_risk_investigation_links_rule_version_check CHECK ((rule_version > 0))
);


ALTER TABLE public.account_risk_investigation_links OWNER TO postgres;

--
-- Name: account_risk_investigation_links_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.account_risk_investigation_links_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.account_risk_investigation_links_id_seq OWNER TO postgres;

--
-- Name: account_risk_investigation_links_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.account_risk_investigation_links_id_seq OWNED BY public.account_risk_investigation_links.id;


--
-- Name: acquisition_consumer_subscriptions; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.acquisition_consumer_subscriptions (
    subscription_id text NOT NULL,
    source_instance_id text NOT NULL,
    stream_id text NOT NULL,
    transport_binding text NOT NULL,
    consumer_id text NOT NULL,
    consumer_component_id text CONSTRAINT acquisition_consumer_subscriptio_consumer_component_id_not_null NOT NULL,
    consumer_component_version text CONSTRAINT acquisition_consumer_subscr_consumer_component_version_not_null NOT NULL,
    routing_contract_id text NOT NULL,
    consumer_contract_version text CONSTRAINT acquisition_consumer_subscri_consumer_contract_version_not_null NOT NULL,
    replay_policy text NOT NULL,
    resource_profile_id text NOT NULL,
    selector_json jsonb NOT NULL,
    selector_sha256 text NOT NULL,
    authority_mode text NOT NULL,
    desired_activation text DEFAULT 'disabled'::text NOT NULL,
    partition_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT acquisition_consumer_subscript_consumer_component_version_check CHECK ((btrim(consumer_component_version) <> ''::text)),
    CONSTRAINT acquisition_consumer_subscripti_consumer_contract_version_check CHECK ((btrim(consumer_contract_version) <> ''::text)),
    CONSTRAINT acquisition_consumer_subscriptions_authority_mode_check CHECK ((authority_mode = ANY (ARRAY['authoritative'::text, 'shadow'::text]))),
    CONSTRAINT acquisition_consumer_subscriptions_consumer_component_id_check CHECK ((btrim(consumer_component_id) <> ''::text)),
    CONSTRAINT acquisition_consumer_subscriptions_consumer_id_check CHECK ((btrim(consumer_id) <> ''::text)),
    CONSTRAINT acquisition_consumer_subscriptions_desired_activation_check CHECK ((desired_activation = ANY (ARRAY['disabled'::text, 'manual_enabled'::text]))),
    CONSTRAINT acquisition_consumer_subscriptions_partition_key_check CHECK ((btrim(partition_key) <> ''::text)),
    CONSTRAINT acquisition_consumer_subscriptions_replay_policy_check CHECK ((replay_policy = ANY (ARRAY['no_replay'::text, 'bounded_replay'::text]))),
    CONSTRAINT acquisition_consumer_subscriptions_resource_profile_id_check CHECK ((btrim(resource_profile_id) <> ''::text)),
    CONSTRAINT acquisition_consumer_subscriptions_routing_contract_id_check CHECK ((btrim(routing_contract_id) <> ''::text)),
    CONSTRAINT acquisition_consumer_subscriptions_selector_json_check CHECK ((jsonb_typeof(selector_json) = 'object'::text)),
    CONSTRAINT acquisition_consumer_subscriptions_selector_sha256_check CHECK ((selector_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT acquisition_consumer_subscriptions_subscription_id_check CHECK ((subscription_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text))
);


ALTER TABLE public.acquisition_consumer_subscriptions OWNER TO adlog_storage_owner;

--
-- Name: acquisition_delivery_outbox; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.acquisition_delivery_outbox (
    delivery_id bigint NOT NULL,
    subscription_id text NOT NULL,
    evidence_uid uuid NOT NULL,
    observation_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    delivery_state text DEFAULT 'queued'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    attempt_count integer DEFAULT 0 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_token uuid,
    lease_until timestamp with time zone,
    heartbeat_at timestamp with time zone,
    last_error_code text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT acquisition_delivery_outbox_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT acquisition_delivery_outbox_check CHECK ((((delivery_state = 'delivered'::text) AND (delivered_at IS NOT NULL)) OR ((delivery_state <> 'delivered'::text) AND (delivered_at IS NULL)))),
    CONSTRAINT acquisition_delivery_outbox_delivery_state_check CHECK ((delivery_state = ANY (ARRAY['queued'::text, 'leased'::text, 'failed'::text, 'delivered'::text, 'quarantined'::text]))),
    CONSTRAINT acquisition_delivery_outbox_error_code_check CHECK (((last_error_code IS NULL) OR (last_error_code ~ '^[a-z][a-z0-9_]{0,119}$'::text))),
    CONSTRAINT acquisition_delivery_outbox_idempotency_key_check CHECK ((idempotency_key ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT acquisition_delivery_outbox_lease_check CHECK ((((delivery_state = 'leased'::text) AND (lease_token IS NOT NULL) AND (lease_until IS NOT NULL)) OR ((delivery_state <> 'leased'::text) AND (lease_token IS NULL) AND (lease_until IS NULL))))
);


ALTER TABLE public.acquisition_delivery_outbox OWNER TO adlog_storage_owner;

--
-- Name: acquisition_delivery_outbox_delivery_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

CREATE SEQUENCE public.acquisition_delivery_outbox_delivery_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.acquisition_delivery_outbox_delivery_id_seq OWNER TO adlog_storage_owner;

--
-- Name: acquisition_delivery_outbox_delivery_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_storage_owner
--

ALTER SEQUENCE public.acquisition_delivery_outbox_delivery_id_seq OWNED BY public.acquisition_delivery_outbox.delivery_id;


--
-- Name: acquisition_source_instances; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.acquisition_source_instances (
    source_instance_id text NOT NULL,
    organization_scope text NOT NULL,
    source_kind text NOT NULL,
    endpoint_identity text NOT NULL,
    adapter_binding text NOT NULL,
    credential_handle text,
    display_name text NOT NULL,
    desired_activation text DEFAULT 'disabled'::text NOT NULL,
    observed_health text DEFAULT 'unknown'::text NOT NULL,
    configuration_sha256 text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT acquisition_source_instances_adapter_binding_check CHECK ((btrim(adapter_binding) <> ''::text)),
    CONSTRAINT acquisition_source_instances_configuration_sha256_check CHECK ((configuration_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT acquisition_source_instances_credential_handle_check CHECK (((credential_handle IS NULL) OR ((credential_handle ~ '^secret:[A-Za-z0-9_.:-]+$'::text) AND (length(credential_handle) <= 507)))),
    CONSTRAINT acquisition_source_instances_desired_activation_check CHECK ((desired_activation = ANY (ARRAY['disabled'::text, 'manual_enabled'::text]))),
    CONSTRAINT acquisition_source_instances_display_name_check CHECK ((btrim(display_name) <> ''::text)),
    CONSTRAINT acquisition_source_instances_endpoint_identity_check CHECK ((btrim(endpoint_identity) <> ''::text)),
    CONSTRAINT acquisition_source_instances_observed_health_check CHECK ((observed_health = ANY (ARRAY['unknown'::text, 'ready'::text, 'degraded'::text, 'blocked'::text]))),
    CONSTRAINT acquisition_source_instances_organization_scope_check CHECK ((btrim(organization_scope) <> ''::text)),
    CONSTRAINT acquisition_source_instances_source_instance_id_check CHECK ((source_instance_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text)),
    CONSTRAINT acquisition_source_instances_source_kind_check CHECK ((btrim(source_kind) <> ''::text))
);


ALTER TABLE public.acquisition_source_instances OWNER TO adlog_storage_owner;

--
-- Name: acquisition_stream_cursors; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.acquisition_stream_cursors (
    source_instance_id text NOT NULL,
    stream_id text NOT NULL,
    transport_binding text NOT NULL,
    cursor_epoch uuid NOT NULL,
    file_generation text NOT NULL,
    byte_offset bigint NOT NULL,
    last_record_sha256 text,
    previous_file_generation text,
    previous_generation_last_record_sha256 text,
    revision bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT acquisition_stream_cursors_byte_offset_check CHECK ((byte_offset >= 0)),
    CONSTRAINT acquisition_stream_cursors_file_generation_check CHECK ((file_generation ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text)),
    CONSTRAINT acquisition_stream_cursors_last_record_sha256_check CHECK (((last_record_sha256 IS NULL) OR (last_record_sha256 ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT acquisition_stream_cursors_previous_generation_last_recor_check CHECK (((previous_generation_last_record_sha256 IS NULL) OR (previous_generation_last_record_sha256 ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT acquisition_stream_cursors_revision_check CHECK ((revision >= 0)),
    CONSTRAINT acquisition_stream_cursors_stream_id_check CHECK ((stream_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text)),
    CONSTRAINT acquisition_stream_cursors_transport_binding_check CHECK ((transport_binding ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text))
);


ALTER TABLE public.acquisition_stream_cursors OWNER TO adlog_storage_owner;

--
-- Name: ad_context_entity_aliases; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ad_context_entity_aliases (
    id bigint NOT NULL,
    entity_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    alias_type text NOT NULL,
    alias_value text NOT NULL,
    normalized_value text NOT NULL,
    first_seen_utc timestamp with time zone NOT NULL,
    last_seen_utc timestamp with time zone NOT NULL,
    source_run_id uuid NOT NULL,
    CONSTRAINT ad_context_entity_aliases_alias_type_check CHECK ((alias_type = ANY (ARRAY['object_guid'::text, 'object_sid'::text, 'distinguished_name'::text, 'sam_account_name'::text])))
);


ALTER TABLE public.ad_context_entity_aliases OWNER TO adlog_user;

--
-- Name: ad_context_entity_aliases_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.ad_context_entity_aliases_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ad_context_entity_aliases_id_seq OWNER TO adlog_user;

--
-- Name: ad_context_entity_aliases_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.ad_context_entity_aliases_id_seq OWNED BY public.ad_context_entity_aliases.id;


--
-- Name: ad_context_entity_versions; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ad_context_entity_versions (
    id bigint NOT NULL,
    entity_id bigint NOT NULL,
    source_section text NOT NULL,
    valid_from_utc timestamp with time zone NOT NULL,
    valid_to_utc timestamp with time zone,
    last_observed_at_utc timestamp with time zone NOT NULL,
    content_sha256 bytea NOT NULL,
    attributes_json jsonb NOT NULL,
    source_run_id uuid NOT NULL,
    CONSTRAINT ad_context_entity_versions_check CHECK (((valid_to_utc IS NULL) OR (valid_to_utc >= valid_from_utc))),
    CONSTRAINT ad_context_entity_versions_content_sha256_check CHECK ((octet_length(content_sha256) = 32))
);


ALTER TABLE public.ad_context_entity_versions OWNER TO adlog_user;

--
-- Name: ad_context_entity_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.ad_context_entity_versions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ad_context_entity_versions_id_seq OWNER TO adlog_user;

--
-- Name: ad_context_entity_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.ad_context_entity_versions_id_seq OWNED BY public.ad_context_entity_versions.id;


--
-- Name: ad_context_event_links; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ad_context_event_links (
    event_db_id bigint NOT NULL,
    context_evidence_id bigint NOT NULL,
    rule_code text NOT NULL,
    relation_status text NOT NULL,
    explanation text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ad_context_event_links_relation_status_check CHECK ((relation_status = ANY (ARRAY['confirmed'::text, 'current_only'::text, 'excluded'::text])))
);


ALTER TABLE public.ad_context_event_links OWNER TO adlog_user;

--
-- Name: COLUMN ad_context_event_links.event_db_id; Type: COMMENT; Schema: public; Owner: adlog_user
--

COMMENT ON COLUMN public.ad_context_event_links.event_db_id IS 'Stable event evidence ID validated by application against events or events_v2_core';


--
-- Name: ad_context_evidence; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ad_context_evidence (
    id bigint NOT NULL,
    evidence_key text NOT NULL,
    evidence_type text NOT NULL,
    source_pack_id text NOT NULL,
    source_run_id uuid NOT NULL,
    observed_at_utc timestamp with time zone NOT NULL,
    locator_json jsonb NOT NULL,
    integrity_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ad_context_evidence_evidence_type_check CHECK ((evidence_type = ANY (ARRAY['entity_observation'::text, 'relation_observation'::text, 'data_quality'::text]))),
    CONSTRAINT ad_context_evidence_integrity_sha256_check CHECK ((octet_length(integrity_sha256) = 32))
);


ALTER TABLE public.ad_context_evidence OWNER TO adlog_user;

--
-- Name: ad_context_evidence_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.ad_context_evidence_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ad_context_evidence_id_seq OWNER TO adlog_user;

--
-- Name: ad_context_evidence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.ad_context_evidence_id_seq OWNED BY public.ad_context_evidence.id;


--
-- Name: ad_context_relation_versions; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ad_context_relation_versions (
    id bigint NOT NULL,
    relation_key text NOT NULL,
    relation_kind text NOT NULL,
    source_entity_id bigint NOT NULL,
    target_entity_id bigint NOT NULL,
    source_section text NOT NULL,
    domain_id bigint NOT NULL,
    valid_from_utc timestamp with time zone NOT NULL,
    valid_to_utc timestamp with time zone,
    last_observed_at_utc timestamp with time zone NOT NULL,
    content_sha256 bytea NOT NULL,
    attributes_json jsonb NOT NULL,
    source_run_id uuid NOT NULL,
    CONSTRAINT ad_context_relation_versions_check CHECK ((source_entity_id <> target_entity_id)),
    CONSTRAINT ad_context_relation_versions_check1 CHECK (((valid_to_utc IS NULL) OR (valid_to_utc >= valid_from_utc))),
    CONSTRAINT ad_context_relation_versions_content_sha256_check CHECK ((octet_length(content_sha256) = 32)),
    CONSTRAINT ad_context_relation_versions_relation_kind_check CHECK ((relation_kind = 'member_of'::text))
);


ALTER TABLE public.ad_context_relation_versions OWNER TO adlog_user;

--
-- Name: ad_context_relation_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.ad_context_relation_versions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ad_context_relation_versions_id_seq OWNER TO adlog_user;

--
-- Name: ad_context_relation_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.ad_context_relation_versions_id_seq OWNED BY public.ad_context_relation_versions.id;


--
-- Name: ad_context_runs; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ad_context_runs (
    run_id uuid NOT NULL,
    source_pack_id text NOT NULL,
    source_pack_version text NOT NULL,
    domain_id bigint NOT NULL,
    mode text NOT NULL,
    observed_at_utc timestamp with time zone NOT NULL,
    bundle_sha256 bytea NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    scope_json jsonb,
    CONSTRAINT ad_context_runs_bundle_sha256_check CHECK ((octet_length(bundle_sha256) = 32)),
    CONSTRAINT ad_context_runs_mode_check CHECK ((mode = ANY (ARRAY['full'::text, 'targeted'::text, 'reconcile'::text]))),
    CONSTRAINT ad_context_runs_scope_json_object CHECK (((scope_json IS NULL) OR (jsonb_typeof(scope_json) = 'object'::text))),
    CONSTRAINT ad_context_runs_status_check CHECK ((status = ANY (ARRAY['importing'::text, 'completed'::text, 'failed'::text])))
);


ALTER TABLE public.ad_context_runs OWNER TO adlog_user;

--
-- Name: ad_context_sections; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ad_context_sections (
    run_id uuid NOT NULL,
    section_name text NOT NULL,
    status text NOT NULL,
    record_count integer NOT NULL,
    duration_ms bigint DEFAULT 0 NOT NULL,
    error_code text,
    CONSTRAINT ad_context_sections_duration_ms_check CHECK ((duration_ms >= 0)),
    CONSTRAINT ad_context_sections_record_count_check CHECK ((record_count >= 0)),
    CONSTRAINT ad_context_sections_status_check CHECK ((status = ANY (ARRAY['complete'::text, 'partial'::text, 'failed'::text, 'skipped'::text])))
);


ALTER TABLE public.ad_context_sections OWNER TO adlog_user;

--
-- Name: ad_snapshot_manifest_sources; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ad_snapshot_manifest_sources (
    manifest_id uuid NOT NULL,
    family text NOT NULL,
    contract_id text NOT NULL,
    source_id text NOT NULL,
    observed_at_utc timestamp with time zone NOT NULL,
    source_state text NOT NULL,
    payload_sha256 bytea NOT NULL,
    reason_code text,
    CONSTRAINT ad_snapshot_manifest_sources_check CHECK ((((source_state = 'complete'::text) AND (reason_code IS NULL)) OR ((source_state <> 'complete'::text) AND (reason_code IS NOT NULL) AND (length(btrim(reason_code)) > 0)))),
    CONSTRAINT ad_snapshot_manifest_sources_contract_id_check CHECK ((length(btrim(contract_id)) > 0)),
    CONSTRAINT ad_snapshot_manifest_sources_family_check CHECK ((family = ANY (ARRAY['ad_context_base'::text, 'ad_privileged_membership'::text, 'ad_vpn_membership'::text, 'ad_domain_posture'::text, 'ad_domain_health'::text, 'ad_gpo_governance'::text, 'users_v2'::text, 'computers_v6'::text, 'gpo_v2'::text]))),
    CONSTRAINT ad_snapshot_manifest_sources_payload_sha256_check CHECK ((octet_length(payload_sha256) = 32)),
    CONSTRAINT ad_snapshot_manifest_sources_source_id_check CHECK ((length(btrim(source_id)) > 0)),
    CONSTRAINT ad_snapshot_manifest_sources_source_state_check CHECK ((source_state = ANY (ARRAY['complete'::text, 'partial'::text, 'failed'::text])))
);


ALTER TABLE public.ad_snapshot_manifest_sources OWNER TO postgres;

--
-- Name: ad_snapshot_manifests; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ad_snapshot_manifests (
    manifest_id uuid NOT NULL,
    domain_id bigint NOT NULL,
    domain_sid text NOT NULL,
    domain_dns text NOT NULL,
    slot_start_utc timestamp with time zone NOT NULL,
    assembled_at_utc timestamp with time zone NOT NULL,
    contract_version text NOT NULL,
    coverage_state text NOT NULL,
    manifest_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    schedule_timezone text,
    scheduled_local_at timestamp without time zone,
    CONSTRAINT ad_snapshot_manifests_check CHECK ((assembled_at_utc >= slot_start_utc)),
    CONSTRAINT ad_snapshot_manifests_contract_version_check CHECK ((contract_version = ANY (ARRAY['sli.ad-snapshot-manifest/1.0'::text, 'sli.ad-snapshot-manifest/2.0'::text]))),
    CONSTRAINT ad_snapshot_manifests_coverage_state_check CHECK ((coverage_state = ANY (ARRAY['complete'::text, 'partial'::text]))),
    CONSTRAINT ad_snapshot_manifests_domain_dns_check CHECK ((length(btrim(domain_dns)) > 0)),
    CONSTRAINT ad_snapshot_manifests_domain_sid_check CHECK ((length(btrim(domain_sid)) > 0)),
    CONSTRAINT ad_snapshot_manifests_manifest_sha256_check CHECK ((octet_length(manifest_sha256) = 32)),
    CONSTRAINT ad_snapshot_manifests_slot_start_utc_check CHECK ((((contract_version = 'sli.ad-snapshot-manifest/1.0'::text) AND (schedule_timezone IS NULL) AND (scheduled_local_at IS NULL) AND (((slot_start_utc AT TIME ZONE 'UTC'::text) = date_trunc('day'::text, (slot_start_utc AT TIME ZONE 'UTC'::text))) OR ((slot_start_utc AT TIME ZONE 'UTC'::text) = (date_trunc('day'::text, (slot_start_utc AT TIME ZONE 'UTC'::text)) + '12:00:00'::interval)))) OR ((contract_version = 'sli.ad-snapshot-manifest/2.0'::text) AND (schedule_timezone = 'Asia/Novosibirsk'::text) AND (scheduled_local_at IS NOT NULL) AND (scheduled_local_at = date_trunc('minute'::text, scheduled_local_at)) AND ((scheduled_local_at)::time without time zone = ANY (ARRAY['06:00:00'::time without time zone, '18:00:00'::time without time zone])) AND (slot_start_utc = (scheduled_local_at AT TIME ZONE 'Asia/Novosibirsk'::text)))))
);


ALTER TABLE public.ad_snapshot_manifests OWNER TO postgres;

--
-- Name: ad_snapshot_projection_outputs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ad_snapshot_projection_outputs (
    manifest_id uuid NOT NULL,
    projection_key text NOT NULL,
    projection_version integer NOT NULL,
    input_sha256 bytea NOT NULL,
    output_sha256 bytea NOT NULL,
    output_identity text NOT NULL,
    payload_json jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ad_snapshot_projection_outputs_allowlist_check CHECK ((((projection_key = 'ad.users.v2'::text) AND (projection_version = 1)) OR ((projection_key = 'ad.computers.v6'::text) AND (projection_version = 1)) OR ((projection_key = 'ad.gpo.v2'::text) AND (projection_version = 1)) OR ((projection_key = 'ad.state'::text) AND (projection_version = 1)))),
    CONSTRAINT ad_snapshot_projection_outputs_identity_check CHECK ((output_identity = (((((manifest_id)::text || ':'::text) || projection_key) || ':v'::text) || (projection_version)::text))),
    CONSTRAINT ad_snapshot_projection_outputs_input_sha256_check CHECK ((octet_length(input_sha256) = 32)),
    CONSTRAINT ad_snapshot_projection_outputs_output_sha256_check CHECK ((octet_length(output_sha256) = 32))
);


ALTER TABLE public.ad_snapshot_projection_outputs OWNER TO postgres;

--
-- Name: ad_snapshot_projection_receipts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ad_snapshot_projection_receipts (
    manifest_id uuid NOT NULL,
    projection_key text NOT NULL,
    projection_version integer NOT NULL,
    status text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    lease_owner text,
    lease_expires_at timestamp with time zone,
    input_sha256 bytea,
    output_sha256 bytea,
    output_identity text,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ad_snapshot_projection_receipts_attempt_count_check CHECK (((attempt_count >= 0) AND (attempt_count <= 16))),
    CONSTRAINT ad_snapshot_projection_receipts_check CHECK (((status = 'running'::text) = ((lease_owner IS NOT NULL) AND (lease_expires_at IS NOT NULL)))),
    CONSTRAINT ad_snapshot_projection_receipts_input_sha256_check CHECK (((input_sha256 IS NULL) OR (octet_length(input_sha256) = 32))),
    CONSTRAINT ad_snapshot_projection_receipts_output_sha256_check CHECK (((output_sha256 IS NULL) OR (octet_length(output_sha256) = 32))),
    CONSTRAINT ad_snapshot_projection_receipts_projection_key_check CHECK ((projection_key = ANY (ARRAY['ad.users.v2'::text, 'ad.computers.v6'::text, 'ad.gpo.v2'::text, 'ad.state'::text]))),
    CONSTRAINT ad_snapshot_projection_receipts_projection_version_check CHECK ((projection_version = 1)),
    CONSTRAINT ad_snapshot_projection_receipts_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])))
);


ALTER TABLE public.ad_snapshot_projection_receipts OWNER TO postgres;

--
-- Name: administrative_activity_v1; Type: TABLE; Schema: public; Owner: adlog_administrative_activity_owner
--

CREATE TABLE public.administrative_activity_v1 (
    activity_id bigint NOT NULL,
    event_uid uuid NOT NULL,
    occurred_at_utc timestamp with time zone NOT NULL,
    recorded_at_utc timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    actor_kind text NOT NULL,
    actor_key text NOT NULL,
    category text NOT NULL,
    action_key text NOT NULL,
    target_kind text,
    target_key text,
    outcome text NOT NULL,
    reason_code text,
    details_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    remote_address inet,
    correlation_id uuid,
    content_hash bytea NOT NULL,
    previous_record_hash bytea NOT NULL,
    record_hash bytea NOT NULL,
    CONSTRAINT administrative_activity_v1_action_key_check CHECK ((action_key ~ '^[a-z][a-z0-9_.-]{0,119}$'::text)),
    CONSTRAINT administrative_activity_v1_actor_key_check CHECK (((btrim(actor_key) <> ''::text) AND (length(actor_key) <= 200))),
    CONSTRAINT administrative_activity_v1_actor_kind_check CHECK ((actor_kind = ANY (ARRAY['session'::text, 'api_key'::text, 'windows'::text, 'system'::text, 'local_operator'::text, 'plugin'::text]))),
    CONSTRAINT administrative_activity_v1_category_check CHECK ((category = ANY (ARRAY['authentication'::text, 'plugin_lifecycle'::text, 'source_configuration'::text, 'access_management'::text, 'report_publication'::text, 'manual_operation'::text]))),
    CONSTRAINT administrative_activity_v1_content_hash_check CHECK ((octet_length(content_hash) = 32)),
    CONSTRAINT administrative_activity_v1_details_json_check CHECK ((jsonb_typeof(details_json) = 'object'::text)),
    CONSTRAINT administrative_activity_v1_details_json_check1 CHECK ((octet_length((details_json)::text) <= 8192)),
    CONSTRAINT administrative_activity_v1_outcome_check CHECK ((outcome = ANY (ARRAY['started'::text, 'succeeded'::text, 'failed'::text, 'denied'::text, 'stopped'::text, 'cancelled'::text]))),
    CONSTRAINT administrative_activity_v1_previous_record_hash_check CHECK ((octet_length(previous_record_hash) = 32)),
    CONSTRAINT administrative_activity_v1_reason_code_check CHECK (((reason_code IS NULL) OR (reason_code ~ '^[a-z][a-z0-9_.-]{0,119}$'::text))),
    CONSTRAINT administrative_activity_v1_record_hash_check CHECK ((octet_length(record_hash) = 32)),
    CONSTRAINT administrative_activity_v1_target_key_check CHECK (((target_key IS NULL) OR (length(target_key) <= 240))),
    CONSTRAINT administrative_activity_v1_target_kind_check CHECK (((target_kind IS NULL) OR (target_kind ~ '^[a-z][a-z0-9_.-]{0,79}$'::text)))
);


ALTER TABLE public.administrative_activity_v1 OWNER TO adlog_administrative_activity_owner;

--
-- Name: administrative_activity_v1_activity_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_administrative_activity_owner
--

ALTER TABLE public.administrative_activity_v1 ALTER COLUMN activity_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.administrative_activity_v1_activity_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: ai_analysis; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ai_analysis (
    id bigint NOT NULL,
    detection_id bigint NOT NULL,
    model_name text NOT NULL,
    prompt_version text NOT NULL,
    analyzed_at timestamp with time zone DEFAULT now() NOT NULL,
    risk text NOT NULL,
    confidence text NOT NULL,
    summary text,
    facts_json text,
    assumptions_json text,
    recommendations_json text,
    raw_response_json text
);


ALTER TABLE public.ai_analysis OWNER TO adlog_user;

--
-- Name: ai_analysis_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.ai_analysis_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ai_analysis_id_seq OWNER TO adlog_user;

--
-- Name: ai_analysis_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.ai_analysis_id_seq OWNED BY public.ai_analysis.id;


--
-- Name: ai_api_runs; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ai_api_runs (
    id bigint NOT NULL,
    provider text DEFAULT 'openai_api'::text NOT NULL,
    model text NOT NULL,
    prompt_version text NOT NULL,
    redaction_level text NOT NULL,
    status text DEFAULT 'prepared'::text NOT NULL,
    query_summary_json text,
    prompt_file_path text,
    request_file_path text,
    result_file_path text,
    report_file_path text,
    ai_call_performed boolean DEFAULT false NOT NULL,
    validation_errors_json text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at text
);


ALTER TABLE public.ai_api_runs OWNER TO adlog_user;

--
-- Name: ai_api_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.ai_api_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ai_api_runs_id_seq OWNER TO adlog_user;

--
-- Name: ai_api_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.ai_api_runs_id_seq OWNED BY public.ai_api_runs.id;


--
-- Name: ai_reviews; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.ai_reviews (
    id bigint NOT NULL,
    ai_analysis_id bigint NOT NULL,
    reviewer_model_name text NOT NULL,
    reviewed_at timestamp with time zone DEFAULT now() NOT NULL,
    report_is_valid boolean NOT NULL,
    unsafe_recommendations_json text,
    missing_evidence_json text,
    issues_json text,
    final_decision text NOT NULL,
    raw_response_json text
);


ALTER TABLE public.ai_reviews OWNER TO adlog_user;

--
-- Name: ai_reviews_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.ai_reviews_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ai_reviews_id_seq OWNER TO adlog_user;

--
-- Name: ai_reviews_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.ai_reviews_id_seq OWNED BY public.ai_reviews.id;


--
-- Name: archive_settings; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.archive_settings (
    key text NOT NULL,
    value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.archive_settings OWNER TO adlog_user;

--
-- Name: auth_api_keys; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.auth_api_keys (
    id bigint NOT NULL,
    key_prefix text NOT NULL,
    key_hash text NOT NULL,
    label text NOT NULL,
    role text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT auth_api_keys_role_check CHECK ((role = ANY (ARRAY['viewer'::text, 'operator'::text, 'admin'::text])))
);


ALTER TABLE public.auth_api_keys OWNER TO adlog_user;

--
-- Name: auth_api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.auth_api_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_api_keys_id_seq OWNER TO adlog_user;

--
-- Name: auth_api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.auth_api_keys_id_seq OWNED BY public.auth_api_keys.id;


--
-- Name: auth_audit; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.auth_audit (
    id bigint NOT NULL,
    actor_type text NOT NULL,
    actor_id bigint,
    action text NOT NULL,
    outcome text NOT NULL,
    remote_address text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.auth_audit OWNER TO adlog_user;

--
-- Name: auth_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.auth_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_audit_id_seq OWNER TO adlog_user;

--
-- Name: auth_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.auth_audit_id_seq OWNED BY public.auth_audit.id;


--
-- Name: auth_sessions; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.auth_sessions (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);


ALTER TABLE public.auth_sessions OWNER TO adlog_user;

--
-- Name: auth_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.auth_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_sessions_id_seq OWNER TO adlog_user;

--
-- Name: auth_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.auth_sessions_id_seq OWNED BY public.auth_sessions.id;


--
-- Name: auth_users; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.auth_users (
    id bigint NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at timestamp with time zone,
    CONSTRAINT auth_users_role_check CHECK ((role = ANY (ARRAY['viewer'::text, 'operator'::text, 'admin'::text])))
);


ALTER TABLE public.auth_users OWNER TO adlog_user;

--
-- Name: auth_users_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.auth_users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_users_id_seq OWNER TO adlog_user;

--
-- Name: auth_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.auth_users_id_seq OWNED BY public.auth_users.id;


--
-- Name: canonical_action_evidence; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.canonical_action_evidence (
    canonical_action_id uuid NOT NULL,
    normalized_event_id uuid NOT NULL,
    evidence_role text NOT NULL,
    entity_role text,
    evidence_order smallint NOT NULL,
    relation_confidence numeric(4,3) DEFAULT 1.000 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT canonical_action_evidence_entity_role_check CHECK (((entity_role IS NULL) OR (entity_role = ANY (ARRAY['actor'::text, 'session_principal'::text, 'affected_entity'::text, 'target_entity'::text, 'container_entity'::text, 'source_host'::text, 'source_ip'::text, 'context'::text, 'affected'::text, 'target'::text, 'container'::text, 'source'::text])))),
    CONSTRAINT canonical_action_evidence_evidence_order_check CHECK (((evidence_order >= 0) AND (evidence_order <= 32767))),
    CONSTRAINT canonical_action_evidence_evidence_role_check CHECK ((evidence_role = ANY (ARRAY['primary'::text, 'supporting'::text, 'state_confirmation'::text, 'context'::text]))),
    CONSTRAINT canonical_action_evidence_relation_confidence_check CHECK (((relation_confidence >= (0)::numeric) AND (relation_confidence <= (1)::numeric)))
);


ALTER TABLE public.canonical_action_evidence OWNER TO adlog_storage_owner;

--
-- Name: canonical_action_state_evidence; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.canonical_action_state_evidence (
    canonical_action_id uuid NOT NULL,
    context_evidence_id bigint NOT NULL,
    assessment_status text NOT NULL,
    change_origin text NOT NULL,
    match_key bytea NOT NULL,
    explanation text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT canonical_action_state_evidence_assessment_status_check CHECK ((assessment_status = ANY (ARRAY['observed'::text, 'partially_confirmed'::text, 'state_confirmed'::text, 'multi_source_confirmed'::text, 'contradicted'::text]))),
    CONSTRAINT canonical_action_state_evidence_change_origin_check CHECK ((change_origin = ANY (ARRAY['baseline_import'::text, 'incremental_sync'::text, 'targeted_reconcile'::text]))),
    CONSTRAINT canonical_action_state_evidence_explanation_check CHECK (((length(explanation) >= 1) AND (length(explanation) <= 2000))),
    CONSTRAINT canonical_action_state_evidence_match_key_check CHECK ((octet_length(match_key) = 32))
);


ALTER TABLE public.canonical_action_state_evidence OWNER TO adlog_storage_owner;

--
-- Name: canonical_actions; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.canonical_actions (
    canonical_action_id uuid NOT NULL,
    action_kind text NOT NULL,
    action_status text NOT NULL,
    semantic_contract_version integer NOT NULL,
    assembler_id text NOT NULL,
    assembler_version text NOT NULL,
    occurred_at_utc timestamp with time zone NOT NULL,
    contribution_key bytea NOT NULL,
    action_sha256 bytea NOT NULL,
    attributes_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    canonical_deduplication_key bytea NOT NULL,
    CONSTRAINT canonical_actions_action_kind_check CHECK (((length(action_kind) >= 1) AND (length(action_kind) <= 160))),
    CONSTRAINT canonical_actions_action_sha256_check CHECK ((octet_length(action_sha256) = 32)),
    CONSTRAINT canonical_actions_action_status_check CHECK ((action_status = ANY (ARRAY['observed'::text, 'partially_confirmed'::text, 'state_confirmed'::text, 'multi_source_confirmed'::text, 'contradicted'::text, 'superseded'::text, 'quarantined'::text]))),
    CONSTRAINT canonical_actions_assembler_id_check CHECK (((length(assembler_id) >= 1) AND (length(assembler_id) <= 160))),
    CONSTRAINT canonical_actions_assembler_version_check CHECK (((length(assembler_version) >= 1) AND (length(assembler_version) <= 80))),
    CONSTRAINT canonical_actions_attributes_json_check CHECK ((jsonb_typeof(attributes_json) = 'object'::text)),
    CONSTRAINT canonical_actions_contribution_key_check CHECK ((octet_length(contribution_key) = 32)),
    CONSTRAINT canonical_actions_dedup_key_length CHECK ((octet_length(canonical_deduplication_key) = 32)),
    CONSTRAINT canonical_actions_semantic_contract_version_check CHECK ((semantic_contract_version > 0))
);


ALTER TABLE public.canonical_actions OWNER TO adlog_storage_owner;

--
-- Name: collection_channel_state; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.collection_channel_state (
    server_hostname text NOT NULL,
    channel text NOT NULL,
    archive_start_utc text NOT NULL,
    last_collection_start_utc text,
    last_successful_collection_utc text,
    last_event_time_utc text,
    last_event_record_id bigint,
    backfill_completed boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_generation_identity text
);


ALTER TABLE public.collection_channel_state OWNER TO adlog_user;

--
-- Name: collection_runs; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.collection_runs (
    id bigint NOT NULL,
    run_started_at timestamp with time zone NOT NULL,
    run_finished_at timestamp with time zone,
    mode text NOT NULL,
    status text DEFAULT 'started'::text NOT NULL,
    tool_version text,
    notes text
);


ALTER TABLE public.collection_runs OWNER TO adlog_user;

--
-- Name: collection_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.collection_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.collection_runs_id_seq OWNER TO adlog_user;

--
-- Name: collection_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.collection_runs_id_seq OWNED BY public.collection_runs.id;


--
-- Name: collector_adaptive_state; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.collector_adaptive_state (
    server text NOT NULL,
    channel text NOT NULL,
    current_limit integer NOT NULL,
    consecutive_completed integer DEFAULT 0 NOT NULL,
    recovery_mode boolean DEFAULT false NOT NULL,
    last_status text,
    last_lag_minutes integer,
    last_action text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.collector_adaptive_state OWNER TO adlog_user;

--
-- Name: collector_channel_runs; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.collector_channel_runs (
    id bigint NOT NULL,
    job_id bigint,
    server text NOT NULL,
    channel text NOT NULL,
    started_utc text,
    finished_utc text,
    status text NOT NULL,
    inserted bigint DEFAULT 0 NOT NULL,
    skipped bigint DEFAULT 0 NOT NULL,
    count bigint DEFAULT 0 NOT NULL,
    partial_count bigint DEFAULT 0 NOT NULL,
    latest_event_record_id bigint,
    lag_minutes integer,
    timeout_seconds integer,
    limit_used integer,
    adaptive_action text,
    error text,
    query_duration_ms integer,
    import_duration_ms integer,
    import_queue_wait_ms integer,
    import_retry_count integer,
    report_duration_ms integer,
    total_duration_ms integer,
    events_per_second double precision,
    last_record_id_delta bigint,
    lag_delta_minutes integer,
    collection_mode text,
    requested_collection_mode text,
    cursor_strategy text,
    cursor_fallback_reason text,
    collector_backend text,
    backend_reason text,
    partial_kind text,
    failure_stage text,
    cursor_commit_allowed boolean,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.collector_channel_runs OWNER TO adlog_user;

--
-- Name: collector_channel_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.collector_channel_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.collector_channel_runs_id_seq OWNER TO adlog_user;

--
-- Name: collector_channel_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.collector_channel_runs_id_seq OWNED BY public.collector_channel_runs.id;


--
-- Name: collector_cursor_audit; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.collector_cursor_audit (
    id bigint NOT NULL,
    job_id bigint,
    trace_id text,
    server text NOT NULL,
    channel text NOT NULL,
    collection_status text NOT NULL,
    import_inserted bigint DEFAULT 0 NOT NULL,
    import_skipped bigint DEFAULT 0 NOT NULL,
    old_record_id bigint,
    proposed_record_id bigint,
    new_record_id bigint,
    old_event_time_utc text,
    proposed_event_time_utc text,
    new_event_time_utc text,
    decision text NOT NULL,
    reason text NOT NULL,
    cursor_strategy text,
    cursor_fallback_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.collector_cursor_audit OWNER TO adlog_user;

--
-- Name: collector_cursor_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.collector_cursor_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.collector_cursor_audit_id_seq OWNER TO adlog_user;

--
-- Name: collector_cursor_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.collector_cursor_audit_id_seq OWNED BY public.collector_cursor_audit.id;


--
-- Name: collector_stage_metrics; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.collector_stage_metrics (
    id bigint NOT NULL,
    job_id bigint,
    server text,
    channel text,
    backend text,
    stage text NOT NULL,
    status text DEFAULT 'completed'::text NOT NULL,
    duration_ms integer,
    events_count bigint,
    bytes_count bigint,
    error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.collector_stage_metrics OWNER TO adlog_user;

--
-- Name: collector_stage_metrics_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.collector_stage_metrics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.collector_stage_metrics_id_seq OWNER TO adlog_user;

--
-- Name: collector_stage_metrics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.collector_stage_metrics_id_seq OWNED BY public.collector_stage_metrics.id;


--
-- Name: computers_report_v5_snapshots; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.computers_report_v5_snapshots (
    snapshot_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    source_run_id uuid,
    contract_id text NOT NULL,
    schema_version integer DEFAULT 1 NOT NULL,
    scope_json jsonb NOT NULL,
    scope_sha256 bytea NOT NULL,
    bucket_start_utc timestamp with time zone NOT NULL,
    captured_at_utc timestamp with time zone NOT NULL,
    source_observed_at_utc timestamp with time zone,
    source_state text NOT NULL,
    object_count integer NOT NULL,
    payload_json jsonb NOT NULL,
    payload_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT computers_report_v5_snapshots_check CHECK ((bucket_start_utc <= captured_at_utc)),
    CONSTRAINT computers_report_v5_snapshots_check1 CHECK (((source_observed_at_utc IS NULL) OR (source_observed_at_utc <= captured_at_utc))),
    CONSTRAINT computers_report_v5_snapshots_contract_id_check CHECK ((contract_id = 'sli.computers-report.v5'::text)),
    CONSTRAINT computers_report_v5_snapshots_object_count_check CHECK ((object_count >= 0)),
    CONSTRAINT computers_report_v5_snapshots_payload_json_check CHECK ((jsonb_typeof(payload_json) = 'object'::text)),
    CONSTRAINT computers_report_v5_snapshots_payload_sha256_check CHECK ((octet_length(payload_sha256) = 32)),
    CONSTRAINT computers_report_v5_snapshots_schema_version_check CHECK ((schema_version = 1)),
    CONSTRAINT computers_report_v5_snapshots_scope_sha256_check CHECK ((octet_length(scope_sha256) = 32)),
    CONSTRAINT computers_report_v5_snapshots_source_state_check CHECK ((source_state = ANY (ARRAY['available'::text, 'empty'::text, 'partial'::text, 'stale'::text])))
);


ALTER TABLE public.computers_report_v5_snapshots OWNER TO postgres;

--
-- Name: computers_report_v5_snapshots_snapshot_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.computers_report_v5_snapshots_snapshot_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.computers_report_v5_snapshots_snapshot_id_seq OWNER TO postgres;

--
-- Name: computers_report_v5_snapshots_snapshot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.computers_report_v5_snapshots_snapshot_id_seq OWNED BY public.computers_report_v5_snapshots.snapshot_id;


--
-- Name: computers_report_v6_snapshots; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.computers_report_v6_snapshots (
    snapshot_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    source_run_id uuid,
    contract_id text NOT NULL,
    schema_version integer DEFAULT 1 NOT NULL,
    scope_json jsonb NOT NULL,
    scope_sha256 bytea NOT NULL,
    bucket_start_utc timestamp with time zone NOT NULL,
    captured_at_utc timestamp with time zone NOT NULL,
    source_observed_at_utc timestamp with time zone,
    source_state text NOT NULL,
    object_count integer NOT NULL,
    payload_json jsonb NOT NULL,
    payload_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT computers_report_v6_snapshots_check CHECK ((bucket_start_utc <= captured_at_utc)),
    CONSTRAINT computers_report_v6_snapshots_check1 CHECK (((source_observed_at_utc IS NULL) OR (source_observed_at_utc <= captured_at_utc))),
    CONSTRAINT computers_report_v6_snapshots_contract_id_check CHECK ((contract_id = 'sli.computers-report.v6'::text)),
    CONSTRAINT computers_report_v6_snapshots_object_count_check CHECK ((object_count >= 0)),
    CONSTRAINT computers_report_v6_snapshots_payload_json_check CHECK ((jsonb_typeof(payload_json) = 'object'::text)),
    CONSTRAINT computers_report_v6_snapshots_payload_sha256_check CHECK ((octet_length(payload_sha256) = 32)),
    CONSTRAINT computers_report_v6_snapshots_schema_version_check CHECK ((schema_version = 1)),
    CONSTRAINT computers_report_v6_snapshots_scope_sha256_check CHECK ((octet_length(scope_sha256) = 32)),
    CONSTRAINT computers_report_v6_snapshots_source_state_check CHECK ((source_state = ANY (ARRAY['available'::text, 'empty'::text, 'partial'::text, 'stale'::text])))
);


ALTER TABLE public.computers_report_v6_snapshots OWNER TO postgres;

--
-- Name: computers_report_v6_snapshots_snapshot_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.computers_report_v6_snapshots_snapshot_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.computers_report_v6_snapshots_snapshot_id_seq OWNER TO postgres;

--
-- Name: computers_report_v6_snapshots_snapshot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.computers_report_v6_snapshots_snapshot_id_seq OWNED BY public.computers_report_v6_snapshots.snapshot_id;


--
-- Name: computers_v6_source_snapshots; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.computers_v6_source_snapshots (
    source_snapshot_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    snapshot_uuid uuid NOT NULL,
    schema_version text DEFAULT '2.0'::text NOT NULL,
    source_started_at_utc timestamp with time zone NOT NULL,
    source_completed_at_utc timestamp with time zone NOT NULL,
    captured_at_utc timestamp with time zone NOT NULL,
    query_dc text NOT NULL,
    search_base text,
    collector_version text NOT NULL,
    collector_sha256 bytea NOT NULL,
    collection_status text NOT NULL,
    base_inventory_status text NOT NULL,
    object_count integer NOT NULL,
    source_options_json jsonb NOT NULL,
    payload_json jsonb NOT NULL,
    payload_sha256 bytea NOT NULL,
    collector_exit_code integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT computers_v6_source_snapshots_base_inventory_status_check CHECK ((base_inventory_status = ANY (ARRAY['observed'::text, 'failed'::text, 'access_denied'::text, 'parse_error'::text]))),
    CONSTRAINT computers_v6_source_snapshots_check CHECK (((jsonb_typeof(payload_json) = 'object'::text) AND (jsonb_typeof((payload_json -> 'metadata'::text)) = 'object'::text) AND (jsonb_typeof((payload_json -> 'objects'::text)) = 'array'::text) AND (octet_length((payload_json)::text) <= 67108864) AND (jsonb_array_length((payload_json -> 'objects'::text)) = object_count) AND ((payload_json ->> 'schema_version'::text) = schema_version) AND (((payload_json -> 'metadata'::text) ->> 'snapshot_id'::text) = (snapshot_uuid)::text) AND (((payload_json -> 'metadata'::text) ->> 'collection_status'::text) = collection_status) AND ((((payload_json -> 'metadata'::text) ->> 'object_count'::text))::integer = object_count))),
    CONSTRAINT computers_v6_source_snapshots_check1 CHECK ((source_started_at_utc <= source_completed_at_utc)),
    CONSTRAINT computers_v6_source_snapshots_check2 CHECK ((source_completed_at_utc <= captured_at_utc)),
    CONSTRAINT computers_v6_source_snapshots_check3 CHECK ((((base_inventory_status = 'observed'::text) AND (collection_status = ANY (ARRAY['complete'::text, 'partial'::text]))) OR ((base_inventory_status <> 'observed'::text) AND (collection_status = 'failed'::text) AND (object_count = 0)))),
    CONSTRAINT computers_v6_source_snapshots_collection_status_check CHECK ((collection_status = ANY (ARRAY['complete'::text, 'partial'::text, 'failed'::text]))),
    CONSTRAINT computers_v6_source_snapshots_collector_exit_code_check CHECK ((collector_exit_code >= 0)),
    CONSTRAINT computers_v6_source_snapshots_collector_sha256_check CHECK (((octet_length(collector_sha256) = 32) AND (collector_sha256 = decode('caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5'::text, 'hex'::text)))),
    CONSTRAINT computers_v6_source_snapshots_collector_version_check CHECK ((length(btrim(collector_version)) > 0)),
    CONSTRAINT computers_v6_source_snapshots_object_count_check CHECK (((object_count >= 0) AND (object_count <= 250000))),
    CONSTRAINT computers_v6_source_snapshots_payload_sha256_check CHECK ((octet_length(payload_sha256) = 32)),
    CONSTRAINT computers_v6_source_snapshots_query_dc_check CHECK ((length(btrim(query_dc)) > 0)),
    CONSTRAINT computers_v6_source_snapshots_schema_version_check CHECK ((schema_version = '2.0'::text)),
    CONSTRAINT computers_v6_source_snapshots_source_options_json_check CHECK (((jsonb_typeof(source_options_json) = 'object'::text) AND (source_options_json ?& ARRAY['server'::text, 'search_base'::text, 'skip_dns'::text, 'collect_ad_site'::text, 'collect_exact_last_logon'::text])))
);


ALTER TABLE public.computers_v6_source_snapshots OWNER TO postgres;

--
-- Name: computers_v6_source_snapshots_source_snapshot_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.computers_v6_source_snapshots_source_snapshot_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.computers_v6_source_snapshots_source_snapshot_id_seq OWNER TO postgres;

--
-- Name: computers_v6_source_snapshots_source_snapshot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.computers_v6_source_snapshots_source_snapshot_id_seq OWNED BY public.computers_v6_source_snapshots.source_snapshot_id;


--
-- Name: core_evidence_manifests; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.core_evidence_manifests (
    evidence_uid uuid NOT NULL,
    source_instance_id text NOT NULL,
    stream_id text NOT NULL,
    transport_binding text NOT NULL,
    cursor_epoch uuid NOT NULL,
    file_generation text NOT NULL,
    cursor_start_byte_offset bigint NOT NULL,
    batch_record_ordinal integer NOT NULL,
    canonical_record_sha256 text NOT NULL,
    object_reference text NOT NULL,
    object_sha256 text NOT NULL,
    object_size_bytes integer NOT NULL,
    verified_at_utc timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT core_evidence_manifests_batch_record_ordinal_check CHECK ((batch_record_ordinal >= 0)),
    CONSTRAINT core_evidence_manifests_canonical_record_sha256_check CHECK ((canonical_record_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT core_evidence_manifests_cursor_start_byte_offset_check CHECK ((cursor_start_byte_offset >= 0)),
    CONSTRAINT core_evidence_manifests_object_reference_check CHECK (((object_reference ~ '^evidence:[A-Za-z0-9_.:-]+$'::text) AND (length(object_reference) <= 509))),
    CONSTRAINT core_evidence_manifests_object_sha256_check CHECK ((object_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT core_evidence_manifests_object_size_bytes_check CHECK (((object_size_bytes >= 1) AND (object_size_bytes <= 65536)))
);


ALTER TABLE public.core_evidence_manifests OWNER TO adlog_storage_owner;

--
-- Name: detection_rules; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.detection_rules (
    id bigint NOT NULL,
    code text NOT NULL,
    name text NOT NULL,
    description text,
    severity_default text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    version text DEFAULT '1'::text NOT NULL
);


ALTER TABLE public.detection_rules OWNER TO adlog_user;

--
-- Name: detection_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.detection_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.detection_rules_id_seq OWNER TO adlog_user;

--
-- Name: detection_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.detection_rules_id_seq OWNED BY public.detection_rules.id;


--
-- Name: detections; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.detections (
    id bigint NOT NULL,
    detection_rule_id bigint NOT NULL,
    primary_event_id bigint,
    server_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    site_id bigint,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    severity text NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    facts_json text,
    evidence_event_ids_json text
);


ALTER TABLE public.detections OWNER TO adlog_user;

--
-- Name: detections_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.detections_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.detections_id_seq OWNER TO adlog_user;

--
-- Name: detections_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.detections_id_seq OWNED BY public.detections.id;


--
-- Name: domain_controller_targets; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.domain_controller_targets (
    id bigint NOT NULL,
    hostname text NOT NULL,
    connect_address text NOT NULL,
    domain_id bigint,
    owner_confirmed_ip inet,
    enabled boolean DEFAULT true NOT NULL,
    source text DEFAULT 'interface'::text NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT domain_controller_targets_connect_address_check CHECK (((length(connect_address) >= 3) AND (length(connect_address) <= 253))),
    CONSTRAINT domain_controller_targets_created_by_check CHECK (((length(created_by) >= 1) AND (length(created_by) <= 256))),
    CONSTRAINT domain_controller_targets_hostname_check CHECK (((length(hostname) >= 1) AND (length(hostname) <= 63))),
    CONSTRAINT domain_controller_targets_source_check CHECK ((source = ANY (ARRAY['interface'::text, 'file_import'::text]))),
    CONSTRAINT domain_controller_targets_updated_by_check CHECK (((length(updated_by) >= 1) AND (length(updated_by) <= 256)))
);


ALTER TABLE public.domain_controller_targets OWNER TO adlog_user;

--
-- Name: domain_controller_targets_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

ALTER TABLE public.domain_controller_targets ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.domain_controller_targets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: domains; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.domains (
    id bigint NOT NULL,
    forest_id bigint NOT NULL,
    fqdn text NOT NULL,
    netbios_name text,
    domain_sid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.domains OWNER TO adlog_user;

--
-- Name: domains_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.domains_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.domains_id_seq OWNER TO adlog_user;

--
-- Name: domains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.domains_id_seq OWNED BY public.domains.id;


--
-- Name: entities_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entities_v2 (
    id integer NOT NULL,
    entity_type_id integer NOT NULL,
    natural_key text NOT NULL,
    display_name text NOT NULL,
    domain_id bigint,
    server_id bigint,
    first_seen_utc timestamp with time zone,
    last_seen_utc timestamp with time zone,
    source_core_sha256 bytea NOT NULL,
    migrated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entities_v2_id_check CHECK ((id > 0)),
    CONSTRAINT entities_v2_source_core_sha256_check CHECK ((octet_length(source_core_sha256) = 32))
);


ALTER TABLE public.entities_v2 OWNER TO adlog_storage_owner;

--
-- Name: entity_identity_merges_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entity_identity_merges_v2 (
    merge_id uuid NOT NULL,
    source_entity_id integer NOT NULL,
    target_entity_id integer NOT NULL,
    source_natural_key text NOT NULL,
    target_natural_key text NOT NULL,
    plan_sha256 bytea NOT NULL,
    source_core_sha256_before bytea NOT NULL,
    target_core_sha256_before bytea NOT NULL,
    source_links_before integer NOT NULL,
    target_links_before integer NOT NULL,
    target_links_after integer NOT NULL,
    source_links_sha256 bytea NOT NULL,
    target_links_before_sha256 bytea NOT NULL,
    target_links_after_sha256 bytea NOT NULL,
    affected_events integer NOT NULL,
    affected_events_sha256 bytea NOT NULL,
    semantic_replay_events integer NOT NULL,
    evidence_json jsonb NOT NULL,
    merged_by text DEFAULT SESSION_USER NOT NULL,
    merged_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entity_identity_merge_distinct CHECK (((source_entity_id <> target_entity_id) AND (source_natural_key <> target_natural_key))),
    CONSTRAINT entity_identity_merge_key_bounds CHECK (((length(source_natural_key) >= 1) AND (length(source_natural_key) <= 1024) AND ((length(target_natural_key) >= 1) AND (length(target_natural_key) <= 1024)))),
    CONSTRAINT entity_identity_merge_link_balance CHECK (((target_links_after >= target_links_before) AND (target_links_after <= (target_links_before + source_links_before)))),
    CONSTRAINT entity_identity_merges_v2_affected_events_check CHECK ((affected_events >= 0)),
    CONSTRAINT entity_identity_merges_v2_affected_events_sha256_check CHECK ((octet_length(affected_events_sha256) = 32)),
    CONSTRAINT entity_identity_merges_v2_evidence_json_check CHECK (((jsonb_typeof(evidence_json) = 'object'::text) AND (octet_length((evidence_json)::text) <= 65536))),
    CONSTRAINT entity_identity_merges_v2_merged_by_check CHECK (((length(merged_by) >= 1) AND (length(merged_by) <= 256))),
    CONSTRAINT entity_identity_merges_v2_plan_sha256_check CHECK ((octet_length(plan_sha256) = 32)),
    CONSTRAINT entity_identity_merges_v2_semantic_replay_events_check CHECK ((semantic_replay_events >= 0)),
    CONSTRAINT entity_identity_merges_v2_source_core_sha256_before_check CHECK ((octet_length(source_core_sha256_before) = 32)),
    CONSTRAINT entity_identity_merges_v2_source_links_before_check CHECK ((source_links_before >= 0)),
    CONSTRAINT entity_identity_merges_v2_source_links_sha256_check CHECK ((octet_length(source_links_sha256) = 32)),
    CONSTRAINT entity_identity_merges_v2_target_core_sha256_before_check CHECK ((octet_length(target_core_sha256_before) = 32)),
    CONSTRAINT entity_identity_merges_v2_target_links_after_check CHECK ((target_links_after >= 0)),
    CONSTRAINT entity_identity_merges_v2_target_links_after_sha256_check CHECK ((octet_length(target_links_after_sha256) = 32)),
    CONSTRAINT entity_identity_merges_v2_target_links_before_check CHECK ((target_links_before >= 0)),
    CONSTRAINT entity_identity_merges_v2_target_links_before_sha256_check CHECK ((octet_length(target_links_before_sha256) = 32))
);


ALTER TABLE public.entity_identity_merges_v2 OWNER TO adlog_storage_owner;

--
-- Name: entities_v2_active; Type: VIEW; Schema: public; Owner: adlog_storage_owner
--

CREATE VIEW public.entities_v2_active WITH (security_barrier='true') AS
 SELECT entity.id,
    entity.entity_type_id,
    entity.natural_key,
    entity.display_name,
    entity.domain_id,
    entity.server_id,
    LEAST(entity.first_seen_utc, merged_observation.first_seen_utc) AS first_seen_utc,
    GREATEST(entity.last_seen_utc, merged_observation.last_seen_utc) AS last_seen_utc,
    entity.source_core_sha256,
    entity.migrated_at
   FROM ((public.entities_v2 entity
     LEFT JOIN public.entity_identity_merges_v2 merged_source ON ((merged_source.source_entity_id = entity.id)))
     LEFT JOIN ( SELECT merged.target_entity_id,
            min(source_entity.first_seen_utc) AS first_seen_utc,
            max(source_entity.last_seen_utc) AS last_seen_utc
           FROM (public.entity_identity_merges_v2 merged
             JOIN public.entities_v2 source_entity ON ((source_entity.id = merged.source_entity_id)))
          GROUP BY merged.target_entity_id) merged_observation ON ((merged_observation.target_entity_id = entity.id)))
  WHERE (merged_source.source_entity_id IS NULL);


ALTER VIEW public.entities_v2_active OWNER TO adlog_storage_owner;

--
-- Name: entities_v2_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

CREATE SEQUENCE public.entities_v2_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.entities_v2_id_seq OWNER TO adlog_storage_owner;

--
-- Name: entities_v2_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_storage_owner
--

ALTER SEQUENCE public.entities_v2_id_seq OWNED BY public.entities_v2.id;


--
-- Name: entity_details_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entity_details_v2 (
    entity_id integer NOT NULL,
    attributes_json jsonb NOT NULL,
    source_details_sha256 bytea NOT NULL,
    migrated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entity_details_v2_source_details_sha256_check CHECK ((octet_length(source_details_sha256) = 32))
);


ALTER TABLE public.entity_details_v2 OWNER TO adlog_storage_owner;

--
-- Name: entity_identity_finding_supersessions_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entity_identity_finding_supersessions_v2 (
    merge_id uuid NOT NULL,
    old_scenario_id uuid CONSTRAINT entity_identity_finding_supersessions__old_scenario_id_not_null NOT NULL,
    new_scenario_id uuid CONSTRAINT entity_identity_finding_supersessions__new_scenario_id_not_null NOT NULL,
    old_finding_id bigint CONSTRAINT entity_identity_finding_supersessions_v_old_finding_id_not_null NOT NULL,
    new_finding_id bigint CONSTRAINT entity_identity_finding_supersessions_v_new_finding_id_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entity_identity_finding_supersession_changed CHECK ((old_finding_id <> new_finding_id))
);


ALTER TABLE public.entity_identity_finding_supersessions_v2 OWNER TO adlog_storage_owner;

--
-- Name: entity_identity_merge_events_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entity_identity_merge_events_v2 (
    merge_id uuid NOT NULL,
    source_event_id bigint NOT NULL,
    source_role_ids smallint[] NOT NULL,
    semantic_replay_required boolean CONSTRAINT entity_identity_merge_events__semantic_replay_required_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_event_sha256 bytea NOT NULL,
    source_occurred_at_utc timestamp with time zone NOT NULL,
    CONSTRAINT entity_identity_merge_event_roles CHECK (((cardinality(source_role_ids) >= 1) AND (cardinality(source_role_ids) <= 32))),
    CONSTRAINT entity_identity_merge_event_source_hash CHECK ((octet_length(source_event_sha256) = 32))
);


ALTER TABLE public.entity_identity_merge_events_v2 OWNER TO adlog_storage_owner;

--
-- Name: entity_identity_scenario_supersessions_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entity_identity_scenario_supersessions_v2 (
    merge_id uuid NOT NULL,
    old_scenario_id uuid CONSTRAINT entity_identity_scenario_supersessions_old_scenario_id_not_null NOT NULL,
    new_scenario_id uuid CONSTRAINT entity_identity_scenario_supersessions_new_scenario_id_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entity_identity_scenario_supersession_changed CHECK ((old_scenario_id <> new_scenario_id))
);


ALTER TABLE public.entity_identity_scenario_supersessions_v2 OWNER TO adlog_storage_owner;

--
-- Name: entity_identity_semantic_replays_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entity_identity_semantic_replays_v2 (
    merge_id uuid NOT NULL,
    source_event_id bigint NOT NULL,
    old_normalized_event_id uuid CONSTRAINT entity_identity_semantic_repla_old_normalized_event_id_not_null NOT NULL,
    new_normalized_event_id uuid CONSTRAINT entity_identity_semantic_repla_new_normalized_event_id_not_null NOT NULL,
    replay_job_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_event_sha256 bytea CONSTRAINT entity_identity_semantic_replays_v_source_event_sha256_not_null NOT NULL,
    source_occurred_at_utc timestamp with time zone CONSTRAINT entity_identity_semantic_replay_source_occurred_at_utc_not_null NOT NULL,
    CONSTRAINT entity_identity_semantic_replay_changed CHECK ((old_normalized_event_id <> new_normalized_event_id)),
    CONSTRAINT entity_identity_semantic_replay_source_hash CHECK ((octet_length(source_event_sha256) = 32))
);


ALTER TABLE public.entity_identity_semantic_replays_v2 OWNER TO adlog_storage_owner;

--
-- Name: entity_state_current; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entity_state_current (
    entity_id integer NOT NULL,
    state_type text NOT NULL,
    status text NOT NULL,
    projection_status text DEFAULT 'normal'::text NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    source_event_db_id bigint NOT NULL,
    rule_id text NOT NULL,
    rule_version text NOT NULL,
    details_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entity_state_current_projection_status_check CHECK ((projection_status = ANY (ARRAY['normal'::text, 'unknown'::text, 'conflict'::text])))
);


ALTER TABLE public.entity_state_current OWNER TO adlog_storage_owner;

--
-- Name: entity_state_projection_jobs; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.entity_state_projection_jobs (
    job_id uuid NOT NULL,
    job_schema_version smallint DEFAULT 1 NOT NULL,
    source_event_db_id bigint NOT NULL,
    candidate_states jsonb NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 5 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_token uuid,
    lease_until timestamp with time zone,
    heartbeat_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT entity_state_projection_jobs_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT entity_state_projection_jobs_max_attempts_check CHECK (((max_attempts >= 1) AND (max_attempts <= 20))),
    CONSTRAINT entity_state_projection_jobs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'completed'::text, 'failed'::text, 'quarantined'::text]))),
    CONSTRAINT entity_state_projection_payload_array CHECK ((jsonb_typeof(candidate_states) = 'array'::text)),
    CONSTRAINT entity_state_projection_payload_bounded CHECK (((jsonb_array_length(candidate_states) >= 1) AND (jsonb_array_length(candidate_states) <= 64)))
);


ALTER TABLE public.entity_state_projection_jobs OWNER TO adlog_storage_owner;

--
-- Name: entity_states; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.entity_states (
    id bigint NOT NULL,
    entity_id bigint NOT NULL,
    state_type text NOT NULL,
    severity text DEFAULT 'info'::text NOT NULL,
    status text DEFAULT 'observed'::text NOT NULL,
    observed_at_utc text NOT NULL,
    summary text,
    evidence_event_id bigint,
    details_json text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.entity_states OWNER TO adlog_user;

--
-- Name: entity_states_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.entity_states_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.entity_states_id_seq OWNER TO adlog_user;

--
-- Name: entity_states_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.entity_states_id_seq OWNED BY public.entity_states.id;


--
-- Name: event_catalog_revisions; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.event_catalog_revisions (
    id smallint NOT NULL,
    version text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT event_catalog_revisions_version_nonempty CHECK (((length(version) >= 1) AND (length(version) <= 255)))
);


ALTER TABLE public.event_catalog_revisions OWNER TO adlog_storage_owner;

--
-- Name: event_catalog_revisions_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.event_catalog_revisions ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.event_catalog_revisions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: event_entity_link_blocks_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.event_entity_link_blocks_v2 (
    entity_id integer NOT NULL,
    block_no integer NOT NULL,
    first_event_id bigint NOT NULL,
    last_event_id bigint NOT NULL,
    event_ids bigint[] NOT NULL,
    role_ids smallint[] NOT NULL,
    identity_sha256 bytea NOT NULL,
    CONSTRAINT event_entity_link_blocks_v2_block_no_check CHECK ((block_no >= 0)),
    CONSTRAINT event_entity_link_blocks_v2_identity_sha256_check CHECK ((octet_length(identity_sha256) = 32)),
    CONSTRAINT event_entity_link_blocks_v2_range CHECK (((first_event_id <= last_event_id) AND (first_event_id = event_ids[1]) AND (last_event_id = event_ids[cardinality(event_ids)]))),
    CONSTRAINT event_entity_link_blocks_v2_size CHECK (((cardinality(event_ids) >= 1) AND (cardinality(event_ids) <= 512) AND (cardinality(event_ids) = cardinality(role_ids))))
);


ALTER TABLE public.event_entity_link_blocks_v2 OWNER TO adlog_storage_owner;

--
-- Name: event_entity_links_v2; Type: VIEW; Schema: public; Owner: adlog_storage_owner
--

CREATE VIEW public.event_entity_links_v2 AS
 SELECT block.entity_id,
    expanded.event_id,
    expanded.role_id
   FROM (public.event_entity_link_blocks_v2 block
     CROSS JOIN LATERAL UNNEST(block.event_ids, block.role_ids) expanded(event_id, role_id));


ALTER VIEW public.event_entity_links_v2 OWNER TO adlog_storage_owner;

--
-- Name: event_facts_v2; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.event_facts_v2 (
    event_id bigint NOT NULL,
    process_name text,
    process_id text,
    target_server_name text,
    service_name text,
    task_name text,
    task_action text,
    task_author text,
    run_as text,
    logon_type text,
    result_code text,
    object_name text,
    share_name text,
    message_sample text,
    powershell_user_name text,
    powershell_command_name text,
    powershell_script_block_text text,
    powershell_process_id text,
    source_facts_sha256 bytea NOT NULL,
    migrated_at timestamp with time zone DEFAULT now() NOT NULL,
    account_target_sid text,
    account_target_name text,
    account_name_before text,
    account_name_after text,
    membership_member_sid text,
    membership_member_name text,
    process_parent_id text,
    process_command_line text,
    process_user_sid text,
    process_user_name text,
    process_user_domain text,
    process_logon_id text,
    service_file text,
    service_account text,
    service_start_type text,
    task_content text,
    task_change text,
    native_process_id text,
    CONSTRAINT event_facts_v2_account_name_after_bounded CHECK (((account_name_after IS NULL) OR (length(account_name_after) <= 512))),
    CONSTRAINT event_facts_v2_account_name_before_bounded CHECK (((account_name_before IS NULL) OR (length(account_name_before) <= 512))),
    CONSTRAINT event_facts_v2_account_target_name_bounded CHECK (((account_target_name IS NULL) OR (length(account_target_name) <= 512))),
    CONSTRAINT event_facts_v2_account_target_sid_bounded CHECK (((account_target_sid IS NULL) OR (length(account_target_sid) <= 512))),
    CONSTRAINT event_facts_v2_logon_type_bounded CHECK (((logon_type IS NULL) OR (length(logon_type) <= 64))),
    CONSTRAINT event_facts_v2_membership_member_name_bounded CHECK (((membership_member_name IS NULL) OR (length(membership_member_name) <= 512))),
    CONSTRAINT event_facts_v2_membership_member_sid_bounded CHECK (((membership_member_sid IS NULL) OR (length(membership_member_sid) <= 512))),
    CONSTRAINT event_facts_v2_message_bounded CHECK (((message_sample IS NULL) OR (length(message_sample) <= 220))),
    CONSTRAINT event_facts_v2_native_process_id_bounded CHECK (((native_process_id IS NULL) OR
CASE
    WHEN (native_process_id ~ '^[1-9][0-9]{0,9}$'::text) THEN (((native_process_id)::numeric >= (1)::numeric) AND ((native_process_id)::numeric <= ('4294967295'::bigint)::numeric))
    ELSE false
END)),
    CONSTRAINT event_facts_v2_object_name_bounded CHECK (((object_name IS NULL) OR (length(object_name) <= 512))),
    CONSTRAINT event_facts_v2_powershell_command_bounded CHECK (((powershell_command_name IS NULL) OR (length(powershell_command_name) <= 512))),
    CONSTRAINT event_facts_v2_powershell_process_id_windows CHECK (((powershell_process_id IS NULL) OR
CASE
    WHEN (powershell_process_id ~ '^[1-9][0-9]{0,9}$'::text) THEN (((powershell_process_id)::numeric >= (1)::numeric) AND ((powershell_process_id)::numeric <= ('4294967295'::bigint)::numeric))
    ELSE false
END)),
    CONSTRAINT event_facts_v2_powershell_script_block_bounded CHECK (((powershell_script_block_text IS NULL) OR (length(powershell_script_block_text) <= 2048))),
    CONSTRAINT event_facts_v2_powershell_user_bounded CHECK (((powershell_user_name IS NULL) OR (length(powershell_user_name) <= 512))),
    CONSTRAINT event_facts_v2_process_command_line_bounded CHECK (((process_command_line IS NULL) OR (octet_length(process_command_line) <= 4096))),
    CONSTRAINT event_facts_v2_process_id_windows CHECK (((process_id IS NULL) OR
CASE
    WHEN (process_id ~ '^[1-9][0-9]{0,9}$'::text) THEN (((process_id)::numeric >= (1)::numeric) AND ((process_id)::numeric <= ('4294967295'::bigint)::numeric))
    ELSE false
END)),
    CONSTRAINT event_facts_v2_process_logon_id_bounded CHECK (((process_logon_id IS NULL) OR (octet_length(process_logon_id) <= 128))),
    CONSTRAINT event_facts_v2_process_name_bounded CHECK (((process_name IS NULL) OR (octet_length(process_name) <= 512))),
    CONSTRAINT event_facts_v2_process_parent_id_bounded CHECK (((process_parent_id IS NULL) OR
CASE
    WHEN (process_parent_id ~ '^[1-9][0-9]{0,9}$'::text) THEN (((process_parent_id)::numeric >= (1)::numeric) AND ((process_parent_id)::numeric <= ('4294967295'::bigint)::numeric))
    ELSE false
END)),
    CONSTRAINT event_facts_v2_process_user_domain_bounded CHECK (((process_user_domain IS NULL) OR (octet_length(process_user_domain) <= 512))),
    CONSTRAINT event_facts_v2_process_user_name_bounded CHECK (((process_user_name IS NULL) OR (octet_length(process_user_name) <= 512))),
    CONSTRAINT event_facts_v2_process_user_sid_bounded CHECK (((process_user_sid IS NULL) OR (octet_length(process_user_sid) <= 512))),
    CONSTRAINT event_facts_v2_result_code_bounded CHECK (((result_code IS NULL) OR (length(result_code) <= 128))),
    CONSTRAINT event_facts_v2_run_as_bounded CHECK (((run_as IS NULL) OR (length(run_as) <= 512))),
    CONSTRAINT event_facts_v2_service_account_bounded CHECK (((service_account IS NULL) OR (octet_length(service_account) <= 512))),
    CONSTRAINT event_facts_v2_service_file_bounded CHECK (((service_file IS NULL) OR (octet_length(service_file) <= 2048))),
    CONSTRAINT event_facts_v2_service_name_bounded CHECK (((service_name IS NULL) OR (length(service_name) <= 512))),
    CONSTRAINT event_facts_v2_service_start_type_bounded CHECK (((service_start_type IS NULL) OR (octet_length(service_start_type) <= 128))),
    CONSTRAINT event_facts_v2_share_name_bounded CHECK (((share_name IS NULL) OR (length(share_name) <= 512))),
    CONSTRAINT event_facts_v2_source_facts_sha256_check CHECK ((octet_length(source_facts_sha256) = 32)),
    CONSTRAINT event_facts_v2_target_server_bounded CHECK (((target_server_name IS NULL) OR (length(target_server_name) <= 512))),
    CONSTRAINT event_facts_v2_task_action_bounded CHECK (((task_action IS NULL) OR (length(task_action) <= 1024))),
    CONSTRAINT event_facts_v2_task_author_bounded CHECK (((task_author IS NULL) OR (length(task_author) <= 512))),
    CONSTRAINT event_facts_v2_task_change_bounded CHECK (((task_change IS NULL) OR (task_change = ANY (ARRAY['created'::text, 'deleted'::text, 'enabled'::text, 'disabled'::text, 'updated'::text])))),
    CONSTRAINT event_facts_v2_task_content_bounded CHECK (((task_content IS NULL) OR (octet_length(task_content) <= 8192))),
    CONSTRAINT event_facts_v2_task_name_bounded CHECK (((task_name IS NULL) OR (length(task_name) <= 512)))
);


ALTER TABLE public.event_facts_v2 OWNER TO adlog_storage_owner;

--
-- Name: event_links; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.event_links (
    id bigint NOT NULL,
    source_event_id bigint NOT NULL,
    target_event_id bigint NOT NULL,
    link_type text NOT NULL,
    confidence double precision DEFAULT 0.0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.event_links OWNER TO adlog_user;

--
-- Name: event_links_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.event_links_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.event_links_id_seq OWNER TO adlog_user;

--
-- Name: event_links_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.event_links_id_seq OWNED BY public.event_links.id;


--
-- Name: events_v2_core; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.events_v2_core (
    id bigint NOT NULL,
    raw_log_file_id bigint,
    server_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    site_id bigint,
    log_source_id bigint NOT NULL,
    event_record_id bigint,
    event_id integer NOT NULL,
    version smallint,
    level smallint,
    task integer,
    opcode integer,
    keywords_id integer,
    provider_id integer,
    channel_id integer NOT NULL,
    computer_id integer,
    time_created_utc timestamp with time zone NOT NULL,
    subject_user_sid text,
    subject_user_name text,
    subject_domain_id integer,
    target_user_sid text,
    target_user_name text,
    target_domain_id integer,
    ip_address text,
    workstation_name text,
    logon_id text,
    correlation_id text,
    normalized_at timestamp with time zone NOT NULL,
    normalized_hash bytea NOT NULL,
    source_core_sha256 bytea NOT NULL,
    migrated_at timestamp with time zone DEFAULT now() NOT NULL,
    noise_class text DEFAULT 'not_classified'::text NOT NULL,
    noise_catalog_version text DEFAULT 'pending-backfill'::text NOT NULL,
    noise_catalog_revision_id smallint,
    CONSTRAINT events_v2_core_id_check CHECK ((id > 0)),
    CONSTRAINT events_v2_core_normalized_hash_check CHECK ((octet_length(normalized_hash) = 32)),
    CONSTRAINT events_v2_core_source_core_sha256_check CHECK ((octet_length(source_core_sha256) = 32))
)
WITH (autovacuum_vacuum_scale_factor='0.01', autovacuum_vacuum_threshold='50000', autovacuum_analyze_scale_factor='0.02', autovacuum_analyze_threshold='50000');


ALTER TABLE public.events_v2_core OWNER TO adlog_storage_owner;

--
-- Name: finding_entities; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.finding_entities (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    entity_id bigint,
    entity_type text,
    display_name text,
    entity_role text DEFAULT 'context'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.finding_entities OWNER TO adlog_user;

--
-- Name: finding_entities_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.finding_entities_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.finding_entities_id_seq OWNER TO adlog_user;

--
-- Name: finding_entities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.finding_entities_id_seq OWNED BY public.finding_entities.id;


--
-- Name: finding_evidence; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.finding_evidence (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    event_id bigint NOT NULL,
    evidence_role text DEFAULT 'supporting_event'::text NOT NULL,
    note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.finding_evidence OWNER TO adlog_user;

--
-- Name: finding_evidence_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.finding_evidence_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.finding_evidence_id_seq OWNER TO adlog_user;

--
-- Name: finding_evidence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.finding_evidence_id_seq OWNED BY public.finding_evidence.id;


--
-- Name: finding_status_history; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.finding_status_history (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    old_status text,
    new_status text NOT NULL,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    changed_by text DEFAULT 'system'::text NOT NULL,
    note text
);


ALTER TABLE public.finding_status_history OWNER TO adlog_user;

--
-- Name: finding_status_history_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.finding_status_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.finding_status_history_id_seq OWNER TO adlog_user;

--
-- Name: finding_status_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.finding_status_history_id_seq OWNED BY public.finding_status_history.id;


--
-- Name: findings; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.findings (
    id bigint NOT NULL,
    fingerprint text NOT NULL,
    rule_code text NOT NULL,
    title text NOT NULL,
    severity text NOT NULL,
    confidence double precision DEFAULT 0.65 NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    first_seen_utc text,
    last_seen_utc text,
    actor text,
    target text,
    source text,
    summary text,
    why_it_matters text,
    recommended_action text,
    evidence_count bigint DEFAULT 0 NOT NULL,
    status_reason text,
    assigned_to text,
    closed_at text,
    repeat_count bigint DEFAULT 0 NOT NULL,
    last_evidence_event_id bigint,
    last_repeat_detected_at text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.findings OWNER TO adlog_user;

--
-- Name: findings_active; Type: VIEW; Schema: public; Owner: adlog_storage_owner
--

CREATE VIEW public.findings_active WITH (security_barrier='true') AS
 SELECT finding.id,
    finding.fingerprint,
    finding.rule_code,
    finding.title,
    finding.severity,
    finding.confidence,
    finding.status,
    finding.first_seen_utc,
    finding.last_seen_utc,
    finding.actor,
    finding.target,
    finding.source,
    finding.summary,
    finding.why_it_matters,
    finding.recommended_action,
    finding.evidence_count,
    finding.status_reason,
    finding.assigned_to,
    finding.closed_at,
    finding.repeat_count,
    finding.last_evidence_event_id,
    finding.last_repeat_detected_at,
    finding.created_at,
    finding.updated_at,
    (superseded.old_finding_id IS NOT NULL) AS identity_superseded,
    superseded.new_finding_id AS superseded_by_finding_id
   FROM (public.findings finding
     LEFT JOIN public.entity_identity_finding_supersessions_v2 superseded ON ((superseded.old_finding_id = finding.id)))
  WHERE ((superseded.old_finding_id IS NULL) OR (finding.status <> 'new'::text) OR (finding.assigned_to IS NOT NULL));


ALTER VIEW public.findings_active OWNER TO adlog_storage_owner;

--
-- Name: findings_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.findings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.findings_id_seq OWNER TO adlog_user;

--
-- Name: findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.findings_id_seq OWNED BY public.findings.id;


--
-- Name: findings_refresh_state; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.findings_refresh_state (
    pipeline_name text NOT NULL,
    last_event_id bigint DEFAULT 0 NOT NULL,
    bootstrap_event_id bigint DEFAULT 0 NOT NULL,
    last_status text DEFAULT 'ready'::text NOT NULL,
    last_started_at timestamp with time zone,
    last_completed_at timestamp with time zone,
    last_failed_at timestamp with time zone,
    last_duration_ms bigint,
    last_scanned_events bigint DEFAULT 0 NOT NULL,
    last_matched_events bigint DEFAULT 0 NOT NULL,
    last_created_findings bigint DEFAULT 0 NOT NULL,
    last_updated_findings bigint DEFAULT 0 NOT NULL,
    last_evidence_added bigint DEFAULT 0 NOT NULL,
    last_manual_status_preserved bigint DEFAULT 0 NOT NULL,
    last_has_more boolean DEFAULT false NOT NULL,
    last_error text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.findings_refresh_state OWNER TO adlog_user;

--
-- Name: forests; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.forests (
    id bigint NOT NULL,
    name text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.forests OWNER TO adlog_user;

--
-- Name: forests_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.forests_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.forests_id_seq OWNER TO adlog_user;

--
-- Name: forests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.forests_id_seq OWNED BY public.forests.id;


--
-- Name: gpo_report_v2_source_snapshots; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.gpo_report_v2_source_snapshots (
    snapshot_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    source_run_id uuid NOT NULL,
    schema_version text NOT NULL,
    collector_version text NOT NULL,
    collection_status text NOT NULL,
    import_status text DEFAULT 'completed'::text NOT NULL,
    source_started_at_utc timestamp with time zone NOT NULL,
    source_completed_at_utc timestamp with time zone NOT NULL,
    source_observed_at_utc timestamp with time zone NOT NULL,
    gpo_count integer NOT NULL,
    scope_count integer NOT NULL,
    link_count integer NOT NULL,
    setting_count integer NOT NULL,
    permission_count integer NOT NULL,
    wmi_filter_count integer NOT NULL,
    payload_json jsonb NOT NULL,
    payload_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT gpo_report_v2_source_snapshots_check CHECK (((jsonb_typeof(payload_json) = 'object'::text) AND ((payload_json ->> 'schema_version'::text) = schema_version) AND (COALESCE(((payload_json ->> 'demo'::text))::boolean, false) = false) AND (jsonb_typeof((payload_json -> 'gpos'::text)) = 'array'::text) AND (jsonb_typeof((payload_json -> 'scopes'::text)) = 'array'::text) AND (jsonb_typeof((payload_json -> 'links'::text)) = 'array'::text) AND (jsonb_typeof((payload_json -> 'settings'::text)) = 'array'::text) AND (jsonb_typeof((payload_json -> 'permissions'::text)) = 'array'::text) AND (jsonb_typeof((payload_json -> 'wmi_filters'::text)) = 'array'::text))),
    CONSTRAINT gpo_report_v2_source_snapshots_check1 CHECK ((source_started_at_utc <= source_completed_at_utc)),
    CONSTRAINT gpo_report_v2_source_snapshots_check2 CHECK ((source_completed_at_utc <= (created_at + '00:05:00'::interval))),
    CONSTRAINT gpo_report_v2_source_snapshots_collection_status_check CHECK ((collection_status = ANY (ARRAY['complete'::text, 'partial'::text, 'failed'::text]))),
    CONSTRAINT gpo_report_v2_source_snapshots_gpo_count_check CHECK (((gpo_count >= 0) AND (gpo_count <= 10000))),
    CONSTRAINT gpo_report_v2_source_snapshots_import_status_check CHECK ((import_status = 'completed'::text)),
    CONSTRAINT gpo_report_v2_source_snapshots_link_count_check CHECK ((link_count >= 0)),
    CONSTRAINT gpo_report_v2_source_snapshots_payload_sha256_check CHECK ((octet_length(payload_sha256) = 32)),
    CONSTRAINT gpo_report_v2_source_snapshots_permission_count_check CHECK ((permission_count >= 0)),
    CONSTRAINT gpo_report_v2_source_snapshots_schema_version_check CHECK ((schema_version = 'sli.ad-gpo.snapshot/1.0'::text)),
    CONSTRAINT gpo_report_v2_source_snapshots_scope_count_check CHECK ((scope_count >= 0)),
    CONSTRAINT gpo_report_v2_source_snapshots_setting_count_check CHECK ((setting_count >= 0)),
    CONSTRAINT gpo_report_v2_source_snapshots_wmi_filter_count_check CHECK ((wmi_filter_count >= 0))
);


ALTER TABLE public.gpo_report_v2_source_snapshots OWNER TO postgres;

--
-- Name: gpo_report_v2_source_snapshots_snapshot_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.gpo_report_v2_source_snapshots_snapshot_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.gpo_report_v2_source_snapshots_snapshot_id_seq OWNER TO postgres;

--
-- Name: gpo_report_v2_source_snapshots_snapshot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.gpo_report_v2_source_snapshots_snapshot_id_seq OWNED BY public.gpo_report_v2_source_snapshots.snapshot_id;


--
-- Name: investigation_audit; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.investigation_audit (
    id bigint NOT NULL,
    investigation_id bigint NOT NULL,
    action text NOT NULL,
    actor text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.investigation_audit OWNER TO adlog_user;

--
-- Name: investigation_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.investigation_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.investigation_audit_id_seq OWNER TO adlog_user;

--
-- Name: investigation_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.investigation_audit_id_seq OWNED BY public.investigation_audit.id;


--
-- Name: investigation_context_evidence; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.investigation_context_evidence (
    investigation_id bigint NOT NULL,
    context_evidence_id bigint NOT NULL,
    relation_status text DEFAULT 'confirmed'::text NOT NULL,
    added_by text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT investigation_context_evidence_relation_status_check CHECK ((relation_status = ANY (ARRAY['confirmed'::text, 'excluded'::text])))
);


ALTER TABLE public.investigation_context_evidence OWNER TO adlog_user;

--
-- Name: investigation_events; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.investigation_events (
    investigation_id bigint NOT NULL,
    event_db_id bigint NOT NULL,
    relation_status text DEFAULT 'confirmed'::text NOT NULL,
    added_by text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT investigation_events_relation_status_check CHECK ((relation_status = ANY (ARRAY['confirmed'::text, 'excluded'::text])))
);


ALTER TABLE public.investigation_events OWNER TO adlog_user;

--
-- Name: COLUMN investigation_events.event_db_id; Type: COMMENT; Schema: public; Owner: adlog_user
--

COMMENT ON COLUMN public.investigation_events.event_db_id IS 'Stable evidence ID validated against events or events_v2_core at mutation time';


--
-- Name: investigation_evidence_refs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.investigation_evidence_refs (
    investigation_id bigint NOT NULL,
    evidence_kind text NOT NULL,
    source_domain_id bigint NOT NULL,
    reference_id text NOT NULL,
    relation_status text DEFAULT 'confirmed'::text NOT NULL,
    added_by text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT investigation_evidence_refs_added_by_check CHECK (((length(added_by) >= 1) AND (length(added_by) <= 200))),
    CONSTRAINT investigation_evidence_refs_evidence_kind_check CHECK ((evidence_kind = 'vpn_accounting_session'::text)),
    CONSTRAINT investigation_evidence_refs_reference_id_check CHECK (((length(reference_id) >= 1) AND (length(reference_id) <= 256))),
    CONSTRAINT investigation_evidence_refs_relation_status_check CHECK ((relation_status = ANY (ARRAY['confirmed'::text, 'excluded'::text])))
);


ALTER TABLE public.investigation_evidence_refs OWNER TO postgres;

--
-- Name: TABLE investigation_evidence_refs; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON TABLE public.investigation_evidence_refs IS 'Typed immutable evidence references; never substitutes a non-Windows source for event_db_id';


--
-- Name: investigation_finding_links; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.investigation_finding_links (
    investigation_id bigint NOT NULL,
    finding_id bigint NOT NULL,
    linked_by text NOT NULL,
    linked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT investigation_finding_links_linked_by_check CHECK (((length(linked_by) >= 1) AND (length(linked_by) <= 256)))
);


ALTER TABLE public.investigation_finding_links OWNER TO adlog_user;

--
-- Name: investigation_notes; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.investigation_notes (
    id bigint NOT NULL,
    investigation_id bigint NOT NULL,
    body text NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT investigation_notes_body_check CHECK (((length(body) >= 1) AND (length(body) <= 4000)))
);


ALTER TABLE public.investigation_notes OWNER TO adlog_user;

--
-- Name: investigation_notes_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.investigation_notes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.investigation_notes_id_seq OWNER TO adlog_user;

--
-- Name: investigation_notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.investigation_notes_id_seq OWNED BY public.investigation_notes.id;


--
-- Name: investigations; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.investigations (
    id bigint NOT NULL,
    title text NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    owner text,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone,
    public_id uuid NOT NULL,
    CONSTRAINT investigations_status_check CHECK ((status = ANY (ARRAY['new'::text, 'active'::text, 'review'::text, 'confirmed'::text, 'closed'::text])))
);


ALTER TABLE public.investigations OWNER TO adlog_user;

--
-- Name: investigations_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.investigations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.investigations_id_seq OWNER TO adlog_user;

--
-- Name: investigations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.investigations_id_seq OWNED BY public.investigations.id;


--
-- Name: log_sources; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.log_sources (
    id bigint NOT NULL,
    name text NOT NULL,
    provider text,
    description text
);


ALTER TABLE public.log_sources OWNER TO adlog_user;

--
-- Name: log_sources_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.log_sources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.log_sources_id_seq OWNER TO adlog_user;

--
-- Name: log_sources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.log_sources_id_seq OWNED BY public.log_sources.id;


--
-- Name: normalized_events; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.normalized_events (
    normalized_event_id uuid NOT NULL,
    source_event_id bigint NOT NULL,
    semantic_contract_version integer NOT NULL,
    normalizer_id text NOT NULL,
    normalizer_version text NOT NULL,
    processing_status text NOT NULL,
    normalized_at timestamp with time zone DEFAULT now() NOT NULL,
    source_event_sha256 bytea NOT NULL,
    semantic_sha256 bytea NOT NULL,
    facts_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    quality_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    failure_code text,
    failure_detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    semantic_type text NOT NULL,
    occurred_at_utc timestamp with time zone NOT NULL,
    source_ingested_at timestamp with time zone NOT NULL,
    roles_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    source_identity_json jsonb NOT NULL,
    CONSTRAINT normalized_events_facts_json_check CHECK ((jsonb_typeof(facts_json) = 'object'::text)),
    CONSTRAINT normalized_events_failure_detail CHECK ((((processing_status = ANY (ARRAY['quarantined'::text, 'failed'::text])) AND (failure_code IS NOT NULL)) OR ((processing_status = ANY (ARRAY['normalized'::text, 'ignored'::text])) AND (failure_code IS NULL) AND (failure_detail IS NULL)))),
    CONSTRAINT normalized_events_normalizer_id_check CHECK (((length(normalizer_id) >= 1) AND (length(normalizer_id) <= 160))),
    CONSTRAINT normalized_events_normalizer_version_check CHECK (((length(normalizer_version) >= 1) AND (length(normalizer_version) <= 80))),
    CONSTRAINT normalized_events_processing_status_check CHECK ((processing_status = ANY (ARRAY['normalized'::text, 'ignored'::text, 'quarantined'::text, 'failed'::text]))),
    CONSTRAINT normalized_events_quality_json_check CHECK ((jsonb_typeof(quality_json) = 'object'::text)),
    CONSTRAINT normalized_events_roles_object CHECK ((jsonb_typeof(roles_json) = 'object'::text)),
    CONSTRAINT normalized_events_semantic_contract_version_check CHECK ((semantic_contract_version > 0)),
    CONSTRAINT normalized_events_semantic_sha256_check CHECK ((octet_length(semantic_sha256) = 32)),
    CONSTRAINT normalized_events_semantic_type_bounded CHECK (((length(semantic_type) >= 1) AND (length(semantic_type) <= 160))),
    CONSTRAINT normalized_events_source_event_sha256_check CHECK ((octet_length(source_event_sha256) = 32)),
    CONSTRAINT normalized_events_source_identity_v2 CHECK (((jsonb_typeof(source_identity_json) = 'object'::text) AND (octet_length((source_identity_json)::text) <= 4096) AND (source_identity_json ?& ARRAY['id'::text, 'server_id'::text, 'domain_id'::text, 'log_source_id'::text, 'event_id'::text, 'time_created_utc'::text, 'normalized_hash'::text, 'migrated_at'::text, 'channel'::text]) AND ((source_identity_json ->> 'normalized_hash'::text) ~ '^[0-9a-f]{64}$'::text) AND (NOT (source_identity_json ?| ARRAY['raw_xml'::text, 'event_data'::text, 'event_data_json'::text]))))
);


ALTER TABLE public.normalized_events OWNER TO adlog_storage_owner;

--
-- Name: object_identity_links; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.object_identity_links (
    id bigint NOT NULL,
    source_object_type text NOT NULL,
    source_object_id text NOT NULL,
    target_object_type text NOT NULL,
    target_object_id text NOT NULL,
    relation_type text DEFAULT 'identity_link'::text NOT NULL,
    source_name text NOT NULL,
    match_method text NOT NULL,
    confidence numeric(5,4) NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT object_identity_links_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric)))
);


ALTER TABLE public.object_identity_links OWNER TO adlog_user;

--
-- Name: object_identity_links_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.object_identity_links_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.object_identity_links_id_seq OWNER TO adlog_user;

--
-- Name: object_identity_links_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.object_identity_links_id_seq OWNED BY public.object_identity_links.id;


--
-- Name: platform_settings; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.platform_settings (
    key text NOT NULL,
    value text NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_settings_key_check CHECK ((key ~ '^[a-z][a-z0-9_.]{1,63}$'::text)),
    CONSTRAINT platform_settings_updated_by_check CHECK (((length(updated_by) >= 1) AND (length(updated_by) <= 256))),
    CONSTRAINT platform_settings_value_check CHECK ((length(value) <= 1024))
);


ALTER TABLE public.platform_settings OWNER TO adlog_user;

--
-- Name: plugin_component_admission_v1; Type: TABLE; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE TABLE public.plugin_component_admission_v1 (
    plugin_id text NOT NULL,
    component_id text NOT NULL,
    admission_mode text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at_utc timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT plugin_component_admission_v1_admission_mode_check CHECK ((admission_mode = ANY (ARRAY['closed'::text, 'open'::text, 'drain_only'::text]))),
    CONSTRAINT plugin_component_admission_v1_check CHECK (((component_id <> 'radius-acquisition'::text) OR (admission_mode <> 'drain_only'::text))),
    CONSTRAINT plugin_component_admission_v1_component_id_check CHECK ((component_id = ANY (ARRAY['radius-acquisition'::text, 'radius-session-observation'::text]))),
    CONSTRAINT plugin_component_admission_v1_revision_check CHECK ((revision >= 1))
);


ALTER TABLE public.plugin_component_admission_v1 OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: plugin_component_leases_v1; Type: TABLE; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE TABLE public.plugin_component_leases_v1 (
    lease_uid uuid NOT NULL,
    plugin_id text NOT NULL,
    component_id text NOT NULL,
    lease_kind text NOT NULL,
    admission_mode_at_acquire text NOT NULL,
    holder_key text NOT NULL,
    acquired_at_utc timestamp with time zone DEFAULT now() NOT NULL,
    expires_at_utc timestamp with time zone NOT NULL,
    released_at_utc timestamp with time zone,
    release_outcome text,
    CONSTRAINT plugin_component_leases_v1_admission_mode_at_acquire_check CHECK ((admission_mode_at_acquire = ANY (ARRAY['open'::text, 'drain_only'::text]))),
    CONSTRAINT plugin_component_leases_v1_check CHECK (((expires_at_utc > acquired_at_utc) AND (expires_at_utc <= (acquired_at_utc + '00:02:00'::interval)))),
    CONSTRAINT plugin_component_leases_v1_check1 CHECK ((((released_at_utc IS NULL) AND (release_outcome IS NULL)) OR ((released_at_utc IS NOT NULL) AND (release_outcome IS NOT NULL)))),
    CONSTRAINT plugin_component_leases_v1_check2 CHECK ((((component_id = 'radius-acquisition'::text) AND (lease_kind = 'source_contact'::text)) OR ((component_id = 'radius-session-observation'::text) AND (lease_kind = 'delivery_claim'::text)))),
    CONSTRAINT plugin_component_leases_v1_holder_key_check CHECK (((btrim(holder_key) <> ''::text) AND (length(holder_key) <= 200))),
    CONSTRAINT plugin_component_leases_v1_lease_kind_check CHECK ((lease_kind = ANY (ARRAY['source_contact'::text, 'delivery_claim'::text]))),
    CONSTRAINT plugin_component_leases_v1_release_outcome_check CHECK (((release_outcome IS NULL) OR (release_outcome = ANY (ARRAY['completed'::text, 'failed'::text, 'cancelled'::text, 'expired'::text]))))
);


ALTER TABLE public.plugin_component_leases_v1 OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: plugin_installations_v1; Type: TABLE; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE TABLE public.plugin_installations_v1 (
    plugin_id text NOT NULL,
    manifest_id text NOT NULL,
    manifest_sha256 text NOT NULL,
    package_version text NOT NULL,
    rollback_version text,
    package_lifecycle text NOT NULL,
    desired_activation text NOT NULL,
    observed_health text NOT NULL,
    component_runtime text NOT NULL,
    queue_state text NOT NULL,
    revision bigint NOT NULL,
    immutable_evidence_count bigint NOT NULL,
    detach_reader_ready boolean DEFAULT false NOT NULL,
    read_report_parity boolean DEFAULT false NOT NULL,
    created_at_utc timestamp with time zone DEFAULT now() NOT NULL,
    updated_at_utc timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT plugin_installations_v1_component_runtime_check CHECK ((component_runtime = ANY (ARRAY['stopped'::text, 'starting'::text, 'running'::text, 'draining'::text, 'failed'::text]))),
    CONSTRAINT plugin_installations_v1_desired_activation_check CHECK ((desired_activation = ANY (ARRAY['disabled'::text, 'enabled_manual'::text]))),
    CONSTRAINT plugin_installations_v1_immutable_evidence_count_check CHECK ((immutable_evidence_count >= 1)),
    CONSTRAINT plugin_installations_v1_manifest_sha256_check CHECK ((manifest_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT plugin_installations_v1_observed_health_check CHECK ((observed_health = ANY (ARRAY['unknown'::text, 'ready'::text, 'degraded'::text, 'blocked'::text]))),
    CONSTRAINT plugin_installations_v1_package_lifecycle_check CHECK ((package_lifecycle = ANY (ARRAY['validated'::text, 'registered'::text, 'detached'::text]))),
    CONSTRAINT plugin_installations_v1_package_version_check CHECK ((package_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'::text)),
    CONSTRAINT plugin_installations_v1_plugin_id_check CHECK ((plugin_id ~ '^[a-z0-9][a-z0-9.-]{2,79}$'::text)),
    CONSTRAINT plugin_installations_v1_queue_state_check CHECK ((queue_state = ANY (ARRAY['drained'::text, 'backlog'::text, 'quarantined'::text]))),
    CONSTRAINT plugin_installations_v1_revision_check CHECK ((revision >= 1)),
    CONSTRAINT plugin_installations_v1_rollback_version_check CHECK (((rollback_version IS NULL) OR (rollback_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'::text)))
);


ALTER TABLE public.plugin_installations_v1 OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: plugin_lifecycle_operations_v1; Type: TABLE; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE TABLE public.plugin_lifecycle_operations_v1 (
    operation_id bigint NOT NULL,
    operation_uid uuid NOT NULL,
    plugin_id text NOT NULL,
    requested_action text NOT NULL,
    expected_revision bigint NOT NULL,
    committed_revision bigint,
    plan_sha256 text NOT NULL,
    confirmation_sha256 text NOT NULL,
    actor_kind text NOT NULL,
    actor_key text NOT NULL,
    outcome text NOT NULL,
    reason_code text,
    created_at_utc timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT plugin_lifecycle_operations_v1_actor_key_check CHECK (((btrim(actor_key) <> ''::text) AND (length(actor_key) <= 200))),
    CONSTRAINT plugin_lifecycle_operations_v1_actor_kind_check CHECK ((actor_kind = ANY (ARRAY['session'::text, 'api_key'::text, 'windows'::text, 'system'::text, 'local_operator'::text]))),
    CONSTRAINT plugin_lifecycle_operations_v1_check CHECK (((committed_revision IS NULL) OR (committed_revision >= expected_revision))),
    CONSTRAINT plugin_lifecycle_operations_v1_confirmation_sha256_check CHECK ((confirmation_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT plugin_lifecycle_operations_v1_expected_revision_check CHECK ((expected_revision >= 1)),
    CONSTRAINT plugin_lifecycle_operations_v1_outcome_check CHECK ((outcome = ANY (ARRAY['started'::text, 'succeeded'::text, 'failed'::text, 'denied'::text, 'cancelled'::text]))),
    CONSTRAINT plugin_lifecycle_operations_v1_plan_sha256_check CHECK ((plan_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT plugin_lifecycle_operations_v1_reason_code_check CHECK (((reason_code IS NULL) OR (reason_code ~ '^[a-z][a-z0-9_.-]{0,119}$'::text))),
    CONSTRAINT plugin_lifecycle_operations_v1_requested_action_check CHECK ((requested_action = ANY (ARRAY['install'::text, 'upgrade'::text, 'rollback'::text, 'enable'::text, 'drain'::text, 'disable'::text, 'detach'::text])))
);


ALTER TABLE public.plugin_lifecycle_operations_v1 OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: plugin_lifecycle_operations_v1_operation_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE public.plugin_lifecycle_operations_v1 ALTER COLUMN operation_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.plugin_lifecycle_operations_v1_operation_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: plugin_state_v1; Type: TABLE; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE TABLE public.plugin_state_v1 (
    plugin_id text NOT NULL,
    configured boolean DEFAULT false NOT NULL,
    last_data_at_utc timestamp with time zone,
    updated_at_utc timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.plugin_state_v1 OWNER TO adlog_plugin_lifecycle_owner;

--
-- Name: post_collection_jobs; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.post_collection_jobs (
    id bigint NOT NULL,
    source_job_id bigint NOT NULL,
    durable_job_id text NOT NULL,
    status text NOT NULL,
    servers_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    report_path text,
    error_id text,
    error_message text,
    worker_id text,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 2 NOT NULL,
    heartbeat_at timestamp with time zone,
    worker_lease_until timestamp with time zone,
    phase text DEFAULT 'queued'::text NOT NULL,
    findings_status text DEFAULT 'queued'::text NOT NULL,
    findings_started_at timestamp with time zone,
    findings_finished_at timestamp with time zone,
    findings_duration_ms bigint,
    findings_scanned_events bigint,
    findings_matched_events bigint,
    findings_created bigint,
    findings_updated bigint,
    findings_evidence_added bigint,
    findings_watermark_before bigint,
    findings_watermark_after bigint,
    findings_error_id text,
    findings_error_message text,
    findings_result_json jsonb,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.post_collection_jobs OWNER TO adlog_user;

--
-- Name: post_collection_jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.post_collection_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.post_collection_jobs_id_seq OWNER TO adlog_user;

--
-- Name: post_collection_jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.post_collection_jobs_id_seq OWNED BY public.post_collection_jobs.id;


--
-- Name: process_episode_evidence; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.process_episode_evidence (
    revision_id uuid NOT NULL,
    evidence_order smallint NOT NULL,
    source_event_id bigint NOT NULL,
    evidence_role text NOT NULL,
    semantic_type text NOT NULL,
    semantic_contract_version integer NOT NULL,
    normalizer_id text NOT NULL,
    normalizer_version text NOT NULL,
    semantic_sha256 bytea NOT NULL,
    observed_at_utc timestamp with time zone NOT NULL,
    domain_id bigint NOT NULL,
    source_host_id bigint NOT NULL,
    source_channel text NOT NULL,
    event_record_id bigint NOT NULL,
    source_event_sha256 bytea NOT NULL,
    source_facts_sha256 bytea NOT NULL,
    CONSTRAINT process_episode_evidence_domain_id_check CHECK ((domain_id > 0)),
    CONSTRAINT process_episode_evidence_event_record_id_check CHECK ((event_record_id >= 0)),
    CONSTRAINT process_episode_evidence_evidence_order_check CHECK (((evidence_order >= 0) AND (evidence_order <= 255))),
    CONSTRAINT process_episode_evidence_evidence_role_check CHECK ((evidence_role = ANY (ARRAY['boot_scope'::text, 'start'::text, 'confirmed_end'::text, 'attached'::text]))),
    CONSTRAINT process_episode_evidence_normalizer_id_check CHECK (((octet_length(normalizer_id) >= 1) AND (octet_length(normalizer_id) <= 128))),
    CONSTRAINT process_episode_evidence_normalizer_version_check CHECK (((octet_length(normalizer_version) >= 1) AND (octet_length(normalizer_version) <= 128))),
    CONSTRAINT process_episode_evidence_semantic_contract_version_check CHECK ((semantic_contract_version > 0)),
    CONSTRAINT process_episode_evidence_semantic_sha256_check CHECK ((octet_length(semantic_sha256) = 32)),
    CONSTRAINT process_episode_evidence_semantic_type_check CHECK (((octet_length(semantic_type) >= 1) AND (octet_length(semantic_type) <= 160))),
    CONSTRAINT process_episode_evidence_source_channel_check CHECK (((octet_length(source_channel) >= 1) AND (octet_length(source_channel) <= 512))),
    CONSTRAINT process_episode_evidence_source_event_sha256_check CHECK ((octet_length(source_event_sha256) = 32)),
    CONSTRAINT process_episode_evidence_source_facts_sha256_check CHECK ((octet_length(source_facts_sha256) = 32)),
    CONSTRAINT process_episode_evidence_source_host_id_check CHECK ((source_host_id > 0))
);


ALTER TABLE public.process_episode_evidence OWNER TO adlog_storage_owner;

--
-- Name: process_episode_revisions; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.process_episode_revisions (
    revision_id uuid NOT NULL,
    episode_id text NOT NULL,
    revision_no integer NOT NULL,
    assembler_id text NOT NULL,
    assembler_version text NOT NULL,
    idempotency_key bytea NOT NULL,
    revision_sha256 bytea NOT NULL,
    revision_payload text NOT NULL,
    evidence_manifest_sha256 bytea NOT NULL,
    evidence_manifest_payload text NOT NULL,
    completeness_state text NOT NULL,
    confirmation_state text NOT NULL,
    ordering_state text NOT NULL,
    domain_id bigint NOT NULL,
    source_host_id bigint NOT NULL,
    display_host text NOT NULL,
    boot_event_id bigint NOT NULL,
    process_id bigint NOT NULL,
    start_event_id bigint NOT NULL,
    started_at_utc timestamp with time zone NOT NULL,
    end_event_id bigint,
    confirmed_end_at_utc timestamp with time zone,
    process_name text,
    parent_process_id bigint,
    parent_episode_id text,
    command_line text,
    user_sid text,
    user_name text,
    user_domain text,
    logon_id text,
    evidence_count smallint NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT process_episode_assembler_bounded CHECK (((octet_length(assembler_id) >= 1) AND (octet_length(assembler_id) <= 128) AND ((octet_length(assembler_version) >= 1) AND (octet_length(assembler_version) <= 64)))),
    CONSTRAINT process_episode_end_exact CHECK ((((confirmation_state = 'confirmed_end'::text) AND (end_event_id IS NOT NULL) AND (confirmed_end_at_utc IS NOT NULL)) OR ((confirmation_state <> 'confirmed_end'::text) AND (end_event_id IS NULL) AND (confirmed_end_at_utc IS NULL)))),
    CONSTRAINT process_episode_id_digest CHECK ((episode_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT process_episode_idempotency_exact CHECK ((idempotency_key = public.digest((convert_to((((((episode_id || ':'::text) || assembler_id) || ':'::text) || assembler_version) || ':'::text), 'UTF8'::name) || revision_sha256), 'sha256'::text))),
    CONSTRAINT process_episode_identity_bounded CHECK (((octet_length(display_host) >= 1) AND (octet_length(display_host) <= 512))),
    CONSTRAINT process_episode_revision_digest_exact CHECK (((revision_sha256 = public.digest(convert_to(revision_payload, 'UTF8'::name), 'sha256'::text)) AND (evidence_manifest_sha256 = public.digest(convert_to(evidence_manifest_payload, 'UTF8'::name), 'sha256'::text)))),
    CONSTRAINT process_episode_revisions_domain_id_check CHECK ((domain_id > 0)),
    CONSTRAINT process_episode_revisions_evidence_count_check CHECK (((evidence_count >= 1) AND (evidence_count <= 256))),
    CONSTRAINT process_episode_revisions_evidence_manifest_payload_check CHECK ((octet_length(evidence_manifest_payload) <= 131072)),
    CONSTRAINT process_episode_revisions_evidence_manifest_sha256_check CHECK ((octet_length(evidence_manifest_sha256) = 32)),
    CONSTRAINT process_episode_revisions_idempotency_key_check CHECK ((octet_length(idempotency_key) = 32)),
    CONSTRAINT process_episode_revisions_parent_process_id_check CHECK (((parent_process_id IS NULL) OR ((parent_process_id >= 1) AND (parent_process_id <= '4294967295'::bigint)))),
    CONSTRAINT process_episode_revisions_process_id_check CHECK (((process_id >= 1) AND (process_id <= '4294967295'::bigint))),
    CONSTRAINT process_episode_revisions_revision_no_check CHECK ((revision_no > 0)),
    CONSTRAINT process_episode_revisions_revision_payload_check CHECK ((octet_length(revision_payload) <= 32768)),
    CONSTRAINT process_episode_revisions_revision_sha256_check CHECK ((octet_length(revision_sha256) = 32)),
    CONSTRAINT process_episode_revisions_source_host_id_check CHECK ((source_host_id > 0)),
    CONSTRAINT process_episode_state_bounded CHECK (((completeness_state = ANY (ARRAY['complete'::text, 'incomplete_open'::text, 'incomplete_parent_unproven'::text, 'conflict_ambiguous_close'::text])) AND (confirmation_state = ANY (ARRAY['confirmed_end'::text, 'open_incomplete'::text, 'ambiguous_conflict'::text])) AND (ordering_state = ANY (ARRAY['source_native'::text, 'cross_channel_uncertain'::text])))),
    CONSTRAINT process_episode_text_bounded CHECK ((((process_name IS NULL) OR (octet_length(process_name) <= 512)) AND ((parent_episode_id IS NULL) OR (parent_episode_id ~ '^[0-9a-f]{64}$'::text)) AND ((command_line IS NULL) OR (octet_length(command_line) <= 4096)) AND ((user_sid IS NULL) OR (octet_length(user_sid) <= 512)) AND ((user_name IS NULL) OR (octet_length(user_name) <= 512)) AND ((user_domain IS NULL) OR (octet_length(user_domain) <= 512)) AND ((logon_id IS NULL) OR (octet_length(logon_id) <= 128))))
);


ALTER TABLE public.process_episode_revisions OWNER TO adlog_storage_owner;

--
-- Name: radius_accounting_class_cache; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.radius_accounting_class_cache (
    source_instance_id text NOT NULL,
    class_scope_sha256 text NOT NULL,
    exact_principal_key text NOT NULL,
    expires_at_utc timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT radius_accounting_class_cache_class_scope_sha256_check CHECK ((class_scope_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT radius_accounting_class_cache_exact_principal_key_check CHECK ((btrim(exact_principal_key) <> ''::text))
);


ALTER TABLE public.radius_accounting_class_cache OWNER TO adlog_storage_owner;

--
-- Name: radius_accounting_session_observations; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.radius_accounting_session_observations (
    observation_id uuid NOT NULL,
    evidence_uid uuid NOT NULL,
    lifecycle_event text NOT NULL,
    session_identity_key text,
    exact_principal_key text,
    identity_state text NOT NULL,
    observed_at_utc timestamp with time zone,
    timestamp_basis text,
    timestamp_state text NOT NULL,
    session_confirmed_by_accounting boolean CONSTRAINT radius_accounting_session_o_session_confirmed_by_accou_not_null NOT NULL,
    producer_contract_id text CONSTRAINT radius_accounting_session_observa_producer_contract_id_not_null NOT NULL,
    resource_groups text[] NOT NULL,
    row_sensitivity text NOT NULL,
    field_categories text[] CONSTRAINT radius_accounting_session_observation_field_categories_not_null NOT NULL,
    evidence_access_requirement text CONSTRAINT radius_accounting_session_o_evidence_access_requiremen_not_null NOT NULL,
    label_policy_version text CONSTRAINT radius_accounting_session_observa_label_policy_version_not_null NOT NULL,
    provenance_json jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT radius_accounting_session_ob_session_confirmed_by_account_check CHECK (session_confirmed_by_accounting),
    CONSTRAINT radius_accounting_session_obs_evidence_access_requirement_check CHECK ((btrim(evidence_access_requirement) <> ''::text)),
    CONSTRAINT radius_accounting_session_observatio_label_policy_version_check CHECK ((btrim(label_policy_version) <> ''::text)),
    CONSTRAINT radius_accounting_session_observations_check CHECK ((((identity_state = 'exact'::text) AND (session_identity_key IS NOT NULL) AND (exact_principal_key IS NOT NULL)) OR ((identity_state = 'unresolved'::text) AND (session_identity_key IS NULL) AND (exact_principal_key IS NULL)))),
    CONSTRAINT radius_accounting_session_observations_check1 CHECK ((((timestamp_state = 'ready'::text) AND (observed_at_utc IS NOT NULL) AND (timestamp_basis IS NOT NULL)) OR ((timestamp_state = 'unresolved'::text) AND (observed_at_utc IS NULL) AND (timestamp_basis IS NULL)))),
    CONSTRAINT radius_accounting_session_observations_field_categories_check CHECK ((cardinality(field_categories) > 0)),
    CONSTRAINT radius_accounting_session_observations_identity_state_check CHECK ((identity_state = ANY (ARRAY['exact'::text, 'unresolved'::text]))),
    CONSTRAINT radius_accounting_session_observations_lifecycle_event_check CHECK ((lifecycle_event = ANY (ARRAY['start'::text, 'interim_update'::text, 'stop'::text]))),
    CONSTRAINT radius_accounting_session_observations_resource_groups_check CHECK ((cardinality(resource_groups) > 0)),
    CONSTRAINT radius_accounting_session_observations_row_sensitivity_check CHECK ((row_sensitivity = ANY (ARRAY['internal'::text, 'restricted'::text, 'confidential'::text]))),
    CONSTRAINT radius_accounting_session_observations_timestamp_state_check CHECK ((timestamp_state = ANY (ARRAY['ready'::text, 'unresolved'::text])))
);


ALTER TABLE public.radius_accounting_session_observations OWNER TO adlog_storage_owner;

--
-- Name: radius_session_identity_overlays; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.radius_session_identity_overlays (
    observation_id uuid NOT NULL,
    attempt_key text NOT NULL,
    evidence_uid uuid NOT NULL,
    session_identity_key text NOT NULL,
    exact_principal_key text NOT NULL,
    resolution_input_sha256 text CONSTRAINT radius_session_identity_overla_resolution_input_sha256_not_null NOT NULL,
    resolver_contract_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT radius_session_identity_overlays_exact_principal_key_check CHECK ((exact_principal_key ~ '^entity:[1-9][0-9]*$'::text)),
    CONSTRAINT radius_session_identity_overlays_resolution_input_sha256_check CHECK ((resolution_input_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT radius_session_identity_overlays_resolver_contract_id_check CHECK (((btrim(resolver_contract_id) <> ''::text) AND (length(resolver_contract_id) <= 160))),
    CONSTRAINT radius_session_identity_overlays_session_identity_key_check CHECK ((session_identity_key ~ '^radius-session:[0-9a-f]{64}$'::text))
);


ALTER TABLE public.radius_session_identity_overlays OWNER TO adlog_storage_owner;

--
-- Name: radius_session_projection_receipts; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.radius_session_projection_receipts (
    delivery_id bigint NOT NULL,
    observation_id uuid NOT NULL,
    outcome text NOT NULL,
    projected_row_count integer NOT NULL,
    consumer_contract_id text CONSTRAINT radius_session_projection_receipt_consumer_contract_id_not_null NOT NULL,
    processed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT radius_session_projection_receipts_consumer_contract_id_check CHECK ((btrim(consumer_contract_id) <> ''::text)),
    CONSTRAINT radius_session_projection_receipts_outcome_check CHECK ((outcome = ANY (ARRAY['projected'::text, 'identity_unresolved'::text, 'timestamp_unresolved'::text]))),
    CONSTRAINT radius_session_projection_receipts_projected_row_count_check CHECK (((projected_row_count >= 0) AND (projected_row_count <= 10000)))
);


ALTER TABLE public.radius_session_projection_receipts OWNER TO adlog_storage_owner;

--
-- Name: radius_session_reconciliation_attempts; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.radius_session_reconciliation_attempts (
    attempt_key text NOT NULL,
    observation_id uuid NOT NULL,
    evidence_uid uuid NOT NULL,
    outcome text NOT NULL,
    evidence_corpus_sha256 text CONSTRAINT radius_session_reconciliation_a_evidence_corpus_sha256_not_null NOT NULL,
    resolver_contract_id text CONSTRAINT radius_session_reconciliation_att_resolver_contract_id_not_null NOT NULL,
    resolution_input_sha256 text,
    writer_contract_id text CONSTRAINT radius_session_reconciliation_attem_writer_contract_id_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT radius_session_reconciliation_atte_evidence_corpus_sha256_check CHECK ((evidence_corpus_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT radius_session_reconciliation_attemp_resolver_contract_id_check CHECK (((btrim(resolver_contract_id) <> ''::text) AND (length(resolver_contract_id) <= 160))),
    CONSTRAINT radius_session_reconciliation_attempts_attempt_key_check CHECK ((attempt_key ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT radius_session_reconciliation_attempts_check CHECK ((((outcome = 'projected'::text) AND (resolution_input_sha256 ~ '^[0-9a-f]{64}$'::text)) OR ((outcome = 'still_unresolved'::text) AND (resolution_input_sha256 IS NULL)))),
    CONSTRAINT radius_session_reconciliation_attempts_outcome_check CHECK ((outcome = ANY (ARRAY['projected'::text, 'still_unresolved'::text]))),
    CONSTRAINT radius_session_reconciliation_attempts_writer_contract_id_check CHECK ((btrim(writer_contract_id) <> ''::text))
);


ALTER TABLE public.radius_session_reconciliation_attempts OWNER TO adlog_storage_owner;

--
-- Name: radius_vpn_session_projection; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.radius_vpn_session_projection (
    session_row_id text NOT NULL,
    session_identity_key text NOT NULL,
    exact_principal_key text NOT NULL,
    generation integer NOT NULL,
    lifecycle_state text NOT NULL,
    completeness text NOT NULL,
    started_at_utc timestamp with time zone,
    last_observed_at_utc timestamp with time zone NOT NULL,
    stopped_at_utc timestamp with time zone,
    duration_seconds bigint,
    observation_count integer NOT NULL,
    anomalies text[] DEFAULT '{}'::text[] NOT NULL,
    read_model_contract_id text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT radius_vpn_session_projection_anomalies_check CHECK ((anomalies <@ ARRAY['start_before_stop'::text])),
    CONSTRAINT radius_vpn_session_projection_check CHECK ((((completeness = 'complete'::text) AND (started_at_utc IS NOT NULL) AND (stopped_at_utc IS NOT NULL) AND (duration_seconds IS NOT NULL)) OR ((completeness = 'missing_start'::text) AND (started_at_utc IS NULL) AND (stopped_at_utc IS NOT NULL) AND (duration_seconds IS NULL)) OR ((completeness = 'missing_stop'::text) AND (started_at_utc IS NOT NULL) AND (stopped_at_utc IS NULL) AND (duration_seconds IS NULL)) OR ((completeness = 'middle_only'::text) AND (started_at_utc IS NULL) AND (stopped_at_utc IS NULL) AND (duration_seconds IS NULL)))),
    CONSTRAINT radius_vpn_session_projection_check1 CHECK ((((started_at_utc IS NULL) OR (started_at_utc <= last_observed_at_utc)) AND ((stopped_at_utc IS NULL) OR (stopped_at_utc <= last_observed_at_utc)))),
    CONSTRAINT radius_vpn_session_projection_completeness_check CHECK ((completeness = ANY (ARRAY['complete'::text, 'missing_start'::text, 'missing_stop'::text, 'middle_only'::text]))),
    CONSTRAINT radius_vpn_session_projection_duration_seconds_check CHECK ((duration_seconds >= 0)),
    CONSTRAINT radius_vpn_session_projection_exact_principal_key_check CHECK ((btrim(exact_principal_key) <> ''::text)),
    CONSTRAINT radius_vpn_session_projection_generation_check CHECK ((generation > 0)),
    CONSTRAINT radius_vpn_session_projection_lifecycle_state_check CHECK ((lifecycle_state = ANY (ARRAY['closed'::text, 'partial_closed'::text, 'open_observed'::text, 'partial_open'::text]))),
    CONSTRAINT radius_vpn_session_projection_observation_count_check CHECK (((observation_count >= 1) AND (observation_count <= 10000))),
    CONSTRAINT radius_vpn_session_projection_read_model_contract_id_check CHECK ((btrim(read_model_contract_id) <> ''::text)),
    CONSTRAINT radius_vpn_session_projection_session_identity_key_check CHECK ((session_identity_key ~ '^radius-session:[0-9a-f]{64}$'::text)),
    CONSTRAINT radius_vpn_session_projection_session_row_id_check CHECK ((session_row_id ~ '^radius-session-row:[0-9a-f]{64}$'::text))
);


ALTER TABLE public.radius_vpn_session_projection OWNER TO adlog_storage_owner;

--
-- Name: radius_vpn_session_coverage_v1; Type: VIEW; Schema: public; Owner: adlog_vpn_session_reader_owner
--

CREATE VIEW public.radius_vpn_session_coverage_v1 WITH (security_barrier='true') AS
 WITH source_domains AS (
         SELECT source.source_instance_id,
            domain_row.id AS domain_id
           FROM (public.acquisition_source_instances source
             JOIN public.domains domain_row ON ((lower(domain_row.fqdn) = lower(source.organization_scope))))
          WHERE (source.source_kind = 'windows.nps.radius'::text)
        ), delivery_counts AS (
         SELECT source_domain_1.domain_id,
            count(*) AS total_delivery_count,
            count(*) FILTER (WHERE (delivery_1.delivery_state = 'queued'::text)) AS queued_delivery_count,
            count(*) FILTER (WHERE (delivery_1.delivery_state = 'leased'::text)) AS leased_delivery_count,
            count(*) FILTER (WHERE (delivery_1.delivery_state = 'failed'::text)) AS failed_delivery_count,
            count(*) FILTER (WHERE (delivery_1.delivery_state = 'delivered'::text)) AS delivered_delivery_count,
            count(*) FILTER (WHERE (delivery_1.delivery_state = 'quarantined'::text)) AS quarantined_delivery_count,
            count(*) FILTER (WHERE (receipt.outcome = 'projected'::text)) AS projected_receipt_count,
            count(*) FILTER (WHERE (receipt.outcome = 'identity_unresolved'::text)) AS identity_unresolved_count,
            count(*) FILTER (WHERE (receipt.outcome = 'timestamp_unresolved'::text)) AS timestamp_unresolved_count,
            min(COALESCE(observation.observed_at_utc, evidence.verified_at_utc)) AS history_available_from_utc,
            max(COALESCE(observation.observed_at_utc, evidence.verified_at_utc)) AS history_available_to_utc
           FROM (((((public.acquisition_delivery_outbox delivery_1
             JOIN public.acquisition_consumer_subscriptions subscription ON ((subscription.subscription_id = delivery_1.subscription_id)))
             JOIN source_domains source_domain_1 ON ((source_domain_1.source_instance_id = subscription.source_instance_id)))
             JOIN public.radius_accounting_session_observations observation ON ((observation.observation_id = delivery_1.observation_id)))
             JOIN public.core_evidence_manifests evidence ON ((evidence.evidence_uid = observation.evidence_uid)))
             LEFT JOIN public.radius_session_projection_receipts receipt ON ((receipt.delivery_id = delivery_1.delivery_id)))
          GROUP BY source_domain_1.domain_id
        ), projection_counts AS (
         SELECT entity_row.domain_id,
            count(*) AS projected_session_count
           FROM (public.radius_vpn_session_projection projection_1
             JOIN public.entities_v2 entity_row ON ((projection_1.exact_principal_key = ('entity:'::text || (entity_row.id)::text))))
          WHERE (entity_row.domain_id IS NOT NULL)
          GROUP BY entity_row.domain_id
        )
 SELECT source_domain.domain_id,
    COALESCE(delivery.total_delivery_count, (0)::bigint) AS total_delivery_count,
    COALESCE(delivery.queued_delivery_count, (0)::bigint) AS queued_delivery_count,
    COALESCE(delivery.leased_delivery_count, (0)::bigint) AS leased_delivery_count,
    COALESCE(delivery.failed_delivery_count, (0)::bigint) AS failed_delivery_count,
    COALESCE(delivery.delivered_delivery_count, (0)::bigint) AS delivered_delivery_count,
    COALESCE(delivery.quarantined_delivery_count, (0)::bigint) AS quarantined_delivery_count,
    COALESCE(delivery.projected_receipt_count, (0)::bigint) AS projected_receipt_count,
    COALESCE(delivery.identity_unresolved_count, (0)::bigint) AS identity_unresolved_count,
    COALESCE(delivery.timestamp_unresolved_count, (0)::bigint) AS timestamp_unresolved_count,
    COALESCE(projection.projected_session_count, (0)::bigint) AS projected_session_count,
    delivery.history_available_from_utc,
    delivery.history_available_to_utc
   FROM ((( SELECT DISTINCT source_domains.domain_id
           FROM source_domains) source_domain
     LEFT JOIN delivery_counts delivery ON ((delivery.domain_id = source_domain.domain_id)))
     LEFT JOIN projection_counts projection ON ((projection.domain_id = source_domain.domain_id)));


ALTER VIEW public.radius_vpn_session_coverage_v1 OWNER TO adlog_vpn_session_reader_owner;

--
-- Name: report_registry_v4; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.report_registry_v4 (
    id bigint NOT NULL,
    report_key text NOT NULL,
    version integer NOT NULL,
    name text NOT NULL,
    owner_name text NOT NULL,
    purpose text NOT NULL,
    dataset_id bigint NOT NULL,
    definition_json jsonb NOT NULL,
    sensitivity text NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    published_at timestamp with time zone,
    created_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    discoverable boolean DEFAULT true NOT NULL,
    requestable boolean DEFAULT false NOT NULL,
    request_profile_json jsonb DEFAULT '{"scope_kinds": ["all"], "max_duration_days": 90}'::jsonb NOT NULL,
    CONSTRAINT report_registry_v4_sensitivity_check CHECK ((sensitivity = ANY (ARRAY['internal'::text, 'restricted'::text, 'confidential'::text]))),
    CONSTRAINT report_registry_v4_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'retired'::text]))),
    CONSTRAINT report_registry_v4_version_check CHECK ((version > 0))
);


ALTER TABLE public.report_registry_v4 OWNER TO adlog_user;

--
-- Name: radius_vpn_operations_v1; Type: VIEW; Schema: public; Owner: adlog_vpn_session_reader_owner
--

CREATE VIEW public.radius_vpn_operations_v1 WITH (security_barrier='true') AS
 SELECT source.source_instance_id,
    source.display_name AS source_display_name,
    domain_row.id AS domain_id,
    source.desired_activation AS source_activation,
    source.observed_health AS source_health,
    source.updated_at AS source_updated_at,
    subscription.subscription_id,
    subscription.desired_activation AS subscription_activation,
    subscription.authority_mode,
    subscription.replay_policy,
    subscription.resource_profile_id,
    cursor_row.revision AS cursor_revision,
    cursor_row.updated_at AS cursor_updated_at,
    COALESCE(coverage.total_delivery_count, (0)::bigint) AS total_delivery_count,
    COALESCE(coverage.queued_delivery_count, (0)::bigint) AS queued_delivery_count,
    COALESCE(coverage.leased_delivery_count, (0)::bigint) AS leased_delivery_count,
    COALESCE(coverage.failed_delivery_count, (0)::bigint) AS failed_delivery_count,
    COALESCE(coverage.delivered_delivery_count, (0)::bigint) AS delivered_delivery_count,
    COALESCE(coverage.quarantined_delivery_count, (0)::bigint) AS quarantined_delivery_count,
    COALESCE(coverage.projected_receipt_count, (0)::bigint) AS projected_receipt_count,
    COALESCE(coverage.identity_unresolved_count, (0)::bigint) AS identity_unresolved_count,
    COALESCE(coverage.timestamp_unresolved_count, (0)::bigint) AS timestamp_unresolved_count,
    COALESCE(coverage.projected_session_count, (0)::bigint) AS projected_session_count,
    ( SELECT count(*) AS count
           FROM public.access_capabilities capability
          WHERE (capability.capability_key = ANY (ARRAY['vpn.sessions.view'::text, 'vpn.session.evidence.read'::text]))) AS registered_capability_count,
    ( SELECT count(*) AS count
           FROM (public.access_capability_assignments assignment
             JOIN public.access_capabilities capability ON ((capability.id = assignment.capability_id)))
          WHERE (capability.capability_key = ANY (ARRAY['vpn.sessions.view'::text, 'vpn.session.evidence.read'::text]))) AS direct_capability_assignment_count,
    ( SELECT count(*) AS count
           FROM (public.access_package_capabilities package_capability
             JOIN public.access_capabilities capability ON ((capability.id = package_capability.capability_id)))
          WHERE (capability.capability_key = ANY (ARRAY['vpn.sessions.view'::text, 'vpn.session.evidence.read'::text]))) AS package_capability_mapping_count,
    COALESCE(( SELECT registry.status
           FROM public.report_registry_v4 registry
          WHERE (registry.report_key = 'vpn.audit'::text)
          ORDER BY registry.version DESC
         LIMIT 1), 'not_registered'::text) AS report_status,
    (EXISTS ( SELECT 1
           FROM pg_roles
          WHERE ((pg_roles.rolname ~~ 'adlog_radius_manual_%'::text) OR (pg_roles.rolname ~~ 'adlog_radius_consumer_%'::text)))) AS ephemeral_login_exists,
    (EXISTS ( SELECT 1
           FROM pg_stat_activity
          WHERE ((pg_stat_activity.application_name = ANY (ARRAY['sli_stage9_radius_manual_worker'::text, 'sli_stage9_radius_session_consumer_worker'::text])) AND (pg_stat_activity.pid <> pg_backend_pid())))) AS manual_worker_session_exists,
    false AS continuous_runtime_enabled,
    false AS autostart_enabled
   FROM ((((public.acquisition_source_instances source
     JOIN public.acquisition_consumer_subscriptions subscription ON ((subscription.source_instance_id = source.source_instance_id)))
     JOIN public.acquisition_stream_cursors cursor_row ON (((cursor_row.source_instance_id = subscription.source_instance_id) AND (cursor_row.stream_id = subscription.stream_id) AND (cursor_row.transport_binding = subscription.transport_binding))))
     JOIN public.domains domain_row ON ((lower(domain_row.fqdn) = lower(source.organization_scope))))
     LEFT JOIN public.radius_vpn_session_coverage_v1 coverage ON ((coverage.domain_id = domain_row.id)))
  WHERE ((source.source_kind = 'windows.nps.radius'::text) AND (subscription.consumer_id = 'sli.windows.vpn-radius'::text));


ALTER VIEW public.radius_vpn_operations_v1 OWNER TO adlog_vpn_session_reader_owner;

--
-- Name: radius_vpn_session_evidence_observations_v1; Type: VIEW; Schema: public; Owner: adlog_vpn_session_reader_owner
--

CREATE VIEW public.radius_vpn_session_evidence_observations_v1 WITH (security_barrier='true') AS
 SELECT DISTINCT projection.session_row_id,
    entity_row.domain_id,
    observation.observation_id,
    observation.lifecycle_event,
    observation.identity_state,
    observation.timestamp_state,
    observation.session_identity_key,
    observation.exact_principal_key,
    observation.observed_at_utc,
    evidence.evidence_uid,
    evidence.source_instance_id,
    evidence.stream_id,
    evidence.transport_binding,
    evidence.object_reference,
    evidence.canonical_record_sha256,
    evidence.object_sha256,
    evidence.object_size_bytes,
    evidence.verified_at_utc
   FROM (((((public.radius_vpn_session_projection projection
     JOIN public.entities_v2 entity_row ON ((projection.exact_principal_key = ('entity:'::text || (entity_row.id)::text))))
     JOIN public.acquisition_delivery_outbox delivery ON (((delivery.subscription_id ~~ 'vpn-radius-session-observations-%-v1'::text) AND (delivery.delivery_state = 'delivered'::text))))
     JOIN public.acquisition_consumer_subscriptions subscription ON ((subscription.subscription_id = delivery.subscription_id)))
     JOIN public.radius_accounting_session_observations observation ON ((observation.observation_id = delivery.observation_id)))
     JOIN public.core_evidence_manifests evidence ON (((evidence.evidence_uid = observation.evidence_uid) AND (evidence.source_instance_id = subscription.source_instance_id))))
  WHERE ((observation.timestamp_state = 'ready'::text) AND (observation.identity_state = 'exact'::text) AND (observation.session_identity_key = projection.session_identity_key) AND (observation.exact_principal_key = projection.exact_principal_key));


ALTER VIEW public.radius_vpn_session_evidence_observations_v1 OWNER TO adlog_vpn_session_reader_owner;

--
-- Name: radius_vpn_session_rows_v1; Type: VIEW; Schema: public; Owner: adlog_vpn_session_reader_owner
--

CREATE VIEW public.radius_vpn_session_rows_v1 WITH (security_barrier='true') AS
 SELECT projection.session_row_id,
    (entity_row.id)::bigint AS entity_id,
    entity_row.domain_id,
    projection.generation,
    projection.lifecycle_state,
    projection.completeness,
    projection.started_at_utc,
    projection.last_observed_at_utc,
    projection.stopped_at_utc,
    projection.duration_seconds,
    projection.observation_count,
    projection.anomalies,
    projection.updated_at
   FROM (public.radius_vpn_session_projection projection
     JOIN public.entities_v2 entity_row ON ((projection.exact_principal_key = ('entity:'::text || (entity_row.id)::text))))
  WHERE (entity_row.domain_id IS NOT NULL);


ALTER VIEW public.radius_vpn_session_rows_v1 OWNER TO adlog_vpn_session_reader_owner;

--
-- Name: raw_batch_lifecycle; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.raw_batch_lifecycle (
    batch_identity text NOT NULL,
    manifest_hash text NOT NULL,
    server text NOT NULL,
    raw_path text NOT NULL,
    trace_id text NOT NULL,
    expected_channels integer DEFAULT 0 NOT NULL,
    committed_channels integer DEFAULT 0 NOT NULL,
    import_outcome text DEFAULT 'unknown'::text NOT NULL,
    cursor_outcome text DEFAULT 'unknown'::text NOT NULL,
    cleanup_outcome text DEFAULT 'retained'::text NOT NULL,
    import_error text,
    cleanup_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    import_recorded_at timestamp with time zone,
    cursor_recorded_at timestamp with time zone,
    cleanup_recorded_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT raw_batch_lifecycle_cleanup_outcome_check CHECK ((cleanup_outcome = ANY (ARRAY['retained'::text, 'delete_authorized'::text, 'deleted'::text, 'delete_failed'::text]))),
    CONSTRAINT raw_batch_lifecycle_committed_channels_check CHECK ((committed_channels >= 0)),
    CONSTRAINT raw_batch_lifecycle_cursor_outcome_check CHECK ((cursor_outcome = ANY (ARRAY['unknown'::text, 'committed'::text, 'not_committed'::text]))),
    CONSTRAINT raw_batch_lifecycle_expected_channels_check CHECK ((expected_channels >= 0)),
    CONSTRAINT raw_batch_lifecycle_identity_sha256 CHECK ((batch_identity ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT raw_batch_lifecycle_import_outcome_check CHECK ((import_outcome = ANY (ARRAY['unknown'::text, 'succeeded'::text, 'failed'::text]))),
    CONSTRAINT raw_batch_lifecycle_manifest_sha256 CHECK ((manifest_hash ~ '^[0-9a-f]{64}$'::text))
);


ALTER TABLE public.raw_batch_lifecycle OWNER TO postgres;

--
-- Name: raw_log_files; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.raw_log_files (
    id bigint NOT NULL,
    collection_run_id bigint,
    server_id bigint NOT NULL,
    log_source_id bigint NOT NULL,
    file_path text NOT NULL,
    file_format text NOT NULL,
    sha256 text NOT NULL,
    size_bytes bigint,
    event_count bigint,
    exported_at text,
    imported_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.raw_log_files OWNER TO adlog_user;

--
-- Name: raw_log_files_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.raw_log_files_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.raw_log_files_id_seq OWNER TO adlog_user;

--
-- Name: raw_log_files_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.raw_log_files_id_seq OWNED BY public.raw_log_files.id;


--
-- Name: report_access_requests_v4; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.report_access_requests_v4 (
    id bigint NOT NULL,
    requester_user_id bigint NOT NULL,
    report_key text NOT NULL,
    report_version integer NOT NULL,
    dataset_version integer NOT NULL,
    requested_scope_json jsonb NOT NULL,
    requested_valid_until timestamp with time zone NOT NULL,
    business_reason text NOT NULL,
    requested_field_categories text[] NOT NULL,
    requested_actions text[] NOT NULL,
    status text DEFAULT 'submitted'::text NOT NULL,
    decision_reason text,
    granted_scope_json jsonb,
    granted_valid_until timestamp with time zone,
    granted_field_categories text[],
    granted_actions text[],
    assignment_id bigint,
    decided_by bigint,
    decided_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT report_access_requests_v4_dataset_version_check CHECK ((dataset_version > 0)),
    CONSTRAINT report_access_requests_v4_report_version_check CHECK ((report_version > 0)),
    CONSTRAINT report_access_requests_v4_status_check CHECK ((status = ANY (ARRAY['submitted'::text, 'reviewing'::text, 'approved'::text, 'approved_limited'::text, 'rejected'::text, 'expired'::text, 'system_cancelled'::text])))
);


ALTER TABLE public.report_access_requests_v4 OWNER TO adlog_user;

--
-- Name: report_access_requests_v4_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.report_access_requests_v4_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.report_access_requests_v4_id_seq OWNER TO adlog_user;

--
-- Name: report_access_requests_v4_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.report_access_requests_v4_id_seq OWNED BY public.report_access_requests_v4.id;


--
-- Name: report_datasets_v4; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.report_datasets_v4 (
    id bigint NOT NULL,
    dataset_key text NOT NULL,
    version integer NOT NULL,
    name text NOT NULL,
    object_type text,
    fields_json jsonb NOT NULL,
    filters_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    actions_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    status text DEFAULT 'published'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT report_datasets_v4_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'retired'::text]))),
    CONSTRAINT report_datasets_v4_version_check CHECK ((version > 0))
);


ALTER TABLE public.report_datasets_v4 OWNER TO adlog_user;

--
-- Name: report_datasets_v4_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.report_datasets_v4_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.report_datasets_v4_id_seq OWNER TO adlog_user;

--
-- Name: report_datasets_v4_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.report_datasets_v4_id_seq OWNED BY public.report_datasets_v4.id;


--
-- Name: report_items; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.report_items (
    id bigint NOT NULL,
    report_id bigint NOT NULL,
    detection_id bigint,
    ai_analysis_id bigint,
    sort_order integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.report_items OWNER TO adlog_user;

--
-- Name: report_items_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.report_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.report_items_id_seq OWNER TO adlog_user;

--
-- Name: report_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.report_items_id_seq OWNED BY public.report_items.id;


--
-- Name: report_registry_v4_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.report_registry_v4_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.report_registry_v4_id_seq OWNER TO adlog_user;

--
-- Name: report_registry_v4_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.report_registry_v4_id_seq OWNED BY public.report_registry_v4.id;


--
-- Name: reports; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.reports (
    id bigint NOT NULL,
    title text NOT NULL,
    report_type text NOT NULL,
    period_start_utc text,
    period_end_utc text,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    file_path text,
    status text DEFAULT 'draft'::text NOT NULL
);


ALTER TABLE public.reports OWNER TO adlog_user;

--
-- Name: reports_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.reports_id_seq OWNER TO adlog_user;

--
-- Name: reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.reports_id_seq OWNED BY public.reports.id;


--
-- Name: runtime_collection_blocks; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.runtime_collection_blocks (
    singleton_id smallint DEFAULT 1 NOT NULL,
    active boolean DEFAULT true NOT NULL,
    reason_code text NOT NULL,
    retry_policy text NOT NULL,
    operator_action text NOT NULL,
    source_worker_id text,
    source_job_id bigint,
    source_server text,
    evidence_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    observed_count bigint DEFAULT 1 NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_probe_at timestamp with time zone,
    last_probe_result text,
    cleared_at timestamp with time zone,
    cleared_by text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT runtime_collection_blocks_observed_count_check CHECK ((observed_count > 0)),
    CONSTRAINT runtime_collection_blocks_singleton_id_check CHECK ((singleton_id = 1))
);


ALTER TABLE public.runtime_collection_blocks OWNER TO adlog_user;

--
-- Name: runtime_collection_runs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.runtime_collection_runs (
    run_id text NOT NULL,
    worker_id text NOT NULL,
    job_id integer,
    status text NOT NULL,
    phase text NOT NULL,
    servers_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    hours integer NOT NULL,
    max_events_per_channel integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    duration_ms integer,
    errors_json jsonb,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.runtime_collection_runs OWNER TO postgres;

--
-- Name: runtime_worker_heartbeats; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.runtime_worker_heartbeats (
    worker_name text NOT NULL,
    worker_id text NOT NULL,
    process_pid integer NOT NULL,
    status text NOT NULL,
    phase text,
    expected_interval_seconds integer NOT NULL,
    details_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp with time zone NOT NULL,
    heartbeat_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT runtime_worker_heartbeats_expected_interval_seconds_check CHECK (((expected_interval_seconds >= 1) AND (expected_interval_seconds <= 86400))),
    CONSTRAINT runtime_worker_heartbeats_name CHECK ((worker_name = ANY (ARRAY['collection'::text, 'ad_context_snapshot'::text, 'ad_snapshot_manifest_coordinator'::text, 'computers_v5_snapshot'::text, 'computers_v6_snapshot'::text, 'computers_v6_source'::text, 'users_v2_snapshot'::text, 'storage_v2_outbox'::text, 'storage_lifecycle'::text, 'post_collection'::text, 'entity_state'::text, 'semantic'::text, 'what_where_when_projection'::text]))),
    CONSTRAINT runtime_worker_heartbeats_process_pid_check CHECK ((process_pid > 0))
);


ALTER TABLE public.runtime_worker_heartbeats OWNER TO adlog_user;

--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.schema_migrations (
    id bigint NOT NULL,
    version integer NOT NULL,
    name text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.schema_migrations OWNER TO adlog_user;

--
-- Name: schema_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.schema_migrations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.schema_migrations_id_seq OWNER TO adlog_user;

--
-- Name: schema_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.schema_migrations_id_seq OWNED BY public.schema_migrations.id;


--
-- Name: semantic_control_health_observations; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_control_health_observations (
    observation_id uuid NOT NULL,
    observation_key bytea NOT NULL,
    control_id text NOT NULL,
    partition_key text NOT NULL,
    coverage_status text NOT NULL,
    reason text NOT NULL,
    observed_at_utc timestamp with time zone NOT NULL,
    source_reference text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_control_health_observations_control_id_check CHECK (((length(control_id) >= 1) AND (length(control_id) <= 160))),
    CONSTRAINT semantic_control_health_observations_coverage_status_check CHECK ((coverage_status = ANY (ARRAY['complete'::text, 'partial'::text, 'unavailable'::text, 'unknown'::text]))),
    CONSTRAINT semantic_control_health_observations_observation_key_check CHECK ((octet_length(observation_key) = 32)),
    CONSTRAINT semantic_control_health_observations_partition_key_check CHECK (((length(partition_key) >= 1) AND (length(partition_key) <= 160))),
    CONSTRAINT semantic_control_health_observations_reason_check CHECK (((length(reason) >= 1) AND (length(reason) <= 2000))),
    CONSTRAINT semantic_control_health_observations_source_reference_check CHECK (((length(source_reference) >= 1) AND (length(source_reference) <= 320)))
);


ALTER TABLE public.semantic_control_health_observations OWNER TO adlog_storage_owner;

--
-- Name: semantic_correlation_candidate_evidence; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_correlation_candidate_evidence (
    candidate_id uuid NOT NULL,
    normalized_event_id uuid CONSTRAINT semantic_correlation_candidate_evi_normalized_event_id_not_null NOT NULL,
    evidence_order smallint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    is_late boolean DEFAULT false NOT NULL,
    CONSTRAINT semantic_correlation_candidate_evidence_evidence_order_check CHECK (((evidence_order >= 0) AND (evidence_order <= 32767)))
);


ALTER TABLE public.semantic_correlation_candidate_evidence OWNER TO adlog_storage_owner;

--
-- Name: semantic_correlation_candidates; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_correlation_candidates (
    candidate_id uuid NOT NULL,
    rule_id text NOT NULL,
    rule_version integer NOT NULL,
    relation_kind text NOT NULL,
    candidate_status text DEFAULT 'matched'::text NOT NULL,
    candidate_key bytea NOT NULL,
    partition_key text NOT NULL,
    window_start_utc timestamp with time zone NOT NULL,
    window_end_utc timestamp with time zone NOT NULL,
    confidence text NOT NULL,
    explanation text NOT NULL,
    evidence_count integer DEFAULT 0 NOT NULL,
    first_matched_at timestamp with time zone DEFAULT now() NOT NULL,
    last_matched_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    reopen_count integer DEFAULT 0 NOT NULL,
    late_evidence_count integer DEFAULT 0 NOT NULL,
    closed_at timestamp with time zone,
    last_evidence_occurred_at timestamp with time zone,
    CONSTRAINT semantic_correlation_candidate_reopen_counts CHECK (((reopen_count >= 0) AND (late_evidence_count >= 0))),
    CONSTRAINT semantic_correlation_candidate_window CHECK (((window_end_utc >= window_start_utc) AND (window_end_utc <= (window_start_utc + '24:00:00'::interval)))),
    CONSTRAINT semantic_correlation_candidates_candidate_key_check CHECK ((octet_length(candidate_key) = 32)),
    CONSTRAINT semantic_correlation_candidates_candidate_status_check CHECK ((candidate_status = ANY (ARRAY['open'::text, 'matched'::text, 'expired'::text, 'quarantined'::text]))),
    CONSTRAINT semantic_correlation_candidates_confidence_check CHECK ((confidence = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text]))),
    CONSTRAINT semantic_correlation_candidates_evidence_count_check CHECK ((evidence_count >= 0)),
    CONSTRAINT semantic_correlation_candidates_explanation_check CHECK (((length(explanation) >= 1) AND (length(explanation) <= 2000))),
    CONSTRAINT semantic_correlation_candidates_partition_key_check CHECK (((length(partition_key) >= 1) AND (length(partition_key) <= 512))),
    CONSTRAINT semantic_correlation_candidates_relation_kind_check CHECK (((length(relation_kind) >= 1) AND (length(relation_kind) <= 200)))
);


ALTER TABLE public.semantic_correlation_candidates OWNER TO adlog_storage_owner;

--
-- Name: semantic_correlation_dispatch_jobs; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_correlation_dispatch_jobs (
    job_id uuid NOT NULL,
    normalized_event_id uuid NOT NULL,
    rule_id text NOT NULL,
    rule_version integer NOT NULL,
    idempotency_key bytea NOT NULL,
    partition_key text NOT NULL,
    occurred_at_utc timestamp with time zone NOT NULL,
    is_late boolean DEFAULT false NOT NULL,
    dispatch_status text DEFAULT 'queued'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 5 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_token uuid,
    lease_until timestamp with time zone,
    heartbeat_at timestamp with time zone,
    last_error_code text,
    last_error_detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT semantic_correlation_dispatch_jobs_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT semantic_correlation_dispatch_jobs_dispatch_status_check CHECK ((dispatch_status = ANY (ARRAY['queued'::text, 'leased'::text, 'completed'::text, 'failed'::text, 'quarantined'::text]))),
    CONSTRAINT semantic_correlation_dispatch_jobs_idempotency_key_check CHECK ((octet_length(idempotency_key) = 32)),
    CONSTRAINT semantic_correlation_dispatch_jobs_max_attempts_check CHECK (((max_attempts >= 1) AND (max_attempts <= 20))),
    CONSTRAINT semantic_correlation_dispatch_jobs_partition_key_check CHECK (((length(partition_key) >= 1) AND (length(partition_key) <= 512))),
    CONSTRAINT semantic_correlation_dispatch_lease CHECK ((((dispatch_status = 'leased'::text) AND (lease_token IS NOT NULL) AND (lease_until IS NOT NULL)) OR ((dispatch_status <> 'leased'::text) AND (lease_token IS NULL) AND (lease_until IS NULL)))),
    CONSTRAINT semantic_correlation_dispatch_terminal CHECK ((((dispatch_status = 'completed'::text) AND (completed_at IS NOT NULL) AND (last_error_code IS NULL)) OR ((dispatch_status = ANY (ARRAY['failed'::text, 'quarantined'::text])) AND (last_error_code IS NOT NULL)) OR (dispatch_status = ANY (ARRAY['queued'::text, 'leased'::text]))))
);


ALTER TABLE public.semantic_correlation_dispatch_jobs OWNER TO adlog_storage_owner;

--
-- Name: semantic_correlation_replays; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_correlation_replays (
    replay_id uuid NOT NULL,
    rule_id text NOT NULL,
    rule_version integer NOT NULL,
    range_start_utc timestamp with time zone NOT NULL,
    range_end_utc timestamp with time zone NOT NULL,
    idempotency_key bytea NOT NULL,
    replay_status text DEFAULT 'queued'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 5 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_token uuid,
    lease_until timestamp with time zone,
    heartbeat_at timestamp with time zone,
    checkpoint_utc timestamp with time zone,
    processed_events bigint DEFAULT 0 NOT NULL,
    matched_candidates bigint DEFAULT 0 NOT NULL,
    last_error_code text,
    last_error_detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT semantic_correlation_replay_lease CHECK ((((replay_status = 'leased'::text) AND (lease_token IS NOT NULL) AND (lease_until IS NOT NULL)) OR ((replay_status <> 'leased'::text) AND (lease_token IS NULL) AND (lease_until IS NULL)))),
    CONSTRAINT semantic_correlation_replay_range CHECK (((range_end_utc > range_start_utc) AND (range_end_utc <= (range_start_utc + '7 days'::interval)))),
    CONSTRAINT semantic_correlation_replay_terminal CHECK ((((replay_status = 'completed'::text) AND (completed_at IS NOT NULL) AND (last_error_code IS NULL)) OR ((replay_status = ANY (ARRAY['failed'::text, 'quarantined'::text])) AND (last_error_code IS NOT NULL)) OR (replay_status = ANY (ARRAY['queued'::text, 'leased'::text])))),
    CONSTRAINT semantic_correlation_replays_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT semantic_correlation_replays_idempotency_key_check CHECK ((octet_length(idempotency_key) = 32)),
    CONSTRAINT semantic_correlation_replays_matched_candidates_check CHECK ((matched_candidates >= 0)),
    CONSTRAINT semantic_correlation_replays_max_attempts_check CHECK (((max_attempts >= 1) AND (max_attempts <= 20))),
    CONSTRAINT semantic_correlation_replays_processed_events_check CHECK ((processed_events >= 0)),
    CONSTRAINT semantic_correlation_replays_replay_status_check CHECK ((replay_status = ANY (ARRAY['queued'::text, 'leased'::text, 'completed'::text, 'failed'::text, 'quarantined'::text])))
);


ALTER TABLE public.semantic_correlation_replays OWNER TO adlog_storage_owner;

--
-- Name: semantic_correlation_rules; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_correlation_rules (
    rule_id text NOT NULL,
    rule_version integer NOT NULL,
    rule_kind text NOT NULL,
    lifecycle_status text DEFAULT 'draft'::text NOT NULL,
    definition_json jsonb NOT NULL,
    definition_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_correlation_rules_definition_json_check CHECK ((jsonb_typeof(definition_json) = 'object'::text)),
    CONSTRAINT semantic_correlation_rules_definition_sha256_check CHECK ((octet_length(definition_sha256) = 32)),
    CONSTRAINT semantic_correlation_rules_lifecycle_status_check CHECK ((lifecycle_status = ANY (ARRAY['draft'::text, 'validated'::text, 'test'::text, 'shadow'::text, 'enabled'::text, 'disabled'::text, 'deprecated'::text]))),
    CONSTRAINT semantic_correlation_rules_rule_id_check CHECK (((length(rule_id) >= 1) AND (length(rule_id) <= 160))),
    CONSTRAINT semantic_correlation_rules_rule_kind_check CHECK ((rule_kind = ANY (ARRAY['action'::text, 'sequence'::text, 'all_of'::text, 'any_of'::text, 'count'::text, 'distinct_count'::text, 'rate'::text, 'state_equals'::text, 'state_changed'::text, 'relationship_added'::text, 'relationship_removed'::text, 'graph_path_created'::text, 'graph_path_removed'::text, 'metric_threshold'::text, 'absence'::text, 'time_condition'::text, 'entity_classification'::text, 'count_then'::text]))),
    CONSTRAINT semantic_correlation_rules_rule_version_check CHECK ((rule_version > 0))
);


ALTER TABLE public.semantic_correlation_rules OWNER TO adlog_storage_owner;

--
-- Name: semantic_correlation_subscriptions; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_correlation_subscriptions (
    rule_id text NOT NULL,
    rule_version integer NOT NULL,
    semantic_type text NOT NULL,
    subscription_order smallint NOT NULL,
    definition_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_correlation_subscriptions_definition_sha256_check CHECK ((octet_length(definition_sha256) = 32)),
    CONSTRAINT semantic_correlation_subscriptions_semantic_type_check CHECK (((length(semantic_type) >= 1) AND (length(semantic_type) <= 160))),
    CONSTRAINT semantic_correlation_subscriptions_subscription_order_check CHECK (((subscription_order >= 0) AND (subscription_order <= 255)))
);


ALTER TABLE public.semantic_correlation_subscriptions OWNER TO adlog_storage_owner;

--
-- Name: semantic_finding_publications; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_finding_publications (
    scenario_id uuid NOT NULL,
    finding_id bigint NOT NULL,
    first_job_id uuid NOT NULL,
    finding_fingerprint text NOT NULL,
    published_evidence_count integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_finding_publications_finding_fingerprint_check CHECK ((finding_fingerprint ~ '^semantic:[0-9a-f]{64}$'::text)),
    CONSTRAINT semantic_finding_publications_published_evidence_count_check CHECK ((published_evidence_count > 0))
);


ALTER TABLE public.semantic_finding_publications OWNER TO adlog_storage_owner;

--
-- Name: semantic_processing_outbox; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_processing_outbox (
    job_id uuid NOT NULL,
    source_event_id bigint NOT NULL,
    job_kind text NOT NULL,
    semantic_contract_version integer NOT NULL,
    processor_id text NOT NULL,
    processor_version text NOT NULL,
    idempotency_key bytea NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 5 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_token uuid,
    lease_until timestamp with time zone,
    heartbeat_at timestamp with time zone,
    payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    last_error_code text,
    last_error_detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    source_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    partition_key text NOT NULL,
    occurred_at_utc timestamp with time zone NOT NULL,
    emitted_at timestamp with time zone DEFAULT now() NOT NULL,
    source_identity_json jsonb NOT NULL,
    CONSTRAINT semantic_processing_outbox_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT semantic_processing_outbox_idempotency_key_check CHECK ((octet_length(idempotency_key) = 32)),
    CONSTRAINT semantic_processing_outbox_job_kind_check CHECK ((job_kind = ANY (ARRAY['normalize_event'::text, 'assemble_action'::text, 'semantic_replay'::text, 'investigation_context'::text, 'semantic_repair'::text, 'semantic_v2_quarantine_repair'::text]))),
    CONSTRAINT semantic_processing_outbox_lease CHECK ((((status = 'leased'::text) AND (lease_token IS NOT NULL) AND (lease_until IS NOT NULL)) OR ((status <> 'leased'::text) AND (lease_token IS NULL) AND (lease_until IS NULL)))),
    CONSTRAINT semantic_processing_outbox_max_attempts_check CHECK (((max_attempts >= 1) AND (max_attempts <= 20))),
    CONSTRAINT semantic_processing_outbox_partition_bounded CHECK (((length(partition_key) >= 1) AND (length(partition_key) <= 160))),
    CONSTRAINT semantic_processing_outbox_payload_json_check CHECK ((jsonb_typeof(payload_json) = 'object'::text)),
    CONSTRAINT semantic_processing_outbox_processor_id_check CHECK (((length(processor_id) >= 1) AND (length(processor_id) <= 160))),
    CONSTRAINT semantic_processing_outbox_processor_version_check CHECK (((length(processor_version) >= 1) AND (length(processor_version) <= 80))),
    CONSTRAINT semantic_processing_outbox_semantic_contract_version_check CHECK ((semantic_contract_version > 0)),
    CONSTRAINT semantic_processing_outbox_source_identity_v2 CHECK (((jsonb_typeof(source_identity_json) = 'object'::text) AND (octet_length((source_identity_json)::text) <= 4096) AND (source_identity_json ?& ARRAY['id'::text, 'server_id'::text, 'domain_id'::text, 'log_source_id'::text, 'event_id'::text, 'time_created_utc'::text, 'normalized_hash'::text, 'migrated_at'::text, 'channel'::text]) AND ((source_identity_json ->> 'normalized_hash'::text) ~ '^[0-9a-f]{64}$'::text) AND (NOT (source_identity_json ?| ARRAY['raw_xml'::text, 'event_data'::text, 'event_data_json'::text])))),
    CONSTRAINT semantic_processing_outbox_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'leased'::text, 'completed'::text, 'failed'::text, 'quarantined'::text]))),
    CONSTRAINT semantic_processing_outbox_terminal CHECK ((((status = 'completed'::text) AND (completed_at IS NOT NULL) AND (last_error_code IS NULL)) OR ((status = ANY (ARRAY['failed'::text, 'quarantined'::text])) AND (last_error_code IS NOT NULL)) OR (status = ANY (ARRAY['queued'::text, 'leased'::text]))))
);


ALTER TABLE public.semantic_processing_outbox OWNER TO adlog_storage_owner;

--
-- Name: semantic_risk_contributions; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_risk_contributions (
    contribution_id uuid NOT NULL,
    scenario_id uuid NOT NULL,
    contribution_key bytea NOT NULL,
    source_kind text NOT NULL,
    canonical_action_id uuid,
    correlation_candidate_id uuid,
    control_reference text,
    policy_id text NOT NULL,
    policy_version integer NOT NULL,
    policy_sha256 bytea NOT NULL,
    risk_class text NOT NULL,
    raw_score numeric(14,4) NOT NULL,
    display_points smallint NOT NULL,
    hard_critical boolean DEFAULT false NOT NULL,
    rationale text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_risk_contribution_hard_critical CHECK (((NOT hard_critical) OR (risk_class = 'critical'::text))),
    CONSTRAINT semantic_risk_contribution_source CHECK ((((source_kind = 'canonical_action'::text) AND (canonical_action_id IS NOT NULL) AND (correlation_candidate_id IS NULL) AND (control_reference IS NULL)) OR ((source_kind = 'correlation_candidate'::text) AND (correlation_candidate_id IS NOT NULL) AND (canonical_action_id IS NULL) AND (control_reference IS NULL)) OR ((source_kind = 'control_health'::text) AND (control_reference IS NOT NULL) AND ((length(control_reference) >= 1) AND (length(control_reference) <= 160)) AND (canonical_action_id IS NULL) AND (correlation_candidate_id IS NULL)))),
    CONSTRAINT semantic_risk_contributions_contribution_key_check CHECK ((octet_length(contribution_key) = 32)),
    CONSTRAINT semantic_risk_contributions_display_points_check CHECK (((display_points >= 0) AND (display_points <= 100))),
    CONSTRAINT semantic_risk_contributions_policy_id_check CHECK (((length(policy_id) >= 1) AND (length(policy_id) <= 160))),
    CONSTRAINT semantic_risk_contributions_policy_sha256_check CHECK ((octet_length(policy_sha256) = 32)),
    CONSTRAINT semantic_risk_contributions_policy_version_check CHECK ((policy_version > 0)),
    CONSTRAINT semantic_risk_contributions_rationale_check CHECK (((length(rationale) >= 1) AND (length(rationale) <= 2000))),
    CONSTRAINT semantic_risk_contributions_raw_score_check CHECK (((raw_score >= (0)::numeric) AND (raw_score <= (100000)::numeric))),
    CONSTRAINT semantic_risk_contributions_risk_class_check CHECK ((risk_class = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text]))),
    CONSTRAINT semantic_risk_contributions_source_kind_check CHECK ((source_kind = ANY (ARRAY['canonical_action'::text, 'correlation_candidate'::text, 'control_health'::text])))
);


ALTER TABLE public.semantic_risk_contributions OWNER TO adlog_storage_owner;

--
-- Name: semantic_risk_evaluation_jobs; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_risk_evaluation_jobs (
    job_id uuid NOT NULL,
    policy_id text NOT NULL,
    policy_version integer NOT NULL,
    source_kind text NOT NULL,
    correlation_candidate_id uuid,
    control_health_id uuid,
    source_reference text NOT NULL,
    evaluation_mode text NOT NULL,
    idempotency_key bytea NOT NULL,
    evaluation_status text DEFAULT 'queued'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 5 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_token uuid,
    lease_until timestamp with time zone,
    heartbeat_at timestamp with time zone,
    last_error_code text,
    last_error_detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    canonical_action_id uuid,
    CONSTRAINT semantic_risk_evaluation_jobs_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT semantic_risk_evaluation_jobs_evaluation_mode_check CHECK ((evaluation_mode = ANY (ARRAY['test'::text, 'shadow'::text, 'enabled'::text]))),
    CONSTRAINT semantic_risk_evaluation_jobs_evaluation_status_check CHECK ((evaluation_status = ANY (ARRAY['queued'::text, 'leased'::text, 'completed'::text, 'failed'::text, 'quarantined'::text]))),
    CONSTRAINT semantic_risk_evaluation_jobs_idempotency_key_check CHECK ((octet_length(idempotency_key) = 32)),
    CONSTRAINT semantic_risk_evaluation_jobs_max_attempts_check CHECK (((max_attempts >= 1) AND (max_attempts <= 20))),
    CONSTRAINT semantic_risk_evaluation_jobs_source_kind_check CHECK ((source_kind = ANY (ARRAY['canonical_action'::text, 'correlation_candidate'::text, 'control_health'::text]))),
    CONSTRAINT semantic_risk_evaluation_jobs_source_reference_check CHECK (((length(source_reference) >= 1) AND (length(source_reference) <= 320))),
    CONSTRAINT semantic_risk_evaluation_lease CHECK ((((evaluation_status = 'leased'::text) AND (lease_token IS NOT NULL) AND (lease_until IS NOT NULL)) OR ((evaluation_status <> 'leased'::text) AND (lease_token IS NULL) AND (lease_until IS NULL)))),
    CONSTRAINT semantic_risk_evaluation_source CHECK ((((source_kind = 'canonical_action'::text) AND (canonical_action_id IS NOT NULL) AND (correlation_candidate_id IS NULL) AND (control_health_id IS NULL) AND (source_reference = (canonical_action_id)::text)) OR ((source_kind = 'correlation_candidate'::text) AND (canonical_action_id IS NULL) AND (correlation_candidate_id IS NOT NULL) AND (control_health_id IS NULL) AND (source_reference = (correlation_candidate_id)::text)) OR ((source_kind = 'control_health'::text) AND (canonical_action_id IS NULL) AND (correlation_candidate_id IS NULL) AND (control_health_id IS NOT NULL) AND (source_reference = (control_health_id)::text)))),
    CONSTRAINT semantic_risk_evaluation_terminal CHECK ((((evaluation_status = 'completed'::text) AND (completed_at IS NOT NULL) AND (last_error_code IS NULL)) OR ((evaluation_status = ANY (ARRAY['failed'::text, 'quarantined'::text])) AND (last_error_code IS NOT NULL)) OR (evaluation_status = ANY (ARRAY['queued'::text, 'leased'::text]))))
);


ALTER TABLE public.semantic_risk_evaluation_jobs OWNER TO adlog_storage_owner;

--
-- Name: semantic_risk_evaluation_results; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_risk_evaluation_results (
    job_id uuid NOT NULL,
    scenario_id uuid,
    evaluation_mode text NOT NULL,
    risk_class text NOT NULL,
    raw_score numeric(14,4) NOT NULL,
    display_score smallint NOT NULL,
    hard_critical boolean NOT NULL,
    confidence text NOT NULL,
    confidence_score smallint NOT NULL,
    coverage_status text NOT NULL,
    evaluation_ms integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    conclusion_state text DEFAULT 'not_checked'::text NOT NULL,
    completeness_snapshot_json jsonb DEFAULT '{"legacy_missing": true, "window_closure": {"closed": false, "window_end_utc": null, "close_deadline_utc": null, "allowed_lateness_seconds": 0, "descriptor_close_timeout_seconds": null}, "captured_at_utc": null, "catalog_completeness": {"entry_count": 0, "schema_v2_ready": 0, "fully_classified": 0, "classification_ratio": 0}, "channel_availability": {"complete": false, "required": [], "available": [], "required_count": 0, "available_count": 0}, "collection_freshness": {"complete": false, "budget_seconds": 1800, "max_age_seconds": null}, "supports_negative_conclusion": false}'::jsonb CONSTRAINT semantic_risk_evaluation_re_completeness_snapshot_json_not_null NOT NULL,
    CONSTRAINT semantic_risk_evaluation_results_confidence_check CHECK ((confidence = ANY (ARRAY['high'::text, 'medium'::text, 'low'::text, 'unknown'::text]))),
    CONSTRAINT semantic_risk_evaluation_results_confidence_score_check CHECK (((confidence_score >= 0) AND (confidence_score <= 100))),
    CONSTRAINT semantic_risk_evaluation_results_coverage_status_check CHECK ((coverage_status = ANY (ARRAY['complete'::text, 'partial'::text, 'unavailable'::text, 'unknown'::text]))),
    CONSTRAINT semantic_risk_evaluation_results_display_score_check CHECK (((display_score >= 0) AND (display_score <= 100))),
    CONSTRAINT semantic_risk_evaluation_results_evaluation_mode_check CHECK ((evaluation_mode = ANY (ARRAY['test'::text, 'shadow'::text, 'enabled'::text]))),
    CONSTRAINT semantic_risk_evaluation_results_evaluation_ms_check CHECK ((evaluation_ms >= 0)),
    CONSTRAINT semantic_risk_evaluation_results_raw_score_check CHECK (((raw_score >= (0)::numeric) AND (raw_score <= (100000)::numeric))),
    CONSTRAINT semantic_risk_evaluation_results_risk_class_check CHECK ((risk_class = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text]))),
    CONSTRAINT semantic_risk_result_completeness_shape CHECK (((jsonb_typeof(completeness_snapshot_json) = 'object'::text) AND (completeness_snapshot_json ? 'catalog_completeness'::text) AND (completeness_snapshot_json ? 'collection_freshness'::text) AND (completeness_snapshot_json ? 'channel_availability'::text) AND (completeness_snapshot_json ? 'window_closure'::text) AND (completeness_snapshot_json ? 'supports_negative_conclusion'::text))),
    CONSTRAINT semantic_risk_result_conclusion_state CHECK ((conclusion_state = ANY (ARRAY['observed'::text, 'not_found'::text, 'not_checked'::text]))),
    CONSTRAINT semantic_risk_result_hard_critical CHECK (((NOT hard_critical) OR (risk_class = 'critical'::text))),
    CONSTRAINT semantic_risk_result_mode CHECK (((evaluation_mode <> 'test'::text) OR (scenario_id IS NULL))),
    CONSTRAINT semantic_risk_result_negative_gate CHECK (((conclusion_state <> 'not_found'::text) OR ((completeness_snapshot_json ->> 'supports_negative_conclusion'::text) = 'true'::text)))
);


ALTER TABLE public.semantic_risk_evaluation_results OWNER TO adlog_storage_owner;

--
-- Name: semantic_risk_policies; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_risk_policies (
    policy_id text NOT NULL,
    policy_version integer NOT NULL,
    source_kind text NOT NULL,
    lifecycle_status text DEFAULT 'draft'::text NOT NULL,
    definition_json jsonb NOT NULL,
    definition_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_risk_policies_definition_json_check CHECK ((jsonb_typeof(definition_json) = 'object'::text)),
    CONSTRAINT semantic_risk_policies_definition_sha256_check CHECK ((octet_length(definition_sha256) = 32)),
    CONSTRAINT semantic_risk_policies_lifecycle_status_check CHECK ((lifecycle_status = ANY (ARRAY['draft'::text, 'validated'::text, 'test'::text, 'shadow'::text, 'enabled'::text, 'disabled'::text, 'deprecated'::text]))),
    CONSTRAINT semantic_risk_policies_policy_id_check CHECK (((length(policy_id) >= 1) AND (length(policy_id) <= 160))),
    CONSTRAINT semantic_risk_policies_policy_version_check CHECK ((policy_version > 0)),
    CONSTRAINT semantic_risk_policies_source_kind_check CHECK ((source_kind = ANY (ARRAY['canonical_action'::text, 'correlation_candidate'::text, 'control_health'::text])))
);


ALTER TABLE public.semantic_risk_policies OWNER TO adlog_storage_owner;

--
-- Name: semantic_risk_policy_subscriptions; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_risk_policy_subscriptions (
    policy_id text NOT NULL,
    policy_version integer NOT NULL,
    source_kind text NOT NULL,
    selector_value text NOT NULL,
    definition_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_risk_policy_subscriptions_definition_sha256_check CHECK ((octet_length(definition_sha256) = 32)),
    CONSTRAINT semantic_risk_policy_subscriptions_selector_value_check CHECK (((length(selector_value) >= 1) AND (length(selector_value) <= 200))),
    CONSTRAINT semantic_risk_policy_subscriptions_source_kind_check CHECK ((source_kind = ANY (ARRAY['canonical_action'::text, 'correlation_candidate'::text, 'control_health'::text])))
);


ALTER TABLE public.semantic_risk_policy_subscriptions OWNER TO adlog_storage_owner;

--
-- Name: semantic_scenario_coverage_history; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_scenario_coverage_history (
    coverage_id uuid NOT NULL,
    scenario_id uuid NOT NULL,
    assessment_key bytea NOT NULL,
    control_id text NOT NULL,
    coverage_status text NOT NULL,
    reason text NOT NULL,
    observed_at_utc timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_scenario_coverage_history_assessment_key_check CHECK ((octet_length(assessment_key) = 32)),
    CONSTRAINT semantic_scenario_coverage_history_control_id_check CHECK (((length(control_id) >= 1) AND (length(control_id) <= 160))),
    CONSTRAINT semantic_scenario_coverage_history_coverage_status_check CHECK ((coverage_status = ANY (ARRAY['complete'::text, 'partial'::text, 'unavailable'::text, 'unknown'::text]))),
    CONSTRAINT semantic_scenario_coverage_history_reason_check CHECK (((length(reason) >= 1) AND (length(reason) <= 2000)))
);


ALTER TABLE public.semantic_scenario_coverage_history OWNER TO adlog_storage_owner;

--
-- Name: semantic_scenario_evidence; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_scenario_evidence (
    scenario_id uuid NOT NULL,
    normalized_event_id uuid NOT NULL,
    evidence_order smallint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_scenario_evidence_evidence_order_check CHECK (((evidence_order >= 0) AND (evidence_order <= 32767)))
);


ALTER TABLE public.semantic_scenario_evidence OWNER TO adlog_storage_owner;

--
-- Name: semantic_scenario_reviews; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_scenario_reviews (
    review_id uuid NOT NULL,
    review_request_id uuid NOT NULL,
    scenario_id uuid NOT NULL,
    supersedes_review_id uuid,
    verdict text NOT NULL,
    review_confidence text NOT NULL,
    rationale text NOT NULL,
    scenario_snapshot_sha256 bytea NOT NULL,
    reviewed_by text NOT NULL,
    reviewer_role text NOT NULL,
    reviewed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_scenario_review_not_self_superseding CHECK (((supersedes_review_id IS NULL) OR (supersedes_review_id <> review_id))),
    CONSTRAINT semantic_scenario_reviews_rationale_check CHECK (((length(rationale) >= 5) AND (length(rationale) <= 2000))),
    CONSTRAINT semantic_scenario_reviews_review_confidence_check CHECK ((review_confidence = ANY (ARRAY['high'::text, 'medium'::text, 'low'::text]))),
    CONSTRAINT semantic_scenario_reviews_reviewed_by_check CHECK (((length(reviewed_by) >= 1) AND (length(reviewed_by) <= 160))),
    CONSTRAINT semantic_scenario_reviews_reviewer_role_check CHECK ((reviewer_role = ANY (ARRAY['viewer'::text, 'operator'::text, 'admin'::text]))),
    CONSTRAINT semantic_scenario_reviews_scenario_snapshot_sha256_check CHECK ((octet_length(scenario_snapshot_sha256) = 32)),
    CONSTRAINT semantic_scenario_reviews_verdict_check CHECK ((verdict = ANY (ARRAY['confirmed_security'::text, 'false_positive'::text, 'benign_expected'::text, 'insufficient_evidence'::text])))
);


ALTER TABLE public.semantic_scenario_reviews OWNER TO adlog_storage_owner;

--
-- Name: semantic_scenario_steps; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_scenario_steps (
    step_id uuid NOT NULL,
    scenario_id uuid NOT NULL,
    step_key bytea NOT NULL,
    source_kind text NOT NULL,
    canonical_action_id uuid,
    correlation_candidate_id uuid,
    control_reference text,
    occurred_at_utc timestamp with time zone NOT NULL,
    title text NOT NULL,
    explanation text NOT NULL,
    confidence text NOT NULL,
    confidence_score smallint NOT NULL,
    confidence_factors_json jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_scenario_step_source CHECK ((((source_kind = 'canonical_action'::text) AND (canonical_action_id IS NOT NULL) AND (correlation_candidate_id IS NULL) AND (control_reference IS NULL)) OR ((source_kind = 'correlation_candidate'::text) AND (correlation_candidate_id IS NOT NULL) AND (canonical_action_id IS NULL) AND (control_reference IS NULL)) OR ((source_kind = 'control_health'::text) AND (control_reference IS NOT NULL) AND ((length(control_reference) >= 1) AND (length(control_reference) <= 160)) AND (canonical_action_id IS NULL) AND (correlation_candidate_id IS NULL)))),
    CONSTRAINT semantic_scenario_steps_confidence_check CHECK ((confidence = ANY (ARRAY['high'::text, 'medium'::text, 'low'::text, 'unknown'::text]))),
    CONSTRAINT semantic_scenario_steps_confidence_factors_json_check CHECK ((jsonb_typeof(confidence_factors_json) = 'object'::text)),
    CONSTRAINT semantic_scenario_steps_confidence_score_check CHECK (((confidence_score >= 0) AND (confidence_score <= 100))),
    CONSTRAINT semantic_scenario_steps_explanation_check CHECK (((length(explanation) >= 1) AND (length(explanation) <= 2000))),
    CONSTRAINT semantic_scenario_steps_source_kind_check CHECK ((source_kind = ANY (ARRAY['canonical_action'::text, 'correlation_candidate'::text, 'control_health'::text]))),
    CONSTRAINT semantic_scenario_steps_step_key_check CHECK ((octet_length(step_key) = 32)),
    CONSTRAINT semantic_scenario_steps_title_check CHECK (((length(title) >= 1) AND (length(title) <= 300)))
);


ALTER TABLE public.semantic_scenario_steps OWNER TO adlog_storage_owner;

--
-- Name: semantic_security_scenarios; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.semantic_security_scenarios (
    scenario_id uuid NOT NULL,
    scenario_kind text NOT NULL,
    result_class text NOT NULL,
    scenario_status text DEFAULT 'open'::text NOT NULL,
    identity_key bytea NOT NULL,
    scenario_key bytea NOT NULL,
    partition_key text NOT NULL,
    strict_keys_json jsonb NOT NULL,
    merge_window_seconds integer NOT NULL,
    title text NOT NULL,
    explanation text NOT NULL,
    first_seen_utc timestamp with time zone NOT NULL,
    last_seen_utc timestamp with time zone NOT NULL,
    risk_class text NOT NULL,
    raw_score numeric(14,4) DEFAULT 0 NOT NULL,
    display_score smallint DEFAULT 0 NOT NULL,
    hard_critical boolean DEFAULT false NOT NULL,
    confidence text DEFAULT 'unknown'::text NOT NULL,
    confidence_score smallint DEFAULT 0 NOT NULL,
    confidence_factors_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    coverage_status text DEFAULT 'unknown'::text NOT NULL,
    step_count integer DEFAULT 0 NOT NULL,
    evidence_count integer DEFAULT 0 NOT NULL,
    contribution_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_scenario_hard_critical CHECK (((NOT hard_critical) OR (risk_class = 'critical'::text))),
    CONSTRAINT semantic_scenario_time_window CHECK (((last_seen_utc >= first_seen_utc) AND (last_seen_utc <= (first_seen_utc + '24:00:00'::interval)))),
    CONSTRAINT semantic_security_scenarios_confidence_check CHECK ((confidence = ANY (ARRAY['high'::text, 'medium'::text, 'low'::text, 'unknown'::text]))),
    CONSTRAINT semantic_security_scenarios_confidence_factors_json_check CHECK ((jsonb_typeof(confidence_factors_json) = 'object'::text)),
    CONSTRAINT semantic_security_scenarios_confidence_score_check CHECK (((confidence_score >= 0) AND (confidence_score <= 100))),
    CONSTRAINT semantic_security_scenarios_contribution_count_check CHECK ((contribution_count >= 0)),
    CONSTRAINT semantic_security_scenarios_coverage_status_check CHECK ((coverage_status = ANY (ARRAY['complete'::text, 'partial'::text, 'unavailable'::text, 'unknown'::text]))),
    CONSTRAINT semantic_security_scenarios_display_score_check CHECK (((display_score >= 0) AND (display_score <= 100))),
    CONSTRAINT semantic_security_scenarios_evidence_count_check CHECK ((evidence_count >= 0)),
    CONSTRAINT semantic_security_scenarios_explanation_check CHECK (((length(explanation) >= 1) AND (length(explanation) <= 2000))),
    CONSTRAINT semantic_security_scenarios_identity_key_check CHECK ((octet_length(identity_key) = 32)),
    CONSTRAINT semantic_security_scenarios_merge_window_seconds_check CHECK (((merge_window_seconds >= 1) AND (merge_window_seconds <= 86400))),
    CONSTRAINT semantic_security_scenarios_partition_key_check CHECK (((length(partition_key) >= 1) AND (length(partition_key) <= 160))),
    CONSTRAINT semantic_security_scenarios_raw_score_check CHECK (((raw_score >= (0)::numeric) AND (raw_score <= (100000)::numeric))),
    CONSTRAINT semantic_security_scenarios_result_class_check CHECK ((result_class = ANY (ARRAY['security_incident'::text, 'security_exposure'::text, 'control_gap'::text]))),
    CONSTRAINT semantic_security_scenarios_risk_class_check CHECK ((risk_class = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text, 'unknown'::text]))),
    CONSTRAINT semantic_security_scenarios_scenario_key_check CHECK ((octet_length(scenario_key) = 32)),
    CONSTRAINT semantic_security_scenarios_scenario_kind_check CHECK (((length(scenario_kind) >= 1) AND (length(scenario_kind) <= 200))),
    CONSTRAINT semantic_security_scenarios_scenario_status_check CHECK ((scenario_status = ANY (ARRAY['open'::text, 'under_review'::text, 'resolved'::text, 'dismissed'::text]))),
    CONSTRAINT semantic_security_scenarios_step_count_check CHECK ((step_count >= 0)),
    CONSTRAINT semantic_security_scenarios_strict_keys_json_check CHECK ((jsonb_typeof(strict_keys_json) = 'object'::text)),
    CONSTRAINT semantic_security_scenarios_title_check CHECK (((length(title) >= 1) AND (length(title) <= 300)))
);


ALTER TABLE public.semantic_security_scenarios OWNER TO adlog_storage_owner;

--
-- Name: servers; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.servers (
    id bigint NOT NULL,
    domain_id bigint NOT NULL,
    site_id bigint,
    hostname text NOT NULL,
    fqdn text,
    role text DEFAULT 'unknown'::text NOT NULL,
    os_name text,
    os_version text,
    os_language text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.servers OWNER TO adlog_user;

--
-- Name: servers_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.servers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.servers_id_seq OWNER TO adlog_user;

--
-- Name: servers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.servers_id_seq OWNED BY public.servers.id;


--
-- Name: sites; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.sites (
    id bigint NOT NULL,
    domain_id bigint NOT NULL,
    name text NOT NULL,
    site_type text DEFAULT 'unknown'::text NOT NULL,
    location text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.sites OWNER TO adlog_user;

--
-- Name: sites_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.sites_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.sites_id_seq OWNER TO adlog_user;

--
-- Name: sites_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.sites_id_seq OWNED BY public.sites.id;


--
-- Name: source_capture_continuity_declarations; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.source_capture_continuity_declarations (
    id bigint NOT NULL,
    collection_run_id bigint CONSTRAINT source_capture_continuity_declaratio_collection_run_id_not_null NOT NULL,
    raw_log_file_id bigint NOT NULL,
    raw_log_sha256 text NOT NULL,
    server_id bigint NOT NULL,
    log_source_id bigint NOT NULL,
    scope_identity text NOT NULL,
    descriptor_source text CONSTRAINT source_capture_continuity_declaratio_descriptor_source_not_null NOT NULL,
    descriptor_stream text CONSTRAINT source_capture_continuity_declaratio_descriptor_stream_not_null NOT NULL,
    provider_name text NOT NULL,
    channel_value text NOT NULL,
    channel_generation_identity text CONSTRAINT source_capture_continuity_d_channel_generation_identit_not_null NOT NULL,
    selector_event_ids jsonb CONSTRAINT source_capture_continuity_declarati_selector_event_ids_not_null NOT NULL,
    query_exhausted boolean NOT NULL,
    capture_after_record_id bigint CONSTRAINT source_capture_continuity_decl_capture_after_record_id_not_null NOT NULL,
    capture_latest_record_id bigint CONSTRAINT source_capture_continuity_dec_capture_latest_record_id_not_null NOT NULL,
    first_event_record_id bigint CONSTRAINT source_capture_continuity_declar_first_event_record_id_not_null NOT NULL,
    last_event_record_id bigint CONSTRAINT source_capture_continuity_declara_last_event_record_id_not_null NOT NULL,
    completeness text DEFAULT 'complete'::text NOT NULL,
    covered_source_events jsonb CONSTRAINT source_capture_continuity_declar_covered_source_events_not_null NOT NULL,
    declaration_sha256 text CONSTRAINT source_capture_continuity_declarati_declaration_sha256_not_null NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT source_capture_continuity_capture_range CHECK (((capture_after_record_id >= 0) AND (capture_latest_record_id > capture_after_record_id) AND (first_event_record_id = (capture_after_record_id + 1)) AND (last_event_record_id = capture_latest_record_id))),
    CONSTRAINT source_capture_continuity_completeness CHECK ((completeness = 'complete'::text)),
    CONSTRAINT source_capture_continuity_covered_events CHECK ((jsonb_typeof(covered_source_events) = 'array'::text)),
    CONSTRAINT source_capture_continuity_descriptor_bounded CHECK (((length(descriptor_source) >= 1) AND (length(descriptor_source) <= 128) AND ((length(descriptor_stream) >= 1) AND (length(descriptor_stream) <= 128)) AND ((length(provider_name) >= 1) AND (length(provider_name) <= 512)) AND ((length(channel_value) >= 1) AND (length(channel_value) <= 512)))),
    CONSTRAINT source_capture_continuity_digest CHECK ((declaration_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT source_capture_continuity_query_exhausted CHECK ((query_exhausted IS TRUE)),
    CONSTRAINT source_capture_continuity_raw_digest CHECK ((raw_log_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT source_capture_continuity_scope_bounded CHECK (((length(scope_identity) >= 1) AND (length(scope_identity) <= 512))),
    CONSTRAINT source_capture_continuity_selector CHECK (((jsonb_typeof(selector_event_ids) = 'array'::text) AND (jsonb_array_length(selector_event_ids) > 0)))
);


ALTER TABLE public.source_capture_continuity_declarations OWNER TO adlog_storage_owner;

--
-- Name: source_capture_continuity_declarations_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

CREATE SEQUENCE public.source_capture_continuity_declarations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.source_capture_continuity_declarations_id_seq OWNER TO adlog_storage_owner;

--
-- Name: source_capture_continuity_declarations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_storage_owner
--

ALTER SEQUENCE public.source_capture_continuity_declarations_id_seq OWNED BY public.source_capture_continuity_declarations.id;


--
-- Name: storage_lifecycle_snapshots; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.storage_lifecycle_snapshots (
    id bigint NOT NULL,
    captured_at timestamp with time zone DEFAULT now() NOT NULL,
    source text NOT NULL,
    source_job_id bigint,
    source_run_id text,
    database_bytes bigint DEFAULT 0 NOT NULL,
    events_estimated_rows bigint DEFAULT 0 NOT NULL,
    events_max_id bigint DEFAULT 0 NOT NULL,
    events_last_24h bigint DEFAULT 0 NOT NULL,
    raw_bytes bigint DEFAULT 0 NOT NULL,
    raw_archive_bytes bigint DEFAULT 0 NOT NULL,
    backups_bytes bigint DEFAULT 0 NOT NULL,
    logs_bytes bigint DEFAULT 0 NOT NULL,
    reports_bytes bigint DEFAULT 0 NOT NULL,
    artifacts_bytes bigint DEFAULT 0 NOT NULL,
    disk_total_bytes bigint DEFAULT 0 NOT NULL,
    disk_used_bytes bigint DEFAULT 0 NOT NULL,
    disk_free_bytes bigint DEFAULT 0 NOT NULL,
    disk_free_percent numeric(7,3) DEFAULT 0 NOT NULL,
    table_stats_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    scan_meta_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.storage_lifecycle_snapshots OWNER TO adlog_user;

--
-- Name: storage_lifecycle_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_user
--

CREATE SEQUENCE public.storage_lifecycle_snapshots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.storage_lifecycle_snapshots_id_seq OWNER TO adlog_user;

--
-- Name: storage_lifecycle_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_user
--

ALTER SEQUENCE public.storage_lifecycle_snapshots_id_seq OWNED BY public.storage_lifecycle_snapshots.id;


--
-- Name: storage_v2_archive_blocks; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_archive_blocks (
    archive_set_id uuid NOT NULL,
    archive_kind text NOT NULL,
    format_version integer NOT NULL,
    block_index integer NOT NULL,
    first_event_id bigint NOT NULL,
    last_event_id bigint NOT NULL,
    row_count integer NOT NULL,
    raw_bytes bigint NOT NULL,
    compressed_bytes bigint NOT NULL,
    raw_sha256 bytea NOT NULL,
    archive_sha256 bytea NOT NULL,
    object_location text NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    published_at timestamp with time zone,
    quarantine_reason text,
    CONSTRAINT storage_v2_archive_blocks_archive_kind_check CHECK ((archive_kind = ANY (ARRAY['event'::text, 'link_detail'::text, 'entity_detail'::text]))),
    CONSTRAINT storage_v2_archive_blocks_archive_sha256_check CHECK ((octet_length(archive_sha256) = 32)),
    CONSTRAINT storage_v2_archive_blocks_block_index_check CHECK ((block_index >= 0)),
    CONSTRAINT storage_v2_archive_blocks_compressed_bytes_check CHECK ((compressed_bytes >= 0)),
    CONSTRAINT storage_v2_archive_blocks_format_version_check CHECK ((format_version > 0)),
    CONSTRAINT storage_v2_archive_blocks_range CHECK ((first_event_id <= last_event_id)),
    CONSTRAINT storage_v2_archive_blocks_raw_bytes_check CHECK ((raw_bytes >= 0)),
    CONSTRAINT storage_v2_archive_blocks_raw_sha256_check CHECK ((octet_length(raw_sha256) = 32)),
    CONSTRAINT storage_v2_archive_blocks_row_count_check CHECK ((row_count >= 0)),
    CONSTRAINT storage_v2_archive_blocks_state_check CHECK ((state = ANY (ARRAY['staging'::text, 'verified'::text, 'published'::text, 'quarantined'::text])))
);


ALTER TABLE public.storage_v2_archive_blocks OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_archive_sets; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_archive_sets (
    archive_set_id uuid NOT NULL,
    archive_kind text NOT NULL,
    format_version integer NOT NULL,
    source_min_event_id bigint NOT NULL,
    source_max_event_id bigint NOT NULL,
    expected_rows bigint NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    published_at timestamp with time zone,
    CONSTRAINT storage_v2_archive_sets_archive_kind_check CHECK ((archive_kind = ANY (ARRAY['event'::text, 'link_detail'::text, 'entity_detail'::text]))),
    CONSTRAINT storage_v2_archive_sets_expected_rows_check CHECK ((expected_rows >= 0)),
    CONSTRAINT storage_v2_archive_sets_format_version_check CHECK ((format_version > 0)),
    CONSTRAINT storage_v2_archive_sets_range CHECK ((source_min_event_id <= source_max_event_id)),
    CONSTRAINT storage_v2_archive_sets_state_check CHECK ((state = ANY (ARRAY['staging'::text, 'verified'::text, 'published'::text, 'quarantined'::text])))
);


ALTER TABLE public.storage_v2_archive_sets OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_backfill_checkpoints; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_backfill_checkpoints (
    worker_name text NOT NULL,
    high_watermark_event_id bigint,
    last_verified_event_id bigint DEFAULT 0 NOT NULL,
    chunk_size integer DEFAULT 25000 NOT NULL,
    state text DEFAULT 'ready'::text NOT NULL,
    lease_token uuid,
    lease_until timestamp with time zone,
    source_rows bigint DEFAULT 0 NOT NULL,
    target_rows bigint DEFAULT 0 NOT NULL,
    source_sha256 bytea,
    target_sha256 bytea,
    last_error text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT storage_v2_backfill_checkpoints_chunk_size_check CHECK (((chunk_size >= 5000) AND (chunk_size <= 50000))),
    CONSTRAINT storage_v2_backfill_checkpoints_state_check CHECK ((state = ANY (ARRAY['ready'::text, 'running'::text, 'paused'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT storage_v2_checkpoint_hashes CHECK ((((source_sha256 IS NULL) OR (octet_length(source_sha256) = 32)) AND ((target_sha256 IS NULL) OR (octet_length(target_sha256) = 32))))
);


ALTER TABLE public.storage_v2_backfill_checkpoints OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_backfill_chunks; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_backfill_chunks (
    worker_name text NOT NULL,
    chunk_start_event_id bigint NOT NULL,
    chunk_end_event_id bigint NOT NULL,
    source_event_rows integer NOT NULL,
    target_event_rows integer NOT NULL,
    source_link_rows bigint DEFAULT 0 NOT NULL,
    target_link_rows bigint DEFAULT 0 NOT NULL,
    source_sha256 bytea NOT NULL,
    target_sha256 bytea NOT NULL,
    archive_event_set_id uuid,
    archive_link_set_id uuid,
    wal_bytes bigint,
    duration_ms bigint NOT NULL,
    status text NOT NULL,
    completed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT storage_v2_backfill_chunks_duration_ms_check CHECK ((duration_ms >= 0)),
    CONSTRAINT storage_v2_backfill_chunks_range CHECK ((chunk_start_event_id <= chunk_end_event_id)),
    CONSTRAINT storage_v2_backfill_chunks_source_event_rows_check CHECK ((source_event_rows >= 0)),
    CONSTRAINT storage_v2_backfill_chunks_source_link_rows_check CHECK ((source_link_rows >= 0)),
    CONSTRAINT storage_v2_backfill_chunks_source_sha256_check CHECK ((octet_length(source_sha256) = 32)),
    CONSTRAINT storage_v2_backfill_chunks_status_check CHECK ((status = ANY (ARRAY['verified'::text, 'failed'::text, 'rolled_back'::text]))),
    CONSTRAINT storage_v2_backfill_chunks_target_event_rows_check CHECK ((target_event_rows >= 0)),
    CONSTRAINT storage_v2_backfill_chunks_target_link_rows_check CHECK ((target_link_rows >= 0)),
    CONSTRAINT storage_v2_backfill_chunks_target_sha256_check CHECK ((octet_length(target_sha256) = 32))
);


ALTER TABLE public.storage_v2_backfill_chunks OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_channel; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_channel (
    id integer NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.storage_v2_channel OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_channel_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_channel ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_channel_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_computer; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_computer (
    id integer NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.storage_v2_computer OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_computer_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_computer ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_computer_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_cutover_state; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_cutover_state (
    singleton boolean DEFAULT true NOT NULL,
    read_mode text DEFAULT 'v1'::text NOT NULL,
    write_mode text DEFAULT 'v1'::text NOT NULL,
    shadow_sample_rate double precision DEFAULT 0.0 NOT NULL,
    archive_root text,
    state_version bigint DEFAULT 1 NOT NULL,
    changed_by text DEFAULT CURRENT_USER NOT NULL,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    rollback_note text,
    CONSTRAINT storage_v2_cutover_state_read_mode_check CHECK ((read_mode = ANY (ARRAY['v1'::text, 'shadow'::text, 'v2'::text]))),
    CONSTRAINT storage_v2_cutover_state_shadow_sample_rate_check CHECK (((shadow_sample_rate >= (0)::double precision) AND (shadow_sample_rate <= (1)::double precision))),
    CONSTRAINT storage_v2_cutover_state_singleton_check CHECK (singleton),
    CONSTRAINT storage_v2_cutover_state_write_mode_check CHECK ((write_mode = ANY (ARRAY['v1'::text, 'v1_outbox'::text, 'v2_primary_compat'::text, 'v2'::text])))
);


ALTER TABLE public.storage_v2_cutover_state OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_domain_name; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_domain_name (
    id integer NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.storage_v2_domain_name OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_domain_name_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_domain_name ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_domain_name_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_entity_identity_allocations; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_entity_identity_allocations (
    id integer DEFAULT nextval('public.entities_v2_id_seq'::regclass) NOT NULL,
    entity_type_id integer NOT NULL,
    natural_key text NOT NULL,
    allocated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.storage_v2_entity_identity_allocations OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_entity_type; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_entity_type (
    id integer NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.storage_v2_entity_type OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_entity_type_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_entity_type ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_entity_type_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_event_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

CREATE SEQUENCE public.storage_v2_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.storage_v2_event_id_seq OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: adlog_storage_owner
--

ALTER SEQUENCE public.storage_v2_event_id_seq OWNED BY public.events_v2_core.id;


--
-- Name: storage_v2_event_identity_allocations; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_event_identity_allocations (
    id bigint DEFAULT nextval('public.storage_v2_event_id_seq'::regclass) NOT NULL,
    server_id bigint NOT NULL,
    channel_id integer NOT NULL,
    event_record_id bigint NOT NULL,
    time_created_utc timestamp with time zone NOT NULL,
    normalized_hash bytea NOT NULL,
    allocated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT storage_v2_event_identity_allocations_normalized_hash_check CHECK ((octet_length(normalized_hash) = 32))
);


ALTER TABLE public.storage_v2_event_identity_allocations OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_extracted_from; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_extracted_from (
    id integer NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.storage_v2_extracted_from OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_extracted_from_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_extracted_from ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_extracted_from_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_keywords; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_keywords (
    id integer NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.storage_v2_keywords OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_keywords_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_keywords ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_keywords_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_outbox; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_outbox (
    id bigint NOT NULL,
    batch_id uuid NOT NULL,
    first_event_id bigint NOT NULL,
    last_event_id bigint NOT NULL,
    event_count integer NOT NULL,
    event_ids bigint[] NOT NULL,
    identity_sha256 bytea NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_token uuid,
    lease_until timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT storage_v2_outbox_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT storage_v2_outbox_event_count_check CHECK ((event_count > 0)),
    CONSTRAINT storage_v2_outbox_identity_sha256_check CHECK ((octet_length(identity_sha256) = 32)),
    CONSTRAINT storage_v2_outbox_ids_bounds CHECK (((event_ids[1] = first_event_id) AND (event_ids[event_count] = last_event_id))),
    CONSTRAINT storage_v2_outbox_ids_count CHECK ((cardinality(event_ids) = event_count)),
    CONSTRAINT storage_v2_outbox_range CHECK ((first_event_id <= last_event_id)),
    CONSTRAINT storage_v2_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'leased'::text, 'completed'::text, 'failed'::text, 'quarantined'::text])))
);


ALTER TABLE public.storage_v2_outbox OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_outbox_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_outbox ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_provider; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_provider (
    id integer NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.storage_v2_provider OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_provider_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_provider ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_provider_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_role; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_role (
    id integer NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.storage_v2_role OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_role_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_role ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_role_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: storage_v2_runtime_authorizations; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_runtime_authorizations (
    singleton boolean DEFAULT true NOT NULL,
    route text NOT NULL,
    authority text NOT NULL,
    preflight_digest text NOT NULL,
    authorization_digest text NOT NULL,
    archive_root text NOT NULL,
    evidence jsonb NOT NULL,
    authorized_by text NOT NULL,
    authorized_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT storage_v2_runtime_authorizations_archive_root_check CHECK ((length(btrim(archive_root)) > 0)),
    CONSTRAINT storage_v2_runtime_authorizations_authorization_digest_check CHECK ((authorization_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT storage_v2_runtime_authorizations_check CHECK ((expires_at > authorized_at)),
    CONSTRAINT storage_v2_runtime_authorizations_preflight_digest_check CHECK ((preflight_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT storage_v2_runtime_authorizations_route_check CHECK ((route = ANY (ARRAY['v2_primary_compat'::text, 'v2'::text]))),
    CONSTRAINT storage_v2_runtime_authorizations_singleton_check CHECK (singleton)
);


ALTER TABLE public.storage_v2_runtime_authorizations OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_shadow_results; Type: TABLE; Schema: public; Owner: adlog_storage_owner
--

CREATE TABLE public.storage_v2_shadow_results (
    id bigint NOT NULL,
    query_kind text NOT NULL,
    sample_key_sha256 bytea NOT NULL,
    v1_result_sha256 bytea NOT NULL,
    v2_result_sha256 bytea NOT NULL,
    identity_match boolean NOT NULL,
    count_match boolean NOT NULL,
    v1_duration_ms double precision NOT NULL,
    v2_duration_ms double precision NOT NULL,
    mismatch_summary text,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT storage_v2_shadow_results_sample_key_sha256_check CHECK ((octet_length(sample_key_sha256) = 32)),
    CONSTRAINT storage_v2_shadow_results_v1_duration_ms_check CHECK ((v1_duration_ms >= (0)::double precision)),
    CONSTRAINT storage_v2_shadow_results_v1_result_sha256_check CHECK ((octet_length(v1_result_sha256) = 32)),
    CONSTRAINT storage_v2_shadow_results_v2_duration_ms_check CHECK ((v2_duration_ms >= (0)::double precision)),
    CONSTRAINT storage_v2_shadow_results_v2_result_sha256_check CHECK ((octet_length(v2_result_sha256) = 32))
);


ALTER TABLE public.storage_v2_shadow_results OWNER TO adlog_storage_owner;

--
-- Name: storage_v2_shadow_results_id_seq; Type: SEQUENCE; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.storage_v2_shadow_results ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.storage_v2_shadow_results_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: user_report_preferences; Type: TABLE; Schema: public; Owner: adlog_user
--

CREATE TABLE public.user_report_preferences (
    user_id bigint NOT NULL,
    report_key text NOT NULL,
    pinned boolean DEFAULT false NOT NULL,
    view_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_report_preferences OWNER TO adlog_user;

--
-- Name: users_report_v2_snapshots; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users_report_v2_snapshots (
    snapshot_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    contract_id text NOT NULL,
    schema_version integer DEFAULT 1 NOT NULL,
    scope_json jsonb NOT NULL,
    scope_sha256 bytea NOT NULL,
    bucket_start_utc timestamp with time zone NOT NULL,
    captured_at_utc timestamp with time zone NOT NULL,
    source_observed_at_utc timestamp with time zone NOT NULL,
    source_state text NOT NULL,
    user_count integer NOT NULL,
    payload_json jsonb NOT NULL,
    payload_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT users_report_v2_snapshots_check CHECK ((bucket_start_utc <= captured_at_utc)),
    CONSTRAINT users_report_v2_snapshots_contract_id_check CHECK ((contract_id = 'sli.users-report.v2'::text)),
    CONSTRAINT users_report_v2_snapshots_payload_json_check CHECK ((jsonb_typeof(payload_json) = 'object'::text)),
    CONSTRAINT users_report_v2_snapshots_payload_sha256_check CHECK ((octet_length(payload_sha256) = 32)),
    CONSTRAINT users_report_v2_snapshots_schema_version_check CHECK ((schema_version = 1)),
    CONSTRAINT users_report_v2_snapshots_scope_sha256_check CHECK ((octet_length(scope_sha256) = 32)),
    CONSTRAINT users_report_v2_snapshots_source_state_check CHECK ((source_state = ANY (ARRAY['complete'::text, 'partial'::text]))),
    CONSTRAINT users_report_v2_snapshots_user_count_check CHECK ((user_count >= 0))
);


ALTER TABLE public.users_report_v2_snapshots OWNER TO postgres;

--
-- Name: users_report_v2_snapshots_snapshot_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_report_v2_snapshots_snapshot_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_report_v2_snapshots_snapshot_id_seq OWNER TO postgres;

--
-- Name: users_report_v2_snapshots_snapshot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_report_v2_snapshots_snapshot_id_seq OWNED BY public.users_report_v2_snapshots.snapshot_id;


--
-- Name: what_where_when_observations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.what_where_when_observations (
    projection_id bigint NOT NULL,
    source_event_id bigint NOT NULL,
    source_event_hash bytea NOT NULL,
    computer_object_guid uuid NOT NULL,
    computer_name text NOT NULL,
    user_name text NOT NULL,
    observed_at_utc timestamp with time zone NOT NULL,
    computer_source_snapshot_id bigint,
    user_snapshot_id bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_key text NOT NULL,
    observed_hour_local timestamp without time zone NOT NULL,
    CONSTRAINT what_where_when_observations_computer_name_check CHECK (((length(btrim(computer_name)) >= 1) AND (length(btrim(computer_name)) <= 512))),
    CONSTRAINT what_where_when_observations_source_event_hash_check CHECK ((octet_length(source_event_hash) = 32)),
    CONSTRAINT what_where_when_observations_user_name_check CHECK (((length(btrim(user_name)) >= 1) AND (length(btrim(user_name)) <= 512)))
);


ALTER TABLE public.what_where_when_observations OWNER TO postgres;

--
-- Name: what_where_when_observations_projection_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.what_where_when_observations_projection_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.what_where_when_observations_projection_id_seq OWNER TO postgres;

--
-- Name: what_where_when_observations_projection_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.what_where_when_observations_projection_id_seq OWNED BY public.what_where_when_observations.projection_id;


--
-- Name: what_where_when_projection_state; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.what_where_when_projection_state (
    singleton boolean DEFAULT true NOT NULL,
    initial_cutoff_utc timestamp with time zone NOT NULL,
    high_water_event_id bigint DEFAULT 0 NOT NULL,
    backfill_completed boolean DEFAULT false NOT NULL,
    computer_source_snapshot_id bigint,
    user_snapshot_id bigint,
    filtered_count bigint DEFAULT 0 NOT NULL,
    unmatched_count bigint DEFAULT 0 NOT NULL,
    ambiguous_count bigint DEFAULT 0 NOT NULL,
    last_cycle_at_utc timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT what_where_when_projection_state_ambiguous_count_check CHECK ((ambiguous_count >= 0)),
    CONSTRAINT what_where_when_projection_state_filtered_count_check CHECK ((filtered_count >= 0)),
    CONSTRAINT what_where_when_projection_state_high_water_event_id_check CHECK ((high_water_event_id >= 0)),
    CONSTRAINT what_where_when_projection_state_singleton_check CHECK (singleton),
    CONSTRAINT what_where_when_projection_state_unmatched_count_check CHECK ((unmatched_count >= 0))
);


ALTER TABLE public.what_where_when_projection_state OWNER TO postgres;

--
-- Name: plugin_namespace_contract_v1; Type: TABLE; Schema: sli_plugin_remote_access; Owner: adlog_plugin_remote_access_owner
--

CREATE TABLE sli_plugin_remote_access.plugin_namespace_contract_v1 (
    plugin_id text NOT NULL,
    contract_id text NOT NULL,
    contract_version integer NOT NULL,
    created_at_utc timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT plugin_namespace_contract_v1_contract_id_check CHECK ((contract_id = 'sli.plugin-postgresql-isolation.v1'::text)),
    CONSTRAINT plugin_namespace_contract_v1_contract_version_check CHECK ((contract_version = 1)),
    CONSTRAINT plugin_namespace_contract_v1_plugin_id_check CHECK ((plugin_id = 'sli.remote-access'::text))
);


ALTER TABLE sli_plugin_remote_access.plugin_namespace_contract_v1 OWNER TO adlog_plugin_remote_access_owner;

--
-- Name: access_audit_v4 id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_audit_v4 ALTER COLUMN id SET DEFAULT nextval('public.access_audit_v4_id_seq'::regclass);


--
-- Name: access_capabilities id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_capabilities ALTER COLUMN id SET DEFAULT nextval('public.access_capabilities_id_seq'::regclass);


--
-- Name: access_capability_assignments id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_capability_assignments ALTER COLUMN id SET DEFAULT nextval('public.access_capability_assignments_id_seq'::regclass);


--
-- Name: access_groups id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_groups ALTER COLUMN id SET DEFAULT nextval('public.access_groups_id_seq'::regclass);


--
-- Name: access_packages id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_packages ALTER COLUMN id SET DEFAULT nextval('public.access_packages_id_seq'::regclass);


--
-- Name: access_report_assignments id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_report_assignments ALTER COLUMN id SET DEFAULT nextval('public.access_report_assignments_id_seq'::regclass);


--
-- Name: access_subject_packages id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_subject_packages ALTER COLUMN id SET DEFAULT nextval('public.access_subject_packages_id_seq'::regclass);


--
-- Name: account_risk_acceptance_audit id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_acceptance_audit ALTER COLUMN id SET DEFAULT nextval('public.account_risk_acceptance_audit_id_seq'::regclass);


--
-- Name: account_risk_acceptances id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_acceptances ALTER COLUMN id SET DEFAULT nextval('public.account_risk_acceptances_id_seq'::regclass);


--
-- Name: account_risk_investigation_links id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_investigation_links ALTER COLUMN id SET DEFAULT nextval('public.account_risk_investigation_links_id_seq'::regclass);


--
-- Name: acquisition_delivery_outbox delivery_id; Type: DEFAULT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_delivery_outbox ALTER COLUMN delivery_id SET DEFAULT nextval('public.acquisition_delivery_outbox_delivery_id_seq'::regclass);


--
-- Name: ad_context_entity_aliases id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_aliases ALTER COLUMN id SET DEFAULT nextval('public.ad_context_entity_aliases_id_seq'::regclass);


--
-- Name: ad_context_entity_versions id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_versions ALTER COLUMN id SET DEFAULT nextval('public.ad_context_entity_versions_id_seq'::regclass);


--
-- Name: ad_context_evidence id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_evidence ALTER COLUMN id SET DEFAULT nextval('public.ad_context_evidence_id_seq'::regclass);


--
-- Name: ad_context_relation_versions id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_relation_versions ALTER COLUMN id SET DEFAULT nextval('public.ad_context_relation_versions_id_seq'::regclass);


--
-- Name: ai_analysis id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ai_analysis ALTER COLUMN id SET DEFAULT nextval('public.ai_analysis_id_seq'::regclass);


--
-- Name: ai_api_runs id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ai_api_runs ALTER COLUMN id SET DEFAULT nextval('public.ai_api_runs_id_seq'::regclass);


--
-- Name: ai_reviews id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ai_reviews ALTER COLUMN id SET DEFAULT nextval('public.ai_reviews_id_seq'::regclass);


--
-- Name: auth_api_keys id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_api_keys ALTER COLUMN id SET DEFAULT nextval('public.auth_api_keys_id_seq'::regclass);


--
-- Name: auth_audit id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_audit ALTER COLUMN id SET DEFAULT nextval('public.auth_audit_id_seq'::regclass);


--
-- Name: auth_sessions id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_sessions ALTER COLUMN id SET DEFAULT nextval('public.auth_sessions_id_seq'::regclass);


--
-- Name: auth_users id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_users ALTER COLUMN id SET DEFAULT nextval('public.auth_users_id_seq'::regclass);


--
-- Name: collection_runs id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collection_runs ALTER COLUMN id SET DEFAULT nextval('public.collection_runs_id_seq'::regclass);


--
-- Name: collector_channel_runs id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collector_channel_runs ALTER COLUMN id SET DEFAULT nextval('public.collector_channel_runs_id_seq'::regclass);


--
-- Name: collector_cursor_audit id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collector_cursor_audit ALTER COLUMN id SET DEFAULT nextval('public.collector_cursor_audit_id_seq'::regclass);


--
-- Name: collector_stage_metrics id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collector_stage_metrics ALTER COLUMN id SET DEFAULT nextval('public.collector_stage_metrics_id_seq'::regclass);


--
-- Name: computers_report_v5_snapshots snapshot_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v5_snapshots ALTER COLUMN snapshot_id SET DEFAULT nextval('public.computers_report_v5_snapshots_snapshot_id_seq'::regclass);


--
-- Name: computers_report_v6_snapshots snapshot_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v6_snapshots ALTER COLUMN snapshot_id SET DEFAULT nextval('public.computers_report_v6_snapshots_snapshot_id_seq'::regclass);


--
-- Name: computers_v6_source_snapshots source_snapshot_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_v6_source_snapshots ALTER COLUMN source_snapshot_id SET DEFAULT nextval('public.computers_v6_source_snapshots_source_snapshot_id_seq'::regclass);


--
-- Name: detection_rules id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detection_rules ALTER COLUMN id SET DEFAULT nextval('public.detection_rules_id_seq'::regclass);


--
-- Name: detections id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detections ALTER COLUMN id SET DEFAULT nextval('public.detections_id_seq'::regclass);


--
-- Name: domains id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.domains ALTER COLUMN id SET DEFAULT nextval('public.domains_id_seq'::regclass);


--
-- Name: entities_v2 id; Type: DEFAULT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entities_v2 ALTER COLUMN id SET DEFAULT nextval('public.entities_v2_id_seq'::regclass);


--
-- Name: entity_states id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.entity_states ALTER COLUMN id SET DEFAULT nextval('public.entity_states_id_seq'::regclass);


--
-- Name: event_links id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.event_links ALTER COLUMN id SET DEFAULT nextval('public.event_links_id_seq'::regclass);


--
-- Name: events_v2_core id; Type: DEFAULT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core ALTER COLUMN id SET DEFAULT nextval('public.storage_v2_event_id_seq'::regclass);


--
-- Name: finding_entities id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_entities ALTER COLUMN id SET DEFAULT nextval('public.finding_entities_id_seq'::regclass);


--
-- Name: finding_evidence id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_evidence ALTER COLUMN id SET DEFAULT nextval('public.finding_evidence_id_seq'::regclass);


--
-- Name: finding_status_history id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_status_history ALTER COLUMN id SET DEFAULT nextval('public.finding_status_history_id_seq'::regclass);


--
-- Name: findings id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.findings ALTER COLUMN id SET DEFAULT nextval('public.findings_id_seq'::regclass);


--
-- Name: forests id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.forests ALTER COLUMN id SET DEFAULT nextval('public.forests_id_seq'::regclass);


--
-- Name: gpo_report_v2_source_snapshots snapshot_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.gpo_report_v2_source_snapshots ALTER COLUMN snapshot_id SET DEFAULT nextval('public.gpo_report_v2_source_snapshots_snapshot_id_seq'::regclass);


--
-- Name: investigation_audit id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_audit ALTER COLUMN id SET DEFAULT nextval('public.investigation_audit_id_seq'::regclass);


--
-- Name: investigation_notes id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_notes ALTER COLUMN id SET DEFAULT nextval('public.investigation_notes_id_seq'::regclass);


--
-- Name: investigations id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigations ALTER COLUMN id SET DEFAULT nextval('public.investigations_id_seq'::regclass);


--
-- Name: log_sources id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.log_sources ALTER COLUMN id SET DEFAULT nextval('public.log_sources_id_seq'::regclass);


--
-- Name: object_identity_links id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.object_identity_links ALTER COLUMN id SET DEFAULT nextval('public.object_identity_links_id_seq'::regclass);


--
-- Name: post_collection_jobs id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.post_collection_jobs ALTER COLUMN id SET DEFAULT nextval('public.post_collection_jobs_id_seq'::regclass);


--
-- Name: raw_log_files id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.raw_log_files ALTER COLUMN id SET DEFAULT nextval('public.raw_log_files_id_seq'::regclass);


--
-- Name: report_access_requests_v4 id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_access_requests_v4 ALTER COLUMN id SET DEFAULT nextval('public.report_access_requests_v4_id_seq'::regclass);


--
-- Name: report_datasets_v4 id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_datasets_v4 ALTER COLUMN id SET DEFAULT nextval('public.report_datasets_v4_id_seq'::regclass);


--
-- Name: report_items id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_items ALTER COLUMN id SET DEFAULT nextval('public.report_items_id_seq'::regclass);


--
-- Name: report_registry_v4 id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_registry_v4 ALTER COLUMN id SET DEFAULT nextval('public.report_registry_v4_id_seq'::regclass);


--
-- Name: reports id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.reports ALTER COLUMN id SET DEFAULT nextval('public.reports_id_seq'::regclass);


--
-- Name: schema_migrations id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.schema_migrations ALTER COLUMN id SET DEFAULT nextval('public.schema_migrations_id_seq'::regclass);


--
-- Name: servers id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.servers ALTER COLUMN id SET DEFAULT nextval('public.servers_id_seq'::regclass);


--
-- Name: sites id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.sites ALTER COLUMN id SET DEFAULT nextval('public.sites_id_seq'::regclass);


--
-- Name: source_capture_continuity_declarations id; Type: DEFAULT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.source_capture_continuity_declarations ALTER COLUMN id SET DEFAULT nextval('public.source_capture_continuity_declarations_id_seq'::regclass);


--
-- Name: storage_lifecycle_snapshots id; Type: DEFAULT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.storage_lifecycle_snapshots ALTER COLUMN id SET DEFAULT nextval('public.storage_lifecycle_snapshots_id_seq'::regclass);


--
-- Name: users_report_v2_snapshots snapshot_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_report_v2_snapshots ALTER COLUMN snapshot_id SET DEFAULT nextval('public.users_report_v2_snapshots_snapshot_id_seq'::regclass);


--
-- Name: what_where_when_observations projection_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_observations ALTER COLUMN projection_id SET DEFAULT nextval('public.what_where_when_observations_projection_id_seq'::regclass);


--
-- Data for Name: access_audit_v4; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_audit_v4 (id, actor_type, actor_id, action, subject_type, subject_id, target_type, target_key, reason, outcome, details_json, remote_address, created_at) FROM stdin;
\.


--
-- Data for Name: access_capabilities; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_capabilities (id, capability_key, label, description, created_at) FROM stdin;
1	workspace.view	Рабочее пространство	Персональная сборка разрешённых модулей	2026-10-01 16:00:29.967528+07
2	reports.catalog	Каталог отчётов	Просмотр каталога и объяснений доступа	2026-10-01 16:00:29.967528+07
3	reports.design	Конструктор отчётов	Создание безопасных представлений datasets	2026-10-01 16:00:29.967528+07
4	reports.publish	Публикация отчётов	Версионирование и публикация отчётов	2026-10-01 16:00:29.967528+07
5	reports.assign	Назначение отчётов	Управление report grants	2026-10-01 16:00:29.967528+07
6	reports.export	Контролируемый экспорт	Экспорт только зарегистрированного представления и разрешённых полей	2026-10-01 16:00:29.967528+07
7	objects.view	Объекты	Поиск и просмотр разрешённых объектов	2026-10-01 16:00:29.967528+07
8	objects.groups	Членство в группах	Direct/nested group paths	2026-10-01 16:00:29.967528+07
9	objects.privileges	Доступ и привилегии	Effective privilege paths	2026-10-01 16:00:29.967528+07
10	events.view	События	Bounded event explorer	2026-10-01 16:00:29.967528+07
11	evidence.exact	Точные доказательства	Exact event_db_id и raw evidence	2026-10-01 16:00:29.967528+07
12	investigations.view	Расследования	Просмотр расследований	2026-10-01 16:00:29.967528+07
13	investigations.manage	Управление расследованиями	Создание и изменение cases	2026-10-01 16:00:29.967528+07
14	tasks.create	Создание задачи	Безопасная контролируемая задача	2026-10-01 16:00:29.967528+07
15	semantic.review	Semantic SHADOW review	Просмотр TEST/SHADOW и калибровка	2026-10-01 16:00:29.967528+07
16	operations.view	Эксплуатация	Workers, queues, PostgreSQL и SLO	2026-10-01 16:00:29.967528+07
17	access.manage	Управление доступом	Пакеты, grants, scopes и сроки	2026-10-01 16:00:29.967528+07
18	access.preview	Предпросмотр доступа	Explain и preview effective access	2026-10-01 16:00:29.967528+07
19	access.impersonate	Просмотр от имени	Административный preview без обхода PDP	2026-10-01 16:00:29.967528+07
20	field.identity_basic	Базовая идентификация	Имена, типы и стабильные ID	2026-10-01 16:00:29.967528+07
21	field.contact	Рабочие контакты	Почта, телефон и расположение	2026-10-01 16:00:29.967528+07
22	field.hr	Кадровые данные	Должность, отдел и руководитель	2026-10-01 16:00:29.967528+07
23	field.security	Данные безопасности	Состояния и security facts	2026-10-01 16:00:29.967528+07
24	field.privilege	Привилегии и отношения	Членства и effective privilege	2026-10-01 16:00:29.967528+07
25	field.technical	Технические атрибуты	SID, GUID, DN, UAC, SPN	2026-10-01 16:00:29.967528+07
26	field.raw_evidence	Raw evidence	EventData, message и точные поля	2026-10-01 16:00:29.967528+07
27	field.sensitive	Чувствительные поля	Ограниченные персональные данные	2026-10-01 16:00:29.967528+07
28	vpn.sessions.view	VPN-сеансы	Просмотр ограниченной проекции RADIUS Accounting без raw evidence	2026-10-01 16:00:32.008079+07
29	vpn.session.evidence.read	Evidence VPN-сеанса	Чтение неизменяемого evidence только через отдельный контролируемый endpoint	2026-10-01 16:00:32.008079+07
30	administrative.activity.view	Журнал административных действий	Ограниченный просмотр общего неизменяемого административного журнала	2026-10-01 16:00:32.903906+07
31	plugins.manage	Управление плагинами	Планирование подтверждаемых lifecycle-действий bundled-плагинов	2026-10-01 16:00:32.981642+07
32	account_risks.accept	Подтверждать допустимость риска учётной записи	Сроковое аудируемое решение для точной пары учётная запись + риск + версия правила	2026-10-01 16:00:34.865523+07
33	field.computer_logon_observation	Наблюдения входов на ПК	Минимальные приблизительные наблюдения: имя ПК, доменный пользователь и время	2026-10-01 16:00:36.853984+07
\.


--
-- Data for Name: access_capability_assignments; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_capability_assignments (id, subject_type, subject_id, capability_id, effect, scope_json, valid_from, valid_until, business_reason, approved_by, source_type, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: access_group_members; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_group_members (group_id, user_id, valid_from, valid_until, source, created_at) FROM stdin;
\.


--
-- Data for Name: access_groups; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_groups (id, group_key, name, description, is_active, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: access_package_capabilities; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_package_capabilities (package_id, capability_id) FROM stdin;
5	1
4	1
3	1
2	1
1	1
5	2
4	2
3	2
2	2
1	2
5	3
5	4
5	5
5	6
4	6
3	6
2	6
3	7
2	7
1	7
3	8
2	8
3	9
2	10
2	11
2	12
1	12
2	13
1	13
3	14
2	14
1	14
2	15
4	16
5	17
5	18
5	19
3	20
2	20
1	20
3	21
3	22
3	23
2	23
1	23
3	24
2	24
3	25
2	25
2	26
5	30
5	31
3	32
2	33
4	33
6	1
6	2
6	6
6	7
6	8
6	9
6	10
6	11
6	12
6	13
6	15
6	20
6	23
6	24
6	25
6	26
7	29
\.


--
-- Data for Name: access_package_reports; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_package_reports (package_id, report_key, field_categories, allowed_actions, scope_json) FROM stdin;
1	security.queue	{identity_basic,security}	{view,create_task,start_case}	{"kind": "all"}
2	investigations.workspace	{identity_basic,security,raw_evidence}	{view,start_case}	{"kind": "all"}
2	events.explorer	{identity_basic,security,technical,raw_evidence}	{view,export,start_case}	{"kind": "all"}
2	security.queue	{identity_basic,security,raw_evidence}	{view,create_task,start_case}	{"kind": "all"}
4	operations.readiness	{technical}	{view,export}	{"kind": "all"}
5	access.center	{}	{view,grant_access}	{"kind": "all"}
3	ad.state	{identity_basic,technical,security}	{view,export}	{"ids": [1], "kind": "domain"}
3	ad.users.v2	{identity_basic,technical,security,privilege,hr,contact}	{view,export}	{"ids": [1], "kind": "domain"}
3	ad.computers.v6	{identity_basic,technical,security}	{view,export}	{"ids": [1], "kind": "domain"}
3	vpn.audit	{identity_basic,technical,security,privilege,hr,contact}	{view,create_task,export}	{"kind": "all"}
3	ad.gpo.v2	{identity_basic,technical,security,privilege}	{view,export}	{"kind": "all"}
2	ad.computer-logons	{computer_logon_observation}	{view}	{"ids": [1], "kind": "domain"}
4	ad.computer-logons	{computer_logon_observation}	{view}	{"ids": [1], "kind": "domain"}
2	security.events.chains	{identity_basic,security,technical,raw_evidence}	{view,export,start_case}	{"kind": "all"}
6	security.events.chains	{identity_basic,security,technical,raw_evidence}	{view,export,start_case}	{"kind": "all"}
\.


--
-- Data for Name: access_packages; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_packages (id, package_key, name, description, is_system, created_at, updated_at) FROM stdin;
1	security_operator	ИБ · операторы	Очередь проблем, влияние, гипотезы и безопасные действия	t	2026-10-01 16:00:29.967528+07	2026-10-01 16:00:29.967528+07
2	security_analyst	ИБ · аналитики	События, evidence, entities и investigations	t	2026-10-01 16:00:29.967528+07	2026-10-01 16:00:29.967528+07
3	ad_auditor	AD · аудит и сопровождение	AD-отчёты, группы, привилегии и GPO	t	2026-10-01 16:00:29.967528+07	2026-10-01 16:00:29.967528+07
4	project_operations	Проект · эксплуатация	Источники, workers, queues, PostgreSQL и readiness	t	2026-10-01 16:00:29.967528+07	2026-10-01 16:00:29.967528+07
5	access_admin	Администраторы доступа	Назначения, explain, preview и audit без автоматического чтения данных	t	2026-10-01 16:00:29.967528+07	2026-10-01 16:00:29.967528+07
6	security_investigation_reader	ИБ · чтение расследований	События безопасности, точные доказательства и сохранённые объяснимые связи без изменения источников	t	2026-10-01 16:00:37.547503+07	2026-10-01 16:00:37.547503+07
7	vpn_evidence_reader	Чтение evidence VPN-сеансов	Чтение evidence в пределах разрешённого отчёта VPN	t	2026-10-06 00:56:41.604366+07	2026-10-06 00:56:41.604366+07
\.


--
-- Data for Name: access_report_assignments; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_report_assignments (id, subject_type, subject_id, report_key, access_level, effect, scope_json, field_categories, allowed_actions, valid_from, valid_until, source_type, business_reason, approved_by, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: access_role_packages; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_role_packages (coarse_role, package_id) FROM stdin;
operator	2
viewer	2
operator	3
admin	4
operator	4
admin	5
admin	6
\.


--
-- Data for Name: access_subject_packages; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.access_subject_packages (id, subject_type, subject_id, package_id, effect, valid_from, valid_until, business_reason, approved_by, source_type, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: account_risk_acceptance_audit; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.account_risk_acceptance_audit (id, acceptance_id, action, actor, snapshot_json, created_at) FROM stdin;
\.


--
-- Data for Name: account_risk_acceptances; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.account_risk_acceptances (id, public_id, entity_id, domain_id, risk_key, rule_version, reason, responsible, status, valid_from, valid_until, created_by, created_at, revoked_by, revoked_at, revoke_reason) FROM stdin;
\.


--
-- Data for Name: account_risk_investigation_links; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.account_risk_investigation_links (id, investigation_id, entity_id, domain_id, risk_key, rule_version, qualification_snapshot, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: acquisition_consumer_subscriptions; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.acquisition_consumer_subscriptions (subscription_id, source_instance_id, stream_id, transport_binding, consumer_id, consumer_component_id, consumer_component_version, routing_contract_id, consumer_contract_version, replay_policy, resource_profile_id, selector_json, selector_sha256, authority_mode, desired_activation, partition_key, created_at) FROM stdin;
\.


--
-- Data for Name: acquisition_delivery_outbox; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.acquisition_delivery_outbox (delivery_id, subscription_id, evidence_uid, observation_id, idempotency_key, delivery_state, created_at, delivered_at, attempt_count, available_at, lease_token, lease_until, heartbeat_at, last_error_code, updated_at) FROM stdin;
\.


--
-- Data for Name: acquisition_source_instances; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.acquisition_source_instances (source_instance_id, organization_scope, source_kind, endpoint_identity, adapter_binding, credential_handle, display_name, desired_activation, observed_health, configuration_sha256, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: acquisition_stream_cursors; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.acquisition_stream_cursors (source_instance_id, stream_id, transport_binding, cursor_epoch, file_generation, byte_offset, last_record_sha256, previous_file_generation, previous_generation_last_record_sha256, revision, updated_at) FROM stdin;
\.


--
-- Data for Name: ad_context_entity_aliases; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ad_context_entity_aliases (id, entity_id, domain_id, alias_type, alias_value, normalized_value, first_seen_utc, last_seen_utc, source_run_id) FROM stdin;
\.


--
-- Data for Name: ad_context_entity_versions; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ad_context_entity_versions (id, entity_id, source_section, valid_from_utc, valid_to_utc, last_observed_at_utc, content_sha256, attributes_json, source_run_id) FROM stdin;
\.


--
-- Data for Name: ad_context_event_links; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ad_context_event_links (event_db_id, context_evidence_id, rule_code, relation_status, explanation, created_at) FROM stdin;
\.


--
-- Data for Name: ad_context_evidence; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ad_context_evidence (id, evidence_key, evidence_type, source_pack_id, source_run_id, observed_at_utc, locator_json, integrity_sha256, created_at) FROM stdin;
\.


--
-- Data for Name: ad_context_relation_versions; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ad_context_relation_versions (id, relation_key, relation_kind, source_entity_id, target_entity_id, source_section, domain_id, valid_from_utc, valid_to_utc, last_observed_at_utc, content_sha256, attributes_json, source_run_id) FROM stdin;
\.


--
-- Data for Name: ad_context_runs; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ad_context_runs (run_id, source_pack_id, source_pack_version, domain_id, mode, observed_at_utc, bundle_sha256, status, created_at, completed_at, scope_json) FROM stdin;
\.


--
-- Data for Name: ad_context_sections; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ad_context_sections (run_id, section_name, status, record_count, duration_ms, error_code) FROM stdin;
\.


--
-- Data for Name: ad_snapshot_manifest_sources; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ad_snapshot_manifest_sources (manifest_id, family, contract_id, source_id, observed_at_utc, source_state, payload_sha256, reason_code) FROM stdin;
\.


--
-- Data for Name: ad_snapshot_manifests; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ad_snapshot_manifests (manifest_id, domain_id, domain_sid, domain_dns, slot_start_utc, assembled_at_utc, contract_version, coverage_state, manifest_sha256, created_at, schedule_timezone, scheduled_local_at) FROM stdin;
\.


--
-- Data for Name: ad_snapshot_projection_outputs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ad_snapshot_projection_outputs (manifest_id, projection_key, projection_version, input_sha256, output_sha256, output_identity, payload_json, created_at) FROM stdin;
\.


--
-- Data for Name: ad_snapshot_projection_receipts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ad_snapshot_projection_receipts (manifest_id, projection_key, projection_version, status, attempt_count, lease_owner, lease_expires_at, input_sha256, output_sha256, output_identity, last_error, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: administrative_activity_v1; Type: TABLE DATA; Schema: public; Owner: adlog_administrative_activity_owner
--

COPY public.administrative_activity_v1 (activity_id, event_uid, occurred_at_utc, recorded_at_utc, actor_kind, actor_key, category, action_key, target_kind, target_key, outcome, reason_code, details_json, remote_address, correlation_id, content_hash, previous_record_hash, record_hash) FROM stdin;
\.


--
-- Data for Name: ai_analysis; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ai_analysis (id, detection_id, model_name, prompt_version, analyzed_at, risk, confidence, summary, facts_json, assumptions_json, recommendations_json, raw_response_json) FROM stdin;
\.


--
-- Data for Name: ai_api_runs; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ai_api_runs (id, provider, model, prompt_version, redaction_level, status, query_summary_json, prompt_file_path, request_file_path, result_file_path, report_file_path, ai_call_performed, validation_errors_json, created_at, completed_at) FROM stdin;
\.


--
-- Data for Name: ai_reviews; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.ai_reviews (id, ai_analysis_id, reviewer_model_name, reviewed_at, report_is_valid, unsafe_recommendations_json, missing_evidence_json, issues_json, final_decision, raw_response_json) FROM stdin;
\.


--
-- Data for Name: archive_settings; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.archive_settings (key, value, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: auth_api_keys; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.auth_api_keys (id, key_prefix, key_hash, label, role, is_active, expires_at, created_at, last_used_at, revoked_at) FROM stdin;
\.


--
-- Data for Name: auth_audit; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.auth_audit (id, actor_type, actor_id, action, outcome, remote_address, created_at) FROM stdin;
\.


--
-- Data for Name: auth_sessions; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.auth_sessions (id, user_id, token_hash, expires_at, revoked_at, created_at, last_used_at) FROM stdin;
\.


--
-- Data for Name: canonical_action_evidence; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.canonical_action_evidence (canonical_action_id, normalized_event_id, evidence_role, entity_role, evidence_order, relation_confidence, created_at) FROM stdin;
\.


--
-- Data for Name: canonical_action_state_evidence; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.canonical_action_state_evidence (canonical_action_id, context_evidence_id, assessment_status, change_origin, match_key, explanation, created_at) FROM stdin;
\.


--
-- Data for Name: canonical_actions; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.canonical_actions (canonical_action_id, action_kind, action_status, semantic_contract_version, assembler_id, assembler_version, occurred_at_utc, contribution_key, action_sha256, attributes_json, created_at, updated_at, canonical_deduplication_key) FROM stdin;
\.


--
-- Data for Name: collection_channel_state; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.collection_channel_state (server_hostname, channel, archive_start_utc, last_collection_start_utc, last_successful_collection_utc, last_event_time_utc, last_event_record_id, backfill_completed, updated_at, channel_generation_identity) FROM stdin;
\.


--
-- Data for Name: collection_runs; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.collection_runs (id, run_started_at, run_finished_at, mode, status, tool_version, notes) FROM stdin;
\.


--
-- Data for Name: collector_adaptive_state; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.collector_adaptive_state (server, channel, current_limit, consecutive_completed, recovery_mode, last_status, last_lag_minutes, last_action, updated_at) FROM stdin;
\.


--
-- Data for Name: collector_channel_runs; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.collector_channel_runs (id, job_id, server, channel, started_utc, finished_utc, status, inserted, skipped, count, partial_count, latest_event_record_id, lag_minutes, timeout_seconds, limit_used, adaptive_action, error, query_duration_ms, import_duration_ms, import_queue_wait_ms, import_retry_count, report_duration_ms, total_duration_ms, events_per_second, last_record_id_delta, lag_delta_minutes, collection_mode, requested_collection_mode, cursor_strategy, cursor_fallback_reason, collector_backend, backend_reason, partial_kind, failure_stage, cursor_commit_allowed, created_at) FROM stdin;
\.


--
-- Data for Name: collector_cursor_audit; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.collector_cursor_audit (id, job_id, trace_id, server, channel, collection_status, import_inserted, import_skipped, old_record_id, proposed_record_id, new_record_id, old_event_time_utc, proposed_event_time_utc, new_event_time_utc, decision, reason, cursor_strategy, cursor_fallback_reason, created_at) FROM stdin;
\.


--
-- Data for Name: collector_stage_metrics; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.collector_stage_metrics (id, job_id, server, channel, backend, stage, status, duration_ms, events_count, bytes_count, error, created_at) FROM stdin;
\.


--
-- Data for Name: computers_report_v5_snapshots; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.computers_report_v5_snapshots (snapshot_id, domain_id, source_run_id, contract_id, schema_version, scope_json, scope_sha256, bucket_start_utc, captured_at_utc, source_observed_at_utc, source_state, object_count, payload_json, payload_sha256, created_at) FROM stdin;
\.


--
-- Data for Name: computers_report_v6_snapshots; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.computers_report_v6_snapshots (snapshot_id, domain_id, source_run_id, contract_id, schema_version, scope_json, scope_sha256, bucket_start_utc, captured_at_utc, source_observed_at_utc, source_state, object_count, payload_json, payload_sha256, created_at) FROM stdin;
\.


--
-- Data for Name: computers_v6_source_snapshots; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.computers_v6_source_snapshots (source_snapshot_id, domain_id, snapshot_uuid, schema_version, source_started_at_utc, source_completed_at_utc, captured_at_utc, query_dc, search_base, collector_version, collector_sha256, collection_status, base_inventory_status, object_count, source_options_json, payload_json, payload_sha256, collector_exit_code, created_at) FROM stdin;
\.


--
-- Data for Name: core_evidence_manifests; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.core_evidence_manifests (evidence_uid, source_instance_id, stream_id, transport_binding, cursor_epoch, file_generation, cursor_start_byte_offset, batch_record_ordinal, canonical_record_sha256, object_reference, object_sha256, object_size_bytes, verified_at_utc, created_at) FROM stdin;
\.


--
-- Data for Name: detection_rules; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.detection_rules (id, code, name, description, severity_default, enabled, version) FROM stdin;
1	AD-LOG-CLEARED	Security log cleared	Security event log was cleared or audit trail was interrupted.	critical	t	1
2	AD-PRIV-GROUP-CHANGE	Privileged group membership changed	Membership of a privileged AD group changed.	high	t	1
3	AD-USER-CREATED-OR-ENABLED	User account created or enabled	User account was created or enabled.	medium	t	1
4	AD-ACCOUNT-LOCKOUT	Account lockout	User account lockout was detected.	medium	t	1
5	AD-MANY-FAILED-LOGONS	Many failed logons	Multiple failed logons were detected for the same principal or source.	medium	t	1
6	AD-SUCCESS-AFTER-FAILURES	Successful logon after failures	Successful logon after repeated failed logons.	high	t	1
7	AD-SPECIAL-LOGON	Special logon	Privileged logon was detected.	medium	t	1
8	AD-AUDIT-POLICY-CHANGE	Audit policy changed	Audit policy was changed.	high	t	1
9	AD-KERBEROS-ANOMALY	Kerberos anomaly candidate	Kerberos authentication or service ticket anomaly candidate.	medium	t	1
10	AD-POWERSHELL-ACTIVITY	PowerShell activity candidate	PowerShell activity that may require review.	medium	t	1
\.


--
-- Data for Name: detections; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.detections (id, detection_rule_id, primary_event_id, server_id, domain_id, site_id, detected_at, severity, status, facts_json, evidence_event_ids_json) FROM stdin;
\.


--
-- Data for Name: domain_controller_targets; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.domain_controller_targets (id, hostname, connect_address, domain_id, owner_confirmed_ip, enabled, source, created_by, created_at, updated_by, updated_at) FROM stdin;
\.


--
-- Data for Name: domains; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.domains (id, forest_id, fqdn, netbios_name, domain_sid, created_at) FROM stdin;
1	1	__SLI_REPORT_DOMAIN__	\N	\N	2026-10-01 16:00:27.575669+07
\.


--
-- Data for Name: entities_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entities_v2 (id, entity_type_id, natural_key, display_name, domain_id, server_id, first_seen_utc, last_seen_utc, source_core_sha256, migrated_at) FROM stdin;
\.


--
-- Data for Name: entity_details_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entity_details_v2 (entity_id, attributes_json, source_details_sha256, migrated_at) FROM stdin;
\.


--
-- Data for Name: entity_identity_finding_supersessions_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entity_identity_finding_supersessions_v2 (merge_id, old_scenario_id, new_scenario_id, old_finding_id, new_finding_id, created_at) FROM stdin;
\.


--
-- Data for Name: entity_identity_merge_events_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entity_identity_merge_events_v2 (merge_id, source_event_id, source_role_ids, semantic_replay_required, created_at, source_event_sha256, source_occurred_at_utc) FROM stdin;
\.


--
-- Data for Name: entity_identity_merges_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entity_identity_merges_v2 (merge_id, source_entity_id, target_entity_id, source_natural_key, target_natural_key, plan_sha256, source_core_sha256_before, target_core_sha256_before, source_links_before, target_links_before, target_links_after, source_links_sha256, target_links_before_sha256, target_links_after_sha256, affected_events, affected_events_sha256, semantic_replay_events, evidence_json, merged_by, merged_at) FROM stdin;
\.


--
-- Data for Name: entity_identity_scenario_supersessions_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entity_identity_scenario_supersessions_v2 (merge_id, old_scenario_id, new_scenario_id, created_at) FROM stdin;
\.


--
-- Data for Name: entity_identity_semantic_replays_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entity_identity_semantic_replays_v2 (merge_id, source_event_id, old_normalized_event_id, new_normalized_event_id, replay_job_id, created_at, source_event_sha256, source_occurred_at_utc) FROM stdin;
\.


--
-- Data for Name: entity_state_current; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entity_state_current (entity_id, state_type, status, projection_status, observed_at, source_event_db_id, rule_id, rule_version, details_json, updated_at) FROM stdin;
\.


--
-- Data for Name: entity_state_projection_jobs; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.entity_state_projection_jobs (job_id, job_schema_version, source_event_db_id, candidate_states, status, attempt_count, max_attempts, available_at, lease_token, lease_until, heartbeat_at, last_error, created_at, updated_at, completed_at) FROM stdin;
\.


--
-- Data for Name: entity_states; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.entity_states (id, entity_id, state_type, severity, status, observed_at_utc, summary, evidence_event_id, details_json, created_at) FROM stdin;
\.


--
-- Data for Name: event_catalog_revisions; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.event_catalog_revisions (id, version, created_at) FROM stdin;
1	2026-07-30-radius-descriptor-v1	2026-10-01 16:00:33.644525+07
2	2026-08-25-descriptor-v7-stage8-process-activity	2026-10-01 16:00:34.432332+07
\.


--
-- Data for Name: event_entity_link_blocks_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.event_entity_link_blocks_v2 (entity_id, block_no, first_event_id, last_event_id, event_ids, role_ids, identity_sha256) FROM stdin;
\.


--
-- Data for Name: event_facts_v2; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.event_facts_v2 (event_id, process_name, process_id, target_server_name, service_name, task_name, task_action, task_author, run_as, logon_type, result_code, object_name, share_name, message_sample, powershell_user_name, powershell_command_name, powershell_script_block_text, powershell_process_id, source_facts_sha256, migrated_at, account_target_sid, account_target_name, account_name_before, account_name_after, membership_member_sid, membership_member_name, process_parent_id, process_command_line, process_user_sid, process_user_name, process_user_domain, process_logon_id, service_file, service_account, service_start_type, task_content, task_change, native_process_id) FROM stdin;
\.


--
-- Data for Name: event_links; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.event_links (id, source_event_id, target_event_id, link_type, confidence, created_at) FROM stdin;
\.


--
-- Data for Name: events_v2_core; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.events_v2_core (id, raw_log_file_id, server_id, domain_id, site_id, log_source_id, event_record_id, event_id, version, level, task, opcode, keywords_id, provider_id, channel_id, computer_id, time_created_utc, subject_user_sid, subject_user_name, subject_domain_id, target_user_sid, target_user_name, target_domain_id, ip_address, workstation_name, logon_id, correlation_id, normalized_at, normalized_hash, source_core_sha256, migrated_at, noise_class, noise_catalog_version, noise_catalog_revision_id) FROM stdin;
\.


--
-- Data for Name: finding_entities; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.finding_entities (id, finding_id, entity_id, entity_type, display_name, entity_role, created_at) FROM stdin;
\.


--
-- Data for Name: finding_evidence; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.finding_evidence (id, finding_id, event_id, evidence_role, note, created_at) FROM stdin;
\.


--
-- Data for Name: finding_status_history; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.finding_status_history (id, finding_id, old_status, new_status, changed_at, changed_by, note) FROM stdin;
\.


--
-- Data for Name: findings; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.findings (id, fingerprint, rule_code, title, severity, confidence, status, first_seen_utc, last_seen_utc, actor, target, source, summary, why_it_matters, recommended_action, evidence_count, status_reason, assigned_to, closed_at, repeat_count, last_evidence_event_id, last_repeat_detected_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: findings_refresh_state; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.findings_refresh_state (pipeline_name, last_event_id, bootstrap_event_id, last_status, last_started_at, last_completed_at, last_failed_at, last_duration_ms, last_scanned_events, last_matched_events, last_created_findings, last_updated_findings, last_evidence_added, last_manual_status_preserved, last_has_more, last_error, updated_at) FROM stdin;
\.


--
-- Data for Name: forests; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.forests (id, name, description, created_at) FROM stdin;
1	__SLI_REPORT_DOMAIN__	\N	2026-10-01 16:00:27.5705+07
\.


--
-- Data for Name: gpo_report_v2_source_snapshots; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.gpo_report_v2_source_snapshots (snapshot_id, domain_id, source_run_id, schema_version, collector_version, collection_status, import_status, source_started_at_utc, source_completed_at_utc, source_observed_at_utc, gpo_count, scope_count, link_count, setting_count, permission_count, wmi_filter_count, payload_json, payload_sha256, created_at) FROM stdin;
\.


--
-- Data for Name: investigation_audit; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.investigation_audit (id, investigation_id, action, actor, payload, created_at) FROM stdin;
\.


--
-- Data for Name: investigation_context_evidence; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.investigation_context_evidence (investigation_id, context_evidence_id, relation_status, added_by, added_at) FROM stdin;
\.


--
-- Data for Name: investigation_events; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.investigation_events (investigation_id, event_db_id, relation_status, added_by, added_at) FROM stdin;
\.


--
-- Data for Name: investigation_evidence_refs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.investigation_evidence_refs (investigation_id, evidence_kind, source_domain_id, reference_id, relation_status, added_by, added_at) FROM stdin;
\.


--
-- Data for Name: investigation_finding_links; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.investigation_finding_links (investigation_id, finding_id, linked_by, linked_at) FROM stdin;
\.


--
-- Data for Name: investigation_notes; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.investigation_notes (id, investigation_id, body, created_by, created_at) FROM stdin;
\.


--
-- Data for Name: investigations; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.investigations (id, title, status, owner, created_by, created_at, updated_at, closed_at, public_id) FROM stdin;
\.


--
-- Data for Name: log_sources; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.log_sources (id, name, provider, description) FROM stdin;
1	Security	Microsoft-Windows-Security-Auditing	Windows Security Event Log
2	System	\N	Windows System Event Log
3	Application	\N	Windows Application Event Log
4	Directory Service	Microsoft-Windows-ActiveDirectory_DomainService	Active Directory Domain Services log
5	DNS Server	Microsoft-Windows-DNS-Server-Service	DNS Server log
6	Windows PowerShell	PowerShell	Windows PowerShell classic log
7	Microsoft-Windows-PowerShell/Operational	Microsoft-Windows-PowerShell	PowerShell operational log
8	Microsoft-Windows-TaskScheduler/Operational	Microsoft-Windows-TaskScheduler	Task Scheduler operational log
\.


--
-- Data for Name: normalized_events; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.normalized_events (normalized_event_id, source_event_id, semantic_contract_version, normalizer_id, normalizer_version, processing_status, normalized_at, source_event_sha256, semantic_sha256, facts_json, quality_json, failure_code, failure_detail, created_at, semantic_type, occurred_at_utc, source_ingested_at, roles_json, source_identity_json) FROM stdin;
\.


--
-- Data for Name: object_identity_links; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.object_identity_links (id, source_object_type, source_object_id, target_object_type, target_object_id, relation_type, source_name, match_method, confidence, observed_at, valid_from, valid_until, created_at) FROM stdin;
\.


--
-- Data for Name: platform_settings; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.platform_settings (key, value, updated_by, updated_at) FROM stdin;
\.


--
-- Data for Name: plugin_component_admission_v1; Type: TABLE DATA; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

COPY public.plugin_component_admission_v1 (plugin_id, component_id, admission_mode, revision, updated_at_utc) FROM stdin;
sli.remote-access	radius-acquisition	closed	1	2026-10-01 16:00:33.136466+07
sli.remote-access	radius-session-observation	closed	1	2026-10-01 16:00:33.136466+07
\.


--
-- Data for Name: plugin_component_leases_v1; Type: TABLE DATA; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

COPY public.plugin_component_leases_v1 (lease_uid, plugin_id, component_id, lease_kind, admission_mode_at_acquire, holder_key, acquired_at_utc, expires_at_utc, released_at_utc, release_outcome) FROM stdin;
\.


--
-- Data for Name: plugin_installations_v1; Type: TABLE DATA; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

COPY public.plugin_installations_v1 (plugin_id, manifest_id, manifest_sha256, package_version, rollback_version, package_lifecycle, desired_activation, observed_health, component_runtime, queue_state, revision, immutable_evidence_count, detach_reader_ready, read_report_parity, created_at_utc, updated_at_utc) FROM stdin;
sli.remote-access	sli.remote-access.package.v1	78ae9bcc2e65f54c8469dd0494f5c951df0cfa53ae33cff84478bc70eaa958bf	0.1.0	\N	validated	disabled	unknown	stopped	drained	1	1	f	f	2026-10-01 16:00:32.981642+07	2026-10-01 16:00:32.981642+07
\.


--
-- Data for Name: plugin_lifecycle_operations_v1; Type: TABLE DATA; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

COPY public.plugin_lifecycle_operations_v1 (operation_id, operation_uid, plugin_id, requested_action, expected_revision, committed_revision, plan_sha256, confirmation_sha256, actor_kind, actor_key, outcome, reason_code, created_at_utc) FROM stdin;
\.


--
-- Data for Name: plugin_state_v1; Type: TABLE DATA; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

COPY public.plugin_state_v1 (plugin_id, configured, last_data_at_utc, updated_at_utc) FROM stdin;
sli.remote-access	f	\N	2026-10-06 07:45:05.157634+07
\.


--
-- Data for Name: post_collection_jobs; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.post_collection_jobs (id, source_job_id, durable_job_id, status, servers_json, queued_at, started_at, finished_at, report_path, error_id, error_message, worker_id, attempt_count, max_attempts, heartbeat_at, worker_lease_until, phase, findings_status, findings_started_at, findings_finished_at, findings_duration_ms, findings_scanned_events, findings_matched_events, findings_created, findings_updated, findings_evidence_added, findings_watermark_before, findings_watermark_after, findings_error_id, findings_error_message, findings_result_json, updated_at) FROM stdin;
\.


--
-- Data for Name: process_episode_evidence; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.process_episode_evidence (revision_id, evidence_order, source_event_id, evidence_role, semantic_type, semantic_contract_version, normalizer_id, normalizer_version, semantic_sha256, observed_at_utc, domain_id, source_host_id, source_channel, event_record_id, source_event_sha256, source_facts_sha256) FROM stdin;
\.


--
-- Data for Name: process_episode_revisions; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.process_episode_revisions (revision_id, episode_id, revision_no, assembler_id, assembler_version, idempotency_key, revision_sha256, revision_payload, evidence_manifest_sha256, evidence_manifest_payload, completeness_state, confirmation_state, ordering_state, domain_id, source_host_id, display_host, boot_event_id, process_id, start_event_id, started_at_utc, end_event_id, confirmed_end_at_utc, process_name, parent_process_id, parent_episode_id, command_line, user_sid, user_name, user_domain, logon_id, evidence_count, recorded_at) FROM stdin;
\.


--
-- Data for Name: radius_accounting_class_cache; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.radius_accounting_class_cache (source_instance_id, class_scope_sha256, exact_principal_key, expires_at_utc, updated_at) FROM stdin;
\.


--
-- Data for Name: radius_accounting_session_observations; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.radius_accounting_session_observations (observation_id, evidence_uid, lifecycle_event, session_identity_key, exact_principal_key, identity_state, observed_at_utc, timestamp_basis, timestamp_state, session_confirmed_by_accounting, producer_contract_id, resource_groups, row_sensitivity, field_categories, evidence_access_requirement, label_policy_version, provenance_json, created_at) FROM stdin;
\.


--
-- Data for Name: radius_session_identity_overlays; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.radius_session_identity_overlays (observation_id, attempt_key, evidence_uid, session_identity_key, exact_principal_key, resolution_input_sha256, resolver_contract_id, created_at) FROM stdin;
\.


--
-- Data for Name: radius_session_projection_receipts; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.radius_session_projection_receipts (delivery_id, observation_id, outcome, projected_row_count, consumer_contract_id, processed_at) FROM stdin;
\.


--
-- Data for Name: radius_session_reconciliation_attempts; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.radius_session_reconciliation_attempts (attempt_key, observation_id, evidence_uid, outcome, evidence_corpus_sha256, resolver_contract_id, resolution_input_sha256, writer_contract_id, created_at) FROM stdin;
\.


--
-- Data for Name: radius_vpn_session_projection; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.radius_vpn_session_projection (session_row_id, session_identity_key, exact_principal_key, generation, lifecycle_state, completeness, started_at_utc, last_observed_at_utc, stopped_at_utc, duration_seconds, observation_count, anomalies, read_model_contract_id, updated_at) FROM stdin;
\.


--
-- Data for Name: raw_batch_lifecycle; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.raw_batch_lifecycle (batch_identity, manifest_hash, server, raw_path, trace_id, expected_channels, committed_channels, import_outcome, cursor_outcome, cleanup_outcome, import_error, cleanup_error, created_at, import_recorded_at, cursor_recorded_at, cleanup_recorded_at, updated_at) FROM stdin;
\.


--
-- Data for Name: raw_log_files; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.raw_log_files (id, collection_run_id, server_id, log_source_id, file_path, file_format, sha256, size_bytes, event_count, exported_at, imported_at) FROM stdin;
\.


--
-- Data for Name: report_access_requests_v4; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.report_access_requests_v4 (id, requester_user_id, report_key, report_version, dataset_version, requested_scope_json, requested_valid_until, business_reason, requested_field_categories, requested_actions, status, decision_reason, granted_scope_json, granted_valid_until, granted_field_categories, granted_actions, assignment_id, decided_by, decided_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: report_datasets_v4; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.report_datasets_v4 (id, dataset_key, version, name, object_type, fields_json, filters_json, actions_json, status, created_at) FROM stdin;
1	security.problems	1	Очередь проблем ИБ	finding	[{"key": "title", "label": "Проблема", "category": "security"}, {"key": "severity", "label": "Risk", "category": "security"}, {"key": "status", "label": "Статус", "category": "security"}, {"key": "evidence_event_id", "label": "Evidence DB ID", "category": "raw_evidence"}]	[{"key": "severity", "ops": ["eq", "in"]}, {"key": "status", "ops": ["eq", "in"]}]	["view", "create_task", "start_case"]	published	2026-10-01 16:00:29.967528+07
2	events.v2	1	События Storage V2	event	[{"key": "id", "label": "Event DB ID", "category": "raw_evidence"}, {"key": "time_created_utc", "label": "UTC", "category": "security"}, {"key": "event_id", "label": "Event ID", "category": "security"}, {"key": "channel", "label": "Канал", "category": "technical"}, {"key": "subject_user_name", "label": "Инициатор", "category": "security"}, {"key": "target_user_name", "label": "Объект", "category": "security"}]	[{"key": "event_id", "ops": ["eq", "in"]}, {"key": "channel", "ops": ["eq"]}, {"key": "time_created_utc", "ops": ["gte", "lte"]}]	["view", "export", "start_case"]	published	2026-10-01 16:00:29.967528+07
3	entities.v2	1	Объекты и сущности	entity	[{"key": "id", "label": "ID", "category": "identity_basic"}, {"key": "entity_type", "label": "Тип", "category": "identity_basic"}, {"key": "display_name", "label": "Имя", "category": "identity_basic"}, {"key": "natural_key", "label": "Natural key", "category": "technical"}, {"key": "last_seen_utc", "label": "Последнее наблюдение", "category": "security"}]	[{"key": "entity_type", "ops": ["eq", "in"]}, {"key": "display_name", "ops": ["contains"]}]	["view", "create_task", "start_case"]	published	2026-10-01 16:00:29.967528+07
7	operations.runtime	1	Готовность и устойчивость проекта	runtime	[{"key": "component", "label": "Компонент", "category": "technical"}, {"key": "state", "label": "Состояние", "category": "technical"}, {"key": "checked_at", "label": "Проверено", "category": "technical"}]	[{"key": "state", "ops": ["eq", "in"]}]	["view", "export"]	published	2026-10-01 16:00:29.967528+07
8	access.subjects	1	Доступы пользователей и групп	access_subject	[{"key": "subject", "label": "Пользователь или группа", "category": "identity_basic"}, {"key": "packages", "label": "Пакеты", "category": "technical"}, {"key": "reports", "label": "Отчёты", "category": "technical"}, {"key": "expires", "label": "Срок", "category": "technical"}]	[]	["view", "grant_access"]	published	2026-10-01 16:00:29.967528+07
4	ad.audit.snapshot	1	__SLI_REPORT_DOMAIN__	ad_infrastructure	[{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "entity_type", "label": "Тип инфраструктуры", "category": "identity_basic"}, {"key": "display_name", "label": "Объект", "category": "identity_basic"}, {"key": "source_section", "label": "Источник сбора", "category": "technical"}, {"key": "domain_controller", "label": "Контроллер домена", "category": "technical"}, {"key": "replication_link", "label": "Связь репликации", "category": "technical"}, {"key": "domain_trust", "label": "Доверие домена", "category": "security"}, {"key": "risk_keys", "label": "Квалифицированные риски", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "risk_key", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}]	["view", "export"]	published	2026-10-01 16:00:29.967528+07
9	ad.accounts.vpn	1	VPN-доступ через группы Active Directory	ad_user	[{"key": "object_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Пользователь", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "enabled", "label": "Включена", "category": "security"}, {"key": "last_logon_utc", "label": "Последний вход", "category": "security"}, {"key": "activity_state", "label": "Состояние активности", "category": "security"}, {"key": "password_never_expires", "label": "Срок действия пароля не ограничен", "category": "security"}, {"key": "admin_count", "label": "Признак защищённой учётной записи", "category": "privilege"}, {"key": "department", "label": "Подразделение", "category": "hr"}, {"key": "title", "label": "Должность", "category": "hr"}, {"key": "email", "label": "Рабочая почта", "category": "contact"}, {"key": "privileged_overlap", "label": "Есть привилегированное членство", "category": "privilege"}, {"key": "observed_at", "label": "Наблюдалось", "category": "security"}]	[{"key": "enabled", "ops": ["eq"]}, {"key": "activity_state", "ops": ["eq", "in"]}, {"key": "privileged_overlap", "ops": ["eq"]}, {"key": "department", "ops": ["eq", "contains"]}]	["view", "create_task", "export"]	published	2026-10-01 16:00:30.081059+07
5	ad.accounts.privileged	1	Привилегированные учётные записи	entity	[{"key": "object_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Учётная запись", "category": "identity_basic"}, {"key": "natural_key", "label": "Login", "category": "technical"}, {"key": "privilege_path", "label": "Путь получения", "category": "privilege"}, {"key": "last_seen_utc", "label": "Наблюдалось", "category": "security"}, {"key": "enabled", "label": "Включена", "category": "security"}, {"key": "is_inactive", "label": "Неактивна", "category": "security"}, {"key": "password_never_expires", "label": "Пароль без срока", "category": "security"}, {"key": "locked_out", "label": "Заблокирована", "category": "security"}, {"key": "last_logon_utc", "label": "Последний вход", "category": "security"}]	[{"key": "privilege", "ops": ["eq", "in"]}]	["view", "create_task", "export"]	published	2026-10-01 16:00:29.967528+07
6	ad.gpo.governance	1	GPO — __SLI_REPORT_DOMAIN__	gpo	[{"key": "object_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "GPO", "category": "identity_basic"}, {"key": "natural_key", "label": "Идентификатор GPO", "category": "identity_basic"}, {"key": "application_state", "label": "Состояние применения", "category": "security"}, {"key": "computer_enabled", "label": "Компьютерная часть включена", "category": "security"}, {"key": "user_enabled", "label": "Пользовательская часть включена", "category": "security"}, {"key": "link_count", "label": "Связи", "category": "security"}, {"key": "link_enabled_count", "label": "Включённые связи", "category": "security"}, {"key": "link_enforced_count", "label": "Принудительные связи", "category": "security"}, {"key": "links", "label": "Наблюдаемые связи", "category": "security"}, {"key": "wmi_filter_present", "label": "WMI-фильтр назначен", "category": "security"}, {"key": "wmi_filter_id", "label": "WMI-фильтр", "category": "security"}, {"key": "permission_count", "label": "Настроенные разрешения", "category": "security"}, {"key": "permission_custom_count", "label": "Нестандартные разрешения", "category": "security"}, {"key": "security_filtering_sids", "label": "Security Filtering — allow SID", "category": "security"}, {"key": "security_filtering_deny_sids", "label": "Security Filtering — deny SID", "category": "security"}, {"key": "startup_script_count", "label": "Startup scripts", "category": "security"}, {"key": "logon_script_count", "label": "Logon scripts", "category": "security"}, {"key": "scheduled_task_count", "label": "Scheduled tasks", "category": "security"}, {"key": "service_count", "label": "Services", "category": "security"}, {"key": "local_group_count", "label": "Local groups", "category": "security"}, {"key": "modified_utc", "label": "Изменена", "category": "security"}, {"key": "observed_at", "label": "Наблюдалось", "category": "security"}, {"key": "settings", "label": "Наблюдаемые настройки GPO", "state": "observed_or_not_collected", "source": "gpmc_xml", "category": "security"}]	[{"key": "application_state", "ops": ["eq"]}, {"key": "link_count", "ops": ["eq"]}, {"key": "has_executable_components", "ops": ["eq"]}]	["view", "create_task", "export"]	published	2026-10-01 16:00:29.967528+07
10	ad.accounts.users	1	Пользователи — __SLI_REPORT_DOMAIN__	ad_user	[{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Пользователь", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "enabled", "label": "Включена", "category": "security"}, {"key": "ou_path", "label": "OU", "category": "identity_basic"}, {"key": "department", "label": "Подразделение", "category": "hr"}, {"key": "title", "label": "Должность", "category": "hr"}, {"key": "email", "label": "Рабочая почта", "category": "contact"}, {"key": "last_logon_utc", "label": "Последний наблюдаемый вход", "category": "security"}, {"key": "password_last_set_utc", "label": "Смена пароля", "category": "security"}, {"key": "direct_privileges", "label": "Прямые привилегии", "category": "privilege"}, {"key": "risks", "label": "Квалифицированные риски", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "department", "ops": ["eq"]}, {"key": "ou", "ops": ["eq"]}, {"key": "risk_key", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}]	["view", "export", "start_case", "accept_risk"]	published	2026-10-01 16:00:34.865523+07
11	ad.assets.computers	1	Компьютеры — __SLI_REPORT_DOMAIN__	ad_computer	[{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "dns_host_name", "label": "DNS-имя", "category": "technical"}, {"key": "computer_type", "label": "Тип", "category": "technical"}, {"key": "enabled", "label": "Включён в AD", "category": "security"}, {"key": "activity_state", "label": "Активность", "category": "security"}, {"key": "ou_path", "label": "Расположение в AD", "category": "identity_basic"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "last_logon_utc", "label": "Последний наблюдаемый вход", "category": "security"}, {"key": "technical_inventory_status", "label": "Техническая инвентаризация", "category": "technical"}, {"key": "ip_addresses", "label": "IP-адреса", "category": "technical"}, {"key": "logical_disks", "label": "Логические диски", "category": "technical"}, {"key": "risks", "label": "Квалифицированные риски", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "risk_key", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "ou", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}]	["view", "export"]	published	2026-10-01 16:00:35.018681+07
14	ad.assets.computers.v5	1	Компьютеры Active Directory v5	ad_computer	[{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "dns_host_name", "label": "DNS-имя", "category": "technical"}, {"key": "distinguished_name", "label": "DN", "category": "technical"}, {"key": "enabled", "label": "Состояние записи AD", "category": "security"}, {"key": "computer_type", "label": "Тип по наблюдаемой ОС", "category": "technical"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "activity", "label": "Приблизительная AD-активность", "category": "security"}, {"key": "quality_issues", "label": "Качество данных", "category": "security"}, {"key": "reasons", "label": "Причины внимания", "category": "security"}, {"key": "semantic_findings", "label": "Точная опубликованная семантика", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "reason_code", "ops": ["eq"]}, {"key": "quality_code", "ops": ["eq"]}, {"key": "enabled", "ops": ["eq"]}, {"key": "type", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "os_version", "ops": ["eq"]}, {"key": "ou", "ops": ["contains"]}, {"key": "q", "ops": ["contains"]}]	["view", "export"]	published	2026-10-01 16:00:35.47853+07
12	ad.assets.computers.v2	1	Компьютеры Active Directory v2	ad_computer	[{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "enabled", "label": "Состояние записи AD", "category": "security"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "activity", "label": "Наблюдаемая AD-активность", "category": "security"}, {"key": "lifecycle", "label": "Жизненный цикл Microsoft", "category": "technical"}, {"key": "evidence", "label": "Полнота данных", "category": "security"}, {"key": "attention_reasons", "label": "Причины внимания", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "reason_code", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "os_version", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}]	["view", "export"]	retired	2026-10-01 16:00:35.356123+07
13	ad.assets.computers.v4	1	Компьютеры Active Directory v4	ad_computer	[{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "dns_host_name", "label": "DNS-имя", "category": "technical"}, {"key": "distinguished_name", "label": "DN", "category": "technical"}, {"key": "enabled", "label": "Состояние записи AD", "category": "security"}, {"key": "computer_type", "label": "Тип по наблюдаемой ОС", "category": "technical"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "activity", "label": "Приблизительная AD-активность", "category": "security"}, {"key": "evidence", "label": "Состояние доказательств", "category": "security"}, {"key": "risks", "label": "Квалифицированные причины внимания", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "risk_key", "ops": ["eq"]}, {"key": "enabled", "ops": ["eq"]}, {"key": "type", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "os_version", "ops": ["eq"]}, {"key": "ou", "ops": ["contains"]}, {"key": "q", "ops": ["contains"]}]	["view", "export"]	retired	2026-10-01 16:00:35.413306+07
15	ad.accounts.users.reference.v2	1	Пользователи Active Directory — reference V1.1	ad_user	[{"key": "displayName", "label": "Пользователь", "category": "identity_basic"}, {"key": "samAccountName", "label": "Логин", "category": "technical"}, {"key": "userPrincipalName", "label": "UPN", "category": "technical"}, {"key": "enabled", "label": "Состояние AD", "category": "security"}, {"key": "lockedOut", "label": "Блокировка", "category": "security"}, {"key": "accountExpirationDate", "label": "Срок учётной записи", "category": "security"}, {"key": "organization", "label": "Организация", "category": "hr"}, {"key": "contacts", "label": "Контакты", "category": "contact"}, {"key": "memberships", "label": "Членство в группах", "category": "privilege"}, {"key": "activity", "label": "Активность", "category": "security"}, {"key": "sourceStates", "label": "Состояния источников", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "account", "ops": ["eq"]}, {"key": "ou", "ops": ["eq"]}, {"key": "department", "ops": ["eq"]}, {"key": "company", "ops": ["eq"]}, {"key": "manager", "ops": ["eq"]}, {"key": "group", "ops": ["eq"]}, {"key": "group_relation", "ops": ["eq"]}, {"key": "profile", "ops": ["eq"]}, {"key": "source", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}]	["view", "export"]	published	2026-10-01 16:00:35.622186+07
16	ad.assets.computers.v6	1	Компьютеры Active Directory v6	ad_computer	[{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "object_guid", "label": "ObjectGUID", "category": "identity_basic"}, {"key": "object_sid", "label": "SID", "category": "security"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "dns_host_name", "label": "DNS-имя", "category": "technical"}, {"key": "distinguished_name", "label": "DN", "category": "technical"}, {"key": "canonical_name", "label": "Canonical name", "category": "technical"}, {"key": "enabled", "label": "Состояние записи AD", "category": "security"}, {"key": "computer_type", "label": "Классификация", "category": "technical"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "activity", "label": "Наблюдаемая AD-активность", "category": "security"}, {"key": "network", "label": "Сеть и AD Site", "category": "technical"}, {"key": "location", "label": "Расположение", "category": "technical"}, {"key": "managed_by", "label": "ManagedBy", "category": "technical"}, {"key": "password_last_set_utc", "label": "PasswordLastSet", "category": "security"}, {"key": "created_utc", "label": "Создан", "category": "technical"}, {"key": "when_changed_utc", "label": "Изменён", "category": "technical"}, {"key": "service_principal_names", "label": "SPN", "category": "security"}, {"key": "delegation", "label": "Делегирование", "category": "security"}, {"key": "quality_issues", "label": "Качество данных", "category": "security"}, {"key": "reasons", "label": "Причины внимания", "category": "security"}, {"key": "semantic_findings", "label": "Точная опубликованная семантика", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "reason_code", "ops": ["eq"]}, {"key": "quality_code", "ops": ["eq"]}, {"key": "enabled", "ops": ["eq"]}, {"key": "type", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "os_version", "ops": ["eq"]}, {"key": "ou", "ops": ["contains"]}, {"key": "ad_site", "ops": ["eq"]}, {"key": "activity", "ops": ["eq"]}, {"key": "threshold_days", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}]	["view", "export"]	published	2026-10-01 16:00:35.827033+07
17	ad.gpo.reference.v2	1	Групповые политики — reference 1.0	gpo	[{"key": "gpos", "label": "GPO", "category": "identity_basic"}, {"key": "scopes", "label": "Области применения", "category": "technical"}, {"key": "links", "label": "Связи", "category": "security"}, {"key": "settings", "label": "Настройки", "category": "security"}, {"key": "permissions", "label": "Права", "category": "privilege"}, {"key": "wmi_filters", "label": "WMI-фильтры", "category": "technical"}, {"key": "source_states", "label": "Качество источников", "category": "security"}]	[{"key": "view", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}, {"key": "reason", "ops": ["eq"]}, {"key": "source_status", "ops": ["eq"]}, {"key": "stale_days", "ops": ["eq"]}]	["view", "export"]	published	2026-10-01 16:00:36.062689+07
18	ad.authentication.computer-logons	1	Наблюдения входов на рабочие станции	ad_computer	[{"key": "entity_id", "label": "ID ПК", "category": "computer_logon_observation"}, {"key": "display_name", "label": "Компьютер", "category": "computer_logon_observation"}, {"key": "last_observed_logon_at_utc", "label": "Последнее наблюдение", "category": "computer_logon_observation"}, {"key": "login_count", "label": "Число входов", "category": "computer_logon_observation"}, {"key": "user_name", "label": "Доменный пользователь", "category": "computer_logon_observation"}, {"key": "observed_at_utc", "label": "Время наблюдения UTC", "category": "computer_logon_observation"}]	[{"key": "q", "ops": ["contains"]}, {"key": "from_utc", "ops": ["gte"]}, {"key": "to_utc_exclusive", "ops": ["lt"]}]	["view"]	published	2026-10-01 16:00:36.853984+07
19	security.events.atomic	1	Действия безопасности	security_event	[{"key": "time_created_utc", "label": "Время", "category": "security"}, {"key": "event_id", "label": "Event ID", "category": "technical"}, {"key": "event_family", "label": "Категория", "category": "security"}, {"key": "actor", "label": "Исполнитель", "category": "security"}, {"key": "affected_account", "label": "Затронутая учётная запись", "category": "security"}, {"key": "member", "label": "Участник группы", "category": "security"}, {"key": "group", "label": "Группа", "category": "security"}, {"key": "source_host", "label": "Источник", "category": "technical"}, {"key": "outcome", "label": "Результат", "category": "security"}, {"key": "evidence", "label": "Исходное доказательство", "category": "raw_evidence"}]	[{"key": "time_from", "ops": ["gte"]}, {"key": "time_to", "ops": ["lt"]}, {"key": "timezone", "ops": ["eq"]}, {"key": "domain_id", "ops": ["eq"]}, {"key": "category", "ops": ["eq"]}, {"key": "event_id", "ops": ["eq"]}, {"key": "outcome", "ops": ["eq"]}, {"key": "actor", "ops": ["eq"]}, {"key": "target", "ops": ["eq"]}, {"key": "group", "ops": ["eq"]}, {"key": "source", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}]	["view", "export", "start_case"]	published	2026-10-01 16:00:37.547503+07
\.


--
-- Data for Name: report_items; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.report_items (id, report_id, detection_id, ai_analysis_id, sort_order) FROM stdin;
\.


--
-- Data for Name: report_registry_v4; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.report_registry_v4 (id, report_key, version, name, owner_name, purpose, dataset_id, definition_json, sensitivity, status, published_at, created_by, created_at, discoverable, requestable, request_profile_json) FROM stdin;
1	investigations.workspace	1	Расследования	ИБ	Дела, evidence и решения аналитика	1	{"actions": ["view", "start_case"], "columns": [{"key": "title", "label": "Проблема", "category": "security"}, {"key": "severity", "label": "Risk", "category": "security"}, {"key": "status", "label": "Статус", "category": "security"}, {"key": "evidence_event_id", "label": "Evidence DB ID", "category": "raw_evidence"}], "filters": [{"key": "severity", "ops": ["eq", "in"]}, {"key": "status", "ops": ["eq", "in"]}], "target_path": "/investigations", "default_sort": [], "export_policy": "disabled", "field_categories": ["security"], "required_capabilities": ["investigations.view"]}	restricted	published	2026-10-01 16:00:29.967528+07	\N	2026-10-01 16:00:29.967528+07	t	t	{"scope_kinds": ["all"], "allowed_actions": ["view", "start_case"], "field_categories": ["security"], "max_duration_days": 90}
3	events.explorer	1	Технические события	ИБ	Bounded evidence explorer с точным event_db_id	2	{"actions": ["view", "export", "start_case"], "columns": [{"key": "id", "label": "Event DB ID", "category": "raw_evidence"}, {"key": "time_created_utc", "label": "UTC", "category": "security"}, {"key": "event_id", "label": "Event ID", "category": "security"}, {"key": "channel", "label": "Канал", "category": "technical"}, {"key": "subject_user_name", "label": "Инициатор", "category": "security"}, {"key": "target_user_name", "label": "Объект", "category": "security"}], "filters": [{"key": "event_id", "ops": ["eq", "in"]}, {"key": "channel", "ops": ["eq"]}, {"key": "time_created_utc", "ops": ["gte", "lte"]}], "target_path": "/events", "default_sort": [], "export_policy": "controlled", "field_categories": ["security", "technical", "raw_evidence"], "required_capabilities": ["events.view"]}	confidential	published	2026-10-01 16:00:29.967528+07	\N	2026-10-01 16:00:29.967528+07	t	t	{"scope_kinds": ["all", "server", "domain", "channel"], "allowed_actions": ["view", "export", "start_case"], "field_categories": ["security", "technical", "raw_evidence"], "max_duration_days": 90}
2	security.queue	1	Очередь проблем ИБ	ИБ	Что произошло, влияние, гипотеза и безопасный следующий шаг	1	{"actions": ["view", "create_task", "start_case"], "columns": [{"key": "title", "label": "Проблема", "category": "security"}, {"key": "severity", "label": "Risk", "category": "security"}, {"key": "status", "label": "Статус", "category": "security"}, {"key": "evidence_event_id", "label": "Evidence DB ID", "category": "raw_evidence"}], "filters": [{"key": "severity", "ops": ["eq", "in"]}, {"key": "status", "ops": ["eq", "in"]}], "target_path": "/problems", "default_sort": [], "export_policy": "disabled", "field_categories": ["security"], "dashboard_metrics": [{"key": "security.open_problems", "icon": "warning", "kind": "required", "tone": "bad", "unit": null, "label": "Проблемы ИБ", "caption": "в доступном срезе очереди", "filters": {}, "priority": 10, "value_path": "summary.total_items", "target_path": "/problems", "freshness_path": "summary.latest_observed_at_utc", "default_selected": false}], "required_capabilities": ["workspace.view"]}	restricted	published	2026-10-01 16:00:29.967528+07	\N	2026-10-01 16:00:29.967528+07	t	t	{"scope_kinds": ["all"], "allowed_actions": ["view", "create_task", "start_case"], "field_categories": ["security"], "max_duration_days": 90}
7	operations.readiness	1	Готовность и устойчивость проекта	Проект	Workers, queues, PostgreSQL и readiness	7	{"actions": ["view", "export"], "columns": [{"key": "component", "label": "Компонент", "category": "technical"}, {"key": "state", "label": "Состояние", "category": "technical"}, {"key": "checked_at", "label": "Проверено", "category": "technical"}], "filters": [{"key": "state", "ops": ["eq", "in"]}], "target_path": "/operations", "default_sort": [], "export_policy": "controlled", "field_categories": ["technical"], "required_capabilities": ["operations.view"]}	internal	published	2026-10-01 16:00:29.967528+07	\N	2026-10-01 16:00:29.967528+07	t	t	{"scope_kinds": ["all"], "allowed_actions": ["view", "export"], "field_categories": ["technical"], "max_duration_days": 90}
8	access.center	1	Доступы пользователей и групп	Администратор доступа	Пакеты, grants, scopes, сроки и explain	8	{"actions": ["view", "grant_access"], "columns": [{"key": "subject", "label": "Пользователь или группа", "category": "identity_basic"}, {"key": "packages", "label": "Пакеты", "category": "technical"}, {"key": "reports", "label": "Отчёты", "category": "technical"}, {"key": "expires", "label": "Срок", "category": "technical"}], "filters": [], "target_path": "/access", "default_sort": [], "export_policy": "disabled", "field_categories": [], "required_capabilities": ["access.manage"]}	confidential	published	2026-10-01 16:00:29.967528+07	\N	2026-10-01 16:00:29.967528+07	t	t	{"scope_kinds": ["all"], "allowed_actions": ["view", "grant_access"], "field_categories": [], "max_duration_days": 90}
9	vpn.audit	1	VPN-доступ и актуальность владельцев	AD / ИТ	Проверка пользователей, получающих VPN-доступ через явно заданные группы Active Directory	9	{"actions": ["view", "create_task", "export"], "columns": [{"key": "object_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Пользователь", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "enabled", "label": "Включена", "category": "security"}, {"key": "last_logon_utc", "label": "Последний вход", "category": "security"}, {"key": "activity_state", "label": "Состояние активности", "category": "security"}, {"key": "password_never_expires", "label": "Срок действия пароля не ограничен", "category": "security"}, {"key": "admin_count", "label": "Признак защищённой учётной записи", "category": "privilege"}, {"key": "department", "label": "Подразделение", "category": "hr"}, {"key": "title", "label": "Должность", "category": "hr"}, {"key": "email", "label": "Рабочая почта", "category": "contact"}, {"key": "privileged_overlap", "label": "Есть привилегированное членство", "category": "privilege"}, {"key": "observed_at", "label": "Наблюдалось", "category": "security"}], "filters": [{"key": "enabled", "ops": ["eq"]}, {"key": "activity_state", "ops": ["eq", "in"]}, {"key": "privileged_overlap", "ops": ["eq"]}, {"key": "department", "ops": ["eq", "contains"]}], "target_path": "/vpn-report", "default_sort": [{"field": "privileged_overlap", "direction": "desc"}, {"field": "activity_state", "direction": "asc"}], "export_policy": "controlled", "field_categories": ["identity_basic", "technical", "security", "privilege", "hr", "contact"], "dashboard_metrics": [{"key": "ad.vpn_disabled_accounts", "icon": "lock", "kind": "optional", "tone": "warn", "unit": null, "label": "Отключённые VPN-учётные записи", "caption": "в назначенных VPN-группах", "filters": {"activity_state": "disabled"}, "priority": 30, "value_path": "summary.disabled_users", "target_path": "/vpn-report", "freshness_path": "summary.latest_observed_at_utc", "default_selected": true}], "required_capabilities": ["objects.groups"]}	confidential	published	2026-10-01 16:00:30.081059+07	\N	2026-10-01 16:00:30.081059+07	t	t	{"scope_kinds": ["all", "server", "domain"], "allowed_actions": ["view", "create_task", "export"], "field_categories": ["identity_basic", "technical", "security", "privilege", "hr", "contact"], "max_duration_days": 90}
4	ad.state	1	__SLI_REPORT_DOMAIN__	AD / ИТ	Работоспособность и защищённость домена, контроллеров, репликации, DNS, политик и доверий	4	{"actions": ["view", "export"], "columns": [{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "entity_type", "label": "Тип инфраструктуры", "category": "identity_basic"}, {"key": "display_name", "label": "Объект", "category": "identity_basic"}, {"key": "source_section", "label": "Источник сбора", "category": "technical"}, {"key": "domain_controller", "label": "Контроллер домена", "category": "technical"}, {"key": "replication_link", "label": "Связь репликации", "category": "technical"}, {"key": "domain_trust", "label": "Доверие домена", "category": "security"}, {"key": "risk_keys", "label": "Квалифицированные риски", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}], "filters": [{"key": "view", "ops": ["eq"]}, {"key": "risk_key", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/ad-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "technical", "security"], "required_capabilities": ["objects.view"]}	restricted	published	2026-10-01 16:00:29.967528+07	\N	2026-10-01 16:00:29.967528+07	t	t	{"scope_kinds": ["all", "server", "domain"], "allowed_actions": ["view", "create_task"], "field_categories": ["identity_basic", "security", "technical"], "max_duration_days": 90}
5	ad.privileged	1	Привилегированные учётные записи	ИБ + ИТ	Direct/nested privileges и evidence path	5	{"actions": ["view", "create_task", "export"], "columns": [{"key": "object_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Учётная запись", "category": "identity_basic"}, {"key": "natural_key", "label": "Login", "category": "technical"}, {"key": "privilege_path", "label": "Путь получения", "category": "privilege"}, {"key": "last_seen_utc", "label": "Наблюдалось", "category": "security"}, {"key": "enabled", "label": "Включена", "category": "security"}, {"key": "is_inactive", "label": "Неактивна", "category": "security"}, {"key": "password_never_expires", "label": "Пароль без срока", "category": "security"}, {"key": "locked_out", "label": "Заблокирована", "category": "security"}, {"key": "last_logon_utc", "label": "Последний вход", "category": "security"}], "filters": [{"key": "privilege", "ops": ["eq", "in"]}], "target_path": "/privileged-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "privilege", "technical", "security"], "dashboard_metrics": [{"key": "ad.privileged_relations", "icon": "key", "kind": "required", "tone": "accent", "unit": null, "label": "Привилегированные связи", "caption": "подтверждено отчётом", "filters": {}, "priority": 20, "value_path": "summary.total_relations", "target_path": "/privileged-report", "freshness_path": "summary.latest_observed_at_utc", "default_selected": false}], "required_capabilities": ["objects.privileges"]}	confidential	retired	2026-10-01 16:00:29.967528+07	\N	2026-10-01 16:00:29.967528+07	t	t	{"scope_kinds": ["all", "server", "domain"], "allowed_actions": ["view", "create_task", "export"], "field_categories": ["identity_basic", "privilege", "technical", "security"], "max_duration_days": 90}
6	ad.gpo.review	1	GPO — __SLI_REPORT_DOMAIN__	AD / ИТ	Наблюдаемые факты GPMC, применение и очередь ручной проверки без автоматического изменения GPO	6	{"actions": ["view", "create_task", "export"], "columns": [{"key": "object_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "GPO", "category": "identity_basic"}, {"key": "natural_key", "label": "Идентификатор GPO", "category": "identity_basic"}, {"key": "application_state", "label": "Состояние применения", "category": "security"}, {"key": "computer_enabled", "label": "Компьютерная часть включена", "category": "security"}, {"key": "user_enabled", "label": "Пользовательская часть включена", "category": "security"}, {"key": "link_count", "label": "Связи", "category": "security"}, {"key": "link_enabled_count", "label": "Включённые связи", "category": "security"}, {"key": "link_enforced_count", "label": "Принудительные связи", "category": "security"}, {"key": "links", "label": "Наблюдаемые связи", "category": "security"}, {"key": "wmi_filter_present", "label": "WMI-фильтр назначен", "category": "security"}, {"key": "wmi_filter_id", "label": "WMI-фильтр", "category": "security"}, {"key": "permission_count", "label": "Настроенные разрешения", "category": "security"}, {"key": "permission_custom_count", "label": "Нестандартные разрешения", "category": "security"}, {"key": "security_filtering_sids", "label": "Security Filtering — allow SID", "category": "security"}, {"key": "security_filtering_deny_sids", "label": "Security Filtering — deny SID", "category": "security"}, {"key": "startup_script_count", "label": "Startup scripts", "category": "security"}, {"key": "logon_script_count", "label": "Logon scripts", "category": "security"}, {"key": "scheduled_task_count", "label": "Scheduled tasks", "category": "security"}, {"key": "service_count", "label": "Services", "category": "security"}, {"key": "local_group_count", "label": "Local groups", "category": "security"}, {"key": "modified_utc", "label": "Изменена", "category": "security"}, {"key": "observed_at", "label": "Наблюдалось", "category": "security"}, {"key": "settings", "label": "Наблюдаемые настройки GPO", "category": "security"}], "filters": [{"key": "application_state", "ops": ["eq"]}, {"key": "link_count", "ops": ["eq"]}, {"key": "has_executable_components", "ops": ["eq"]}], "target_path": "/gpo-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "security"], "dashboard_metrics": [{"key": "ad.gpo_manual_review", "icon": "settings", "kind": "optional", "tone": "good", "unit": null, "label": "GPO на ручной проверке", "caption": "требуют решения специалиста", "filters": {}, "priority": 40, "value_path": "summary.manual_review_count", "target_path": "/gpo-report", "freshness_path": "summary.latest_observed_at_utc", "default_selected": true}], "required_capabilities": ["objects.view"]}	restricted	retired	2026-10-01 16:00:29.967528+07	\N	2026-10-01 16:00:29.967528+07	t	t	{"scope_kinds": ["all", "server", "domain"], "allowed_actions": ["view", "create_task"], "field_categories": ["identity_basic", "security"], "max_duration_days": 90}
12	ad.computers.v2	1	Компьютеры v2	AD / ИТ	Evidence-first рабочая очередь компьютерных записей AD без подмены состояния учётной записи состоянием устройства	12	{"actions": ["view", "export"], "columns": [{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "enabled", "label": "Состояние записи AD", "category": "security"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "activity", "label": "Наблюдаемая AD-активность", "category": "security"}, {"key": "lifecycle", "label": "Жизненный цикл Microsoft", "category": "technical"}, {"key": "evidence", "label": "Полнота данных", "category": "security"}, {"key": "attention_reasons", "label": "Причины внимания", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}], "filters": [{"key": "view", "ops": ["eq"]}, {"key": "reason_code", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "os_version", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/computers-v2-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "technical", "security"], "required_capabilities": ["objects.view"]}	restricted	retired	2026-10-01 16:00:35.356123+07	\N	2026-10-01 16:00:35.356123+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
10	ad.users	1	Пользователи — __SLI_REPORT_DOMAIN__	ИБ + администраторы доступов	Единое рабочее пространство состояния, прямых привилегий и рисков учётных записей AD	10	{"actions": ["view", "export", "start_case", "accept_risk"], "columns": [{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Пользователь", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "enabled", "label": "Включена", "category": "security"}, {"key": "ou_path", "label": "OU", "category": "identity_basic"}, {"key": "department", "label": "Подразделение", "category": "hr"}, {"key": "title", "label": "Должность", "category": "hr"}, {"key": "email", "label": "Рабочая почта", "category": "contact"}, {"key": "last_logon_utc", "label": "Последний наблюдаемый вход", "category": "security"}, {"key": "password_last_set_utc", "label": "Смена пароля", "category": "security"}, {"key": "direct_privileges", "label": "Прямые привилегии", "category": "privilege"}, {"key": "risks", "label": "Квалифицированные риски", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}], "filters": [{"key": "view", "ops": ["eq"]}, {"key": "department", "ops": ["eq"]}, {"key": "ou", "ops": ["eq"]}, {"key": "risk_key", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/users-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "technical", "security", "privilege", "hr", "contact"], "required_capabilities": ["objects.view"]}	confidential	retired	2026-10-01 16:00:34.865523+07	\N	2026-10-01 16:00:34.865523+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
11	ad.computers	1	Компьютеры — __SLI_REPORT_DOMAIN__	AD / ИТ	Рабочие станции, серверы, активность, операционные системы, квалифицированные риски и опубликованная семантика	11	{"actions": ["view", "export"], "columns": [{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "dns_host_name", "label": "DNS-имя", "category": "technical"}, {"key": "computer_type", "label": "Тип", "category": "technical"}, {"key": "enabled", "label": "Включён в AD", "category": "security"}, {"key": "activity_state", "label": "Активность", "category": "security"}, {"key": "ou_path", "label": "Расположение в AD", "category": "identity_basic"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "last_logon_utc", "label": "Последний наблюдаемый вход", "category": "security"}, {"key": "technical_inventory_status", "label": "Техническая инвентаризация", "category": "technical"}, {"key": "ip_addresses", "label": "IP-адреса", "category": "technical"}, {"key": "logical_disks", "label": "Логические диски", "category": "technical"}, {"key": "risks", "label": "Квалифицированные риски", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}], "filters": [{"key": "view", "ops": ["eq"]}, {"key": "risk_key", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "ou", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/computers-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "technical", "security"], "required_capabilities": ["objects.view"]}	restricted	retired	2026-10-01 16:00:35.018681+07	\N	2026-10-01 16:00:35.018681+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
13	ad.computers.v4	1	Компьютеры v4	AD / ИТ	Рабочий отчёт V1 с исправленными когортами AD, явными evidence-ограничениями и сохранёнными сценариями инвентаризации	13	{"actions": ["view", "export"], "columns": [{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "dns_host_name", "label": "DNS-имя", "category": "technical"}, {"key": "distinguished_name", "label": "DN", "category": "technical"}, {"key": "enabled", "label": "Состояние записи AD", "category": "security"}, {"key": "computer_type", "label": "Тип по наблюдаемой ОС", "category": "technical"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "activity", "label": "Приблизительная AD-активность", "category": "security"}, {"key": "evidence", "label": "Состояние доказательств", "category": "security"}, {"key": "risks", "label": "Квалифицированные причины внимания", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}], "filters": [{"key": "view", "ops": ["eq"]}, {"key": "risk_key", "ops": ["eq"]}, {"key": "enabled", "ops": ["eq"]}, {"key": "type", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "os_version", "ops": ["eq"]}, {"key": "ou", "ops": ["contains"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/computers-v4-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "technical", "security"], "required_capabilities": ["objects.view"]}	restricted	retired	2026-10-01 16:00:35.413306+07	\N	2026-10-01 16:00:35.413306+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
14	ad.computers.v5	1	Компьютеры v5	AD / ИТ	Интерактивный evidence-first отчёт по утверждённому AD Inventory Evidence reference с изменениями, качеством данных и точной опубликованной семантикой	14	{"actions": ["view", "export"], "columns": [{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "dns_host_name", "label": "DNS-имя", "category": "technical"}, {"key": "distinguished_name", "label": "DN", "category": "technical"}, {"key": "enabled", "label": "Состояние записи AD", "category": "security"}, {"key": "computer_type", "label": "Тип по наблюдаемой ОС", "category": "technical"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "activity", "label": "Приблизительная AD-активность", "category": "security"}, {"key": "quality_issues", "label": "Качество данных", "category": "security"}, {"key": "reasons", "label": "Причины внимания", "category": "security"}, {"key": "semantic_findings", "label": "Точная опубликованная семантика", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}], "filters": [{"key": "view", "ops": ["eq"]}, {"key": "reason_code", "ops": ["eq"]}, {"key": "quality_code", "ops": ["eq"]}, {"key": "enabled", "ops": ["eq"]}, {"key": "type", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "os_version", "ops": ["eq"]}, {"key": "ou", "ops": ["contains"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/computers-v5-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "technical", "security"], "required_capabilities": ["objects.view"]}	restricted	retired	2026-10-01 16:00:35.47853+07	\N	2026-10-01 16:00:35.47853+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
15	ad.users.v2	1	Пользователи — __SLI_REPORT_DOMAIN__	AD / ИБ	Интерактивный evidence-first отчёт по пользователям AD на основе утверждённого reference V1.1	15	{"actions": ["view", "export"], "columns": [{"key": "displayName", "label": "Пользователь", "category": "identity_basic"}, {"key": "samAccountName", "label": "Логин", "category": "technical"}, {"key": "userPrincipalName", "label": "UPN", "category": "technical"}, {"key": "enabled", "label": "Состояние AD", "category": "security"}, {"key": "lockedOut", "label": "Блокировка", "category": "security"}, {"key": "accountExpirationDate", "label": "Срок учётной записи", "category": "security"}, {"key": "organization", "label": "Организация", "category": "hr"}, {"key": "contacts", "label": "Контакты", "category": "contact"}, {"key": "memberships", "label": "Членство в группах", "category": "privilege"}, {"key": "activity", "label": "Активность", "category": "security"}, {"key": "sourceStates", "label": "Состояния источников", "category": "security"}], "filters": [{"key": "view", "ops": ["eq"]}, {"key": "account", "ops": ["eq"]}, {"key": "ou", "ops": ["eq"]}, {"key": "department", "ops": ["eq"]}, {"key": "company", "ops": ["eq"]}, {"key": "manager", "ops": ["eq"]}, {"key": "group", "ops": ["eq"]}, {"key": "group_relation", "ops": ["eq"]}, {"key": "profile", "ops": ["eq"]}, {"key": "source", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/users-v2-report", "default_sort": [], "export_policy": "controlled-client-from-authorized-snapshot", "field_categories": ["identity_basic", "technical", "security", "privilege", "hr", "contact"], "required_capabilities": ["objects.view"]}	restricted	published	2026-10-01 16:00:35.622186+07	\N	2026-10-01 16:00:35.622186+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
16	ad.computers.v6	1	Компьютеры — __SLI_REPORT_DOMAIN__	AD / ИТ	Evidence-first инвентарь компьютеров AD по утверждённому executable reference с явными состояниями источников	16	{"actions": ["view", "export"], "columns": [{"key": "entity_id", "label": "ID объекта", "category": "identity_basic"}, {"key": "object_guid", "label": "ObjectGUID", "category": "identity_basic"}, {"key": "object_sid", "label": "SID", "category": "security"}, {"key": "display_name", "label": "Компьютер", "category": "identity_basic"}, {"key": "natural_key", "label": "Учётная запись", "category": "technical"}, {"key": "dns_host_name", "label": "DNS-имя", "category": "technical"}, {"key": "distinguished_name", "label": "DN", "category": "technical"}, {"key": "canonical_name", "label": "Canonical name", "category": "technical"}, {"key": "enabled", "label": "Состояние записи AD", "category": "security"}, {"key": "computer_type", "label": "Классификация", "category": "technical"}, {"key": "operating_system", "label": "Операционная система", "category": "technical"}, {"key": "operating_system_version", "label": "Версия ОС", "category": "technical"}, {"key": "activity", "label": "Наблюдаемая AD-активность", "category": "security"}, {"key": "network", "label": "Сеть и AD Site", "category": "technical"}, {"key": "location", "label": "Расположение", "category": "technical"}, {"key": "managed_by", "label": "ManagedBy", "category": "technical"}, {"key": "password_last_set_utc", "label": "PasswordLastSet", "category": "security"}, {"key": "created_utc", "label": "Создан", "category": "technical"}, {"key": "when_changed_utc", "label": "Изменён", "category": "technical"}, {"key": "service_principal_names", "label": "SPN", "category": "security"}, {"key": "delegation", "label": "Делегирование", "category": "security"}, {"key": "quality_issues", "label": "Качество данных", "category": "security"}, {"key": "reasons", "label": "Причины внимания", "category": "security"}, {"key": "semantic_findings", "label": "Точная опубликованная семантика", "category": "security"}, {"key": "observed_at_utc", "label": "Наблюдалось", "category": "security"}], "filters": [{"key": "view", "ops": ["eq"]}, {"key": "reason_code", "ops": ["eq"]}, {"key": "quality_code", "ops": ["eq"]}, {"key": "enabled", "ops": ["eq"]}, {"key": "type", "ops": ["eq"]}, {"key": "os", "ops": ["eq"]}, {"key": "os_version", "ops": ["eq"]}, {"key": "ou", "ops": ["contains"]}, {"key": "ad_site", "ops": ["eq"]}, {"key": "activity", "ops": ["eq"]}, {"key": "threshold_days", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/computers-v6-report", "default_sort": [], "export_policy": "controlled", "field_categories": ["identity_basic", "technical", "security"], "required_capabilities": ["objects.view"]}	restricted	published	2026-10-01 16:00:35.827033+07	\N	2026-10-01 16:00:35.827033+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
17	ad.gpo.v2	1	Групповые политики — __SLI_REPORT_DOMAIN__	AD / ИБ	Самостоятельный evidence-first отчёт по GPO из sli.ad-gpo.snapshot/1.0; не является RSoP и не изменяет ad.gpo.review	17	{"actions": ["view", "export"], "pagination": false, "target_path": "/gpo-v2-report", "default_view": "attention", "export_policy": "controlled-client-from-authorized-snapshot", "field_categories": ["identity_basic", "technical", "security", "privilege"], "previous_snapshot": "latest-two-compatible-completed", "snapshot_contract": "sli.ad-gpo.snapshot/1.0", "required_capabilities": ["objects.view"]}	restricted	published	2026-10-01 16:00:36.062689+07	\N	2026-10-01 16:00:36.062689+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
18	ad.computer-logons	1	что где когда	AD / ИТ	Приблизительная история успешных входов доменных пользователей на рабочие станции __SLI_REPORT_DOMAIN__	18	{"actions": ["view"], "columns": [{"key": "entity_id", "label": "ID ПК", "category": "computer_logon_observation"}, {"key": "display_name", "label": "Компьютер", "category": "computer_logon_observation"}, {"key": "last_observed_logon_at_utc", "label": "Последнее наблюдение", "category": "computer_logon_observation"}, {"key": "login_count", "label": "Число входов", "category": "computer_logon_observation"}, {"key": "user_name", "label": "Доменный пользователь", "category": "computer_logon_observation"}, {"key": "observed_at_utc", "label": "Время наблюдения UTC", "category": "computer_logon_observation"}], "filters": [{"key": "q", "ops": ["contains"]}, {"key": "from_utc", "ops": ["gte"]}, {"key": "to_utc_exclusive", "ops": ["lt"]}], "target_path": "/what-where-when-report", "default_sort": ["display_name", "asc"], "export_policy": "disabled", "field_categories": ["computer_logon_observation"], "required_capabilities": ["objects.view"]}	restricted	published	2026-10-01 16:00:36.853984+07	\N	2026-10-01 16:00:36.853984+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
19	security.events.chains	1	Действия безопасности	ИБ	Проверяемая история действий, доказанные последовательности и явные пробелы покрытия без автоматического обвинительного вывода	19	{"actions": ["view", "export", "start_case"], "columns": [{"key": "time_created_utc", "label": "Время", "category": "security"}, {"key": "event_id", "label": "Event ID", "category": "technical"}, {"key": "event_family", "label": "Категория", "category": "security"}, {"key": "actor", "label": "Исполнитель", "category": "security"}, {"key": "affected_account", "label": "Затронутая учётная запись", "category": "security"}, {"key": "member", "label": "Участник группы", "category": "security"}, {"key": "group", "label": "Группа", "category": "security"}, {"key": "source_host", "label": "Источник", "category": "technical"}, {"key": "outcome", "label": "Результат", "category": "security"}, {"key": "evidence", "label": "Исходное доказательство", "category": "raw_evidence"}], "filters": [{"key": "time_from", "ops": ["gte"]}, {"key": "time_to", "ops": ["lt"]}, {"key": "timezone", "ops": ["eq"]}, {"key": "domain_id", "ops": ["eq"]}, {"key": "category", "ops": ["eq"]}, {"key": "event_id", "ops": ["eq"]}, {"key": "outcome", "ops": ["eq"]}, {"key": "actor", "ops": ["eq"]}, {"key": "target", "ops": ["eq"]}, {"key": "group", "ops": ["eq"]}, {"key": "source", "ops": ["eq"]}, {"key": "q", "ops": ["contains"]}], "target_path": "/security-events-report", "default_sort": ["time_created_utc", "desc"], "export_policy": "controlled", "field_categories": ["identity_basic", "security", "technical", "raw_evidence"], "required_capabilities": ["events.view", "evidence.exact"]}	confidential	published	2026-10-01 16:00:37.547503+07	\N	2026-10-01 16:00:37.547503+07	t	f	{"scope_kinds": ["all"], "max_duration_days": 90}
\.


--
-- Data for Name: reports; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.reports (id, title, report_type, period_start_utc, period_end_utc, generated_at, file_path, status) FROM stdin;
\.


--
-- Data for Name: runtime_collection_blocks; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.runtime_collection_blocks (singleton_id, active, reason_code, retry_policy, operator_action, source_worker_id, source_job_id, source_server, evidence_json, observed_count, first_seen_at, last_seen_at, last_probe_at, last_probe_result, cleared_at, cleared_by, updated_at) FROM stdin;
\.


--
-- Data for Name: runtime_collection_runs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.runtime_collection_runs (run_id, worker_id, job_id, status, phase, servers_json, hours, max_events_per_channel, created_at, started_at, finished_at, duration_ms, errors_json, updated_at) FROM stdin;
\.


--
-- Data for Name: runtime_worker_heartbeats; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.runtime_worker_heartbeats (worker_name, worker_id, process_pid, status, phase, expected_interval_seconds, details_json, started_at, heartbeat_at, updated_at) FROM stdin;
\.


--
-- Data for Name: schema_migrations; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.schema_migrations (id, version, name, applied_at) FROM stdin;
1	1	initial_postgres_schema	2026-10-01 16:00:27.416738+07
2	2	stage_4_1_persistent_findings	2026-10-01 16:00:27.416738+07
3	3	stage_4_3_ai_api_prompt_runs	2026-10-01 16:00:27.416738+07
4	4	stage_4_4_ai_report_pipeline	2026-10-01 16:00:27.416738+07
5	5	db_0_1_postgres_readiness	2026-10-01 16:00:27.416738+07
6	6	findings_pg1_incremental_pipeline	2026-10-01 16:00:27.416738+07
7	7	storage_lifecycle2_measurement_and_backup_rehearsal	2026-10-01 16:00:27.416738+07
8	8	ops_stability1_runtime_contracts	2026-10-01 16:00:27.416738+07
9	9	storage_v2_foundation	2026-10-01 16:00:27.724092+07
10	10	storage_v2_backfill_support	2026-10-01 16:00:27.845927+07
11	11	storage_v2_runtime_routing	2026-10-01 16:00:27.926107+07
12	12	storage_v2_external_reference_cutover	2026-10-01 16:00:28.024723+07
13	14	local_auth_runtime_guard	2026-10-01 16:00:28.133877+07
14	15	investigation_cases	2026-10-01 16:00:28.420474+07
15	16	investigation_evidence_v2	2026-10-01 16:00:28.516484+07
16	17	ad_context_foundation	2026-10-01 16:00:28.570115+07
17	18	investigation_public_identity	2026-10-01 16:00:28.655785+07
18	19	entity_state_projection	2026-10-01 16:00:28.713784+07
19	20	casefold_search_indexes	2026-10-01 16:00:28.867242+07
20	21	storage_v2_entity_detail_kind	2026-10-01 16:00:28.915271+07
21	22	semantic_processing_foundation	2026-10-01 16:00:28.98727+07
22	23	canonical_action_confirmation_statuses	2026-10-01 16:00:29.080723+07
23	24	canonical_action_state_evidence	2026-10-01 16:00:29.142587+07
24	25	semantic_persistence_contract	2026-10-01 16:00:29.207657+07
25	26	semantic_correlation_foundation	2026-10-01 16:00:29.283214+07
26	27	semantic_dispatch_foundation	2026-10-01 16:00:29.365436+07
27	28	semantic_risk_scenarios	2026-10-01 16:00:29.442788+07
28	29	semantic_risk_runtime	2026-10-01 16:00:29.533851+07
29	30	entity_state_evidence_identity	2026-10-01 16:00:29.631916+07
30	31	entity_state_conflict_key_privilege	2026-10-01 16:00:29.684903+07
31	32	runtime_worker_heartbeats	2026-10-01 16:00:29.73876+07
32	33	semantic_calibration_reviews	2026-10-01 16:00:29.818004+07
33	34	ad_context_entities_v2	2026-10-01 16:00:29.884189+07
34	35	sli_v4_access_reports_objects	2026-10-01 16:00:29.967528+07
35	36	ad_audit_vpn_gpo_source	2026-10-01 16:00:30.081059+07
36	37	platform_owner_access	2026-10-01 16:00:30.137607+07
37	38	runtime_collection_blocks	2026-10-01 16:00:30.217509+07
38	39	stage6_dashboard_metrics	2026-10-01 16:00:30.294176+07
39	40	stage6_report_access_requests	2026-10-01 16:00:30.351133+07
40	41	stage6_report_workspaces	2026-10-01 16:00:30.432507+07
41	42	stage6_report_workspace_routes	2026-10-01 16:00:30.509575+07
42	43	collection_runtime_indexes	2026-10-01 16:00:30.569369+07
43	44	entities_v2_recent_index	2026-10-01 16:00:30.625281+07
44	45	ad_context_shared_entity_identity	2026-10-01 16:00:30.694146+07
45	46	ad_context_snapshot_heartbeat	2026-10-01 16:00:30.773007+07
46	47	collector_partial_failure_evidence	2026-10-01 16:00:30.848141+07
47	48	event_noise_classification_columns	2026-10-01 16:00:30.925092+07
48	49	event_noise_browse_index	2026-10-01 16:00:31.015641+07
49	50	semantic_worker_least_privilege	2026-10-01 16:00:31.080117+07
50	51	event_catalog_revision_reference	2026-10-01 16:00:31.157829+07
51	52	semantic_conclusion_completeness	2026-10-01 16:00:31.220238+07
52	53	semantic_canonical_action_risk	2026-10-01 16:00:31.296958+07
53	54	semantic_worker_runtime_schema_guard	2026-10-01 16:00:31.362332+07
54	55	semantic_finding_publication	2026-10-01 16:00:31.435763+07
55	56	privileged_account_state_fields	2026-10-01 16:00:31.51311+07
56	57	privileged_security_category	2026-10-01 16:00:31.590667+07
57	58	radius_accounting_transaction_foundation	2026-10-01 16:00:31.652151+07
58	59	radius_identity_spine_resolver	2026-10-01 16:00:31.7603+07
59	60	radius_identity_resolver_owner	2026-10-01 16:00:31.837408+07
60	61	radius_session_consumer_projection	2026-10-01 16:00:31.915206+07
61	62	vpn_session_report_read_boundary	2026-10-01 16:00:32.008079+07
62	63	radius_vpn_operations_read_boundary	2026-10-01 16:00:32.10084+07
63	64	vpn_session_canonical_identity_read_boundary	2026-10-01 16:00:32.19307+07
64	65	radius_session_reconciliation_overlay	2026-10-01 16:00:32.27013+07
65	66	administrative_activity_journal	2026-10-01 16:00:32.363768+07
66	67	plugin_remote_access_namespace	2026-10-01 16:00:32.456223+07
67	68	entity_identity_merge_r7	2026-10-01 16:00:32.534143+07
68	69	entity_identity_runtime_repair	2026-10-01 16:00:32.657205+07
69	70	entity_identity_bounded_lookup	2026-10-01 16:00:32.733544+07
70	71	semantic_source_retention_decoupling	2026-10-01 16:00:32.789453+07
71	72	administrative_activity_reader	2026-10-01 16:00:32.903906+07
72	73	plugin_lifecycle_registry	2026-10-01 16:00:32.981642+07
73	74	plugin_bundled_install_executor	2026-10-01 16:00:33.064087+07
74	75	plugin_component_admission	2026-10-01 16:00:33.136466+07
75	76	plugin_runtime_activation_executor	2026-10-01 16:00:33.230712+07
76	77	storage_lifecycle_runtime_maintenance	2026-10-01 16:00:33.292094+07
77	78	plugin_runtime_guard_read_boundary	2026-10-01 16:00:33.366088+07
78	79	semantic_finding_report_reader	2026-10-01 16:00:33.444688+07
79	80	radius_session_reconciliation_projection	2026-10-01 16:00:33.498714+07
80	81	g11a3_preflight_read_boundary	2026-10-01 16:00:33.567159+07
81	82	radius_event_catalog_revision_registration	2026-10-01 16:00:33.644525+07
82	83	vpn_session_evidence_read_boundary	2026-10-01 16:00:33.722246+07
83	84	dc_powershell_warm_facts	2026-10-01 16:00:33.790573+07
84	85	dc_powershell_origin_context	2026-10-01 16:00:33.861209+07
85	86	ad_account_change_warm_facts	2026-10-01 16:00:33.938636+07
86	87	ad_group_membership_warm_facts	2026-10-01 16:00:33.99478+07
87	88	source_capture_continuity_declarations	2026-10-01 16:00:34.062221+07
88	89	process_activity_foundation	2026-10-01 16:00:34.157409+07
89	90	storage_v2_direct_identity	2026-10-01 16:00:34.264098+07
90	91	storage_v2_runtime_authorization	2026-10-01 16:00:34.355932+07
91	92	current_event_catalog_revision	2026-10-01 16:00:34.432332+07
92	93	storage_v2_runtime_authorization_reader	2026-10-01 16:00:34.509083+07
93	94	storage_v2_runtime_authorization_owner	2026-10-01 16:00:34.571932+07
94	96	storage_v2_direct_ingest_worker_grants	2026-10-01 16:00:34.62756+07
95	97	storage_v2_drop_legacy_v1_relations	2026-10-01 16:00:34.711501+07
96	98	radius_session_consumer_manifest_hash	2026-10-01 16:00:34.788751+07
97	99	users_report_v1	2026-10-01 16:00:34.865523+07
98	100	users_report_domain_scope	2026-10-01 16:00:34.943806+07
99	101	computers_report_v1	2026-10-01 16:00:35.018681+07
100	102	active_directory_report_v1	2026-10-01 16:00:35.074461+07
101	103	domain_qualified_report_names	2026-10-01 16:00:35.140744+07
102	104	gpo_evidence_first_v1	2026-10-01 16:00:35.216881+07
103	105	105_gpo_settings_evidence_v2	2026-10-01 16:00:35.29397+07
104	106	computers_report_v2	2026-10-01 16:00:35.356123+07
105	107	computers_report_v4	2026-10-01 16:00:35.413306+07
106	108	computers_report_v5	2026-10-01 16:00:35.47853+07
107	109	computers_v5_snapshot_heartbeat	2026-10-01 16:00:35.570076+07
108	110	users_report_v2_reference	2026-10-01 16:00:35.622186+07
109	111	users_report_v2_source_snapshot_identity	2026-10-01 16:00:35.708582+07
110	112	users_v2_replaces_users_v1	2026-10-01 16:00:35.767893+07
111	113	computers_report_v6	2026-10-01 16:00:35.827033+07
112	114	computers_v6_source_snapshot	2026-10-01 16:00:35.903249+07
113	115	computers_v6_replaces_v1_v5	2026-10-01 16:00:35.985114+07
114	116	gpo_report_v2_reference	2026-10-01 16:00:36.062689+07
115	117	gpo_v2_snapshot_ingest_grant	2026-10-01 16:00:36.140201+07
116	118	gpo_v2_snapshot_ingest_select_grant	2026-10-01 16:00:36.217923+07
117	119	hide_legacy_vpn_retire_privileged_report	2026-10-01 16:00:36.295265+07
118	120	gpo_v2_replaces_legacy_catalog	2026-10-01 16:00:36.373085+07
119	121	ad_snapshot_manifest_foundation	2026-10-01 16:00:36.513509+07
120	122	ad_snapshot_runtime_grants	2026-10-01 16:00:36.598692+07
121	123	ad_snapshot_manifest_utc_slots	2026-10-01 16:00:36.657166+07
122	124	ad_snapshot_coordinator_heartbeat	2026-10-01 16:00:36.725922+07
123	125	what_where_when_projection	2026-10-01 16:00:36.775185+07
124	126	what_where_when_report	2026-10-01 16:00:36.853984+07
125	127	raw_batch_lifecycle	2026-10-01 16:00:36.919771+07
126	128	ad_snapshot_v2_schedule	2026-10-01 16:00:37.014051+07
127	129	ad_snapshot_projection_retention	2026-10-01 16:00:37.105184+07
128	130	what_where_when_hourly_compaction	2026-10-01 16:00:37.177099+07
129	131	ad_snapshot_seven_day_ring	2026-10-01 16:00:37.285379+07
130	132	ad_snapshot_delete_authorization	2026-10-01 16:00:37.413858+07
131	133	runtime_collection_history_restoration	2026-10-01 16:00:37.500097+07
132	134	security_events_chains_report	2026-10-01 16:00:37.547503+07
133	135	semantic_cross_dc_partitions	2026-10-01 16:00:37.607244+07
134	136	investigation_typed_evidence_refs	2026-10-01 16:00:37.672011+07
135	137	semantic_count_then_rule_kind	2026-10-01 16:00:37.747778+07
136	138	normalized_event_versioned_identity	2026-10-01 16:00:37.809803+07
137	139	investigation_evidence_refs_runtime_acl	2026-10-01 16:00:37.886576+07
138	140	semantic_investigation_context_acl	2026-10-01 16:00:37.963511+07
139	141	semantic_dispatch_rule_lock_acl	2026-10-01 16:00:38.021897+07
140	142	semantic_processor_version_gate_and_repair	2026-10-01 16:00:38.101023+07
141	143	semantic_v2_quarantine_repair	2026-10-01 16:00:38.177461+07
142	144	ad_context_evidence_record_key_index	2026-10-01 16:00:38.264035+07
143	145	ad_context_domain_sid_grant	2026-10-06 00:56:41.120115+07
144	146	platform_settings	2026-10-06 00:56:41.120115+07
145	147	domain_controller_targets	2026-10-06 00:56:41.120115+07
146	148	vpn_session_reader_domains_grant	2026-10-06 00:56:41.120115+07
147	149	investigation_finding_links	2026-10-06 00:56:41.120115+07
148	150	storage_v2_event_bigint	2026-10-06 00:56:41.120115+07
150	151	organization_neutral_radius_access	2026-10-06 00:56:41.604366+07
152	152	plugin_state	2026-10-06 07:45:05.157634+07
\.


--
-- Data for Name: semantic_control_health_observations; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_control_health_observations (observation_id, observation_key, control_id, partition_key, coverage_status, reason, observed_at_utc, source_reference, created_at) FROM stdin;
\.


--
-- Data for Name: semantic_correlation_candidate_evidence; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_correlation_candidate_evidence (candidate_id, normalized_event_id, evidence_order, created_at, is_late) FROM stdin;
\.


--
-- Data for Name: semantic_correlation_candidates; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_correlation_candidates (candidate_id, rule_id, rule_version, relation_kind, candidate_status, candidate_key, partition_key, window_start_utc, window_end_utc, confidence, explanation, evidence_count, first_matched_at, last_matched_at, created_at, updated_at, reopen_count, late_evidence_count, closed_at, last_evidence_occurred_at) FROM stdin;
\.


--
-- Data for Name: semantic_correlation_dispatch_jobs; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_correlation_dispatch_jobs (job_id, normalized_event_id, rule_id, rule_version, idempotency_key, partition_key, occurred_at_utc, is_late, dispatch_status, attempt_count, max_attempts, available_at, lease_token, lease_until, heartbeat_at, last_error_code, last_error_detail, created_at, updated_at, completed_at) FROM stdin;
\.


--
-- Data for Name: semantic_correlation_replays; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_correlation_replays (replay_id, rule_id, rule_version, range_start_utc, range_end_utc, idempotency_key, replay_status, attempt_count, max_attempts, available_at, lease_token, lease_until, heartbeat_at, checkpoint_utc, processed_events, matched_candidates, last_error_code, last_error_detail, created_at, updated_at, completed_at) FROM stdin;
\.


--
-- Data for Name: semantic_correlation_rules; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_correlation_rules (rule_id, rule_version, rule_kind, lifecycle_status, definition_json, definition_sha256, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: semantic_correlation_subscriptions; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_correlation_subscriptions (rule_id, rule_version, semantic_type, subscription_order, definition_sha256, created_at) FROM stdin;
\.


--
-- Data for Name: semantic_finding_publications; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_finding_publications (scenario_id, finding_id, first_job_id, finding_fingerprint, published_evidence_count, created_at) FROM stdin;
\.


--
-- Data for Name: semantic_processing_outbox; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_processing_outbox (job_id, source_event_id, job_kind, semantic_contract_version, processor_id, processor_version, idempotency_key, status, attempt_count, max_attempts, available_at, lease_token, lease_until, heartbeat_at, payload_json, last_error_code, last_error_detail, created_at, updated_at, completed_at, source_id, domain_id, partition_key, occurred_at_utc, emitted_at, source_identity_json) FROM stdin;
\.


--
-- Data for Name: semantic_risk_contributions; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_risk_contributions (contribution_id, scenario_id, contribution_key, source_kind, canonical_action_id, correlation_candidate_id, control_reference, policy_id, policy_version, policy_sha256, risk_class, raw_score, display_points, hard_critical, rationale, created_at) FROM stdin;
\.


--
-- Data for Name: semantic_risk_evaluation_jobs; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_risk_evaluation_jobs (job_id, policy_id, policy_version, source_kind, correlation_candidate_id, control_health_id, source_reference, evaluation_mode, idempotency_key, evaluation_status, attempt_count, max_attempts, available_at, lease_token, lease_until, heartbeat_at, last_error_code, last_error_detail, created_at, updated_at, completed_at, canonical_action_id) FROM stdin;
\.


--
-- Data for Name: semantic_risk_evaluation_results; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_risk_evaluation_results (job_id, scenario_id, evaluation_mode, risk_class, raw_score, display_score, hard_critical, confidence, confidence_score, coverage_status, evaluation_ms, created_at, conclusion_state, completeness_snapshot_json) FROM stdin;
\.


--
-- Data for Name: semantic_risk_policies; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_risk_policies (policy_id, policy_version, source_kind, lifecycle_status, definition_json, definition_sha256, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: semantic_risk_policy_subscriptions; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_risk_policy_subscriptions (policy_id, policy_version, source_kind, selector_value, definition_sha256, created_at) FROM stdin;
\.


--
-- Data for Name: semantic_scenario_coverage_history; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_scenario_coverage_history (coverage_id, scenario_id, assessment_key, control_id, coverage_status, reason, observed_at_utc, created_at) FROM stdin;
\.


--
-- Data for Name: semantic_scenario_evidence; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_scenario_evidence (scenario_id, normalized_event_id, evidence_order, created_at) FROM stdin;
\.


--
-- Data for Name: semantic_scenario_reviews; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_scenario_reviews (review_id, review_request_id, scenario_id, supersedes_review_id, verdict, review_confidence, rationale, scenario_snapshot_sha256, reviewed_by, reviewer_role, reviewed_at) FROM stdin;
\.


--
-- Data for Name: semantic_scenario_steps; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_scenario_steps (step_id, scenario_id, step_key, source_kind, canonical_action_id, correlation_candidate_id, control_reference, occurred_at_utc, title, explanation, confidence, confidence_score, confidence_factors_json, created_at) FROM stdin;
\.


--
-- Data for Name: semantic_security_scenarios; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.semantic_security_scenarios (scenario_id, scenario_kind, result_class, scenario_status, identity_key, scenario_key, partition_key, strict_keys_json, merge_window_seconds, title, explanation, first_seen_utc, last_seen_utc, risk_class, raw_score, display_score, hard_critical, confidence, confidence_score, confidence_factors_json, coverage_status, step_count, evidence_count, contribution_count, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: servers; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.servers (id, domain_id, site_id, hostname, fqdn, role, os_name, os_version, os_language, is_active, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: sites; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.sites (id, domain_id, name, site_type, location, created_at) FROM stdin;
\.


--
-- Data for Name: source_capture_continuity_declarations; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.source_capture_continuity_declarations (id, collection_run_id, raw_log_file_id, raw_log_sha256, server_id, log_source_id, scope_identity, descriptor_source, descriptor_stream, provider_name, channel_value, channel_generation_identity, selector_event_ids, query_exhausted, capture_after_record_id, capture_latest_record_id, first_event_record_id, last_event_record_id, completeness, covered_source_events, declaration_sha256, recorded_at) FROM stdin;
\.


--
-- Data for Name: storage_lifecycle_snapshots; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.storage_lifecycle_snapshots (id, captured_at, source, source_job_id, source_run_id, database_bytes, events_estimated_rows, events_max_id, events_last_24h, raw_bytes, raw_archive_bytes, backups_bytes, logs_bytes, reports_bytes, artifacts_bytes, disk_total_bytes, disk_used_bytes, disk_free_bytes, disk_free_percent, table_stats_json, scan_meta_json, created_at) FROM stdin;
\.


--
-- Data for Name: storage_v2_archive_blocks; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_archive_blocks (archive_set_id, archive_kind, format_version, block_index, first_event_id, last_event_id, row_count, raw_bytes, compressed_bytes, raw_sha256, archive_sha256, object_location, state, created_at, verified_at, published_at, quarantine_reason) FROM stdin;
\.


--
-- Data for Name: storage_v2_archive_sets; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_archive_sets (archive_set_id, archive_kind, format_version, source_min_event_id, source_max_event_id, expected_rows, state, created_at, verified_at, published_at) FROM stdin;
\.


--
-- Data for Name: storage_v2_backfill_checkpoints; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_backfill_checkpoints (worker_name, high_watermark_event_id, last_verified_event_id, chunk_size, state, lease_token, lease_until, source_rows, target_rows, source_sha256, target_sha256, last_error, updated_at) FROM stdin;
\.


--
-- Data for Name: storage_v2_backfill_chunks; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_backfill_chunks (worker_name, chunk_start_event_id, chunk_end_event_id, source_event_rows, target_event_rows, source_link_rows, target_link_rows, source_sha256, target_sha256, archive_event_set_id, archive_link_set_id, wal_bytes, duration_ms, status, completed_at) FROM stdin;
\.


--
-- Data for Name: storage_v2_channel; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_channel (id, value) FROM stdin;
\.


--
-- Data for Name: storage_v2_computer; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_computer (id, value) FROM stdin;
\.


--
-- Data for Name: storage_v2_cutover_state; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_cutover_state (singleton, read_mode, write_mode, shadow_sample_rate, archive_root, state_version, changed_by, changed_at, rollback_note) FROM stdin;
t	v2	v2	0	\N	1	adlog_storage_owner	2026-10-01 16:00:27.926107+07	\N
\.


--
-- Data for Name: storage_v2_domain_name; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_domain_name (id, value) FROM stdin;
\.


--
-- Data for Name: storage_v2_entity_identity_allocations; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_entity_identity_allocations (id, entity_type_id, natural_key, allocated_at) FROM stdin;
\.


--
-- Data for Name: storage_v2_entity_type; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_entity_type (id, value) FROM stdin;
\.


--
-- Data for Name: storage_v2_event_identity_allocations; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_event_identity_allocations (id, server_id, channel_id, event_record_id, time_created_utc, normalized_hash, allocated_at) FROM stdin;
\.


--
-- Data for Name: storage_v2_extracted_from; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_extracted_from (id, value) FROM stdin;
\.


--
-- Data for Name: storage_v2_keywords; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_keywords (id, value) FROM stdin;
\.


--
-- Data for Name: storage_v2_outbox; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_outbox (id, batch_id, first_event_id, last_event_id, event_count, event_ids, identity_sha256, state, attempt_count, available_at, lease_token, lease_until, last_error, created_at, completed_at) FROM stdin;
\.


--
-- Data for Name: storage_v2_provider; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_provider (id, value) FROM stdin;
\.


--
-- Data for Name: storage_v2_role; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_role (id, value) FROM stdin;
\.


--
-- Data for Name: storage_v2_runtime_authorizations; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_runtime_authorizations (singleton, route, authority, preflight_digest, authorization_digest, archive_root, evidence, authorized_by, authorized_at, expires_at, revoked_at) FROM stdin;
\.


--
-- Data for Name: storage_v2_shadow_results; Type: TABLE DATA; Schema: public; Owner: adlog_storage_owner
--

COPY public.storage_v2_shadow_results (id, query_kind, sample_key_sha256, v1_result_sha256, v2_result_sha256, identity_match, count_match, v1_duration_ms, v2_duration_ms, mismatch_summary, observed_at) FROM stdin;
\.


--
-- Data for Name: user_report_preferences; Type: TABLE DATA; Schema: public; Owner: adlog_user
--

COPY public.user_report_preferences (user_id, report_key, pinned, view_json, updated_at) FROM stdin;
\.


--
-- Data for Name: users_report_v2_snapshots; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users_report_v2_snapshots (snapshot_id, domain_id, contract_id, schema_version, scope_json, scope_sha256, bucket_start_utc, captured_at_utc, source_observed_at_utc, source_state, user_count, payload_json, payload_sha256, created_at) FROM stdin;
\.


--
-- Data for Name: what_where_when_observations; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.what_where_when_observations (projection_id, source_event_id, source_event_hash, computer_object_guid, computer_name, user_name, observed_at_utc, computer_source_snapshot_id, user_snapshot_id, created_at, user_key, observed_hour_local) FROM stdin;
\.


--
-- Data for Name: what_where_when_projection_state; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.what_where_when_projection_state (singleton, initial_cutoff_utc, high_water_event_id, backfill_completed, computer_source_snapshot_id, user_snapshot_id, filtered_count, unmatched_count, ambiguous_count, last_cycle_at_utc, updated_at) FROM stdin;
t	2025-10-01 16:00:36.775185+07	0	f	\N	\N	0	0	0	\N	2026-10-01 16:00:36.775185+07
\.


--
-- Data for Name: plugin_namespace_contract_v1; Type: TABLE DATA; Schema: sli_plugin_remote_access; Owner: adlog_plugin_remote_access_owner
--

COPY sli_plugin_remote_access.plugin_namespace_contract_v1 (plugin_id, contract_id, contract_version, created_at_utc) FROM stdin;
sli.remote-access	sli.plugin-postgresql-isolation.v1	1	2026-10-01 16:00:32.456223+07
\.


--
-- Name: access_audit_v4_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.access_audit_v4_id_seq', 1, false);


--
-- Name: access_capabilities_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.access_capabilities_id_seq', 33, true);


--
-- Name: access_capability_assignments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.access_capability_assignments_id_seq', 1, false);


--
-- Name: access_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.access_groups_id_seq', 1, false);


--
-- Name: access_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.access_packages_id_seq', 8, true);


--
-- Name: access_report_assignments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.access_report_assignments_id_seq', 1, false);


--
-- Name: access_subject_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.access_subject_packages_id_seq', 1, false);


--
-- Name: account_risk_acceptance_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.account_risk_acceptance_audit_id_seq', 1, false);


--
-- Name: account_risk_acceptances_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.account_risk_acceptances_id_seq', 1, false);


--
-- Name: account_risk_investigation_links_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.account_risk_investigation_links_id_seq', 1, false);


--
-- Name: acquisition_delivery_outbox_delivery_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.acquisition_delivery_outbox_delivery_id_seq', 1, false);


--
-- Name: ad_context_entity_aliases_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.ad_context_entity_aliases_id_seq', 1, false);


--
-- Name: ad_context_entity_versions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.ad_context_entity_versions_id_seq', 1, false);


--
-- Name: ad_context_evidence_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.ad_context_evidence_id_seq', 1, false);


--
-- Name: ad_context_relation_versions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.ad_context_relation_versions_id_seq', 1, false);


--
-- Name: administrative_activity_v1_activity_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_administrative_activity_owner
--

SELECT pg_catalog.setval('public.administrative_activity_v1_activity_id_seq', 1, false);


--
-- Name: ai_analysis_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.ai_analysis_id_seq', 1, false);


--
-- Name: ai_api_runs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.ai_api_runs_id_seq', 1, false);


--
-- Name: ai_reviews_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.ai_reviews_id_seq', 1, false);


--
-- Name: auth_api_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.auth_api_keys_id_seq', 1, false);


--
-- Name: auth_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.auth_audit_id_seq', 1, false);


--
-- Name: auth_sessions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.auth_sessions_id_seq', 1, false);


--
-- Name: auth_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.auth_users_id_seq', 1, false);


--
-- Name: collection_runs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.collection_runs_id_seq', 1, false);


--
-- Name: collector_channel_runs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.collector_channel_runs_id_seq', 1, false);


--
-- Name: collector_cursor_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.collector_cursor_audit_id_seq', 1, false);


--
-- Name: collector_stage_metrics_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.collector_stage_metrics_id_seq', 1, false);


--
-- Name: computers_report_v5_snapshots_snapshot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.computers_report_v5_snapshots_snapshot_id_seq', 1, false);


--
-- Name: computers_report_v6_snapshots_snapshot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.computers_report_v6_snapshots_snapshot_id_seq', 1, false);


--
-- Name: computers_v6_source_snapshots_source_snapshot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.computers_v6_source_snapshots_source_snapshot_id_seq', 1, false);


--
-- Name: detection_rules_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.detection_rules_id_seq', 10, true);


--
-- Name: detections_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.detections_id_seq', 1, false);


--
-- Name: domain_controller_targets_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.domain_controller_targets_id_seq', 1, false);


--
-- Name: domains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.domains_id_seq', 1, true);


--
-- Name: entities_v2_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.entities_v2_id_seq', 1, false);


--
-- Name: entity_states_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.entity_states_id_seq', 1, false);


--
-- Name: event_catalog_revisions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.event_catalog_revisions_id_seq', 2, true);


--
-- Name: event_links_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.event_links_id_seq', 1, false);


--
-- Name: finding_entities_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.finding_entities_id_seq', 1, false);


--
-- Name: finding_evidence_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.finding_evidence_id_seq', 1, false);


--
-- Name: finding_status_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.finding_status_history_id_seq', 1, false);


--
-- Name: findings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.findings_id_seq', 1, false);


--
-- Name: forests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.forests_id_seq', 1, true);


--
-- Name: gpo_report_v2_source_snapshots_snapshot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.gpo_report_v2_source_snapshots_snapshot_id_seq', 1, false);


--
-- Name: investigation_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.investigation_audit_id_seq', 1, false);


--
-- Name: investigation_notes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.investigation_notes_id_seq', 1, false);


--
-- Name: investigations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.investigations_id_seq', 1, false);


--
-- Name: log_sources_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.log_sources_id_seq', 8, true);


--
-- Name: object_identity_links_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.object_identity_links_id_seq', 1, false);


--
-- Name: plugin_lifecycle_operations_v1_operation_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

SELECT pg_catalog.setval('public.plugin_lifecycle_operations_v1_operation_id_seq', 1, false);


--
-- Name: post_collection_jobs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.post_collection_jobs_id_seq', 1, false);


--
-- Name: raw_log_files_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.raw_log_files_id_seq', 1, false);


--
-- Name: report_access_requests_v4_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.report_access_requests_v4_id_seq', 1, false);


--
-- Name: report_datasets_v4_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.report_datasets_v4_id_seq', 19, true);


--
-- Name: report_items_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.report_items_id_seq', 1, false);


--
-- Name: report_registry_v4_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.report_registry_v4_id_seq', 19, true);


--
-- Name: reports_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.reports_id_seq', 1, false);


--
-- Name: schema_migrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.schema_migrations_id_seq', 152, true);


--
-- Name: servers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.servers_id_seq', 1, false);


--
-- Name: sites_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.sites_id_seq', 1, false);


--
-- Name: source_capture_continuity_declarations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.source_capture_continuity_declarations_id_seq', 1, false);


--
-- Name: storage_lifecycle_snapshots_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_user
--

SELECT pg_catalog.setval('public.storage_lifecycle_snapshots_id_seq', 1, false);


--
-- Name: storage_v2_channel_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_channel_id_seq', 1, false);


--
-- Name: storage_v2_computer_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_computer_id_seq', 1, false);


--
-- Name: storage_v2_domain_name_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_domain_name_id_seq', 1, false);


--
-- Name: storage_v2_entity_type_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_entity_type_id_seq', 1, false);


--
-- Name: storage_v2_event_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_event_id_seq', 1, false);


--
-- Name: storage_v2_extracted_from_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_extracted_from_id_seq', 1, false);


--
-- Name: storage_v2_keywords_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_keywords_id_seq', 1, false);


--
-- Name: storage_v2_outbox_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_outbox_id_seq', 1, false);


--
-- Name: storage_v2_provider_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_provider_id_seq', 1, false);


--
-- Name: storage_v2_role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_role_id_seq', 1, false);


--
-- Name: storage_v2_shadow_results_id_seq; Type: SEQUENCE SET; Schema: public; Owner: adlog_storage_owner
--

SELECT pg_catalog.setval('public.storage_v2_shadow_results_id_seq', 1, false);


--
-- Name: users_report_v2_snapshots_snapshot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.users_report_v2_snapshots_snapshot_id_seq', 1, false);


--
-- Name: what_where_when_observations_projection_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.what_where_when_observations_projection_id_seq', 1, false);


--
-- Name: access_audit_v4 access_audit_v4_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_audit_v4
    ADD CONSTRAINT access_audit_v4_pkey PRIMARY KEY (id);


--
-- Name: access_capabilities access_capabilities_capability_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_capabilities
    ADD CONSTRAINT access_capabilities_capability_key_key UNIQUE (capability_key);


--
-- Name: access_capabilities access_capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_capabilities
    ADD CONSTRAINT access_capabilities_pkey PRIMARY KEY (id);


--
-- Name: access_capability_assignments access_capability_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_capability_assignments
    ADD CONSTRAINT access_capability_assignments_pkey PRIMARY KEY (id);


--
-- Name: access_group_members access_group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_group_members
    ADD CONSTRAINT access_group_members_pkey PRIMARY KEY (group_id, user_id);


--
-- Name: access_groups access_groups_group_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_groups
    ADD CONSTRAINT access_groups_group_key_key UNIQUE (group_key);


--
-- Name: access_groups access_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_groups
    ADD CONSTRAINT access_groups_pkey PRIMARY KEY (id);


--
-- Name: access_package_capabilities access_package_capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_package_capabilities
    ADD CONSTRAINT access_package_capabilities_pkey PRIMARY KEY (package_id, capability_id);


--
-- Name: access_package_reports access_package_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_package_reports
    ADD CONSTRAINT access_package_reports_pkey PRIMARY KEY (package_id, report_key);


--
-- Name: access_packages access_packages_package_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_packages
    ADD CONSTRAINT access_packages_package_key_key UNIQUE (package_key);


--
-- Name: access_packages access_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_packages
    ADD CONSTRAINT access_packages_pkey PRIMARY KEY (id);


--
-- Name: access_platform_owners access_platform_owners_owner_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_platform_owners
    ADD CONSTRAINT access_platform_owners_owner_key_key UNIQUE (owner_key);


--
-- Name: access_platform_owners access_platform_owners_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_platform_owners
    ADD CONSTRAINT access_platform_owners_pkey PRIMARY KEY (user_id);


--
-- Name: access_report_assignments access_report_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_report_assignments
    ADD CONSTRAINT access_report_assignments_pkey PRIMARY KEY (id);


--
-- Name: access_role_packages access_role_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_role_packages
    ADD CONSTRAINT access_role_packages_pkey PRIMARY KEY (coarse_role, package_id);


--
-- Name: access_subject_packages access_subject_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_subject_packages
    ADD CONSTRAINT access_subject_packages_pkey PRIMARY KEY (id);


--
-- Name: access_subject_packages access_subject_packages_subject_type_subject_id_package_id__key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_subject_packages
    ADD CONSTRAINT access_subject_packages_subject_type_subject_id_package_id__key UNIQUE (subject_type, subject_id, package_id, effect, source_type);


--
-- Name: account_risk_acceptance_audit account_risk_acceptance_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_acceptance_audit
    ADD CONSTRAINT account_risk_acceptance_audit_pkey PRIMARY KEY (id);


--
-- Name: account_risk_acceptances account_risk_acceptances_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_acceptances
    ADD CONSTRAINT account_risk_acceptances_pkey PRIMARY KEY (id);


--
-- Name: account_risk_acceptances account_risk_acceptances_public_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_acceptances
    ADD CONSTRAINT account_risk_acceptances_public_id_key UNIQUE (public_id);


--
-- Name: account_risk_investigation_links account_risk_investigation_links_investigation_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_investigation_links
    ADD CONSTRAINT account_risk_investigation_links_investigation_id_key UNIQUE (investigation_id);


--
-- Name: account_risk_investigation_links account_risk_investigation_links_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_investigation_links
    ADD CONSTRAINT account_risk_investigation_links_pkey PRIMARY KEY (id);


--
-- Name: acquisition_consumer_subscriptions acquisition_consumer_subscrip_source_instance_id_stream_id__key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_consumer_subscriptions
    ADD CONSTRAINT acquisition_consumer_subscrip_source_instance_id_stream_id__key UNIQUE (source_instance_id, stream_id, transport_binding, consumer_id, partition_key);


--
-- Name: acquisition_consumer_subscriptions acquisition_consumer_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_consumer_subscriptions
    ADD CONSTRAINT acquisition_consumer_subscriptions_pkey PRIMARY KEY (subscription_id);


--
-- Name: acquisition_delivery_outbox acquisition_delivery_outbox_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_delivery_outbox
    ADD CONSTRAINT acquisition_delivery_outbox_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: acquisition_delivery_outbox acquisition_delivery_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_delivery_outbox
    ADD CONSTRAINT acquisition_delivery_outbox_pkey PRIMARY KEY (delivery_id);


--
-- Name: acquisition_delivery_outbox acquisition_delivery_outbox_subscription_id_observation_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_delivery_outbox
    ADD CONSTRAINT acquisition_delivery_outbox_subscription_id_observation_id_key UNIQUE (subscription_id, observation_id);


--
-- Name: acquisition_source_instances acquisition_source_instances_organization_scope_source_kind_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_source_instances
    ADD CONSTRAINT acquisition_source_instances_organization_scope_source_kind_key UNIQUE (organization_scope, source_kind, endpoint_identity);


--
-- Name: acquisition_source_instances acquisition_source_instances_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_source_instances
    ADD CONSTRAINT acquisition_source_instances_pkey PRIMARY KEY (source_instance_id);


--
-- Name: acquisition_stream_cursors acquisition_stream_cursors_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_stream_cursors
    ADD CONSTRAINT acquisition_stream_cursors_pkey PRIMARY KEY (source_instance_id, stream_id, transport_binding);


--
-- Name: ad_context_entity_aliases ad_context_entity_aliases_domain_id_alias_type_normalized_v_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_aliases
    ADD CONSTRAINT ad_context_entity_aliases_domain_id_alias_type_normalized_v_key UNIQUE (domain_id, alias_type, normalized_value);


--
-- Name: ad_context_entity_aliases ad_context_entity_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_aliases
    ADD CONSTRAINT ad_context_entity_aliases_pkey PRIMARY KEY (id);


--
-- Name: ad_context_entity_versions ad_context_entity_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_versions
    ADD CONSTRAINT ad_context_entity_versions_pkey PRIMARY KEY (id);


--
-- Name: ad_context_event_links ad_context_event_links_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_event_links
    ADD CONSTRAINT ad_context_event_links_pkey PRIMARY KEY (event_db_id, context_evidence_id, rule_code);


--
-- Name: ad_context_evidence ad_context_evidence_evidence_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_evidence
    ADD CONSTRAINT ad_context_evidence_evidence_key_key UNIQUE (evidence_key);


--
-- Name: ad_context_evidence ad_context_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_evidence
    ADD CONSTRAINT ad_context_evidence_pkey PRIMARY KEY (id);


--
-- Name: ad_context_relation_versions ad_context_relation_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_relation_versions
    ADD CONSTRAINT ad_context_relation_versions_pkey PRIMARY KEY (id);


--
-- Name: ad_context_runs ad_context_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_runs
    ADD CONSTRAINT ad_context_runs_pkey PRIMARY KEY (run_id);


--
-- Name: ad_context_sections ad_context_sections_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_sections
    ADD CONSTRAINT ad_context_sections_pkey PRIMARY KEY (run_id, section_name);


--
-- Name: ad_snapshot_manifest_sources ad_snapshot_manifest_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_manifest_sources
    ADD CONSTRAINT ad_snapshot_manifest_sources_pkey PRIMARY KEY (manifest_id, family);


--
-- Name: ad_snapshot_manifests ad_snapshot_manifests_domain_id_slot_start_utc_contract_ver_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_manifests
    ADD CONSTRAINT ad_snapshot_manifests_domain_id_slot_start_utc_contract_ver_key UNIQUE (domain_id, slot_start_utc, contract_version);


--
-- Name: ad_snapshot_manifests ad_snapshot_manifests_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_manifests
    ADD CONSTRAINT ad_snapshot_manifests_pkey PRIMARY KEY (manifest_id);


--
-- Name: ad_snapshot_projection_outputs ad_snapshot_projection_outputs_output_identity_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_projection_outputs
    ADD CONSTRAINT ad_snapshot_projection_outputs_output_identity_key UNIQUE (output_identity);


--
-- Name: ad_snapshot_projection_outputs ad_snapshot_projection_outputs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_projection_outputs
    ADD CONSTRAINT ad_snapshot_projection_outputs_pkey PRIMARY KEY (manifest_id, projection_key, projection_version);


--
-- Name: ad_snapshot_projection_receipts ad_snapshot_projection_receipts_completed_output_check; Type: CHECK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE public.ad_snapshot_projection_receipts
    ADD CONSTRAINT ad_snapshot_projection_receipts_completed_output_check CHECK (((status <> 'completed'::text) OR ((input_sha256 IS NOT NULL) AND (output_sha256 IS NOT NULL) AND (output_identity IS NOT NULL) AND (octet_length(input_sha256) = 32) AND (octet_length(output_sha256) = 32) AND (output_identity = (((((manifest_id)::text || ':'::text) || projection_key) || ':v'::text) || (projection_version)::text))))) NOT VALID;


--
-- Name: ad_snapshot_projection_receipts ad_snapshot_projection_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_projection_receipts
    ADD CONSTRAINT ad_snapshot_projection_receipts_pkey PRIMARY KEY (manifest_id, projection_key, projection_version);


--
-- Name: administrative_activity_v1 administrative_activity_v1_event_uid_key; Type: CONSTRAINT; Schema: public; Owner: adlog_administrative_activity_owner
--

ALTER TABLE ONLY public.administrative_activity_v1
    ADD CONSTRAINT administrative_activity_v1_event_uid_key UNIQUE (event_uid);


--
-- Name: administrative_activity_v1 administrative_activity_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_administrative_activity_owner
--

ALTER TABLE ONLY public.administrative_activity_v1
    ADD CONSTRAINT administrative_activity_v1_pkey PRIMARY KEY (activity_id);


--
-- Name: administrative_activity_v1 administrative_activity_v1_record_hash_key; Type: CONSTRAINT; Schema: public; Owner: adlog_administrative_activity_owner
--

ALTER TABLE ONLY public.administrative_activity_v1
    ADD CONSTRAINT administrative_activity_v1_record_hash_key UNIQUE (record_hash);


--
-- Name: ai_analysis ai_analysis_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ai_analysis
    ADD CONSTRAINT ai_analysis_pkey PRIMARY KEY (id);


--
-- Name: ai_api_runs ai_api_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ai_api_runs
    ADD CONSTRAINT ai_api_runs_pkey PRIMARY KEY (id);


--
-- Name: ai_reviews ai_reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ai_reviews
    ADD CONSTRAINT ai_reviews_pkey PRIMARY KEY (id);


--
-- Name: archive_settings archive_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.archive_settings
    ADD CONSTRAINT archive_settings_pkey PRIMARY KEY (key);


--
-- Name: auth_api_keys auth_api_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_api_keys
    ADD CONSTRAINT auth_api_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: auth_api_keys auth_api_keys_key_prefix_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_api_keys
    ADD CONSTRAINT auth_api_keys_key_prefix_key UNIQUE (key_prefix);


--
-- Name: auth_api_keys auth_api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_api_keys
    ADD CONSTRAINT auth_api_keys_pkey PRIMARY KEY (id);


--
-- Name: auth_audit auth_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_audit
    ADD CONSTRAINT auth_audit_pkey PRIMARY KEY (id);


--
-- Name: auth_sessions auth_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_pkey PRIMARY KEY (id);


--
-- Name: auth_sessions auth_sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: auth_users auth_users_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_users
    ADD CONSTRAINT auth_users_pkey PRIMARY KEY (id);


--
-- Name: canonical_action_evidence canonical_action_evidence_canonical_action_id_evidence_orde_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_action_evidence
    ADD CONSTRAINT canonical_action_evidence_canonical_action_id_evidence_orde_key UNIQUE (canonical_action_id, evidence_order);


--
-- Name: canonical_action_evidence canonical_action_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_action_evidence
    ADD CONSTRAINT canonical_action_evidence_pkey PRIMARY KEY (canonical_action_id, normalized_event_id, evidence_role);


--
-- Name: canonical_action_state_evidence canonical_action_state_evidence_match_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_action_state_evidence
    ADD CONSTRAINT canonical_action_state_evidence_match_key_key UNIQUE (match_key);


--
-- Name: canonical_action_state_evidence canonical_action_state_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_action_state_evidence
    ADD CONSTRAINT canonical_action_state_evidence_pkey PRIMARY KEY (canonical_action_id, context_evidence_id);


--
-- Name: canonical_actions canonical_actions_dedup_identity_unique; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_actions
    ADD CONSTRAINT canonical_actions_dedup_identity_unique UNIQUE (semantic_contract_version, assembler_id, assembler_version, canonical_deduplication_key);


--
-- Name: canonical_actions canonical_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_actions
    ADD CONSTRAINT canonical_actions_pkey PRIMARY KEY (canonical_action_id);


--
-- Name: canonical_actions canonical_actions_semantic_contract_version_assembler_id_as_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_actions
    ADD CONSTRAINT canonical_actions_semantic_contract_version_assembler_id_as_key UNIQUE (semantic_contract_version, assembler_id, assembler_version, contribution_key);


--
-- Name: collection_channel_state collection_channel_state_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collection_channel_state
    ADD CONSTRAINT collection_channel_state_pkey PRIMARY KEY (server_hostname, channel);


--
-- Name: collection_runs collection_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collection_runs
    ADD CONSTRAINT collection_runs_pkey PRIMARY KEY (id);


--
-- Name: collector_adaptive_state collector_adaptive_state_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collector_adaptive_state
    ADD CONSTRAINT collector_adaptive_state_pkey PRIMARY KEY (server, channel);


--
-- Name: collector_channel_runs collector_channel_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collector_channel_runs
    ADD CONSTRAINT collector_channel_runs_pkey PRIMARY KEY (id);


--
-- Name: collector_cursor_audit collector_cursor_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collector_cursor_audit
    ADD CONSTRAINT collector_cursor_audit_pkey PRIMARY KEY (id);


--
-- Name: collector_stage_metrics collector_stage_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.collector_stage_metrics
    ADD CONSTRAINT collector_stage_metrics_pkey PRIMARY KEY (id);


--
-- Name: computers_report_v5_snapshots computers_report_v5_snapshots_domain_id_scope_sha256_bucket_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v5_snapshots
    ADD CONSTRAINT computers_report_v5_snapshots_domain_id_scope_sha256_bucket_key UNIQUE (domain_id, scope_sha256, bucket_start_utc, contract_id, schema_version);


--
-- Name: computers_report_v5_snapshots computers_report_v5_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v5_snapshots
    ADD CONSTRAINT computers_report_v5_snapshots_pkey PRIMARY KEY (snapshot_id);


--
-- Name: computers_report_v6_snapshots computers_report_v6_snapshots_domain_id_scope_sha256_bucket_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v6_snapshots
    ADD CONSTRAINT computers_report_v6_snapshots_domain_id_scope_sha256_bucket_key UNIQUE (domain_id, scope_sha256, bucket_start_utc, contract_id, schema_version);


--
-- Name: computers_report_v6_snapshots computers_report_v6_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v6_snapshots
    ADD CONSTRAINT computers_report_v6_snapshots_pkey PRIMARY KEY (snapshot_id);


--
-- Name: computers_v6_source_snapshots computers_v6_source_snapshots_domain_id_snapshot_uuid_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_v6_source_snapshots
    ADD CONSTRAINT computers_v6_source_snapshots_domain_id_snapshot_uuid_key UNIQUE (domain_id, snapshot_uuid);


--
-- Name: computers_v6_source_snapshots computers_v6_source_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_v6_source_snapshots
    ADD CONSTRAINT computers_v6_source_snapshots_pkey PRIMARY KEY (source_snapshot_id);


--
-- Name: core_evidence_manifests core_evidence_manifests_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.core_evidence_manifests
    ADD CONSTRAINT core_evidence_manifests_pkey PRIMARY KEY (evidence_uid);


--
-- Name: core_evidence_manifests core_evidence_manifests_source_instance_id_stream_id_transp_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.core_evidence_manifests
    ADD CONSTRAINT core_evidence_manifests_source_instance_id_stream_id_transp_key UNIQUE (source_instance_id, stream_id, transport_binding, cursor_epoch, file_generation, cursor_start_byte_offset, batch_record_ordinal);


--
-- Name: detection_rules detection_rules_code_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_code_key UNIQUE (code);


--
-- Name: detection_rules detection_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_pkey PRIMARY KEY (id);


--
-- Name: detections detections_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_pkey PRIMARY KEY (id);


--
-- Name: domain_controller_targets domain_controller_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.domain_controller_targets
    ADD CONSTRAINT domain_controller_targets_pkey PRIMARY KEY (id);


--
-- Name: domains domains_forest_id_fqdn_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_forest_id_fqdn_key UNIQUE (forest_id, fqdn);


--
-- Name: domains domains_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);


--
-- Name: entities_v2 entities_v2_natural_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entities_v2
    ADD CONSTRAINT entities_v2_natural_key UNIQUE (entity_type_id, natural_key);


--
-- Name: entities_v2 entities_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entities_v2
    ADD CONSTRAINT entities_v2_pkey PRIMARY KEY (id);


--
-- Name: entity_details_v2 entity_details_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_details_v2
    ADD CONSTRAINT entity_details_v2_pkey PRIMARY KEY (entity_id);


--
-- Name: entity_identity_finding_supersessions_v2 entity_identity_finding_supersessions_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_finding_supersessions_v2
    ADD CONSTRAINT entity_identity_finding_supersessions_v2_pkey PRIMARY KEY (merge_id, old_finding_id, new_finding_id);


--
-- Name: entity_identity_merge_events_v2 entity_identity_merge_events_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_merge_events_v2
    ADD CONSTRAINT entity_identity_merge_events_v2_pkey PRIMARY KEY (merge_id, source_event_id);


--
-- Name: entity_identity_merges_v2 entity_identity_merges_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_merges_v2
    ADD CONSTRAINT entity_identity_merges_v2_pkey PRIMARY KEY (merge_id);


--
-- Name: entity_identity_merges_v2 entity_identity_merges_v2_source_entity_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_merges_v2
    ADD CONSTRAINT entity_identity_merges_v2_source_entity_id_key UNIQUE (source_entity_id);


--
-- Name: entity_identity_merges_v2 entity_identity_merges_v2_source_entity_id_target_entity_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_merges_v2
    ADD CONSTRAINT entity_identity_merges_v2_source_entity_id_target_entity_id_key UNIQUE (source_entity_id, target_entity_id);


--
-- Name: entity_identity_merges_v2 entity_identity_merges_v2_source_natural_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_merges_v2
    ADD CONSTRAINT entity_identity_merges_v2_source_natural_key_key UNIQUE (source_natural_key);


--
-- Name: entity_identity_scenario_supersessions_v2 entity_identity_scenario_supersessions_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_scenario_supersessions_v2
    ADD CONSTRAINT entity_identity_scenario_supersessions_v2_pkey PRIMARY KEY (merge_id, old_scenario_id, new_scenario_id);


--
-- Name: entity_identity_semantic_replays_v2 entity_identity_semantic_replays_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_semantic_replays_v2
    ADD CONSTRAINT entity_identity_semantic_replays_v2_pkey PRIMARY KEY (merge_id, source_event_id, old_normalized_event_id);


--
-- Name: entity_state_current entity_state_current_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_state_current
    ADD CONSTRAINT entity_state_current_pkey PRIMARY KEY (entity_id, state_type);


--
-- Name: entity_state_projection_jobs entity_state_projection_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_state_projection_jobs
    ADD CONSTRAINT entity_state_projection_jobs_pkey PRIMARY KEY (job_id);


--
-- Name: entity_state_projection_jobs entity_state_projection_jobs_source_event_db_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_state_projection_jobs
    ADD CONSTRAINT entity_state_projection_jobs_source_event_db_id_key UNIQUE (source_event_db_id);


--
-- Name: entity_states entity_states_entity_id_state_type_evidence_event_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.entity_states
    ADD CONSTRAINT entity_states_entity_id_state_type_evidence_event_id_key UNIQUE (entity_id, state_type, evidence_event_id);


--
-- Name: entity_states entity_states_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.entity_states
    ADD CONSTRAINT entity_states_pkey PRIMARY KEY (id);


--
-- Name: event_catalog_revisions event_catalog_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.event_catalog_revisions
    ADD CONSTRAINT event_catalog_revisions_pkey PRIMARY KEY (id);


--
-- Name: event_catalog_revisions event_catalog_revisions_version_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.event_catalog_revisions
    ADD CONSTRAINT event_catalog_revisions_version_key UNIQUE (version);


--
-- Name: event_entity_link_blocks_v2 event_entity_link_blocks_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.event_entity_link_blocks_v2
    ADD CONSTRAINT event_entity_link_blocks_v2_pkey PRIMARY KEY (entity_id, block_no);


--
-- Name: event_facts_v2 event_facts_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.event_facts_v2
    ADD CONSTRAINT event_facts_v2_pkey PRIMARY KEY (event_id);


--
-- Name: event_links event_links_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.event_links
    ADD CONSTRAINT event_links_pkey PRIMARY KEY (id);


--
-- Name: event_links event_links_source_event_id_target_event_id_link_type_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.event_links
    ADD CONSTRAINT event_links_source_event_id_target_event_id_link_type_key UNIQUE (source_event_id, target_event_id, link_type);


--
-- Name: events_v2_core events_v2_core_noise_catalog_version; Type: CHECK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.events_v2_core
    ADD CONSTRAINT events_v2_core_noise_catalog_version CHECK (((length(noise_catalog_version) >= 1) AND (length(noise_catalog_version) <= 255))) NOT VALID;


--
-- Name: events_v2_core events_v2_core_noise_class; Type: CHECK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE public.events_v2_core
    ADD CONSTRAINT events_v2_core_noise_class CHECK ((noise_class = ANY (ARRAY['signal'::text, 'context'::text, 'noise'::text, 'not_classified'::text]))) NOT VALID;


--
-- Name: events_v2_core events_v2_core_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_core_pkey PRIMARY KEY (id);


--
-- Name: events_v2_core events_v2_source_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_source_key UNIQUE (server_id, channel_id, event_record_id, time_created_utc);


--
-- Name: finding_entities finding_entities_finding_id_entity_id_entity_role_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_entities
    ADD CONSTRAINT finding_entities_finding_id_entity_id_entity_role_key UNIQUE (finding_id, entity_id, entity_role);


--
-- Name: finding_entities finding_entities_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_entities
    ADD CONSTRAINT finding_entities_pkey PRIMARY KEY (id);


--
-- Name: finding_evidence finding_evidence_finding_id_event_id_evidence_role_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_evidence
    ADD CONSTRAINT finding_evidence_finding_id_event_id_evidence_role_key UNIQUE (finding_id, event_id, evidence_role);


--
-- Name: finding_evidence finding_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_evidence
    ADD CONSTRAINT finding_evidence_pkey PRIMARY KEY (id);


--
-- Name: finding_status_history finding_status_history_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_status_history
    ADD CONSTRAINT finding_status_history_pkey PRIMARY KEY (id);


--
-- Name: findings findings_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_fingerprint_key UNIQUE (fingerprint);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: findings_refresh_state findings_refresh_state_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.findings_refresh_state
    ADD CONSTRAINT findings_refresh_state_pkey PRIMARY KEY (pipeline_name);


--
-- Name: forests forests_name_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.forests
    ADD CONSTRAINT forests_name_key UNIQUE (name);


--
-- Name: forests forests_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.forests
    ADD CONSTRAINT forests_pkey PRIMARY KEY (id);


--
-- Name: gpo_report_v2_source_snapshots gpo_report_v2_source_snapshots_domain_id_source_run_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.gpo_report_v2_source_snapshots
    ADD CONSTRAINT gpo_report_v2_source_snapshots_domain_id_source_run_id_key UNIQUE (domain_id, source_run_id);


--
-- Name: gpo_report_v2_source_snapshots gpo_report_v2_source_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.gpo_report_v2_source_snapshots
    ADD CONSTRAINT gpo_report_v2_source_snapshots_pkey PRIMARY KEY (snapshot_id);


--
-- Name: investigation_audit investigation_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_audit
    ADD CONSTRAINT investigation_audit_pkey PRIMARY KEY (id);


--
-- Name: investigation_context_evidence investigation_context_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_context_evidence
    ADD CONSTRAINT investigation_context_evidence_pkey PRIMARY KEY (investigation_id, context_evidence_id);


--
-- Name: investigation_events investigation_events_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_events
    ADD CONSTRAINT investigation_events_pkey PRIMARY KEY (investigation_id, event_db_id);


--
-- Name: investigation_evidence_refs investigation_evidence_refs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.investigation_evidence_refs
    ADD CONSTRAINT investigation_evidence_refs_pkey PRIMARY KEY (investigation_id, evidence_kind, source_domain_id, reference_id);


--
-- Name: investigation_finding_links investigation_finding_links_finding_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_finding_links
    ADD CONSTRAINT investigation_finding_links_finding_key UNIQUE (finding_id);


--
-- Name: investigation_finding_links investigation_finding_links_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_finding_links
    ADD CONSTRAINT investigation_finding_links_pkey PRIMARY KEY (investigation_id, finding_id);


--
-- Name: investigation_notes investigation_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_notes
    ADD CONSTRAINT investigation_notes_pkey PRIMARY KEY (id);


--
-- Name: investigations investigations_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigations
    ADD CONSTRAINT investigations_pkey PRIMARY KEY (id);


--
-- Name: log_sources log_sources_name_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.log_sources
    ADD CONSTRAINT log_sources_name_key UNIQUE (name);


--
-- Name: log_sources log_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.log_sources
    ADD CONSTRAINT log_sources_pkey PRIMARY KEY (id);


--
-- Name: normalized_events normalized_events_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.normalized_events
    ADD CONSTRAINT normalized_events_pkey PRIMARY KEY (normalized_event_id);


--
-- Name: normalized_events normalized_events_source_event_id_semantic_contract_version_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.normalized_events
    ADD CONSTRAINT normalized_events_source_event_id_semantic_contract_version_key UNIQUE (source_event_id, semantic_contract_version, normalizer_id, normalizer_version);


--
-- Name: object_identity_links object_identity_links_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.object_identity_links
    ADD CONSTRAINT object_identity_links_pkey PRIMARY KEY (id);


--
-- Name: object_identity_links object_identity_links_source_object_type_source_object_id_t_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.object_identity_links
    ADD CONSTRAINT object_identity_links_source_object_type_source_object_id_t_key UNIQUE (source_object_type, source_object_id, target_object_type, target_object_id, relation_type, source_name);


--
-- Name: platform_settings platform_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.platform_settings
    ADD CONSTRAINT platform_settings_pkey PRIMARY KEY (key);


--
-- Name: plugin_component_admission_v1 plugin_component_admission_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_component_admission_v1
    ADD CONSTRAINT plugin_component_admission_v1_pkey PRIMARY KEY (plugin_id, component_id);


--
-- Name: plugin_component_leases_v1 plugin_component_leases_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_component_leases_v1
    ADD CONSTRAINT plugin_component_leases_v1_pkey PRIMARY KEY (lease_uid);


--
-- Name: plugin_installations_v1 plugin_installations_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_installations_v1
    ADD CONSTRAINT plugin_installations_v1_pkey PRIMARY KEY (plugin_id);


--
-- Name: plugin_lifecycle_operations_v1 plugin_lifecycle_operations_v1_operation_uid_key; Type: CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_lifecycle_operations_v1
    ADD CONSTRAINT plugin_lifecycle_operations_v1_operation_uid_key UNIQUE (operation_uid);


--
-- Name: plugin_lifecycle_operations_v1 plugin_lifecycle_operations_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_lifecycle_operations_v1
    ADD CONSTRAINT plugin_lifecycle_operations_v1_pkey PRIMARY KEY (operation_id);


--
-- Name: plugin_state_v1 plugin_state_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_state_v1
    ADD CONSTRAINT plugin_state_v1_pkey PRIMARY KEY (plugin_id);


--
-- Name: post_collection_jobs post_collection_jobs_durable_job_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.post_collection_jobs
    ADD CONSTRAINT post_collection_jobs_durable_job_id_key UNIQUE (durable_job_id);


--
-- Name: post_collection_jobs post_collection_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.post_collection_jobs
    ADD CONSTRAINT post_collection_jobs_pkey PRIMARY KEY (id);


--
-- Name: process_episode_evidence process_episode_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.process_episode_evidence
    ADD CONSTRAINT process_episode_evidence_pkey PRIMARY KEY (revision_id, evidence_order);


--
-- Name: process_episode_evidence process_episode_evidence_revision_id_source_event_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.process_episode_evidence
    ADD CONSTRAINT process_episode_evidence_revision_id_source_event_id_key UNIQUE (revision_id, source_event_id);


--
-- Name: process_episode_revisions process_episode_identity_unique; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.process_episode_revisions
    ADD CONSTRAINT process_episode_identity_unique UNIQUE (episode_id, revision_no);


--
-- Name: process_episode_revisions process_episode_revisions_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.process_episode_revisions
    ADD CONSTRAINT process_episode_revisions_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: process_episode_revisions process_episode_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.process_episode_revisions
    ADD CONSTRAINT process_episode_revisions_pkey PRIMARY KEY (revision_id);


--
-- Name: radius_accounting_class_cache radius_accounting_class_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_accounting_class_cache
    ADD CONSTRAINT radius_accounting_class_cache_pkey PRIMARY KEY (source_instance_id, class_scope_sha256);


--
-- Name: radius_accounting_session_observations radius_accounting_session_observations_evidence_uid_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_accounting_session_observations
    ADD CONSTRAINT radius_accounting_session_observations_evidence_uid_key UNIQUE (evidence_uid);


--
-- Name: radius_accounting_session_observations radius_accounting_session_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_accounting_session_observations
    ADD CONSTRAINT radius_accounting_session_observations_pkey PRIMARY KEY (observation_id);


--
-- Name: radius_session_identity_overlays radius_session_identity_overlays_attempt_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_identity_overlays
    ADD CONSTRAINT radius_session_identity_overlays_attempt_key_key UNIQUE (attempt_key);


--
-- Name: radius_session_identity_overlays radius_session_identity_overlays_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_identity_overlays
    ADD CONSTRAINT radius_session_identity_overlays_pkey PRIMARY KEY (observation_id);


--
-- Name: radius_session_projection_receipts radius_session_projection_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_projection_receipts
    ADD CONSTRAINT radius_session_projection_receipts_pkey PRIMARY KEY (delivery_id);


--
-- Name: radius_session_reconciliation_attempts radius_session_reconciliation_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_reconciliation_attempts
    ADD CONSTRAINT radius_session_reconciliation_attempts_pkey PRIMARY KEY (attempt_key);


--
-- Name: radius_session_reconciliation_attempts radius_session_reconciliation_observation_id_evidence_corpu_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_reconciliation_attempts
    ADD CONSTRAINT radius_session_reconciliation_observation_id_evidence_corpu_key UNIQUE (observation_id, evidence_corpus_sha256, resolver_contract_id);


--
-- Name: radius_vpn_session_projection radius_vpn_session_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_vpn_session_projection
    ADD CONSTRAINT radius_vpn_session_projection_pkey PRIMARY KEY (session_row_id);


--
-- Name: radius_vpn_session_projection radius_vpn_session_projection_session_identity_key_generati_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_vpn_session_projection
    ADD CONSTRAINT radius_vpn_session_projection_session_identity_key_generati_key UNIQUE (session_identity_key, generation);


--
-- Name: raw_batch_lifecycle raw_batch_lifecycle_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.raw_batch_lifecycle
    ADD CONSTRAINT raw_batch_lifecycle_pkey PRIMARY KEY (batch_identity);


--
-- Name: raw_batch_lifecycle raw_batch_lifecycle_raw_path_manifest_hash_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.raw_batch_lifecycle
    ADD CONSTRAINT raw_batch_lifecycle_raw_path_manifest_hash_key UNIQUE (raw_path, manifest_hash);


--
-- Name: raw_log_files raw_log_files_file_path_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.raw_log_files
    ADD CONSTRAINT raw_log_files_file_path_key UNIQUE (file_path);


--
-- Name: raw_log_files raw_log_files_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.raw_log_files
    ADD CONSTRAINT raw_log_files_pkey PRIMARY KEY (id);


--
-- Name: raw_log_files raw_log_files_server_id_log_source_id_sha256_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.raw_log_files
    ADD CONSTRAINT raw_log_files_server_id_log_source_id_sha256_key UNIQUE (server_id, log_source_id, sha256);


--
-- Name: report_access_requests_v4 report_access_requests_v4_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_access_requests_v4
    ADD CONSTRAINT report_access_requests_v4_pkey PRIMARY KEY (id);


--
-- Name: report_datasets_v4 report_datasets_v4_dataset_key_version_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_datasets_v4
    ADD CONSTRAINT report_datasets_v4_dataset_key_version_key UNIQUE (dataset_key, version);


--
-- Name: report_datasets_v4 report_datasets_v4_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_datasets_v4
    ADD CONSTRAINT report_datasets_v4_pkey PRIMARY KEY (id);


--
-- Name: report_items report_items_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_items
    ADD CONSTRAINT report_items_pkey PRIMARY KEY (id);


--
-- Name: report_registry_v4 report_registry_v4_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_registry_v4
    ADD CONSTRAINT report_registry_v4_pkey PRIMARY KEY (id);


--
-- Name: report_registry_v4 report_registry_v4_report_key_version_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_registry_v4
    ADD CONSTRAINT report_registry_v4_report_key_version_key UNIQUE (report_key, version);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: runtime_collection_blocks runtime_collection_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.runtime_collection_blocks
    ADD CONSTRAINT runtime_collection_blocks_pkey PRIMARY KEY (singleton_id);


--
-- Name: runtime_collection_runs runtime_collection_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.runtime_collection_runs
    ADD CONSTRAINT runtime_collection_runs_pkey PRIMARY KEY (run_id);


--
-- Name: runtime_worker_heartbeats runtime_worker_heartbeats_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.runtime_worker_heartbeats
    ADD CONSTRAINT runtime_worker_heartbeats_pkey PRIMARY KEY (worker_name);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_version_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_version_key UNIQUE (version);


--
-- Name: semantic_control_health_observations semantic_control_health_observations_observation_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_control_health_observations
    ADD CONSTRAINT semantic_control_health_observations_observation_key_key UNIQUE (observation_key);


--
-- Name: semantic_control_health_observations semantic_control_health_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_control_health_observations
    ADD CONSTRAINT semantic_control_health_observations_pkey PRIMARY KEY (observation_id);


--
-- Name: semantic_correlation_candidates semantic_correlation_candidat_rule_id_rule_version_candidat_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_candidates
    ADD CONSTRAINT semantic_correlation_candidat_rule_id_rule_version_candidat_key UNIQUE (rule_id, rule_version, candidate_key);


--
-- Name: semantic_correlation_candidate_evidence semantic_correlation_candidate__candidate_id_evidence_order_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_candidate_evidence
    ADD CONSTRAINT semantic_correlation_candidate__candidate_id_evidence_order_key UNIQUE (candidate_id, evidence_order);


--
-- Name: semantic_correlation_candidate_evidence semantic_correlation_candidate_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_candidate_evidence
    ADD CONSTRAINT semantic_correlation_candidate_evidence_pkey PRIMARY KEY (candidate_id, normalized_event_id);


--
-- Name: semantic_correlation_candidates semantic_correlation_candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_candidates
    ADD CONSTRAINT semantic_correlation_candidates_pkey PRIMARY KEY (candidate_id);


--
-- Name: semantic_correlation_dispatch_jobs semantic_correlation_dispatch_jobs_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_dispatch_jobs
    ADD CONSTRAINT semantic_correlation_dispatch_jobs_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: semantic_correlation_dispatch_jobs semantic_correlation_dispatch_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_dispatch_jobs
    ADD CONSTRAINT semantic_correlation_dispatch_jobs_pkey PRIMARY KEY (job_id);


--
-- Name: semantic_correlation_dispatch_jobs semantic_correlation_dispatch_normalized_event_id_rule_id_r_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_dispatch_jobs
    ADD CONSTRAINT semantic_correlation_dispatch_normalized_event_id_rule_id_r_key UNIQUE (normalized_event_id, rule_id, rule_version);


--
-- Name: semantic_correlation_replays semantic_correlation_replays_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_replays
    ADD CONSTRAINT semantic_correlation_replays_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: semantic_correlation_replays semantic_correlation_replays_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_replays
    ADD CONSTRAINT semantic_correlation_replays_pkey PRIMARY KEY (replay_id);


--
-- Name: semantic_correlation_rules semantic_correlation_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_rules
    ADD CONSTRAINT semantic_correlation_rules_pkey PRIMARY KEY (rule_id, rule_version);


--
-- Name: semantic_correlation_rules semantic_correlation_rules_rule_id_rule_version_definition__key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_rules
    ADD CONSTRAINT semantic_correlation_rules_rule_id_rule_version_definition__key UNIQUE (rule_id, rule_version, definition_sha256);


--
-- Name: semantic_correlation_subscriptions semantic_correlation_subscrip_rule_id_rule_version_subscrip_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_subscriptions
    ADD CONSTRAINT semantic_correlation_subscrip_rule_id_rule_version_subscrip_key UNIQUE (rule_id, rule_version, subscription_order);


--
-- Name: semantic_correlation_subscriptions semantic_correlation_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_subscriptions
    ADD CONSTRAINT semantic_correlation_subscriptions_pkey PRIMARY KEY (rule_id, rule_version, semantic_type);


--
-- Name: semantic_finding_publications semantic_finding_publications_finding_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_finding_publications
    ADD CONSTRAINT semantic_finding_publications_finding_fingerprint_key UNIQUE (finding_fingerprint);


--
-- Name: semantic_finding_publications semantic_finding_publications_finding_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_finding_publications
    ADD CONSTRAINT semantic_finding_publications_finding_id_key UNIQUE (finding_id);


--
-- Name: semantic_finding_publications semantic_finding_publications_first_job_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_finding_publications
    ADD CONSTRAINT semantic_finding_publications_first_job_id_key UNIQUE (first_job_id);


--
-- Name: semantic_finding_publications semantic_finding_publications_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_finding_publications
    ADD CONSTRAINT semantic_finding_publications_pkey PRIMARY KEY (scenario_id);


--
-- Name: semantic_finding_publications semantic_finding_publications_scenario_id_finding_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_finding_publications
    ADD CONSTRAINT semantic_finding_publications_scenario_id_finding_id_key UNIQUE (scenario_id, finding_id);


--
-- Name: semantic_processing_outbox semantic_processing_outbox_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_processing_outbox
    ADD CONSTRAINT semantic_processing_outbox_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: semantic_processing_outbox semantic_processing_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_processing_outbox
    ADD CONSTRAINT semantic_processing_outbox_pkey PRIMARY KEY (job_id);


--
-- Name: semantic_processing_outbox semantic_processing_outbox_source_event_id_job_kind_semanti_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_processing_outbox
    ADD CONSTRAINT semantic_processing_outbox_source_event_id_job_kind_semanti_key UNIQUE (source_event_id, job_kind, semantic_contract_version, processor_id, processor_version);


--
-- Name: semantic_risk_contributions semantic_risk_contributions_contribution_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_contributions
    ADD CONSTRAINT semantic_risk_contributions_contribution_key_key UNIQUE (contribution_key);


--
-- Name: semantic_risk_contributions semantic_risk_contributions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_contributions
    ADD CONSTRAINT semantic_risk_contributions_pkey PRIMARY KEY (contribution_id);


--
-- Name: semantic_risk_evaluation_jobs semantic_risk_evaluation_jobs_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_jobs
    ADD CONSTRAINT semantic_risk_evaluation_jobs_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: semantic_risk_evaluation_jobs semantic_risk_evaluation_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_jobs
    ADD CONSTRAINT semantic_risk_evaluation_jobs_pkey PRIMARY KEY (job_id);


--
-- Name: semantic_risk_evaluation_jobs semantic_risk_evaluation_jobs_policy_id_policy_version_sour_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_jobs
    ADD CONSTRAINT semantic_risk_evaluation_jobs_policy_id_policy_version_sour_key UNIQUE (policy_id, policy_version, source_kind, source_reference, evaluation_mode);


--
-- Name: semantic_risk_evaluation_results semantic_risk_evaluation_results_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_results
    ADD CONSTRAINT semantic_risk_evaluation_results_pkey PRIMARY KEY (job_id);


--
-- Name: semantic_risk_policies semantic_risk_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_policies
    ADD CONSTRAINT semantic_risk_policies_pkey PRIMARY KEY (policy_id, policy_version);


--
-- Name: semantic_risk_policies semantic_risk_policies_policy_id_policy_version_definition__key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_policies
    ADD CONSTRAINT semantic_risk_policies_policy_id_policy_version_definition__key UNIQUE (policy_id, policy_version, definition_sha256);


--
-- Name: semantic_risk_policy_subscriptions semantic_risk_policy_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_policy_subscriptions
    ADD CONSTRAINT semantic_risk_policy_subscriptions_pkey PRIMARY KEY (policy_id, policy_version);


--
-- Name: semantic_scenario_coverage_history semantic_scenario_coverage_histo_scenario_id_assessment_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_coverage_history
    ADD CONSTRAINT semantic_scenario_coverage_histo_scenario_id_assessment_key_key UNIQUE (scenario_id, assessment_key);


--
-- Name: semantic_scenario_coverage_history semantic_scenario_coverage_history_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_coverage_history
    ADD CONSTRAINT semantic_scenario_coverage_history_pkey PRIMARY KEY (coverage_id);


--
-- Name: semantic_scenario_evidence semantic_scenario_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_evidence
    ADD CONSTRAINT semantic_scenario_evidence_pkey PRIMARY KEY (scenario_id, normalized_event_id);


--
-- Name: semantic_scenario_evidence semantic_scenario_evidence_scenario_id_evidence_order_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_evidence
    ADD CONSTRAINT semantic_scenario_evidence_scenario_id_evidence_order_key UNIQUE (scenario_id, evidence_order);


--
-- Name: semantic_scenario_reviews semantic_scenario_reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_reviews
    ADD CONSTRAINT semantic_scenario_reviews_pkey PRIMARY KEY (review_id);


--
-- Name: semantic_scenario_reviews semantic_scenario_reviews_review_request_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_reviews
    ADD CONSTRAINT semantic_scenario_reviews_review_request_id_key UNIQUE (review_request_id);


--
-- Name: semantic_scenario_steps semantic_scenario_steps_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_steps
    ADD CONSTRAINT semantic_scenario_steps_pkey PRIMARY KEY (step_id);


--
-- Name: semantic_scenario_steps semantic_scenario_steps_step_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_steps
    ADD CONSTRAINT semantic_scenario_steps_step_key_key UNIQUE (step_key);


--
-- Name: semantic_security_scenarios semantic_security_scenarios_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_security_scenarios
    ADD CONSTRAINT semantic_security_scenarios_pkey PRIMARY KEY (scenario_id);


--
-- Name: semantic_security_scenarios semantic_security_scenarios_scenario_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_security_scenarios
    ADD CONSTRAINT semantic_security_scenarios_scenario_key_key UNIQUE (scenario_key);


--
-- Name: servers servers_domain_id_hostname_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.servers
    ADD CONSTRAINT servers_domain_id_hostname_key UNIQUE (domain_id, hostname);


--
-- Name: servers servers_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.servers
    ADD CONSTRAINT servers_pkey PRIMARY KEY (id);


--
-- Name: sites sites_domain_id_name_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.sites
    ADD CONSTRAINT sites_domain_id_name_key UNIQUE (domain_id, name);


--
-- Name: sites sites_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.sites
    ADD CONSTRAINT sites_pkey PRIMARY KEY (id);


--
-- Name: source_capture_continuity_declarations source_capture_continuity_dec_scope_identity_declaration_sh_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.source_capture_continuity_declarations
    ADD CONSTRAINT source_capture_continuity_dec_scope_identity_declaration_sh_key UNIQUE (scope_identity, declaration_sha256);


--
-- Name: source_capture_continuity_declarations source_capture_continuity_declarations_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.source_capture_continuity_declarations
    ADD CONSTRAINT source_capture_continuity_declarations_pkey PRIMARY KEY (id);


--
-- Name: storage_lifecycle_snapshots storage_lifecycle_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.storage_lifecycle_snapshots
    ADD CONSTRAINT storage_lifecycle_snapshots_pkey PRIMARY KEY (id);


--
-- Name: storage_lifecycle_snapshots storage_lifecycle_snapshots_source_run_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.storage_lifecycle_snapshots
    ADD CONSTRAINT storage_lifecycle_snapshots_source_run_id_key UNIQUE (source_run_id);


--
-- Name: storage_v2_archive_blocks storage_v2_archive_blocks_location_unique; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_archive_blocks
    ADD CONSTRAINT storage_v2_archive_blocks_location_unique UNIQUE (object_location);


--
-- Name: storage_v2_archive_blocks storage_v2_archive_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_archive_blocks
    ADD CONSTRAINT storage_v2_archive_blocks_pkey PRIMARY KEY (archive_set_id, archive_kind, block_index);


--
-- Name: storage_v2_archive_sets storage_v2_archive_sets_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_archive_sets
    ADD CONSTRAINT storage_v2_archive_sets_pkey PRIMARY KEY (archive_set_id);


--
-- Name: storage_v2_backfill_checkpoints storage_v2_backfill_checkpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_backfill_checkpoints
    ADD CONSTRAINT storage_v2_backfill_checkpoints_pkey PRIMARY KEY (worker_name);


--
-- Name: storage_v2_backfill_chunks storage_v2_backfill_chunks_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_backfill_chunks
    ADD CONSTRAINT storage_v2_backfill_chunks_pkey PRIMARY KEY (worker_name, chunk_start_event_id, chunk_end_event_id);


--
-- Name: storage_v2_channel storage_v2_channel_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_channel
    ADD CONSTRAINT storage_v2_channel_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_channel storage_v2_channel_value_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_channel
    ADD CONSTRAINT storage_v2_channel_value_key UNIQUE (value);


--
-- Name: storage_v2_computer storage_v2_computer_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_computer
    ADD CONSTRAINT storage_v2_computer_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_computer storage_v2_computer_value_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_computer
    ADD CONSTRAINT storage_v2_computer_value_key UNIQUE (value);


--
-- Name: storage_v2_cutover_state storage_v2_cutover_state_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_cutover_state
    ADD CONSTRAINT storage_v2_cutover_state_pkey PRIMARY KEY (singleton);


--
-- Name: storage_v2_domain_name storage_v2_domain_name_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_domain_name
    ADD CONSTRAINT storage_v2_domain_name_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_domain_name storage_v2_domain_name_value_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_domain_name
    ADD CONSTRAINT storage_v2_domain_name_value_key UNIQUE (value);


--
-- Name: storage_v2_entity_identity_allocations storage_v2_entity_identity_alloc_entity_type_id_natural_key_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_entity_identity_allocations
    ADD CONSTRAINT storage_v2_entity_identity_alloc_entity_type_id_natural_key_key UNIQUE (entity_type_id, natural_key);


--
-- Name: storage_v2_entity_identity_allocations storage_v2_entity_identity_allocations_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_entity_identity_allocations
    ADD CONSTRAINT storage_v2_entity_identity_allocations_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_entity_type storage_v2_entity_type_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_entity_type
    ADD CONSTRAINT storage_v2_entity_type_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_entity_type storage_v2_entity_type_value_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_entity_type
    ADD CONSTRAINT storage_v2_entity_type_value_key UNIQUE (value);


--
-- Name: storage_v2_event_identity_allocations storage_v2_event_identity_all_server_id_channel_id_event_re_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_event_identity_allocations
    ADD CONSTRAINT storage_v2_event_identity_all_server_id_channel_id_event_re_key UNIQUE (server_id, channel_id, event_record_id, time_created_utc);


--
-- Name: storage_v2_event_identity_allocations storage_v2_event_identity_allocations_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_event_identity_allocations
    ADD CONSTRAINT storage_v2_event_identity_allocations_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_extracted_from storage_v2_extracted_from_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_extracted_from
    ADD CONSTRAINT storage_v2_extracted_from_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_extracted_from storage_v2_extracted_from_value_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_extracted_from
    ADD CONSTRAINT storage_v2_extracted_from_value_key UNIQUE (value);


--
-- Name: storage_v2_keywords storage_v2_keywords_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_keywords
    ADD CONSTRAINT storage_v2_keywords_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_keywords storage_v2_keywords_value_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_keywords
    ADD CONSTRAINT storage_v2_keywords_value_key UNIQUE (value);


--
-- Name: storage_v2_outbox storage_v2_outbox_batch_id_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_outbox
    ADD CONSTRAINT storage_v2_outbox_batch_id_key UNIQUE (batch_id);


--
-- Name: storage_v2_outbox storage_v2_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_outbox
    ADD CONSTRAINT storage_v2_outbox_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_provider storage_v2_provider_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_provider
    ADD CONSTRAINT storage_v2_provider_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_provider storage_v2_provider_value_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_provider
    ADD CONSTRAINT storage_v2_provider_value_key UNIQUE (value);


--
-- Name: storage_v2_role storage_v2_role_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_role
    ADD CONSTRAINT storage_v2_role_pkey PRIMARY KEY (id);


--
-- Name: storage_v2_role storage_v2_role_value_key; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_role
    ADD CONSTRAINT storage_v2_role_value_key UNIQUE (value);


--
-- Name: storage_v2_runtime_authorizations storage_v2_runtime_authorizations_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_runtime_authorizations
    ADD CONSTRAINT storage_v2_runtime_authorizations_pkey PRIMARY KEY (singleton);


--
-- Name: storage_v2_shadow_results storage_v2_shadow_results_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_shadow_results
    ADD CONSTRAINT storage_v2_shadow_results_pkey PRIMARY KEY (id);


--
-- Name: user_report_preferences user_report_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.user_report_preferences
    ADD CONSTRAINT user_report_preferences_pkey PRIMARY KEY (user_id, report_key);


--
-- Name: users_report_v2_snapshots users_report_v2_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_report_v2_snapshots
    ADD CONSTRAINT users_report_v2_snapshots_pkey PRIMARY KEY (snapshot_id);


--
-- Name: users_report_v2_snapshots users_report_v2_snapshots_source_observed_unique; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_report_v2_snapshots
    ADD CONSTRAINT users_report_v2_snapshots_source_observed_unique UNIQUE (domain_id, scope_sha256, source_observed_at_utc, contract_id, schema_version);


--
-- Name: what_where_when_observations what_where_when_observations_hourly_identity; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_observations
    ADD CONSTRAINT what_where_when_observations_hourly_identity UNIQUE (computer_object_guid, user_key, observed_hour_local);


--
-- Name: what_where_when_observations what_where_when_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_observations
    ADD CONSTRAINT what_where_when_observations_pkey PRIMARY KEY (projection_id);


--
-- Name: what_where_when_observations what_where_when_observations_source_event_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_observations
    ADD CONSTRAINT what_where_when_observations_source_event_id_key UNIQUE (source_event_id);


--
-- Name: what_where_when_projection_state what_where_when_projection_state_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_projection_state
    ADD CONSTRAINT what_where_when_projection_state_pkey PRIMARY KEY (singleton);


--
-- Name: plugin_namespace_contract_v1 plugin_namespace_contract_v1_pkey; Type: CONSTRAINT; Schema: sli_plugin_remote_access; Owner: adlog_plugin_remote_access_owner
--

ALTER TABLE ONLY sli_plugin_remote_access.plugin_namespace_contract_v1
    ADD CONSTRAINT plugin_namespace_contract_v1_pkey PRIMARY KEY (plugin_id);


--
-- Name: access_capability_assignments_subject_idx; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX access_capability_assignments_subject_idx ON public.access_capability_assignments USING btree (subject_type, subject_id, effect, valid_until);


--
-- Name: access_report_assignments_subject_idx; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX access_report_assignments_subject_idx ON public.access_report_assignments USING btree (subject_type, subject_id, report_key, effect, valid_until);


--
-- Name: account_risk_acceptances_active_key; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX account_risk_acceptances_active_key ON public.account_risk_acceptances USING btree (entity_id, risk_key, rule_version) WHERE (status = 'active'::text);


--
-- Name: account_risk_acceptances_domain_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX account_risk_acceptances_domain_status ON public.account_risk_acceptances USING btree (domain_id, status, valid_until);


--
-- Name: account_risk_investigation_links_subject; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX account_risk_investigation_links_subject ON public.account_risk_investigation_links USING btree (entity_id, risk_key, created_at DESC);


--
-- Name: acquisition_delivery_outbox_claim_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX acquisition_delivery_outbox_claim_idx ON public.acquisition_delivery_outbox USING btree (delivery_state, available_at, lease_until, created_at, delivery_id);


--
-- Name: administrative_activity_category_idx; Type: INDEX; Schema: public; Owner: adlog_administrative_activity_owner
--

CREATE INDEX administrative_activity_category_idx ON public.administrative_activity_v1 USING btree (category, occurred_at_utc DESC, activity_id DESC);


--
-- Name: administrative_activity_occurred_idx; Type: INDEX; Schema: public; Owner: adlog_administrative_activity_owner
--

CREATE INDEX administrative_activity_occurred_idx ON public.administrative_activity_v1 USING btree (occurred_at_utc DESC, activity_id DESC);


--
-- Name: auth_sessions_active_idx; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX auth_sessions_active_idx ON public.auth_sessions USING btree (token_hash, expires_at) WHERE (revoked_at IS NULL);


--
-- Name: auth_users_username_lower_uq; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE UNIQUE INDEX auth_users_username_lower_uq ON public.auth_users USING btree (lower(username));


--
-- Name: core_evidence_manifest_hash_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX core_evidence_manifest_hash_idx ON public.core_evidence_manifests USING btree (source_instance_id, stream_id, canonical_record_sha256);


--
-- Name: domain_controller_targets_domain_idx; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX domain_controller_targets_domain_idx ON public.domain_controller_targets USING btree (domain_id);


--
-- Name: domain_controller_targets_hostname_key; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE UNIQUE INDEX domain_controller_targets_hostname_key ON public.domain_controller_targets USING btree (lower(hostname));


--
-- Name: idx_ad_context_evidence_run_type_record_key; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_ad_context_evidence_run_type_record_key ON public.ad_context_evidence USING btree (source_run_id, evidence_type, ((locator_json ->> 'record_key'::text)));


--
-- Name: idx_ad_context_relation_source_current; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_ad_context_relation_source_current ON public.ad_context_relation_versions USING btree (source_entity_id, relation_kind) WHERE (valid_to_utc IS NULL);


--
-- Name: idx_ad_context_relation_target_current; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_ad_context_relation_target_current ON public.ad_context_relation_versions USING btree (target_entity_id, relation_kind) WHERE (valid_to_utc IS NULL);


--
-- Name: idx_ad_snapshot_manifests_slot; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ad_snapshot_manifests_slot ON public.ad_snapshot_manifests USING btree (domain_id, slot_start_utc DESC, manifest_id);


--
-- Name: idx_ad_snapshot_projection_receipts_claim; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ad_snapshot_projection_receipts_claim ON public.ad_snapshot_projection_receipts USING btree (status, lease_expires_at, attempt_count, created_at);


--
-- Name: idx_ai_api_runs_status_time; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_ai_api_runs_status_time ON public.ai_api_runs USING btree (status, created_at);


--
-- Name: idx_canonical_action_evidence_event; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_canonical_action_evidence_event ON public.canonical_action_evidence USING btree (normalized_event_id, canonical_action_id);


--
-- Name: idx_canonical_action_state_evidence_context; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_canonical_action_state_evidence_context ON public.canonical_action_state_evidence USING btree (context_evidence_id, canonical_action_id);


--
-- Name: idx_canonical_actions_occurred; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_canonical_actions_occurred ON public.canonical_actions USING btree (action_kind, occurred_at_utc DESC, canonical_action_id);


--
-- Name: idx_collector_channel_runs_server_channel_time; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_collector_channel_runs_server_channel_time ON public.collector_channel_runs USING btree (server, channel, created_at);


--
-- Name: idx_collector_cursor_audit_created; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_collector_cursor_audit_created ON public.collector_cursor_audit USING btree (created_at DESC);


--
-- Name: idx_collector_cursor_audit_server_channel; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_collector_cursor_audit_server_channel ON public.collector_cursor_audit USING btree (server, channel, id DESC);


--
-- Name: idx_collector_stage_metrics_job_server_channel; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_collector_stage_metrics_job_server_channel ON public.collector_stage_metrics USING btree (job_id, server, channel, created_at);


--
-- Name: idx_computers_report_v5_snapshots_latest; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_computers_report_v5_snapshots_latest ON public.computers_report_v5_snapshots USING btree (domain_id, scope_sha256, captured_at_utc DESC, snapshot_id DESC);


--
-- Name: idx_computers_report_v5_snapshots_retention; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_computers_report_v5_snapshots_retention ON public.computers_report_v5_snapshots USING btree (captured_at_utc, snapshot_id);


--
-- Name: idx_computers_report_v6_snapshots_latest; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_computers_report_v6_snapshots_latest ON public.computers_report_v6_snapshots USING btree (domain_id, scope_sha256, captured_at_utc DESC, snapshot_id DESC);


--
-- Name: idx_computers_report_v6_snapshots_retention; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_computers_report_v6_snapshots_retention ON public.computers_report_v6_snapshots USING btree (captured_at_utc, snapshot_id);


--
-- Name: idx_computers_v6_source_snapshots_latest; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_computers_v6_source_snapshots_latest ON public.computers_v6_source_snapshots USING btree (domain_id, source_completed_at_utc DESC, source_snapshot_id DESC);


--
-- Name: idx_computers_v6_source_snapshots_retention; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_computers_v6_source_snapshots_retention ON public.computers_v6_source_snapshots USING btree (captured_at_utc, source_snapshot_id);


--
-- Name: idx_detections_status; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_detections_status ON public.detections USING btree (status, detected_at);


--
-- Name: idx_entities_v2_display_casefold; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_entities_v2_display_casefold ON public.entities_v2 USING btree (lower(display_name) text_pattern_ops, last_seen_utc DESC, id DESC);


--
-- Name: idx_entities_v2_natural_casefold; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_entities_v2_natural_casefold ON public.entities_v2 USING btree (lower(natural_key) text_pattern_ops, last_seen_utc DESC, id DESC);


--
-- Name: idx_entities_v2_recent; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_entities_v2_recent ON public.entities_v2 USING btree (last_seen_utc DESC, id DESC);


--
-- Name: idx_entity_state_current_observed; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_entity_state_current_observed ON public.entity_state_current USING btree (observed_at DESC, source_event_db_id DESC);


--
-- Name: idx_entity_state_projection_claim; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_entity_state_projection_claim ON public.entity_state_projection_jobs USING btree (status, available_at, lease_until, source_event_db_id);


--
-- Name: idx_entity_states_entity; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_entity_states_entity ON public.entity_states USING btree (entity_id, observed_at_utc);


--
-- Name: idx_event_entity_link_blocks_v2_event_range; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_event_entity_link_blocks_v2_event_range ON public.event_entity_link_blocks_v2 USING brin (first_event_id, last_event_id) WITH (pages_per_range='32');


--
-- Name: idx_event_facts_v2_process; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_event_facts_v2_process ON public.event_facts_v2 USING btree (process_name) WHERE (process_name IS NOT NULL);


--
-- Name: idx_event_facts_v2_target_server; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_event_facts_v2_target_server ON public.event_facts_v2 USING btree (target_server_name) WHERE (target_server_name IS NOT NULL);


--
-- Name: idx_event_facts_v2_task; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_event_facts_v2_task ON public.event_facts_v2 USING btree (task_name) WHERE (task_name IS NOT NULL);


--
-- Name: idx_event_links_target; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_event_links_target ON public.event_links USING btree (target_event_id);


--
-- Name: idx_events_v2_browse_visible_latest; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_browse_visible_latest ON public.events_v2_core USING btree (time_created_utc DESC, COALESCE(event_record_id, ('-1'::integer)::bigint) DESC, id DESC) WHERE (noise_class = ANY (ARRAY['signal'::text, 'not_classified'::text]));


--
-- Name: idx_events_v2_channel_event_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_channel_event_time ON public.events_v2_core USING btree (channel_id, event_id, time_created_utc DESC, id DESC);


--
-- Name: idx_events_v2_event_id_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_event_id_time ON public.events_v2_core USING btree (event_id, time_created_utc DESC, id DESC);


--
-- Name: idx_events_v2_ip_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_ip_time ON public.events_v2_core USING btree (ip_address, time_created_utc DESC) WHERE (ip_address IS NOT NULL);


--
-- Name: idx_events_v2_latest; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_latest ON public.events_v2_core USING btree (time_created_utc DESC, event_record_id DESC, id DESC);


--
-- Name: idx_events_v2_logon_id_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_logon_id_time ON public.events_v2_core USING btree (logon_id, time_created_utc DESC) WHERE (logon_id IS NOT NULL);


--
-- Name: idx_events_v2_server_channel_latest; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_server_channel_latest ON public.events_v2_core USING btree (server_id, channel_id, time_created_utc DESC, event_record_id DESC);


--
-- Name: idx_events_v2_server_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_server_time ON public.events_v2_core USING btree (server_id, time_created_utc DESC, id DESC);


--
-- Name: idx_events_v2_subject_casefold_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_subject_casefold_time ON public.events_v2_core USING btree (lower(subject_user_name) text_pattern_ops, time_created_utc DESC, id DESC) WHERE (subject_user_name IS NOT NULL);


--
-- Name: idx_events_v2_subject_user_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_subject_user_time ON public.events_v2_core USING btree (subject_user_name, time_created_utc DESC) WHERE (subject_user_name IS NOT NULL);


--
-- Name: idx_events_v2_target_casefold_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_target_casefold_time ON public.events_v2_core USING btree (lower(target_user_name) text_pattern_ops, time_created_utc DESC, id DESC) WHERE (target_user_name IS NOT NULL);


--
-- Name: idx_events_v2_target_user_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_events_v2_target_user_time ON public.events_v2_core USING btree (target_user_name, time_created_utc DESC) WHERE (target_user_name IS NOT NULL);


--
-- Name: idx_finding_entities_name; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_finding_entities_name ON public.finding_entities USING btree (display_name);


--
-- Name: idx_finding_evidence_event; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_finding_evidence_event ON public.finding_evidence USING btree (event_id);


--
-- Name: idx_findings_rule; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_findings_rule ON public.findings USING btree (rule_code, last_seen_utc);


--
-- Name: idx_findings_status_severity; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_findings_status_severity ON public.findings USING btree (status, severity, last_seen_utc);


--
-- Name: idx_gpo_report_v2_source_snapshots_latest; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_gpo_report_v2_source_snapshots_latest ON public.gpo_report_v2_source_snapshots USING btree (domain_id, source_completed_at_utc DESC, snapshot_id DESC);


--
-- Name: idx_gpo_report_v2_source_snapshots_retention; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_gpo_report_v2_source_snapshots_retention ON public.gpo_report_v2_source_snapshots USING btree (created_at, snapshot_id);


--
-- Name: idx_normalized_events_semantic_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_normalized_events_semantic_time ON public.normalized_events USING btree (semantic_type, occurred_at_utc DESC, normalized_event_id);


--
-- Name: idx_normalized_events_source; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_normalized_events_source ON public.normalized_events USING btree (source_event_id, normalized_at DESC);


--
-- Name: idx_post_collection_jobs_lease; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_post_collection_jobs_lease ON public.post_collection_jobs USING btree (status, worker_lease_until);


--
-- Name: idx_post_collection_jobs_source_job_id; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_post_collection_jobs_source_job_id ON public.post_collection_jobs USING btree (source_job_id);


--
-- Name: idx_post_collection_jobs_status; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_post_collection_jobs_status ON public.post_collection_jobs USING btree (status, queued_at);


--
-- Name: idx_raw_batch_lifecycle_retained; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_raw_batch_lifecycle_retained ON public.raw_batch_lifecycle USING btree (updated_at DESC) WHERE (cleanup_outcome <> 'deleted'::text);


--
-- Name: idx_raw_batch_lifecycle_trace; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_raw_batch_lifecycle_trace ON public.raw_batch_lifecycle USING btree (trace_id, server);


--
-- Name: idx_runtime_collection_runs_created; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_runtime_collection_runs_created ON public.runtime_collection_runs USING btree (created_at DESC);


--
-- Name: idx_runtime_collection_runs_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_runtime_collection_runs_status ON public.runtime_collection_runs USING btree (status, updated_at DESC);


--
-- Name: idx_semantic_control_health_latest; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_control_health_latest ON public.semantic_control_health_observations USING btree (partition_key, control_id, observed_at_utc DESC, observation_id);


--
-- Name: idx_semantic_correlation_candidate_evidence_event; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_correlation_candidate_evidence_event ON public.semantic_correlation_candidate_evidence USING btree (normalized_event_id, candidate_id);


--
-- Name: idx_semantic_correlation_candidate_partition; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_correlation_candidate_partition ON public.semantic_correlation_candidates USING btree (partition_key, window_end_utc DESC, candidate_id);


--
-- Name: idx_semantic_correlation_dispatch_claim; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_correlation_dispatch_claim ON public.semantic_correlation_dispatch_jobs USING btree (dispatch_status, available_at, lease_until, created_at);


--
-- Name: idx_semantic_correlation_dispatch_partition; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_correlation_dispatch_partition ON public.semantic_correlation_dispatch_jobs USING btree (partition_key, occurred_at_utc, job_id);


--
-- Name: idx_semantic_correlation_replay_claim; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_correlation_replay_claim ON public.semantic_correlation_replays USING btree (replay_status, available_at, lease_until, created_at);


--
-- Name: idx_semantic_correlation_subscription_type; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_correlation_subscription_type ON public.semantic_correlation_subscriptions USING btree (semantic_type, rule_id, rule_version);


--
-- Name: idx_semantic_outbox_partition_claim; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_outbox_partition_claim ON public.semantic_processing_outbox USING btree (partition_key, status, available_at, created_at);


--
-- Name: idx_semantic_processing_outbox_claim; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_processing_outbox_claim ON public.semantic_processing_outbox USING btree (status, available_at, lease_until, created_at);


--
-- Name: idx_semantic_risk_contribution_scenario; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_risk_contribution_scenario ON public.semantic_risk_contributions USING btree (scenario_id, created_at, contribution_id);


--
-- Name: idx_semantic_risk_evaluation_action; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_risk_evaluation_action ON public.semantic_risk_evaluation_jobs USING btree (canonical_action_id) WHERE (canonical_action_id IS NOT NULL);


--
-- Name: idx_semantic_risk_evaluation_claim; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_risk_evaluation_claim ON public.semantic_risk_evaluation_jobs USING btree (evaluation_status, available_at, lease_until, created_at);


--
-- Name: idx_semantic_risk_evaluation_source; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_risk_evaluation_source ON public.semantic_risk_evaluation_jobs USING btree (source_kind, source_reference, evaluation_mode, job_id);


--
-- Name: idx_semantic_risk_result_conclusion; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_risk_result_conclusion ON public.semantic_risk_evaluation_results USING btree (conclusion_state, created_at, job_id);


--
-- Name: idx_semantic_risk_result_metrics; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_risk_result_metrics ON public.semantic_risk_evaluation_results USING btree (evaluation_mode, created_at, risk_class, coverage_status);


--
-- Name: idx_semantic_risk_subscription_source; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_risk_subscription_source ON public.semantic_risk_policy_subscriptions USING btree (source_kind, selector_value, policy_id, policy_version);


--
-- Name: idx_semantic_scenario_coverage_latest; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_scenario_coverage_latest ON public.semantic_scenario_coverage_history USING btree (scenario_id, control_id, observed_at_utc DESC, coverage_id);


--
-- Name: idx_semantic_scenario_evidence_event; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_scenario_evidence_event ON public.semantic_scenario_evidence USING btree (normalized_event_id, scenario_id);


--
-- Name: idx_semantic_scenario_identity_window; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_scenario_identity_window ON public.semantic_security_scenarios USING btree (identity_key, scenario_status, last_seen_utc DESC, scenario_id);


--
-- Name: idx_semantic_scenario_partition_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_scenario_partition_time ON public.semantic_security_scenarios USING btree (partition_key, last_seen_utc DESC, scenario_id);


--
-- Name: idx_semantic_scenario_review_latest; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_scenario_review_latest ON public.semantic_scenario_reviews USING btree (scenario_id, reviewed_at DESC, review_id DESC);


--
-- Name: idx_semantic_scenario_step_scenario; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_semantic_scenario_step_scenario ON public.semantic_scenario_steps USING btree (scenario_id, occurred_at_utc, step_id);


--
-- Name: idx_storage_lifecycle_snapshots_captured; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_storage_lifecycle_snapshots_captured ON public.storage_lifecycle_snapshots USING btree (captured_at DESC);


--
-- Name: idx_storage_lifecycle_snapshots_source_job_id; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX idx_storage_lifecycle_snapshots_source_job_id ON public.storage_lifecycle_snapshots USING btree (source_job_id);


--
-- Name: idx_storage_v2_archive_blocks_lookup; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_storage_v2_archive_blocks_lookup ON public.storage_v2_archive_blocks USING btree (archive_kind, state, first_event_id, last_event_id);


--
-- Name: idx_storage_v2_checkpoints_lease; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_storage_v2_checkpoints_lease ON public.storage_v2_backfill_checkpoints USING btree (state, lease_until);


--
-- Name: idx_storage_v2_outbox_claim; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_storage_v2_outbox_claim ON public.storage_v2_outbox USING btree (state, available_at, lease_until, id);


--
-- Name: idx_storage_v2_shadow_kind_time; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_storage_v2_shadow_kind_time ON public.storage_v2_shadow_results USING btree (query_kind, observed_at DESC);


--
-- Name: idx_storage_v2_shadow_mismatch; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX idx_storage_v2_shadow_mismatch ON public.storage_v2_shadow_results USING btree (observed_at DESC) WHERE ((NOT identity_match) OR (NOT count_match));


--
-- Name: idx_users_report_v2_snapshots_latest; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_report_v2_snapshots_latest ON public.users_report_v2_snapshots USING btree (domain_id, scope_sha256, captured_at_utc DESC, snapshot_id DESC);


--
-- Name: idx_users_report_v2_snapshots_retention; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_report_v2_snapshots_retention ON public.users_report_v2_snapshots USING btree (captured_at_utc, snapshot_id);


--
-- Name: idx_users_report_v2_snapshots_source_observed; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_report_v2_snapshots_source_observed ON public.users_report_v2_snapshots USING btree (domain_id, scope_sha256, source_observed_at_utc DESC, snapshot_id DESC);


--
-- Name: idx_what_where_when_observations_computer_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_what_where_when_observations_computer_time ON public.what_where_when_observations USING btree (computer_object_guid, observed_at_utc DESC, projection_id DESC);


--
-- Name: idx_what_where_when_observations_retention; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_what_where_when_observations_retention ON public.what_where_when_observations USING btree (observed_at_utc, projection_id);


--
-- Name: investigation_audit_case_created_idx; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX investigation_audit_case_created_idx ON public.investigation_audit USING btree (investigation_id, created_at DESC);


--
-- Name: investigation_evidence_refs_domain_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX investigation_evidence_refs_domain_idx ON public.investigation_evidence_refs USING btree (source_domain_id, investigation_id);


--
-- Name: investigations_public_id_uidx; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE UNIQUE INDEX investigations_public_id_uidx ON public.investigations USING btree (public_id);


--
-- Name: investigations_status_updated_idx; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX investigations_status_updated_idx ON public.investigations USING btree (status, updated_at DESC);


--
-- Name: plugin_component_one_active_lease_v1; Type: INDEX; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE UNIQUE INDEX plugin_component_one_active_lease_v1 ON public.plugin_component_leases_v1 USING btree (plugin_id, component_id) WHERE (released_at_utc IS NULL);


--
-- Name: process_episode_evidence_source_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX process_episode_evidence_source_idx ON public.process_episode_evidence USING btree (domain_id, source_host_id, source_channel, event_record_id, source_event_id);


--
-- Name: process_episode_identity_time_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX process_episode_identity_time_idx ON public.process_episode_revisions USING btree (domain_id, source_host_id, boot_event_id, process_id, started_at_utc, start_event_id);


--
-- Name: radius_accounting_class_cache_expiry_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX radius_accounting_class_cache_expiry_idx ON public.radius_accounting_class_cache USING btree (source_instance_id, expires_at_utc);


--
-- Name: radius_session_reconciliation_attempt_observation_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX radius_session_reconciliation_attempt_observation_idx ON public.radius_session_reconciliation_attempts USING btree (observation_id, created_at, attempt_key);


--
-- Name: radius_vpn_session_projection_principal_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX radius_vpn_session_projection_principal_idx ON public.radius_vpn_session_projection USING btree (exact_principal_key, last_observed_at_utc DESC, session_row_id);


--
-- Name: radius_vpn_session_projection_state_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX radius_vpn_session_projection_state_idx ON public.radius_vpn_session_projection USING btree (lifecycle_state, last_observed_at_utc DESC, session_row_id);


--
-- Name: report_access_requests_v4_active_unique; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE UNIQUE INDEX report_access_requests_v4_active_unique ON public.report_access_requests_v4 USING btree (requester_user_id, report_key, requested_scope_json) WHERE (status = ANY (ARRAY['submitted'::text, 'reviewing'::text]));


--
-- Name: report_access_requests_v4_status_idx; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE INDEX report_access_requests_v4_status_idx ON public.report_access_requests_v4 USING btree (status, created_at DESC);


--
-- Name: source_capture_continuity_declarations_scope_idx; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE INDEX source_capture_continuity_declarations_scope_idx ON public.source_capture_continuity_declarations USING btree (server_id, log_source_id, descriptor_source, descriptor_stream, provider_name, channel_generation_identity, first_event_record_id, last_event_record_id);


--
-- Name: uq_ad_context_entity_version_open; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE UNIQUE INDEX uq_ad_context_entity_version_open ON public.ad_context_entity_versions USING btree (entity_id, source_section) WHERE (valid_to_utc IS NULL);


--
-- Name: uq_ad_context_relation_version_open; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE UNIQUE INDEX uq_ad_context_relation_version_open ON public.ad_context_relation_versions USING btree (domain_id, relation_key) WHERE (valid_to_utc IS NULL);


--
-- Name: uq_entity_states_evidence_identity; Type: INDEX; Schema: public; Owner: adlog_user
--

CREATE UNIQUE INDEX uq_entity_states_evidence_identity ON public.entity_states USING btree (entity_id, state_type, evidence_event_id);


--
-- Name: uq_semantic_correlation_rule_enabled; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE UNIQUE INDEX uq_semantic_correlation_rule_enabled ON public.semantic_correlation_rules USING btree (rule_id) WHERE (lifecycle_status = 'enabled'::text);


--
-- Name: uq_semantic_risk_policy_enabled; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE UNIQUE INDEX uq_semantic_risk_policy_enabled ON public.semantic_risk_policies USING btree (policy_id) WHERE (lifecycle_status = 'enabled'::text);


--
-- Name: uq_semantic_scenario_review_superseded_once; Type: INDEX; Schema: public; Owner: adlog_storage_owner
--

CREATE UNIQUE INDEX uq_semantic_scenario_review_superseded_once ON public.semantic_scenario_reviews USING btree (supersedes_review_id) WHERE (supersedes_review_id IS NOT NULL);


--
-- Name: account_risk_acceptances account_risk_acceptance_audit_trigger; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER account_risk_acceptance_audit_trigger AFTER INSERT OR UPDATE ON public.account_risk_acceptances FOR EACH ROW EXECUTE FUNCTION public.audit_account_risk_acceptance_change();


--
-- Name: administrative_activity_v1 administrative_activity_reject_truncate; Type: TRIGGER; Schema: public; Owner: adlog_administrative_activity_owner
--

CREATE TRIGGER administrative_activity_reject_truncate BEFORE TRUNCATE ON public.administrative_activity_v1 FOR EACH STATEMENT EXECUTE FUNCTION public.reject_administrative_activity_mutation_v1();


--
-- Name: administrative_activity_v1 administrative_activity_reject_update_delete; Type: TRIGGER; Schema: public; Owner: adlog_administrative_activity_owner
--

CREATE TRIGGER administrative_activity_reject_update_delete BEFORE DELETE OR UPDATE ON public.administrative_activity_v1 FOR EACH ROW EXECUTE FUNCTION public.reject_administrative_activity_mutation_v1();


--
-- Name: events_v2_core events_v2_core_catalog_revision; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER events_v2_core_catalog_revision BEFORE INSERT OR UPDATE OF noise_catalog_version ON public.events_v2_core FOR EACH ROW EXECUTE FUNCTION public.set_event_noise_catalog_revision();


--
-- Name: plugin_lifecycle_operations_v1 plugin_lifecycle_operations_reject_truncate; Type: TRIGGER; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE TRIGGER plugin_lifecycle_operations_reject_truncate BEFORE TRUNCATE ON public.plugin_lifecycle_operations_v1 FOR EACH STATEMENT EXECUTE FUNCTION public.reject_plugin_lifecycle_operation_mutation_v1();


--
-- Name: plugin_lifecycle_operations_v1 plugin_lifecycle_operations_reject_update_delete; Type: TRIGGER; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

CREATE TRIGGER plugin_lifecycle_operations_reject_update_delete BEFORE DELETE OR UPDATE ON public.plugin_lifecycle_operations_v1 FOR EACH ROW EXECUTE FUNCTION public.reject_plugin_lifecycle_operation_mutation_v1();


--
-- Name: process_episode_evidence process_episode_evidence_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER process_episode_evidence_immutable BEFORE DELETE OR UPDATE ON public.process_episode_evidence FOR EACH ROW EXECUTE FUNCTION public.process_episode_evidence_reject_mutation();


--
-- Name: process_episode_evidence process_episode_evidence_no_truncate; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER process_episode_evidence_no_truncate BEFORE TRUNCATE ON public.process_episode_evidence FOR EACH STATEMENT EXECUTE FUNCTION public.process_episode_evidence_reject_mutation();


--
-- Name: process_episode_revisions process_episode_revisions_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER process_episode_revisions_immutable BEFORE DELETE OR UPDATE ON public.process_episode_revisions FOR EACH ROW EXECUTE FUNCTION public.process_episode_evidence_reject_mutation();


--
-- Name: process_episode_revisions process_episode_revisions_no_truncate; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER process_episode_revisions_no_truncate BEFORE TRUNCATE ON public.process_episode_revisions FOR EACH STATEMENT EXECUTE FUNCTION public.process_episode_evidence_reject_mutation();


--
-- Name: source_capture_continuity_declarations source_capture_continuity_declarations_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER source_capture_continuity_declarations_immutable BEFORE DELETE OR UPDATE ON public.source_capture_continuity_declarations FOR EACH ROW EXECUTE FUNCTION public.source_capture_continuity_declarations_reject_mutation();


--
-- Name: ad_snapshot_manifest_sources trg_ad_snapshot_manifest_sources_immutable; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_ad_snapshot_manifest_sources_immutable BEFORE DELETE OR UPDATE OR TRUNCATE ON public.ad_snapshot_manifest_sources FOR EACH STATEMENT EXECUTE FUNCTION public.ad_snapshot_manifest_reject_mutation();


--
-- Name: ad_snapshot_manifests trg_ad_snapshot_manifests_immutable; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_ad_snapshot_manifests_immutable BEFORE DELETE OR UPDATE OR TRUNCATE ON public.ad_snapshot_manifests FOR EACH STATEMENT EXECUTE FUNCTION public.ad_snapshot_manifest_reject_mutation();


--
-- Name: ad_snapshot_manifests trg_ad_snapshot_manifests_v2_schedule_header; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_ad_snapshot_manifests_v2_schedule_header BEFORE INSERT ON public.ad_snapshot_manifests FOR EACH ROW EXECUTE FUNCTION public.ad_snapshot_manifest_apply_v2_schedule_header();


--
-- Name: ad_snapshot_projection_outputs trg_ad_snapshot_projection_outputs_immutable; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_ad_snapshot_projection_outputs_immutable BEFORE DELETE OR UPDATE OR TRUNCATE ON public.ad_snapshot_projection_outputs FOR EACH STATEMENT EXECUTE FUNCTION public.ad_snapshot_projection_output_reject_mutation();


--
-- Name: entity_identity_finding_supersessions_v2 trg_entity_identity_finding_supersessions_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_entity_identity_finding_supersessions_immutable BEFORE DELETE OR UPDATE ON public.entity_identity_finding_supersessions_v2 FOR EACH ROW EXECUTE FUNCTION public.enforce_entity_identity_merge_immutability();


--
-- Name: entity_identity_merge_events_v2 trg_entity_identity_merge_events_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_entity_identity_merge_events_immutable BEFORE DELETE OR UPDATE ON public.entity_identity_merge_events_v2 FOR EACH ROW EXECUTE FUNCTION public.enforce_entity_identity_merge_immutability();


--
-- Name: entity_identity_merges_v2 trg_entity_identity_merge_flat_graph; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_entity_identity_merge_flat_graph BEFORE INSERT ON public.entity_identity_merges_v2 FOR EACH ROW EXECUTE FUNCTION public.validate_entity_identity_merge_flat_graph();


--
-- Name: entity_identity_merges_v2 trg_entity_identity_merges_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_entity_identity_merges_immutable BEFORE DELETE OR UPDATE ON public.entity_identity_merges_v2 FOR EACH ROW EXECUTE FUNCTION public.enforce_entity_identity_merge_immutability();


--
-- Name: entity_identity_scenario_supersessions_v2 trg_entity_identity_scenario_supersessions_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_entity_identity_scenario_supersessions_immutable BEFORE DELETE OR UPDATE ON public.entity_identity_scenario_supersessions_v2 FOR EACH ROW EXECUTE FUNCTION public.enforce_entity_identity_merge_immutability();


--
-- Name: entity_identity_semantic_replays_v2 trg_entity_identity_semantic_replays_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_entity_identity_semantic_replays_immutable BEFORE DELETE OR UPDATE ON public.entity_identity_semantic_replays_v2 FOR EACH ROW EXECUTE FUNCTION public.enforce_entity_identity_merge_immutability();


--
-- Name: event_entity_link_blocks_v2 trg_event_entity_link_block_reject_merged; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_event_entity_link_block_reject_merged BEFORE INSERT OR UPDATE ON public.event_entity_link_blocks_v2 FOR EACH ROW EXECUTE FUNCTION public.reject_merged_entity_link_block();


--
-- Name: normalized_events trg_normalized_event_source_identity_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_normalized_event_source_identity_immutable BEFORE UPDATE ON public.normalized_events FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_source_identity_immutability();


--
-- Name: semantic_control_health_observations trg_semantic_control_health_immutability; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_control_health_immutability BEFORE UPDATE ON public.semantic_control_health_observations FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_control_health_immutability();


--
-- Name: semantic_correlation_rules trg_semantic_correlation_rule_immutability; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_correlation_rule_immutability BEFORE UPDATE ON public.semantic_correlation_rules FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_correlation_rule_immutability();


--
-- Name: semantic_finding_publications trg_semantic_finding_publication_immutability; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_finding_publication_immutability BEFORE DELETE OR UPDATE ON public.semantic_finding_publications FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_finding_publication_immutability();


--
-- Name: semantic_processing_outbox trg_semantic_outbox_source_identity_immutable; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_outbox_source_identity_immutable BEFORE UPDATE ON public.semantic_processing_outbox FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_source_identity_immutability();


--
-- Name: semantic_risk_contributions trg_semantic_risk_contribution_immutability; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_risk_contribution_immutability BEFORE UPDATE ON public.semantic_risk_contributions FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_risk_contribution_immutability();


--
-- Name: semantic_risk_policies trg_semantic_risk_policy_immutability; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_risk_policy_immutability BEFORE UPDATE ON public.semantic_risk_policies FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_risk_policy_immutability();


--
-- Name: semantic_risk_evaluation_results trg_semantic_risk_result_immutability; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_risk_result_immutability BEFORE UPDATE ON public.semantic_risk_evaluation_results FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_risk_result_immutability();


--
-- Name: semantic_risk_policy_subscriptions trg_semantic_risk_subscription_draft_only; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_risk_subscription_draft_only BEFORE INSERT OR DELETE OR UPDATE ON public.semantic_risk_policy_subscriptions FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_risk_subscription_draft_only();


--
-- Name: semantic_scenario_reviews trg_semantic_scenario_review_immutability; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_scenario_review_immutability BEFORE DELETE OR UPDATE ON public.semantic_scenario_reviews FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_scenario_review_immutability();


--
-- Name: semantic_correlation_subscriptions trg_semantic_subscription_draft_only; Type: TRIGGER; Schema: public; Owner: adlog_storage_owner
--

CREATE TRIGGER trg_semantic_subscription_draft_only BEFORE INSERT OR DELETE OR UPDATE ON public.semantic_correlation_subscriptions FOR EACH ROW EXECUTE FUNCTION public.enforce_semantic_subscription_draft_only();


--
-- Name: access_capability_assignments access_capability_assignments_capability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_capability_assignments
    ADD CONSTRAINT access_capability_assignments_capability_id_fkey FOREIGN KEY (capability_id) REFERENCES public.access_capabilities(id) ON DELETE CASCADE;


--
-- Name: access_group_members access_group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_group_members
    ADD CONSTRAINT access_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.access_groups(id) ON DELETE CASCADE;


--
-- Name: access_group_members access_group_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_group_members
    ADD CONSTRAINT access_group_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.auth_users(id) ON DELETE CASCADE;


--
-- Name: access_package_capabilities access_package_capabilities_capability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_package_capabilities
    ADD CONSTRAINT access_package_capabilities_capability_id_fkey FOREIGN KEY (capability_id) REFERENCES public.access_capabilities(id) ON DELETE CASCADE;


--
-- Name: access_package_capabilities access_package_capabilities_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_package_capabilities
    ADD CONSTRAINT access_package_capabilities_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.access_packages(id) ON DELETE CASCADE;


--
-- Name: access_package_reports access_package_reports_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_package_reports
    ADD CONSTRAINT access_package_reports_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.access_packages(id) ON DELETE CASCADE;


--
-- Name: access_platform_owners access_platform_owners_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_platform_owners
    ADD CONSTRAINT access_platform_owners_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.auth_users(id) ON DELETE RESTRICT;


--
-- Name: access_role_packages access_role_packages_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_role_packages
    ADD CONSTRAINT access_role_packages_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.access_packages(id) ON DELETE CASCADE;


--
-- Name: access_subject_packages access_subject_packages_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.access_subject_packages
    ADD CONSTRAINT access_subject_packages_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.access_packages(id) ON DELETE CASCADE;


--
-- Name: account_risk_acceptance_audit account_risk_acceptance_audit_acceptance_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_acceptance_audit
    ADD CONSTRAINT account_risk_acceptance_audit_acceptance_id_fkey FOREIGN KEY (acceptance_id) REFERENCES public.account_risk_acceptances(id) ON DELETE RESTRICT;


--
-- Name: account_risk_acceptances account_risk_acceptances_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_acceptances
    ADD CONSTRAINT account_risk_acceptances_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: account_risk_acceptances account_risk_acceptances_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_acceptances
    ADD CONSTRAINT account_risk_acceptances_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id) ON DELETE RESTRICT;


--
-- Name: account_risk_investigation_links account_risk_investigation_links_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_investigation_links
    ADD CONSTRAINT account_risk_investigation_links_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: account_risk_investigation_links account_risk_investigation_links_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_investigation_links
    ADD CONSTRAINT account_risk_investigation_links_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id) ON DELETE RESTRICT;


--
-- Name: account_risk_investigation_links account_risk_investigation_links_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.account_risk_investigation_links
    ADD CONSTRAINT account_risk_investigation_links_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE RESTRICT;


--
-- Name: acquisition_consumer_subscriptions acquisition_consumer_subscrip_source_instance_id_stream_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_consumer_subscriptions
    ADD CONSTRAINT acquisition_consumer_subscrip_source_instance_id_stream_id_fkey FOREIGN KEY (source_instance_id, stream_id, transport_binding) REFERENCES public.acquisition_stream_cursors(source_instance_id, stream_id, transport_binding);


--
-- Name: acquisition_delivery_outbox acquisition_delivery_outbox_evidence_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_delivery_outbox
    ADD CONSTRAINT acquisition_delivery_outbox_evidence_uid_fkey FOREIGN KEY (evidence_uid) REFERENCES public.core_evidence_manifests(evidence_uid);


--
-- Name: acquisition_delivery_outbox acquisition_delivery_outbox_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_delivery_outbox
    ADD CONSTRAINT acquisition_delivery_outbox_observation_id_fkey FOREIGN KEY (observation_id) REFERENCES public.radius_accounting_session_observations(observation_id);


--
-- Name: acquisition_delivery_outbox acquisition_delivery_outbox_subscription_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_delivery_outbox
    ADD CONSTRAINT acquisition_delivery_outbox_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES public.acquisition_consumer_subscriptions(subscription_id);


--
-- Name: acquisition_stream_cursors acquisition_stream_cursors_source_instance_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.acquisition_stream_cursors
    ADD CONSTRAINT acquisition_stream_cursors_source_instance_id_fkey FOREIGN KEY (source_instance_id) REFERENCES public.acquisition_source_instances(source_instance_id);


--
-- Name: ad_context_entity_aliases ad_context_entity_aliases_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_aliases
    ADD CONSTRAINT ad_context_entity_aliases_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: ad_context_entity_aliases ad_context_entity_aliases_entity_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_aliases
    ADD CONSTRAINT ad_context_entity_aliases_entity_id_v2_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id) ON DELETE CASCADE;


--
-- Name: ad_context_entity_aliases ad_context_entity_aliases_source_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_aliases
    ADD CONSTRAINT ad_context_entity_aliases_source_run_id_fkey FOREIGN KEY (source_run_id) REFERENCES public.ad_context_runs(run_id) ON DELETE RESTRICT;


--
-- Name: ad_context_entity_versions ad_context_entity_versions_entity_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_versions
    ADD CONSTRAINT ad_context_entity_versions_entity_id_v2_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id) ON DELETE CASCADE;


--
-- Name: ad_context_entity_versions ad_context_entity_versions_source_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_entity_versions
    ADD CONSTRAINT ad_context_entity_versions_source_run_id_fkey FOREIGN KEY (source_run_id) REFERENCES public.ad_context_runs(run_id) ON DELETE RESTRICT;


--
-- Name: ad_context_event_links ad_context_event_links_context_evidence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_event_links
    ADD CONSTRAINT ad_context_event_links_context_evidence_id_fkey FOREIGN KEY (context_evidence_id) REFERENCES public.ad_context_evidence(id) ON DELETE RESTRICT;


--
-- Name: ad_context_evidence ad_context_evidence_source_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_evidence
    ADD CONSTRAINT ad_context_evidence_source_run_id_fkey FOREIGN KEY (source_run_id) REFERENCES public.ad_context_runs(run_id) ON DELETE RESTRICT;


--
-- Name: ad_context_relation_versions ad_context_relation_versions_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_relation_versions
    ADD CONSTRAINT ad_context_relation_versions_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: ad_context_relation_versions ad_context_relation_versions_source_entity_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_relation_versions
    ADD CONSTRAINT ad_context_relation_versions_source_entity_id_v2_fkey FOREIGN KEY (source_entity_id) REFERENCES public.entities_v2(id) ON DELETE CASCADE;


--
-- Name: ad_context_relation_versions ad_context_relation_versions_source_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_relation_versions
    ADD CONSTRAINT ad_context_relation_versions_source_run_id_fkey FOREIGN KEY (source_run_id) REFERENCES public.ad_context_runs(run_id) ON DELETE RESTRICT;


--
-- Name: ad_context_relation_versions ad_context_relation_versions_target_entity_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_relation_versions
    ADD CONSTRAINT ad_context_relation_versions_target_entity_id_v2_fkey FOREIGN KEY (target_entity_id) REFERENCES public.entities_v2(id) ON DELETE CASCADE;


--
-- Name: ad_context_runs ad_context_runs_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_runs
    ADD CONSTRAINT ad_context_runs_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: ad_context_sections ad_context_sections_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ad_context_sections
    ADD CONSTRAINT ad_context_sections_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.ad_context_runs(run_id) ON DELETE CASCADE;


--
-- Name: ad_snapshot_manifest_sources ad_snapshot_manifest_sources_manifest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_manifest_sources
    ADD CONSTRAINT ad_snapshot_manifest_sources_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.ad_snapshot_manifests(manifest_id) ON DELETE RESTRICT;


--
-- Name: ad_snapshot_manifests ad_snapshot_manifests_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_manifests
    ADD CONSTRAINT ad_snapshot_manifests_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: ad_snapshot_projection_outputs ad_snapshot_projection_outputs_manifest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_projection_outputs
    ADD CONSTRAINT ad_snapshot_projection_outputs_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.ad_snapshot_manifests(manifest_id) ON DELETE RESTRICT;


--
-- Name: ad_snapshot_projection_receipts ad_snapshot_projection_receipts_manifest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ad_snapshot_projection_receipts
    ADD CONSTRAINT ad_snapshot_projection_receipts_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.ad_snapshot_manifests(manifest_id) ON DELETE RESTRICT;


--
-- Name: ai_analysis ai_analysis_detection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ai_analysis
    ADD CONSTRAINT ai_analysis_detection_id_fkey FOREIGN KEY (detection_id) REFERENCES public.detections(id);


--
-- Name: ai_reviews ai_reviews_ai_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.ai_reviews
    ADD CONSTRAINT ai_reviews_ai_analysis_id_fkey FOREIGN KEY (ai_analysis_id) REFERENCES public.ai_analysis(id);


--
-- Name: auth_sessions auth_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.auth_users(id) ON DELETE CASCADE;


--
-- Name: canonical_action_evidence canonical_action_evidence_canonical_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_action_evidence
    ADD CONSTRAINT canonical_action_evidence_canonical_action_id_fkey FOREIGN KEY (canonical_action_id) REFERENCES public.canonical_actions(canonical_action_id) ON DELETE RESTRICT;


--
-- Name: canonical_action_evidence canonical_action_evidence_normalized_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_action_evidence
    ADD CONSTRAINT canonical_action_evidence_normalized_event_id_fkey FOREIGN KEY (normalized_event_id) REFERENCES public.normalized_events(normalized_event_id) ON DELETE RESTRICT;


--
-- Name: canonical_action_state_evidence canonical_action_state_evidence_canonical_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_action_state_evidence
    ADD CONSTRAINT canonical_action_state_evidence_canonical_action_id_fkey FOREIGN KEY (canonical_action_id) REFERENCES public.canonical_actions(canonical_action_id) ON DELETE RESTRICT;


--
-- Name: canonical_action_state_evidence canonical_action_state_evidence_context_evidence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.canonical_action_state_evidence
    ADD CONSTRAINT canonical_action_state_evidence_context_evidence_id_fkey FOREIGN KEY (context_evidence_id) REFERENCES public.ad_context_evidence(id) ON DELETE RESTRICT;


--
-- Name: computers_report_v5_snapshots computers_report_v5_snapshots_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v5_snapshots
    ADD CONSTRAINT computers_report_v5_snapshots_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: computers_report_v5_snapshots computers_report_v5_snapshots_source_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v5_snapshots
    ADD CONSTRAINT computers_report_v5_snapshots_source_run_id_fkey FOREIGN KEY (source_run_id) REFERENCES public.ad_context_runs(run_id) ON DELETE RESTRICT;


--
-- Name: computers_report_v6_snapshots computers_report_v6_snapshots_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v6_snapshots
    ADD CONSTRAINT computers_report_v6_snapshots_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: computers_report_v6_snapshots computers_report_v6_snapshots_source_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_report_v6_snapshots
    ADD CONSTRAINT computers_report_v6_snapshots_source_run_id_fkey FOREIGN KEY (source_run_id) REFERENCES public.ad_context_runs(run_id) ON DELETE RESTRICT;


--
-- Name: computers_v6_source_snapshots computers_v6_source_snapshots_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.computers_v6_source_snapshots
    ADD CONSTRAINT computers_v6_source_snapshots_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: core_evidence_manifests core_evidence_manifests_source_instance_id_stream_id_trans_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.core_evidence_manifests
    ADD CONSTRAINT core_evidence_manifests_source_instance_id_stream_id_trans_fkey FOREIGN KEY (source_instance_id, stream_id, transport_binding) REFERENCES public.acquisition_stream_cursors(source_instance_id, stream_id, transport_binding);


--
-- Name: detections detections_detection_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_detection_rule_id_fkey FOREIGN KEY (detection_rule_id) REFERENCES public.detection_rules(id);


--
-- Name: detections detections_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);


--
-- Name: detections detections_primary_event_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_primary_event_id_v2_fkey FOREIGN KEY (primary_event_id) REFERENCES public.events_v2_core(id);


--
-- Name: detections detections_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.servers(id);


--
-- Name: detections detections_site_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_site_id_fkey FOREIGN KEY (site_id) REFERENCES public.sites(id);


--
-- Name: domain_controller_targets domain_controller_targets_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.domain_controller_targets
    ADD CONSTRAINT domain_controller_targets_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: domains domains_forest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_forest_id_fkey FOREIGN KEY (forest_id) REFERENCES public.forests(id);


--
-- Name: entities_v2 entities_v2_entity_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entities_v2
    ADD CONSTRAINT entities_v2_entity_type_id_fkey FOREIGN KEY (entity_type_id) REFERENCES public.storage_v2_entity_type(id);


--
-- Name: entity_details_v2 entity_details_v2_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_details_v2
    ADD CONSTRAINT entity_details_v2_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id) ON DELETE CASCADE;


--
-- Name: entity_identity_finding_supersessions_v2 entity_identity_finding_super_merge_id_old_scenario_id_new_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_finding_supersessions_v2
    ADD CONSTRAINT entity_identity_finding_super_merge_id_old_scenario_id_new_fkey FOREIGN KEY (merge_id, old_scenario_id, new_scenario_id) REFERENCES public.entity_identity_scenario_supersessions_v2(merge_id, old_scenario_id, new_scenario_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_finding_supersessions_v2 entity_identity_finding_supersessions_v2_merge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_finding_supersessions_v2
    ADD CONSTRAINT entity_identity_finding_supersessions_v2_merge_id_fkey FOREIGN KEY (merge_id) REFERENCES public.entity_identity_merges_v2(merge_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_finding_supersessions_v2 entity_identity_finding_supersessions_v2_new_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_finding_supersessions_v2
    ADD CONSTRAINT entity_identity_finding_supersessions_v2_new_finding_id_fkey FOREIGN KEY (new_finding_id) REFERENCES public.findings(id) ON DELETE RESTRICT;


--
-- Name: entity_identity_finding_supersessions_v2 entity_identity_finding_supersessions_v2_old_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_finding_supersessions_v2
    ADD CONSTRAINT entity_identity_finding_supersessions_v2_old_finding_id_fkey FOREIGN KEY (old_finding_id) REFERENCES public.findings(id) ON DELETE RESTRICT;


--
-- Name: entity_identity_merge_events_v2 entity_identity_merge_events_v2_merge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_merge_events_v2
    ADD CONSTRAINT entity_identity_merge_events_v2_merge_id_fkey FOREIGN KEY (merge_id) REFERENCES public.entity_identity_merges_v2(merge_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_merges_v2 entity_identity_merges_v2_source_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_merges_v2
    ADD CONSTRAINT entity_identity_merges_v2_source_entity_id_fkey FOREIGN KEY (source_entity_id) REFERENCES public.entities_v2(id) ON DELETE RESTRICT;


--
-- Name: entity_identity_merges_v2 entity_identity_merges_v2_target_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_merges_v2
    ADD CONSTRAINT entity_identity_merges_v2_target_entity_id_fkey FOREIGN KEY (target_entity_id) REFERENCES public.entities_v2(id) ON DELETE RESTRICT;


--
-- Name: entity_identity_scenario_supersessions_v2 entity_identity_scenario_supersessions_v2_merge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_scenario_supersessions_v2
    ADD CONSTRAINT entity_identity_scenario_supersessions_v2_merge_id_fkey FOREIGN KEY (merge_id) REFERENCES public.entity_identity_merges_v2(merge_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_scenario_supersessions_v2 entity_identity_scenario_supersessions_v2_new_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_scenario_supersessions_v2
    ADD CONSTRAINT entity_identity_scenario_supersessions_v2_new_scenario_id_fkey FOREIGN KEY (new_scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_scenario_supersessions_v2 entity_identity_scenario_supersessions_v2_old_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_scenario_supersessions_v2
    ADD CONSTRAINT entity_identity_scenario_supersessions_v2_old_scenario_id_fkey FOREIGN KEY (old_scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_semantic_replays_v2 entity_identity_semantic_replays_v2_merge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_semantic_replays_v2
    ADD CONSTRAINT entity_identity_semantic_replays_v2_merge_id_fkey FOREIGN KEY (merge_id) REFERENCES public.entity_identity_merges_v2(merge_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_semantic_replays_v2 entity_identity_semantic_replays_v2_replay_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_semantic_replays_v2
    ADD CONSTRAINT entity_identity_semantic_replays_v2_replay_job_id_fkey FOREIGN KEY (replay_job_id) REFERENCES public.semantic_processing_outbox(job_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_semantic_replays_v2 entity_identity_semantic_replays_v_new_normalized_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_semantic_replays_v2
    ADD CONSTRAINT entity_identity_semantic_replays_v_new_normalized_event_id_fkey FOREIGN KEY (new_normalized_event_id) REFERENCES public.normalized_events(normalized_event_id) ON DELETE RESTRICT;


--
-- Name: entity_identity_semantic_replays_v2 entity_identity_semantic_replays_v_old_normalized_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_identity_semantic_replays_v2
    ADD CONSTRAINT entity_identity_semantic_replays_v_old_normalized_event_id_fkey FOREIGN KEY (old_normalized_event_id) REFERENCES public.normalized_events(normalized_event_id) ON DELETE RESTRICT;


--
-- Name: entity_state_current entity_state_current_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_state_current
    ADD CONSTRAINT entity_state_current_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id) ON DELETE RESTRICT;


--
-- Name: entity_state_current entity_state_current_source_event_db_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.entity_state_current
    ADD CONSTRAINT entity_state_current_source_event_db_id_fkey FOREIGN KEY (source_event_db_id) REFERENCES public.events_v2_core(id) ON DELETE RESTRICT;


--
-- Name: entity_states entity_states_entity_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.entity_states
    ADD CONSTRAINT entity_states_entity_id_v2_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id);


--
-- Name: entity_states entity_states_evidence_event_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.entity_states
    ADD CONSTRAINT entity_states_evidence_event_id_v2_fkey FOREIGN KEY (evidence_event_id) REFERENCES public.events_v2_core(id);


--
-- Name: event_entity_link_blocks_v2 event_entity_link_blocks_v2_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.event_entity_link_blocks_v2
    ADD CONSTRAINT event_entity_link_blocks_v2_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id) ON DELETE CASCADE;


--
-- Name: event_facts_v2 event_facts_v2_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.event_facts_v2
    ADD CONSTRAINT event_facts_v2_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events_v2_core(id) ON DELETE CASCADE;


--
-- Name: event_links event_links_source_event_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.event_links
    ADD CONSTRAINT event_links_source_event_id_v2_fkey FOREIGN KEY (source_event_id) REFERENCES public.events_v2_core(id);


--
-- Name: event_links event_links_target_event_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.event_links
    ADD CONSTRAINT event_links_target_event_id_v2_fkey FOREIGN KEY (target_event_id) REFERENCES public.events_v2_core(id);


--
-- Name: events_v2_core events_v2_core_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_core_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.storage_v2_channel(id);


--
-- Name: events_v2_core events_v2_core_computer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_core_computer_id_fkey FOREIGN KEY (computer_id) REFERENCES public.storage_v2_computer(id);


--
-- Name: events_v2_core events_v2_core_keywords_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_core_keywords_id_fkey FOREIGN KEY (keywords_id) REFERENCES public.storage_v2_keywords(id);


--
-- Name: events_v2_core events_v2_core_noise_catalog_revision_fk; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_core_noise_catalog_revision_fk FOREIGN KEY (noise_catalog_revision_id) REFERENCES public.event_catalog_revisions(id) NOT VALID;


--
-- Name: events_v2_core events_v2_core_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_core_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.storage_v2_provider(id);


--
-- Name: events_v2_core events_v2_core_subject_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_core_subject_domain_id_fkey FOREIGN KEY (subject_domain_id) REFERENCES public.storage_v2_domain_name(id);


--
-- Name: events_v2_core events_v2_core_target_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.events_v2_core
    ADD CONSTRAINT events_v2_core_target_domain_id_fkey FOREIGN KEY (target_domain_id) REFERENCES public.storage_v2_domain_name(id);


--
-- Name: finding_entities finding_entities_entity_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_entities
    ADD CONSTRAINT finding_entities_entity_id_v2_fkey FOREIGN KEY (entity_id) REFERENCES public.entities_v2(id);


--
-- Name: finding_entities finding_entities_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_entities
    ADD CONSTRAINT finding_entities_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_evidence finding_evidence_event_id_v2_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_evidence
    ADD CONSTRAINT finding_evidence_event_id_v2_fkey FOREIGN KEY (event_id) REFERENCES public.events_v2_core(id);


--
-- Name: finding_evidence finding_evidence_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_evidence
    ADD CONSTRAINT finding_evidence_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_status_history finding_status_history_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.finding_status_history
    ADD CONSTRAINT finding_status_history_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: gpo_report_v2_source_snapshots gpo_report_v2_source_snapshots_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.gpo_report_v2_source_snapshots
    ADD CONSTRAINT gpo_report_v2_source_snapshots_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: investigation_audit investigation_audit_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_audit
    ADD CONSTRAINT investigation_audit_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: investigation_context_evidence investigation_context_evidence_context_evidence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_context_evidence
    ADD CONSTRAINT investigation_context_evidence_context_evidence_id_fkey FOREIGN KEY (context_evidence_id) REFERENCES public.ad_context_evidence(id) ON DELETE RESTRICT;


--
-- Name: investigation_context_evidence investigation_context_evidence_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_context_evidence
    ADD CONSTRAINT investigation_context_evidence_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: investigation_events investigation_events_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_events
    ADD CONSTRAINT investigation_events_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: investigation_evidence_refs investigation_evidence_refs_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.investigation_evidence_refs
    ADD CONSTRAINT investigation_evidence_refs_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE RESTRICT;


--
-- Name: investigation_evidence_refs investigation_evidence_refs_source_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.investigation_evidence_refs
    ADD CONSTRAINT investigation_evidence_refs_source_domain_id_fkey FOREIGN KEY (source_domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: investigation_finding_links investigation_finding_links_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_finding_links
    ADD CONSTRAINT investigation_finding_links_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE RESTRICT;


--
-- Name: investigation_finding_links investigation_finding_links_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_finding_links
    ADD CONSTRAINT investigation_finding_links_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE RESTRICT;


--
-- Name: investigation_notes investigation_notes_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.investigation_notes
    ADD CONSTRAINT investigation_notes_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: plugin_component_admission_v1 plugin_component_admission_v1_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_component_admission_v1
    ADD CONSTRAINT plugin_component_admission_v1_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.plugin_installations_v1(plugin_id);


--
-- Name: plugin_component_leases_v1 plugin_component_leases_v1_plugin_id_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_component_leases_v1
    ADD CONSTRAINT plugin_component_leases_v1_plugin_id_component_id_fkey FOREIGN KEY (plugin_id, component_id) REFERENCES public.plugin_component_admission_v1(plugin_id, component_id);


--
-- Name: plugin_lifecycle_operations_v1 plugin_lifecycle_operations_v1_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_lifecycle_operations_v1
    ADD CONSTRAINT plugin_lifecycle_operations_v1_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.plugin_installations_v1(plugin_id);


--
-- Name: plugin_state_v1 plugin_state_v1_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

ALTER TABLE ONLY public.plugin_state_v1
    ADD CONSTRAINT plugin_state_v1_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.plugin_installations_v1(plugin_id);


--
-- Name: process_episode_evidence process_episode_evidence_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.process_episode_evidence
    ADD CONSTRAINT process_episode_evidence_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.process_episode_revisions(revision_id) ON DELETE RESTRICT;


--
-- Name: radius_accounting_class_cache radius_accounting_class_cache_source_instance_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_accounting_class_cache
    ADD CONSTRAINT radius_accounting_class_cache_source_instance_id_fkey FOREIGN KEY (source_instance_id) REFERENCES public.acquisition_source_instances(source_instance_id);


--
-- Name: radius_accounting_session_observations radius_accounting_session_observations_evidence_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_accounting_session_observations
    ADD CONSTRAINT radius_accounting_session_observations_evidence_uid_fkey FOREIGN KEY (evidence_uid) REFERENCES public.core_evidence_manifests(evidence_uid);


--
-- Name: radius_session_identity_overlays radius_session_identity_overlays_attempt_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_identity_overlays
    ADD CONSTRAINT radius_session_identity_overlays_attempt_key_fkey FOREIGN KEY (attempt_key) REFERENCES public.radius_session_reconciliation_attempts(attempt_key);


--
-- Name: radius_session_identity_overlays radius_session_identity_overlays_evidence_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_identity_overlays
    ADD CONSTRAINT radius_session_identity_overlays_evidence_uid_fkey FOREIGN KEY (evidence_uid) REFERENCES public.core_evidence_manifests(evidence_uid);


--
-- Name: radius_session_identity_overlays radius_session_identity_overlays_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_identity_overlays
    ADD CONSTRAINT radius_session_identity_overlays_observation_id_fkey FOREIGN KEY (observation_id) REFERENCES public.radius_accounting_session_observations(observation_id);


--
-- Name: radius_session_projection_receipts radius_session_projection_receipts_delivery_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_projection_receipts
    ADD CONSTRAINT radius_session_projection_receipts_delivery_id_fkey FOREIGN KEY (delivery_id) REFERENCES public.acquisition_delivery_outbox(delivery_id);


--
-- Name: radius_session_projection_receipts radius_session_projection_receipts_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_projection_receipts
    ADD CONSTRAINT radius_session_projection_receipts_observation_id_fkey FOREIGN KEY (observation_id) REFERENCES public.radius_accounting_session_observations(observation_id);


--
-- Name: radius_session_reconciliation_attempts radius_session_reconciliation_attempts_evidence_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_reconciliation_attempts
    ADD CONSTRAINT radius_session_reconciliation_attempts_evidence_uid_fkey FOREIGN KEY (evidence_uid) REFERENCES public.core_evidence_manifests(evidence_uid);


--
-- Name: radius_session_reconciliation_attempts radius_session_reconciliation_attempts_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.radius_session_reconciliation_attempts
    ADD CONSTRAINT radius_session_reconciliation_attempts_observation_id_fkey FOREIGN KEY (observation_id) REFERENCES public.radius_accounting_session_observations(observation_id);


--
-- Name: raw_log_files raw_log_files_collection_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.raw_log_files
    ADD CONSTRAINT raw_log_files_collection_run_id_fkey FOREIGN KEY (collection_run_id) REFERENCES public.collection_runs(id);


--
-- Name: raw_log_files raw_log_files_log_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.raw_log_files
    ADD CONSTRAINT raw_log_files_log_source_id_fkey FOREIGN KEY (log_source_id) REFERENCES public.log_sources(id);


--
-- Name: raw_log_files raw_log_files_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.raw_log_files
    ADD CONSTRAINT raw_log_files_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.servers(id);


--
-- Name: report_access_requests_v4 report_access_requests_v4_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_access_requests_v4
    ADD CONSTRAINT report_access_requests_v4_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public.auth_users(id);


--
-- Name: report_access_requests_v4 report_access_requests_v4_requester_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_access_requests_v4
    ADD CONSTRAINT report_access_requests_v4_requester_user_id_fkey FOREIGN KEY (requester_user_id) REFERENCES public.auth_users(id) ON DELETE CASCADE;


--
-- Name: report_items report_items_ai_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_items
    ADD CONSTRAINT report_items_ai_analysis_id_fkey FOREIGN KEY (ai_analysis_id) REFERENCES public.ai_analysis(id);


--
-- Name: report_items report_items_detection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_items
    ADD CONSTRAINT report_items_detection_id_fkey FOREIGN KEY (detection_id) REFERENCES public.detections(id);


--
-- Name: report_items report_items_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_items
    ADD CONSTRAINT report_items_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.reports(id);


--
-- Name: report_registry_v4 report_registry_v4_dataset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.report_registry_v4
    ADD CONSTRAINT report_registry_v4_dataset_id_fkey FOREIGN KEY (dataset_id) REFERENCES public.report_datasets_v4(id);


--
-- Name: semantic_correlation_candidate_evidence semantic_correlation_candidate_evidenc_normalized_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_candidate_evidence
    ADD CONSTRAINT semantic_correlation_candidate_evidenc_normalized_event_id_fkey FOREIGN KEY (normalized_event_id) REFERENCES public.normalized_events(normalized_event_id) ON DELETE RESTRICT;


--
-- Name: semantic_correlation_candidate_evidence semantic_correlation_candidate_evidence_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_candidate_evidence
    ADD CONSTRAINT semantic_correlation_candidate_evidence_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES public.semantic_correlation_candidates(candidate_id) ON DELETE RESTRICT;


--
-- Name: semantic_correlation_candidates semantic_correlation_candidates_rule_id_rule_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_candidates
    ADD CONSTRAINT semantic_correlation_candidates_rule_id_rule_version_fkey FOREIGN KEY (rule_id, rule_version) REFERENCES public.semantic_correlation_rules(rule_id, rule_version) ON DELETE RESTRICT;


--
-- Name: semantic_correlation_dispatch_jobs semantic_correlation_dispatch_jobs_normalized_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_dispatch_jobs
    ADD CONSTRAINT semantic_correlation_dispatch_jobs_normalized_event_id_fkey FOREIGN KEY (normalized_event_id) REFERENCES public.normalized_events(normalized_event_id) ON DELETE RESTRICT;


--
-- Name: semantic_correlation_dispatch_jobs semantic_correlation_dispatch_jobs_rule_id_rule_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_dispatch_jobs
    ADD CONSTRAINT semantic_correlation_dispatch_jobs_rule_id_rule_version_fkey FOREIGN KEY (rule_id, rule_version) REFERENCES public.semantic_correlation_rules(rule_id, rule_version) ON DELETE RESTRICT;


--
-- Name: semantic_correlation_replays semantic_correlation_replays_rule_id_rule_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_replays
    ADD CONSTRAINT semantic_correlation_replays_rule_id_rule_version_fkey FOREIGN KEY (rule_id, rule_version) REFERENCES public.semantic_correlation_rules(rule_id, rule_version) ON DELETE RESTRICT;


--
-- Name: semantic_correlation_subscriptions semantic_correlation_subscriptions_rule_id_rule_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_correlation_subscriptions
    ADD CONSTRAINT semantic_correlation_subscriptions_rule_id_rule_version_fkey FOREIGN KEY (rule_id, rule_version) REFERENCES public.semantic_correlation_rules(rule_id, rule_version) ON DELETE RESTRICT;


--
-- Name: semantic_finding_publications semantic_finding_publications_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_finding_publications
    ADD CONSTRAINT semantic_finding_publications_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE RESTRICT;


--
-- Name: semantic_finding_publications semantic_finding_publications_first_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_finding_publications
    ADD CONSTRAINT semantic_finding_publications_first_job_id_fkey FOREIGN KEY (first_job_id) REFERENCES public.semantic_risk_evaluation_results(job_id) ON DELETE RESTRICT;


--
-- Name: semantic_finding_publications semantic_finding_publications_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_finding_publications
    ADD CONSTRAINT semantic_finding_publications_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_contributions semantic_risk_contributions_canonical_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_contributions
    ADD CONSTRAINT semantic_risk_contributions_canonical_action_id_fkey FOREIGN KEY (canonical_action_id) REFERENCES public.canonical_actions(canonical_action_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_contributions semantic_risk_contributions_correlation_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_contributions
    ADD CONSTRAINT semantic_risk_contributions_correlation_candidate_id_fkey FOREIGN KEY (correlation_candidate_id) REFERENCES public.semantic_correlation_candidates(candidate_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_contributions semantic_risk_contributions_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_contributions
    ADD CONSTRAINT semantic_risk_contributions_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_evaluation_jobs semantic_risk_evaluation_jobs_canonical_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_jobs
    ADD CONSTRAINT semantic_risk_evaluation_jobs_canonical_action_id_fkey FOREIGN KEY (canonical_action_id) REFERENCES public.canonical_actions(canonical_action_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_evaluation_jobs semantic_risk_evaluation_jobs_control_health_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_jobs
    ADD CONSTRAINT semantic_risk_evaluation_jobs_control_health_id_fkey FOREIGN KEY (control_health_id) REFERENCES public.semantic_control_health_observations(observation_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_evaluation_jobs semantic_risk_evaluation_jobs_correlation_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_jobs
    ADD CONSTRAINT semantic_risk_evaluation_jobs_correlation_candidate_id_fkey FOREIGN KEY (correlation_candidate_id) REFERENCES public.semantic_correlation_candidates(candidate_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_evaluation_jobs semantic_risk_evaluation_jobs_policy_id_policy_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_jobs
    ADD CONSTRAINT semantic_risk_evaluation_jobs_policy_id_policy_version_fkey FOREIGN KEY (policy_id, policy_version) REFERENCES public.semantic_risk_policies(policy_id, policy_version) ON DELETE RESTRICT;


--
-- Name: semantic_risk_evaluation_results semantic_risk_evaluation_results_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_results
    ADD CONSTRAINT semantic_risk_evaluation_results_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.semantic_risk_evaluation_jobs(job_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_evaluation_results semantic_risk_evaluation_results_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_evaluation_results
    ADD CONSTRAINT semantic_risk_evaluation_results_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: semantic_risk_policy_subscriptions semantic_risk_policy_subscription_policy_id_policy_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_risk_policy_subscriptions
    ADD CONSTRAINT semantic_risk_policy_subscription_policy_id_policy_version_fkey FOREIGN KEY (policy_id, policy_version) REFERENCES public.semantic_risk_policies(policy_id, policy_version) ON DELETE RESTRICT;


--
-- Name: semantic_scenario_coverage_history semantic_scenario_coverage_history_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_coverage_history
    ADD CONSTRAINT semantic_scenario_coverage_history_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: semantic_scenario_evidence semantic_scenario_evidence_normalized_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_evidence
    ADD CONSTRAINT semantic_scenario_evidence_normalized_event_id_fkey FOREIGN KEY (normalized_event_id) REFERENCES public.normalized_events(normalized_event_id) ON DELETE RESTRICT;


--
-- Name: semantic_scenario_evidence semantic_scenario_evidence_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_evidence
    ADD CONSTRAINT semantic_scenario_evidence_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: semantic_scenario_reviews semantic_scenario_reviews_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_reviews
    ADD CONSTRAINT semantic_scenario_reviews_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: semantic_scenario_reviews semantic_scenario_reviews_supersedes_review_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_reviews
    ADD CONSTRAINT semantic_scenario_reviews_supersedes_review_id_fkey FOREIGN KEY (supersedes_review_id) REFERENCES public.semantic_scenario_reviews(review_id) ON DELETE RESTRICT;


--
-- Name: semantic_scenario_steps semantic_scenario_steps_canonical_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_steps
    ADD CONSTRAINT semantic_scenario_steps_canonical_action_id_fkey FOREIGN KEY (canonical_action_id) REFERENCES public.canonical_actions(canonical_action_id) ON DELETE RESTRICT;


--
-- Name: semantic_scenario_steps semantic_scenario_steps_correlation_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_steps
    ADD CONSTRAINT semantic_scenario_steps_correlation_candidate_id_fkey FOREIGN KEY (correlation_candidate_id) REFERENCES public.semantic_correlation_candidates(candidate_id) ON DELETE RESTRICT;


--
-- Name: semantic_scenario_steps semantic_scenario_steps_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.semantic_scenario_steps
    ADD CONSTRAINT semantic_scenario_steps_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.semantic_security_scenarios(scenario_id) ON DELETE RESTRICT;


--
-- Name: servers servers_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.servers
    ADD CONSTRAINT servers_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);


--
-- Name: servers servers_site_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.servers
    ADD CONSTRAINT servers_site_id_fkey FOREIGN KEY (site_id) REFERENCES public.sites(id);


--
-- Name: sites sites_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.sites
    ADD CONSTRAINT sites_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);


--
-- Name: source_capture_continuity_declarations source_capture_continuity_declarations_collection_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.source_capture_continuity_declarations
    ADD CONSTRAINT source_capture_continuity_declarations_collection_run_id_fkey FOREIGN KEY (collection_run_id) REFERENCES public.collection_runs(id);


--
-- Name: source_capture_continuity_declarations source_capture_continuity_declarations_log_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.source_capture_continuity_declarations
    ADD CONSTRAINT source_capture_continuity_declarations_log_source_id_fkey FOREIGN KEY (log_source_id) REFERENCES public.log_sources(id);


--
-- Name: source_capture_continuity_declarations source_capture_continuity_declarations_raw_log_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.source_capture_continuity_declarations
    ADD CONSTRAINT source_capture_continuity_declarations_raw_log_file_id_fkey FOREIGN KEY (raw_log_file_id) REFERENCES public.raw_log_files(id);


--
-- Name: source_capture_continuity_declarations source_capture_continuity_declarations_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.source_capture_continuity_declarations
    ADD CONSTRAINT source_capture_continuity_declarations_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.servers(id);


--
-- Name: storage_v2_archive_blocks storage_v2_archive_blocks_archive_set_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_archive_blocks
    ADD CONSTRAINT storage_v2_archive_blocks_archive_set_id_fkey FOREIGN KEY (archive_set_id) REFERENCES public.storage_v2_archive_sets(archive_set_id) ON DELETE RESTRICT;


--
-- Name: storage_v2_backfill_chunks storage_v2_backfill_chunks_archive_event_set_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_backfill_chunks
    ADD CONSTRAINT storage_v2_backfill_chunks_archive_event_set_id_fkey FOREIGN KEY (archive_event_set_id) REFERENCES public.storage_v2_archive_sets(archive_set_id);


--
-- Name: storage_v2_backfill_chunks storage_v2_backfill_chunks_archive_link_set_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_backfill_chunks
    ADD CONSTRAINT storage_v2_backfill_chunks_archive_link_set_id_fkey FOREIGN KEY (archive_link_set_id) REFERENCES public.storage_v2_archive_sets(archive_set_id);


--
-- Name: storage_v2_backfill_chunks storage_v2_backfill_chunks_worker_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_backfill_chunks
    ADD CONSTRAINT storage_v2_backfill_chunks_worker_name_fkey FOREIGN KEY (worker_name) REFERENCES public.storage_v2_backfill_checkpoints(worker_name) ON DELETE CASCADE;


--
-- Name: storage_v2_entity_identity_allocations storage_v2_entity_identity_allocations_entity_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_entity_identity_allocations
    ADD CONSTRAINT storage_v2_entity_identity_allocations_entity_type_id_fkey FOREIGN KEY (entity_type_id) REFERENCES public.storage_v2_entity_type(id);


--
-- Name: storage_v2_event_identity_allocations storage_v2_event_identity_allocations_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_storage_owner
--

ALTER TABLE ONLY public.storage_v2_event_identity_allocations
    ADD CONSTRAINT storage_v2_event_identity_allocations_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.storage_v2_channel(id);


--
-- Name: user_report_preferences user_report_preferences_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: adlog_user
--

ALTER TABLE ONLY public.user_report_preferences
    ADD CONSTRAINT user_report_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.auth_users(id) ON DELETE CASCADE;


--
-- Name: users_report_v2_snapshots users_report_v2_snapshots_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_report_v2_snapshots
    ADD CONSTRAINT users_report_v2_snapshots_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE RESTRICT;


--
-- Name: what_where_when_observations what_where_when_observations_computer_source_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_observations
    ADD CONSTRAINT what_where_when_observations_computer_source_snapshot_id_fkey FOREIGN KEY (computer_source_snapshot_id) REFERENCES public.computers_v6_source_snapshots(source_snapshot_id) ON DELETE SET NULL;


--
-- Name: what_where_when_observations what_where_when_observations_user_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_observations
    ADD CONSTRAINT what_where_when_observations_user_snapshot_id_fkey FOREIGN KEY (user_snapshot_id) REFERENCES public.users_report_v2_snapshots(snapshot_id) ON DELETE SET NULL;


--
-- Name: what_where_when_projection_state what_where_when_projection_state_user_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_projection_state
    ADD CONSTRAINT what_where_when_projection_state_user_snapshot_id_fkey FOREIGN KEY (user_snapshot_id) REFERENCES public.users_report_v2_snapshots(snapshot_id) ON DELETE SET NULL;


--
-- Name: what_where_when_projection_state www_projection_state_computer_source_snapshot_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.what_where_when_projection_state
    ADD CONSTRAINT www_projection_state_computer_source_snapshot_fkey FOREIGN KEY (computer_source_snapshot_id) REFERENCES public.computers_v6_source_snapshots(source_snapshot_id) ON DELETE SET NULL;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

GRANT USAGE ON SCHEMA public TO adlog_user;
GRANT ALL ON SCHEMA public TO adlog_storage_owner;
GRANT USAGE ON SCHEMA public TO adlog_radius_identity_resolver;
GRANT USAGE ON SCHEMA public TO adlog_vpn_session_reader_owner;
GRANT USAGE ON SCHEMA public TO adlog_administrative_activity_owner;
GRANT USAGE ON SCHEMA public TO adlog_plugin_lifecycle_owner;
GRANT USAGE ON SCHEMA public TO adlog_radius_preflight_reader;


--
-- Name: SCHEMA sli_plugin_remote_access; Type: ACL; Schema: -; Owner: adlog_plugin_remote_access_owner
--

GRANT USAGE ON SCHEMA sli_plugin_remote_access TO adlog_plugin_remote_access_runtime;


--
-- Name: FUNCTION acquire_plugin_component_lease_v1(p_lease_uid uuid, p_plugin_id text, p_component_id text, p_lease_kind text, p_holder_key text); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.acquire_plugin_component_lease_v1(p_lease_uid uuid, p_plugin_id text, p_component_id text, p_lease_kind text, p_holder_key text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.acquire_plugin_component_lease_v1(p_lease_uid uuid, p_plugin_id text, p_component_id text, p_lease_kind text, p_holder_key text) TO adlog_radius_accounting_worker;
GRANT ALL ON FUNCTION public.acquire_plugin_component_lease_v1(p_lease_uid uuid, p_plugin_id text, p_component_id text, p_lease_kind text, p_holder_key text) TO adlog_radius_session_consumer;


--
-- Name: FUNCTION ad_snapshot_manifest_reject_mutation(); Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON FUNCTION public.ad_snapshot_manifest_reject_mutation() FROM PUBLIC;


--
-- Name: FUNCTION ad_snapshot_projection_output_reject_mutation(); Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON FUNCTION public.ad_snapshot_projection_output_reject_mutation() FROM PUBLIC;


--
-- Name: FUNCTION append_administrative_activity_v1(p_event_uid uuid, p_occurred_at_utc timestamp with time zone, p_actor_kind text, p_actor_key text, p_category text, p_action_key text, p_target_kind text, p_target_key text, p_outcome text, p_reason_code text, p_details_json jsonb, p_remote_address inet, p_correlation_id uuid); Type: ACL; Schema: public; Owner: adlog_administrative_activity_owner
--

REVOKE ALL ON FUNCTION public.append_administrative_activity_v1(p_event_uid uuid, p_occurred_at_utc timestamp with time zone, p_actor_kind text, p_actor_key text, p_category text, p_action_key text, p_target_kind text, p_target_key text, p_outcome text, p_reason_code text, p_details_json jsonb, p_remote_address inet, p_correlation_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.append_administrative_activity_v1(p_event_uid uuid, p_occurred_at_utc timestamp with time zone, p_actor_kind text, p_actor_key text, p_category text, p_action_key text, p_target_kind text, p_target_key text, p_outcome text, p_reason_code text, p_details_json jsonb, p_remote_address inet, p_correlation_id uuid) TO adlog_user;
GRANT ALL ON FUNCTION public.append_administrative_activity_v1(p_event_uid uuid, p_occurred_at_utc timestamp with time zone, p_actor_kind text, p_actor_key text, p_category text, p_action_key text, p_target_kind text, p_target_key text, p_outcome text, p_reason_code text, p_details_json jsonb, p_remote_address inet, p_correlation_id uuid) TO adlog_plugin_lifecycle_owner;


--
-- Name: FUNCTION entity_v2_is_active(p_entity_id bigint); Type: ACL; Schema: public; Owner: adlog_storage_owner
--

REVOKE ALL ON FUNCTION public.entity_v2_is_active(p_entity_id bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION public.entity_v2_is_active(p_entity_id bigint) TO adlog_user;


--
-- Name: FUNCTION execute_bundled_plugin_install_v1(p_operation_uid uuid, p_plugin_id text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.execute_bundled_plugin_install_v1(p_operation_uid uuid, p_plugin_id text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.execute_bundled_plugin_install_v1(p_operation_uid uuid, p_plugin_id text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text) TO adlog_plugin_lifecycle_executor;


--
-- Name: FUNCTION execute_plugin_runtime_transition_v1(p_operation_uid uuid, p_action text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.execute_plugin_runtime_transition_v1(p_operation_uid uuid, p_action text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.execute_plugin_runtime_transition_v1(p_operation_uid uuid, p_action text, p_expected_revision bigint, p_plan_sha256 text, p_confirmation text, p_actor_kind text, p_actor_key text) TO adlog_plugin_lifecycle_executor;


--
-- Name: PROCEDURE expire_ad_snapshot_seven_day_ring(IN p_published_manifest_id uuid); Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON PROCEDURE public.expire_ad_snapshot_seven_day_ring(IN p_published_manifest_id uuid) FROM PUBLIC;
GRANT ALL ON PROCEDURE public.expire_ad_snapshot_seven_day_ring(IN p_published_manifest_id uuid) TO adlog_user;


--
-- Name: FUNCTION finish_remote_access_plugin_drain_v1(); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.finish_remote_access_plugin_drain_v1() FROM PUBLIC;
GRANT ALL ON FUNCTION public.finish_remote_access_plugin_drain_v1() TO adlog_user;


--
-- Name: FUNCTION is_semantic_finding_published_v1(p_finding_id bigint); Type: ACL; Schema: public; Owner: adlog_storage_owner
--

REVOKE ALL ON FUNCTION public.is_semantic_finding_published_v1(p_finding_id bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION public.is_semantic_finding_published_v1(p_finding_id bigint) TO adlog_user;


--
-- Name: FUNCTION observe_remote_access_plugin_v1(p_configured boolean, p_received boolean); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.observe_remote_access_plugin_v1(p_configured boolean, p_received boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION public.observe_remote_access_plugin_v1(p_configured boolean, p_received boolean) TO adlog_user;


--
-- Name: FUNCTION read_administrative_activity_v1(p_before_activity_id bigint, p_limit integer, p_category text); Type: ACL; Schema: public; Owner: adlog_administrative_activity_owner
--

REVOKE ALL ON FUNCTION public.read_administrative_activity_v1(p_before_activity_id bigint, p_limit integer, p_category text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.read_administrative_activity_v1(p_before_activity_id bigint, p_limit integer, p_category text) TO adlog_user;


--
-- Name: FUNCTION read_plugin_component_runtime_guard_v1(p_plugin_id text, p_component_id text); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.read_plugin_component_runtime_guard_v1(p_plugin_id text, p_component_id text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.read_plugin_component_runtime_guard_v1(p_plugin_id text, p_component_id text) TO adlog_user;


--
-- Name: FUNCTION read_plugin_installations_v1(p_limit integer); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.read_plugin_installations_v1(p_limit integer) FROM PUBLIC;
GRANT ALL ON FUNCTION public.read_plugin_installations_v1(p_limit integer) TO adlog_user;


--
-- Name: FUNCTION read_plugin_runtime_queue_nonterminal_v1(); Type: ACL; Schema: public; Owner: adlog_storage_owner
--

REVOKE ALL ON FUNCTION public.read_plugin_runtime_queue_nonterminal_v1() FROM PUBLIC;
GRANT ALL ON FUNCTION public.read_plugin_runtime_queue_nonterminal_v1() TO adlog_plugin_lifecycle_owner;


--
-- Name: FUNCTION read_plugin_states_v1(); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.read_plugin_states_v1() FROM PUBLIC;
GRANT ALL ON FUNCTION public.read_plugin_states_v1() TO adlog_user;


--
-- Name: FUNCTION reject_administrative_activity_mutation_v1(); Type: ACL; Schema: public; Owner: adlog_administrative_activity_owner
--

REVOKE ALL ON FUNCTION public.reject_administrative_activity_mutation_v1() FROM PUBLIC;


--
-- Name: FUNCTION reject_merged_entity_link_block(); Type: ACL; Schema: public; Owner: adlog_storage_owner
--

REVOKE ALL ON FUNCTION public.reject_merged_entity_link_block() FROM PUBLIC;


--
-- Name: FUNCTION reject_plugin_lifecycle_operation_mutation_v1(); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.reject_plugin_lifecycle_operation_mutation_v1() FROM PUBLIC;


--
-- Name: FUNCTION release_plugin_component_lease_v1(p_lease_uid uuid, p_holder_key text, p_outcome text); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.release_plugin_component_lease_v1(p_lease_uid uuid, p_holder_key text, p_outcome text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.release_plugin_component_lease_v1(p_lease_uid uuid, p_holder_key text, p_outcome text) TO adlog_radius_accounting_worker;
GRANT ALL ON FUNCTION public.release_plugin_component_lease_v1(p_lease_uid uuid, p_holder_key text, p_outcome text) TO adlog_radius_session_consumer;


--
-- Name: FUNCTION resolve_entity_identity_v2(candidate integer); Type: ACL; Schema: public; Owner: adlog_storage_owner
--

REVOKE ALL ON FUNCTION public.resolve_entity_identity_v2(candidate integer) FROM PUBLIC;
GRANT ALL ON FUNCTION public.resolve_entity_identity_v2(candidate integer) TO adlog_user;
GRANT ALL ON FUNCTION public.resolve_entity_identity_v2(candidate integer) TO adlog_storage_worker;
GRANT ALL ON FUNCTION public.resolve_entity_identity_v2(candidate integer) TO adlog_semantic_worker;


--
-- Name: FUNCTION set_plugin_enabled_v1(p_plugin_id text, p_enabled boolean, p_revision bigint, p_actor_kind text, p_actor_id bigint, p_configured boolean); Type: ACL; Schema: public; Owner: adlog_plugin_lifecycle_owner
--

REVOKE ALL ON FUNCTION public.set_plugin_enabled_v1(p_plugin_id text, p_enabled boolean, p_revision bigint, p_actor_kind text, p_actor_id bigint, p_configured boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION public.set_plugin_enabled_v1(p_plugin_id text, p_enabled boolean, p_revision bigint, p_actor_kind text, p_actor_id bigint, p_configured boolean) TO adlog_user;


--
-- Name: FUNCTION sli_g11a3_preflight_state_v1(); Type: ACL; Schema: public; Owner: adlog_radius_preflight_reader
--

REVOKE ALL ON FUNCTION public.sli_g11a3_preflight_state_v1() FROM PUBLIC;
GRANT ALL ON FUNCTION public.sli_g11a3_preflight_state_v1() TO adlog_user;


--
-- Name: FUNCTION sli_radius_resolve_principal_key(organization_fqdn text, distinguished_name text); Type: ACL; Schema: public; Owner: adlog_radius_identity_resolver
--

REVOKE ALL ON FUNCTION public.sli_radius_resolve_principal_key(organization_fqdn text, distinguished_name text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.sli_radius_resolve_principal_key(organization_fqdn text, distinguished_name text) TO adlog_radius_accounting_worker;


--
-- Name: FUNCTION write_process_episode_revision_v89(p jsonb); Type: ACL; Schema: public; Owner: adlog_storage_owner
--

REVOKE ALL ON FUNCTION public.write_process_episode_revision_v89(p jsonb) FROM PUBLIC;
GRANT ALL ON FUNCTION public.write_process_episode_revision_v89(p jsonb) TO adlog_semantic_worker;


--
-- Name: COLUMN access_capabilities.id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(id) ON TABLE public.access_capabilities TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN access_capabilities.capability_key; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(capability_key) ON TABLE public.access_capabilities TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN access_capability_assignments.capability_id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(capability_id) ON TABLE public.access_capability_assignments TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN access_package_capabilities.capability_id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(capability_id) ON TABLE public.access_package_capabilities TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN access_platform_owners.user_id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(user_id) ON TABLE public.access_platform_owners TO adlog_plugin_lifecycle_owner;


--
-- Name: TABLE account_risk_acceptance_audit; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.account_risk_acceptance_audit TO adlog_user;


--
-- Name: SEQUENCE account_risk_acceptance_audit_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.account_risk_acceptance_audit_id_seq TO adlog_user;


--
-- Name: TABLE account_risk_acceptances; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.account_risk_acceptances TO adlog_user;


--
-- Name: SEQUENCE account_risk_acceptances_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.account_risk_acceptances_id_seq TO adlog_user;


--
-- Name: TABLE account_risk_investigation_links; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT ON TABLE public.account_risk_investigation_links TO adlog_user;


--
-- Name: SEQUENCE account_risk_investigation_links_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.account_risk_investigation_links_id_seq TO adlog_user;


--
-- Name: TABLE acquisition_consumer_subscriptions; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.acquisition_consumer_subscriptions TO adlog_radius_accounting_worker;


--
-- Name: COLUMN acquisition_consumer_subscriptions.subscription_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(subscription_id) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;
GRANT SELECT(subscription_id) ON TABLE public.acquisition_consumer_subscriptions TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_consumer_subscriptions.source_instance_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(source_instance_id) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;
GRANT SELECT(source_instance_id) ON TABLE public.acquisition_consumer_subscriptions TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_consumer_subscriptions.stream_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(stream_id) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;
GRANT SELECT(stream_id) ON TABLE public.acquisition_consumer_subscriptions TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_consumer_subscriptions.transport_binding; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(transport_binding) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;
GRANT SELECT(transport_binding) ON TABLE public.acquisition_consumer_subscriptions TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_consumer_subscriptions.consumer_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(consumer_id) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_consumer_subscriptions.replay_policy; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(replay_policy) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_consumer_subscriptions.resource_profile_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(resource_profile_id) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_consumer_subscriptions.authority_mode; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(authority_mode) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_consumer_subscriptions.desired_activation; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(desired_activation) ON TABLE public.acquisition_consumer_subscriptions TO adlog_vpn_session_reader_owner;
GRANT SELECT(desired_activation) ON TABLE public.acquisition_consumer_subscriptions TO adlog_radius_preflight_reader;


--
-- Name: TABLE acquisition_delivery_outbox; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.acquisition_delivery_outbox TO adlog_radius_accounting_worker;
GRANT SELECT ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: COLUMN acquisition_delivery_outbox.delivery_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(delivery_id) ON TABLE public.acquisition_delivery_outbox TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_delivery_outbox.subscription_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(subscription_id) ON TABLE public.acquisition_delivery_outbox TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_delivery_outbox.observation_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(observation_id) ON TABLE public.acquisition_delivery_outbox TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_delivery_outbox.delivery_state; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(delivery_state) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;
GRANT SELECT(delivery_state) ON TABLE public.acquisition_delivery_outbox TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_delivery_outbox.delivered_at; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(delivered_at) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: COLUMN acquisition_delivery_outbox.attempt_count; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(attempt_count) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: COLUMN acquisition_delivery_outbox.available_at; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(available_at) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: COLUMN acquisition_delivery_outbox.lease_token; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(lease_token) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: COLUMN acquisition_delivery_outbox.lease_until; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(lease_until) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: COLUMN acquisition_delivery_outbox.heartbeat_at; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(heartbeat_at) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: COLUMN acquisition_delivery_outbox.last_error_code; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(last_error_code) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: COLUMN acquisition_delivery_outbox.updated_at; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(updated_at) ON TABLE public.acquisition_delivery_outbox TO adlog_radius_session_consumer;


--
-- Name: SEQUENCE acquisition_delivery_outbox_delivery_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.acquisition_delivery_outbox_delivery_id_seq TO adlog_radius_accounting_worker;


--
-- Name: TABLE acquisition_source_instances; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.acquisition_source_instances TO adlog_radius_accounting_worker;


--
-- Name: COLUMN acquisition_source_instances.source_instance_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(source_instance_id) ON TABLE public.acquisition_source_instances TO adlog_vpn_session_reader_owner;
GRANT SELECT(source_instance_id) ON TABLE public.acquisition_source_instances TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_source_instances.organization_scope; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(organization_scope) ON TABLE public.acquisition_source_instances TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_source_instances.source_kind; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(source_kind) ON TABLE public.acquisition_source_instances TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_source_instances.display_name; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(display_name) ON TABLE public.acquisition_source_instances TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_source_instances.desired_activation; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(desired_activation) ON TABLE public.acquisition_source_instances TO adlog_vpn_session_reader_owner;
GRANT SELECT(desired_activation) ON TABLE public.acquisition_source_instances TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_source_instances.observed_health; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(observed_health) ON TABLE public.acquisition_source_instances TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN acquisition_source_instances.updated_at; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(updated_at) ON TABLE public.acquisition_source_instances TO adlog_vpn_session_reader_owner;


--
-- Name: TABLE acquisition_stream_cursors; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,UPDATE ON TABLE public.acquisition_stream_cursors TO adlog_radius_accounting_worker;


--
-- Name: COLUMN acquisition_stream_cursors.source_instance_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(source_instance_id) ON TABLE public.acquisition_stream_cursors TO adlog_vpn_session_reader_owner;
GRANT SELECT(source_instance_id) ON TABLE public.acquisition_stream_cursors TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_stream_cursors.stream_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(stream_id) ON TABLE public.acquisition_stream_cursors TO adlog_vpn_session_reader_owner;
GRANT SELECT(stream_id) ON TABLE public.acquisition_stream_cursors TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_stream_cursors.transport_binding; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(transport_binding) ON TABLE public.acquisition_stream_cursors TO adlog_vpn_session_reader_owner;
GRANT SELECT(transport_binding) ON TABLE public.acquisition_stream_cursors TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_stream_cursors.revision; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(revision) ON TABLE public.acquisition_stream_cursors TO adlog_vpn_session_reader_owner;
GRANT SELECT(revision) ON TABLE public.acquisition_stream_cursors TO adlog_radius_preflight_reader;


--
-- Name: COLUMN acquisition_stream_cursors.updated_at; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(updated_at) ON TABLE public.acquisition_stream_cursors TO adlog_vpn_session_reader_owner;


--
-- Name: TABLE ad_context_entity_aliases; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.ad_context_entity_aliases TO adlog_context_worker;


--
-- Name: COLUMN ad_context_entity_aliases.entity_id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(entity_id) ON TABLE public.ad_context_entity_aliases TO adlog_radius_identity_resolver;


--
-- Name: COLUMN ad_context_entity_aliases.domain_id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(domain_id) ON TABLE public.ad_context_entity_aliases TO adlog_radius_identity_resolver;


--
-- Name: COLUMN ad_context_entity_aliases.alias_type; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(alias_type) ON TABLE public.ad_context_entity_aliases TO adlog_radius_identity_resolver;


--
-- Name: COLUMN ad_context_entity_aliases.normalized_value; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(normalized_value) ON TABLE public.ad_context_entity_aliases TO adlog_radius_identity_resolver;


--
-- Name: SEQUENCE ad_context_entity_aliases_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.ad_context_entity_aliases_id_seq TO adlog_context_worker;


--
-- Name: TABLE ad_context_entity_versions; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.ad_context_entity_versions TO adlog_context_worker;


--
-- Name: SEQUENCE ad_context_entity_versions_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.ad_context_entity_versions_id_seq TO adlog_context_worker;


--
-- Name: TABLE ad_context_evidence; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT REFERENCES ON TABLE public.ad_context_evidence TO adlog_storage_owner;
GRANT SELECT,INSERT,UPDATE ON TABLE public.ad_context_evidence TO adlog_context_worker;


--
-- Name: SEQUENCE ad_context_evidence_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.ad_context_evidence_id_seq TO adlog_context_worker;


--
-- Name: TABLE ad_context_relation_versions; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.ad_context_relation_versions TO adlog_context_worker;


--
-- Name: SEQUENCE ad_context_relation_versions_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.ad_context_relation_versions_id_seq TO adlog_context_worker;


--
-- Name: TABLE ad_context_runs; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.ad_context_runs TO adlog_context_worker;


--
-- Name: TABLE ad_context_sections; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.ad_context_sections TO adlog_context_worker;


--
-- Name: TABLE ad_snapshot_manifest_sources; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT ON TABLE public.ad_snapshot_manifest_sources TO adlog_context_worker;
GRANT SELECT,INSERT ON TABLE public.ad_snapshot_manifest_sources TO adlog_user;


--
-- Name: TABLE ad_snapshot_manifests; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT ON TABLE public.ad_snapshot_manifests TO adlog_context_worker;
GRANT SELECT,INSERT ON TABLE public.ad_snapshot_manifests TO adlog_user;


--
-- Name: TABLE ad_snapshot_projection_outputs; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT ON TABLE public.ad_snapshot_projection_outputs TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.ad_snapshot_projection_outputs TO adlog_context_worker;


--
-- Name: TABLE ad_snapshot_projection_receipts; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.ad_snapshot_projection_receipts TO adlog_context_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.ad_snapshot_projection_receipts TO adlog_user;


--
-- Name: COLUMN auth_api_keys.id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(id) ON TABLE public.auth_api_keys TO adlog_plugin_lifecycle_owner;


--
-- Name: COLUMN auth_api_keys.role; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(role) ON TABLE public.auth_api_keys TO adlog_plugin_lifecycle_owner;


--
-- Name: COLUMN auth_api_keys.is_active; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(is_active) ON TABLE public.auth_api_keys TO adlog_plugin_lifecycle_owner;


--
-- Name: COLUMN auth_api_keys.expires_at; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(expires_at) ON TABLE public.auth_api_keys TO adlog_plugin_lifecycle_owner;


--
-- Name: COLUMN auth_api_keys.revoked_at; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(revoked_at) ON TABLE public.auth_api_keys TO adlog_plugin_lifecycle_owner;


--
-- Name: COLUMN auth_users.id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(id) ON TABLE public.auth_users TO adlog_plugin_lifecycle_owner;


--
-- Name: COLUMN auth_users.role; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(role) ON TABLE public.auth_users TO adlog_plugin_lifecycle_owner;


--
-- Name: COLUMN auth_users.is_active; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(is_active) ON TABLE public.auth_users TO adlog_plugin_lifecycle_owner;


--
-- Name: TABLE canonical_action_evidence; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.canonical_action_evidence TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.canonical_action_evidence TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.canonical_action_evidence TO adlog_semantic_worker;


--
-- Name: TABLE canonical_action_state_evidence; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.canonical_action_state_evidence TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.canonical_action_state_evidence TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.canonical_action_state_evidence TO adlog_semantic_worker;


--
-- Name: TABLE canonical_actions; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.canonical_actions TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.canonical_actions TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.canonical_actions TO adlog_semantic_worker;


--
-- Name: TABLE collection_channel_state; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT ON TABLE public.collection_channel_state TO adlog_semantic_worker;


--
-- Name: TABLE collection_runs; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT REFERENCES ON TABLE public.collection_runs TO adlog_storage_owner;


--
-- Name: TABLE computers_report_v5_snapshots; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE ON TABLE public.computers_report_v5_snapshots TO adlog_user;


--
-- Name: SEQUENCE computers_report_v5_snapshots_snapshot_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.computers_report_v5_snapshots_snapshot_id_seq TO adlog_user;


--
-- Name: TABLE computers_report_v6_snapshots; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE ON TABLE public.computers_report_v6_snapshots TO adlog_user;


--
-- Name: SEQUENCE computers_report_v6_snapshots_snapshot_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.computers_report_v6_snapshots_snapshot_id_seq TO adlog_user;


--
-- Name: TABLE computers_v6_source_snapshots; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE ON TABLE public.computers_v6_source_snapshots TO adlog_user;


--
-- Name: SEQUENCE computers_v6_source_snapshots_source_snapshot_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.computers_v6_source_snapshots_source_snapshot_id_seq TO adlog_user;


--
-- Name: TABLE core_evidence_manifests; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.core_evidence_manifests TO adlog_radius_accounting_worker;


--
-- Name: COLUMN core_evidence_manifests.evidence_uid; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(evidence_uid) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;
GRANT SELECT(evidence_uid) ON TABLE public.core_evidence_manifests TO adlog_radius_session_consumer;


--
-- Name: COLUMN core_evidence_manifests.source_instance_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(source_instance_id) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN core_evidence_manifests.stream_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(stream_id) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN core_evidence_manifests.transport_binding; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(transport_binding) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN core_evidence_manifests.canonical_record_sha256; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(canonical_record_sha256) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;
GRANT SELECT(canonical_record_sha256) ON TABLE public.core_evidence_manifests TO adlog_radius_session_consumer;


--
-- Name: COLUMN core_evidence_manifests.object_reference; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(object_reference) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN core_evidence_manifests.object_sha256; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(object_sha256) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN core_evidence_manifests.object_size_bytes; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(object_size_bytes) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN core_evidence_manifests.verified_at_utc; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(verified_at_utc) ON TABLE public.core_evidence_manifests TO adlog_vpn_session_reader_owner;


--
-- Name: TABLE domains; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT ON TABLE public.domains TO adlog_context_worker;


--
-- Name: COLUMN domains.id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(id) ON TABLE public.domains TO adlog_radius_identity_resolver;
GRANT SELECT(id) ON TABLE public.domains TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN domains.fqdn; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(fqdn) ON TABLE public.domains TO adlog_radius_identity_resolver;
GRANT SELECT(fqdn) ON TABLE public.domains TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN domains.domain_sid; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT UPDATE(domain_sid) ON TABLE public.domains TO adlog_context_worker;


--
-- Name: TABLE entities_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.entities_v2 TO adlog_storage_worker;
GRANT SELECT,REFERENCES ON TABLE public.entities_v2 TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.entities_v2 TO adlog_context_worker;


--
-- Name: COLUMN entities_v2.id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(id) ON TABLE public.entities_v2 TO adlog_vpn_session_reader_owner;
GRANT SELECT(id) ON TABLE public.entities_v2 TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN entities_v2.domain_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(domain_id) ON TABLE public.entities_v2 TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN entity_identity_merges_v2.merge_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(merge_id) ON TABLE public.entity_identity_merges_v2 TO adlog_semantic_worker;


--
-- Name: COLUMN entity_identity_merges_v2.source_natural_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(source_natural_key) ON TABLE public.entity_identity_merges_v2 TO adlog_semantic_worker;


--
-- Name: COLUMN entity_identity_merges_v2.target_natural_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(target_natural_key) ON TABLE public.entity_identity_merges_v2 TO adlog_semantic_worker;


--
-- Name: TABLE entities_v2_active; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.entities_v2_active TO adlog_user;
GRANT SELECT ON TABLE public.entities_v2_active TO adlog_storage_worker;


--
-- Name: SEQUENCE entities_v2_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.entities_v2_id_seq TO adlog_context_worker;
GRANT SELECT,USAGE ON SEQUENCE public.entities_v2_id_seq TO adlog_storage_worker;


--
-- Name: TABLE entity_details_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.entity_details_v2 TO adlog_storage_worker;
GRANT SELECT ON TABLE public.entity_details_v2 TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.entity_details_v2 TO adlog_context_worker;


--
-- Name: TABLE entity_identity_finding_supersessions_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.entity_identity_finding_supersessions_v2 TO adlog_semantic_worker;
GRANT SELECT ON TABLE public.entity_identity_finding_supersessions_v2 TO adlog_user;


--
-- Name: TABLE entity_identity_merge_events_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.entity_identity_merge_events_v2 TO adlog_semantic_worker;


--
-- Name: TABLE entity_identity_scenario_supersessions_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.entity_identity_scenario_supersessions_v2 TO adlog_semantic_worker;
GRANT SELECT ON TABLE public.entity_identity_scenario_supersessions_v2 TO adlog_user;


--
-- Name: TABLE entity_identity_semantic_replays_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.entity_identity_semantic_replays_v2 TO adlog_semantic_worker;


--
-- Name: TABLE entity_state_current; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.entity_state_current TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.entity_state_current TO adlog_storage_worker;


--
-- Name: TABLE entity_state_projection_jobs; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.entity_state_projection_jobs TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.entity_state_projection_jobs TO adlog_storage_worker;


--
-- Name: TABLE entity_states; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT INSERT ON TABLE public.entity_states TO adlog_storage_worker;


--
-- Name: COLUMN entity_states.entity_id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(entity_id) ON TABLE public.entity_states TO adlog_storage_worker;


--
-- Name: COLUMN entity_states.state_type; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(state_type) ON TABLE public.entity_states TO adlog_storage_worker;


--
-- Name: COLUMN entity_states.evidence_event_id; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(evidence_event_id) ON TABLE public.entity_states TO adlog_storage_worker;


--
-- Name: SEQUENCE entity_states_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT USAGE ON SEQUENCE public.entity_states_id_seq TO adlog_storage_worker;


--
-- Name: TABLE event_entity_link_blocks_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.event_entity_link_blocks_v2 TO adlog_storage_worker;
GRANT SELECT ON TABLE public.event_entity_link_blocks_v2 TO adlog_user;


--
-- Name: TABLE event_entity_links_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.event_entity_links_v2 TO adlog_storage_worker;
GRANT SELECT ON TABLE public.event_entity_links_v2 TO adlog_user;


--
-- Name: TABLE event_facts_v2; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.event_facts_v2 TO adlog_storage_worker;
GRANT SELECT ON TABLE public.event_facts_v2 TO adlog_user;


--
-- Name: TABLE events_v2_core; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.events_v2_core TO adlog_storage_worker;
GRANT SELECT,REFERENCES ON TABLE public.events_v2_core TO adlog_user;
GRANT SELECT ON TABLE public.events_v2_core TO adlog_semantic_worker;


--
-- Name: TABLE finding_entities; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT ON TABLE public.finding_entities TO adlog_semantic_worker;


--
-- Name: SEQUENCE finding_entities_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.finding_entities_id_seq TO adlog_semantic_worker;


--
-- Name: TABLE finding_evidence; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT ON TABLE public.finding_evidence TO adlog_semantic_worker;


--
-- Name: SEQUENCE finding_evidence_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.finding_evidence_id_seq TO adlog_semantic_worker;


--
-- Name: TABLE finding_status_history; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT ON TABLE public.finding_status_history TO adlog_semantic_worker;


--
-- Name: SEQUENCE finding_status_history_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.finding_status_history_id_seq TO adlog_semantic_worker;


--
-- Name: TABLE findings; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.findings TO adlog_semantic_worker;
GRANT SELECT,REFERENCES ON TABLE public.findings TO adlog_storage_owner;


--
-- Name: TABLE findings_active; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.findings_active TO adlog_user;


--
-- Name: SEQUENCE findings_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.findings_id_seq TO adlog_semantic_worker;


--
-- Name: TABLE gpo_report_v2_source_snapshots; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE ON TABLE public.gpo_report_v2_source_snapshots TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.gpo_report_v2_source_snapshots TO adlog_context_worker;


--
-- Name: SEQUENCE gpo_report_v2_source_snapshots_snapshot_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.gpo_report_v2_source_snapshots_snapshot_id_seq TO adlog_user;
GRANT SELECT,USAGE ON SEQUENCE public.gpo_report_v2_source_snapshots_snapshot_id_seq TO adlog_context_worker;


--
-- Name: TABLE investigation_evidence_refs; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT ON TABLE public.investigation_evidence_refs TO adlog_user;


--
-- Name: TABLE log_sources; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT REFERENCES ON TABLE public.log_sources TO adlog_storage_owner;


--
-- Name: TABLE normalized_events; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.normalized_events TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.normalized_events TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.normalized_events TO adlog_semantic_worker;


--
-- Name: TABLE process_episode_evidence; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.process_episode_evidence TO adlog_semantic_worker;


--
-- Name: TABLE process_episode_revisions; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.process_episode_revisions TO adlog_semantic_worker;


--
-- Name: TABLE radius_accounting_class_cache; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.radius_accounting_class_cache TO adlog_radius_accounting_worker;


--
-- Name: TABLE radius_accounting_session_observations; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.radius_accounting_session_observations TO adlog_radius_accounting_worker;
GRANT SELECT ON TABLE public.radius_accounting_session_observations TO adlog_radius_session_consumer;


--
-- Name: COLUMN radius_accounting_session_observations.observation_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(observation_id) ON TABLE public.radius_accounting_session_observations TO adlog_vpn_session_reader_owner;
GRANT SELECT(observation_id) ON TABLE public.radius_accounting_session_observations TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_accounting_session_observations.evidence_uid; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(evidence_uid) ON TABLE public.radius_accounting_session_observations TO adlog_vpn_session_reader_owner;
GRANT SELECT(evidence_uid) ON TABLE public.radius_accounting_session_observations TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_accounting_session_observations.lifecycle_event; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(lifecycle_event) ON TABLE public.radius_accounting_session_observations TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_accounting_session_observations.session_identity_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(session_identity_key) ON TABLE public.radius_accounting_session_observations TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_accounting_session_observations.exact_principal_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(exact_principal_key) ON TABLE public.radius_accounting_session_observations TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_accounting_session_observations.identity_state; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(identity_state) ON TABLE public.radius_accounting_session_observations TO adlog_radius_session_reconciliation_writer;
GRANT SELECT(identity_state) ON TABLE public.radius_accounting_session_observations TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_accounting_session_observations.observed_at_utc; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(observed_at_utc) ON TABLE public.radius_accounting_session_observations TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_accounting_session_observations.timestamp_state; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(timestamp_state) ON TABLE public.radius_accounting_session_observations TO adlog_vpn_session_reader_owner;


--
-- Name: TABLE radius_session_identity_overlays; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_identity_overlays.observation_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(observation_id) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_reconciliation_writer;
GRANT SELECT(observation_id) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_consumer;


--
-- Name: COLUMN radius_session_identity_overlays.attempt_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(attempt_key) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_identity_overlays.evidence_uid; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(evidence_uid) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_identity_overlays.session_identity_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(session_identity_key) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_reconciliation_writer;
GRANT SELECT(session_identity_key) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_consumer;


--
-- Name: COLUMN radius_session_identity_overlays.exact_principal_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(exact_principal_key) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_reconciliation_writer;
GRANT SELECT(exact_principal_key) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_consumer;


--
-- Name: COLUMN radius_session_identity_overlays.resolution_input_sha256; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(resolution_input_sha256) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_identity_overlays.resolver_contract_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(resolver_contract_id) ON TABLE public.radius_session_identity_overlays TO adlog_radius_session_reconciliation_writer;


--
-- Name: TABLE radius_session_projection_receipts; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.radius_session_projection_receipts TO adlog_radius_session_consumer;


--
-- Name: COLUMN radius_session_projection_receipts.delivery_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(delivery_id) ON TABLE public.radius_session_projection_receipts TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_session_projection_receipts.observation_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(observation_id) ON TABLE public.radius_session_projection_receipts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_projection_receipts.outcome; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(outcome) ON TABLE public.radius_session_projection_receipts TO adlog_vpn_session_reader_owner;
GRANT SELECT(outcome) ON TABLE public.radius_session_projection_receipts TO adlog_radius_session_reconciliation_writer;


--
-- Name: TABLE radius_session_reconciliation_attempts; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_reconciliation_attempts.attempt_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(attempt_key) ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_reconciliation_attempts.observation_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(observation_id) ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_reconciliation_attempts.evidence_uid; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(evidence_uid) ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_reconciliation_attempts.outcome; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(outcome) ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_reconciliation_attempts.evidence_corpus_sha256; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(evidence_corpus_sha256) ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_reconciliation_attempts.resolver_contract_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(resolver_contract_id) ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_reconciliation_attempts.resolution_input_sha256; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(resolution_input_sha256) ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: COLUMN radius_session_reconciliation_attempts.writer_contract_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT INSERT(writer_contract_id) ON TABLE public.radius_session_reconciliation_attempts TO adlog_radius_session_reconciliation_writer;


--
-- Name: TABLE radius_vpn_session_projection; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.radius_vpn_session_projection TO adlog_radius_session_consumer;


--
-- Name: COLUMN radius_vpn_session_projection.session_row_id; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(session_row_id) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.session_identity_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(session_identity_key) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.exact_principal_key; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(exact_principal_key) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.generation; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(generation) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.lifecycle_state; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(lifecycle_state) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.completeness; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(completeness) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.started_at_utc; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(started_at_utc) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.last_observed_at_utc; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(last_observed_at_utc) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.stopped_at_utc; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(stopped_at_utc) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.duration_seconds; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(duration_seconds) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.observation_count; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(observation_count) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.anomalies; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(anomalies) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN radius_vpn_session_projection.updated_at; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT(updated_at) ON TABLE public.radius_vpn_session_projection TO adlog_vpn_session_reader_owner;


--
-- Name: TABLE radius_vpn_session_coverage_v1; Type: ACL; Schema: public; Owner: adlog_vpn_session_reader_owner
--

GRANT SELECT ON TABLE public.radius_vpn_session_coverage_v1 TO adlog_user;


--
-- Name: COLUMN report_registry_v4.report_key; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(report_key) ON TABLE public.report_registry_v4 TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN report_registry_v4.version; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(version) ON TABLE public.report_registry_v4 TO adlog_vpn_session_reader_owner;


--
-- Name: COLUMN report_registry_v4.status; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(status) ON TABLE public.report_registry_v4 TO adlog_vpn_session_reader_owner;


--
-- Name: TABLE radius_vpn_operations_v1; Type: ACL; Schema: public; Owner: adlog_vpn_session_reader_owner
--

GRANT SELECT ON TABLE public.radius_vpn_operations_v1 TO adlog_user;


--
-- Name: TABLE radius_vpn_session_evidence_observations_v1; Type: ACL; Schema: public; Owner: adlog_vpn_session_reader_owner
--

GRANT SELECT ON TABLE public.radius_vpn_session_evidence_observations_v1 TO adlog_user;


--
-- Name: TABLE radius_vpn_session_rows_v1; Type: ACL; Schema: public; Owner: adlog_vpn_session_reader_owner
--

GRANT SELECT ON TABLE public.radius_vpn_session_rows_v1 TO adlog_user;


--
-- Name: TABLE raw_batch_lifecycle; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.raw_batch_lifecycle TO adlog_user;


--
-- Name: TABLE raw_log_files; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT REFERENCES ON TABLE public.raw_log_files TO adlog_storage_owner;
GRANT SELECT,INSERT,UPDATE ON TABLE public.raw_log_files TO adlog_storage_worker;


--
-- Name: SEQUENCE raw_log_files_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.raw_log_files_id_seq TO adlog_storage_worker;


--
-- Name: TABLE runtime_collection_blocks; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.runtime_collection_blocks TO adlog_storage_worker;


--
-- Name: TABLE runtime_collection_runs; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.runtime_collection_runs TO adlog_user;


--
-- Name: TABLE runtime_worker_heartbeats; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.runtime_worker_heartbeats TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.runtime_worker_heartbeats TO adlog_semantic_worker;


--
-- Name: TABLE schema_migrations; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.schema_migrations TO adlog_storage_owner;
GRANT SELECT ON TABLE public.schema_migrations TO adlog_context_worker;
GRANT SELECT ON TABLE public.schema_migrations TO adlog_semantic_worker;


--
-- Name: COLUMN schema_migrations.version; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(version) ON TABLE public.schema_migrations TO adlog_radius_preflight_reader;


--
-- Name: COLUMN schema_migrations.name; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT(name) ON TABLE public.schema_migrations TO adlog_radius_preflight_reader;


--
-- Name: SEQUENCE schema_migrations_id_seq; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT SELECT,USAGE ON SEQUENCE public.schema_migrations_id_seq TO adlog_storage_owner;


--
-- Name: TABLE semantic_control_health_observations; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_control_health_observations TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.semantic_control_health_observations TO adlog_storage_worker;
GRANT SELECT,INSERT ON TABLE public.semantic_control_health_observations TO adlog_semantic_worker;


--
-- Name: TABLE semantic_correlation_candidate_evidence; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_correlation_candidate_evidence TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_candidate_evidence TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_candidate_evidence TO adlog_semantic_worker;


--
-- Name: TABLE semantic_correlation_candidates; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_correlation_candidates TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_candidates TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_candidates TO adlog_semantic_worker;


--
-- Name: TABLE semantic_correlation_dispatch_jobs; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_correlation_dispatch_jobs TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_dispatch_jobs TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_dispatch_jobs TO adlog_semantic_worker;


--
-- Name: TABLE semantic_correlation_replays; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_correlation_replays TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_replays TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_replays TO adlog_semantic_worker;


--
-- Name: TABLE semantic_correlation_rules; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_correlation_rules TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_correlation_rules TO adlog_storage_worker;
GRANT SELECT ON TABLE public.semantic_correlation_rules TO adlog_semantic_worker;


--
-- Name: COLUMN semantic_correlation_rules.updated_at; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT UPDATE(updated_at) ON TABLE public.semantic_correlation_rules TO adlog_semantic_worker;


--
-- Name: TABLE semantic_correlation_subscriptions; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_correlation_subscriptions TO adlog_user;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.semantic_correlation_subscriptions TO adlog_storage_worker;
GRANT SELECT ON TABLE public.semantic_correlation_subscriptions TO adlog_semantic_worker;


--
-- Name: TABLE semantic_finding_publications; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.semantic_finding_publications TO adlog_semantic_worker;


--
-- Name: TABLE semantic_processing_outbox; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.semantic_processing_outbox TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_processing_outbox TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_processing_outbox TO adlog_semantic_worker;


--
-- Name: TABLE semantic_risk_contributions; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_risk_contributions TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.semantic_risk_contributions TO adlog_storage_worker;
GRANT SELECT,INSERT ON TABLE public.semantic_risk_contributions TO adlog_semantic_worker;


--
-- Name: TABLE semantic_risk_evaluation_jobs; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_risk_evaluation_jobs TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_risk_evaluation_jobs TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_risk_evaluation_jobs TO adlog_semantic_worker;


--
-- Name: TABLE semantic_risk_evaluation_results; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_risk_evaluation_results TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.semantic_risk_evaluation_results TO adlog_storage_worker;
GRANT SELECT,INSERT ON TABLE public.semantic_risk_evaluation_results TO adlog_semantic_worker;


--
-- Name: TABLE semantic_risk_policies; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_risk_policies TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_risk_policies TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_risk_policies TO adlog_semantic_worker;


--
-- Name: TABLE semantic_risk_policy_subscriptions; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_risk_policy_subscriptions TO adlog_user;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.semantic_risk_policy_subscriptions TO adlog_storage_worker;
GRANT SELECT ON TABLE public.semantic_risk_policy_subscriptions TO adlog_semantic_worker;


--
-- Name: TABLE semantic_scenario_coverage_history; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_scenario_coverage_history TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.semantic_scenario_coverage_history TO adlog_storage_worker;
GRANT SELECT,INSERT ON TABLE public.semantic_scenario_coverage_history TO adlog_semantic_worker;


--
-- Name: TABLE semantic_scenario_evidence; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_scenario_evidence TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.semantic_scenario_evidence TO adlog_storage_worker;
GRANT SELECT,INSERT ON TABLE public.semantic_scenario_evidence TO adlog_semantic_worker;


--
-- Name: TABLE semantic_scenario_reviews; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.semantic_scenario_reviews TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.semantic_scenario_reviews TO adlog_storage_worker;


--
-- Name: TABLE semantic_scenario_steps; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_scenario_steps TO adlog_user;
GRANT SELECT,INSERT ON TABLE public.semantic_scenario_steps TO adlog_storage_worker;
GRANT SELECT,INSERT ON TABLE public.semantic_scenario_steps TO adlog_semantic_worker;


--
-- Name: TABLE semantic_security_scenarios; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.semantic_security_scenarios TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_security_scenarios TO adlog_storage_worker;
GRANT SELECT,INSERT,UPDATE ON TABLE public.semantic_security_scenarios TO adlog_semantic_worker;


--
-- Name: TABLE servers; Type: ACL; Schema: public; Owner: adlog_user
--

GRANT REFERENCES ON TABLE public.servers TO adlog_storage_owner;


--
-- Name: TABLE source_capture_continuity_declarations; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.source_capture_continuity_declarations TO adlog_user;


--
-- Name: SEQUENCE source_capture_continuity_declarations_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.source_capture_continuity_declarations_id_seq TO adlog_user;


--
-- Name: TABLE storage_v2_archive_blocks; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_archive_blocks TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_archive_blocks TO adlog_user;
GRANT SELECT ON TABLE public.storage_v2_archive_blocks TO adlog_semantic_worker;


--
-- Name: TABLE storage_v2_archive_sets; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_archive_sets TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_archive_sets TO adlog_user;
GRANT SELECT ON TABLE public.storage_v2_archive_sets TO adlog_semantic_worker;


--
-- Name: TABLE storage_v2_backfill_checkpoints; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_backfill_checkpoints TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_backfill_chunks; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_backfill_chunks TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_channel; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_channel TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_channel TO adlog_user;
GRANT SELECT ON TABLE public.storage_v2_channel TO adlog_semantic_worker;


--
-- Name: SEQUENCE storage_v2_channel_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_channel_id_seq TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_computer; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_computer TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_computer TO adlog_user;
GRANT SELECT ON TABLE public.storage_v2_computer TO adlog_semantic_worker;


--
-- Name: SEQUENCE storage_v2_computer_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_computer_id_seq TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_cutover_state; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.storage_v2_cutover_state TO adlog_user;


--
-- Name: TABLE storage_v2_domain_name; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_domain_name TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_domain_name TO adlog_user;


--
-- Name: SEQUENCE storage_v2_domain_name_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_domain_name_id_seq TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_entity_identity_allocations; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.storage_v2_entity_identity_allocations TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_entity_type; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_entity_type TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_entity_type TO adlog_user;
GRANT SELECT,INSERT,UPDATE ON TABLE public.storage_v2_entity_type TO adlog_context_worker;


--
-- Name: SEQUENCE storage_v2_entity_type_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_entity_type_id_seq TO adlog_storage_worker;
GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_entity_type_id_seq TO adlog_context_worker;


--
-- Name: SEQUENCE storage_v2_event_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_event_id_seq TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_event_identity_allocations; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT ON TABLE public.storage_v2_event_identity_allocations TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_extracted_from; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_extracted_from TO adlog_storage_worker;


--
-- Name: SEQUENCE storage_v2_extracted_from_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_extracted_from_id_seq TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_keywords; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_keywords TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_keywords TO adlog_user;
GRANT SELECT ON TABLE public.storage_v2_keywords TO adlog_semantic_worker;


--
-- Name: SEQUENCE storage_v2_keywords_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_keywords_id_seq TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_outbox; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_outbox TO adlog_storage_worker;
GRANT SELECT,INSERT ON TABLE public.storage_v2_outbox TO adlog_user;


--
-- Name: SEQUENCE storage_v2_outbox_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_outbox_id_seq TO adlog_storage_worker;
GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_outbox_id_seq TO adlog_user;


--
-- Name: TABLE storage_v2_provider; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_provider TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_provider TO adlog_user;
GRANT SELECT ON TABLE public.storage_v2_provider TO adlog_semantic_worker;


--
-- Name: SEQUENCE storage_v2_provider_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_provider_id_seq TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_role; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_role TO adlog_storage_worker;
GRANT SELECT ON TABLE public.storage_v2_role TO adlog_user;


--
-- Name: SEQUENCE storage_v2_role_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_role_id_seq TO adlog_storage_worker;


--
-- Name: TABLE storage_v2_runtime_authorizations; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT ON TABLE public.storage_v2_runtime_authorizations TO adlog_user;


--
-- Name: TABLE storage_v2_shadow_results; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.storage_v2_shadow_results TO adlog_storage_worker;
GRANT INSERT ON TABLE public.storage_v2_shadow_results TO adlog_user;


--
-- Name: SEQUENCE storage_v2_shadow_results_id_seq; Type: ACL; Schema: public; Owner: adlog_storage_owner
--

GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_shadow_results_id_seq TO adlog_storage_worker;
GRANT SELECT,USAGE ON SEQUENCE public.storage_v2_shadow_results_id_seq TO adlog_user;


--
-- Name: TABLE users_report_v2_snapshots; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE ON TABLE public.users_report_v2_snapshots TO adlog_user;


--
-- Name: SEQUENCE users_report_v2_snapshots_snapshot_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.users_report_v2_snapshots_snapshot_id_seq TO adlog_user;


--
-- Name: TABLE what_where_when_observations; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE ON TABLE public.what_where_when_observations TO adlog_user;


--
-- Name: SEQUENCE what_where_when_observations_projection_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.what_where_when_observations_projection_id_seq TO adlog_user;


--
-- Name: TABLE what_where_when_projection_state; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.what_where_when_projection_state TO adlog_user;


--
-- Name: TABLE plugin_namespace_contract_v1; Type: ACL; Schema: sli_plugin_remote_access; Owner: adlog_plugin_remote_access_owner
--

GRANT SELECT ON TABLE sli_plugin_remote_access.plugin_namespace_contract_v1 TO adlog_plugin_remote_access_runtime;


--
-- PostgreSQL database dump complete
--


