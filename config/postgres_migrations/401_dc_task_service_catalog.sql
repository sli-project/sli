begin;
select pg_advisory_xact_lock(hashtext('sli_dc_task_service_catalog401'));
set local lock_timeout='5s';
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=400 and name='password_detection_status')
       or exists(select 1 from public.schema_migrations where version>=401) then
        raise exception 'dc_task_service401_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
set local search_path=pg_catalog,public;

-- The publisher accepts only these server-owned definition pins.
create table public.dc_catalog_policies401(
    policy_id text primary key,
    action_kind text not null unique,
    scenario_kind text not null unique,
    evidence_type text not null,
    object_field text not null,
    definition_sha256 bytea not null
);
revoke all on public.dc_catalog_policies401 from public,adlog_user,adlog_semantic_worker;
with definitions(policy_id,action_kind,scenario_kind,evidence_type,object_field,document) as (
    values
    ('l1-dc-scheduled-task-created','scheduled_task.created','security.dc_scheduled_task_created',
     'scheduled_task.created.fragment','task_name',
     $policy${"expected_evidence_count":1,"explanation":"An attested event records a new scheduled task on a domain controller.","merge_window_seconds":300,"result_class":"security_incident","risk":{"class":"high","display_points":60,"rationale":"Verify whether this change on a domain controller was planned.","raw_score":"60"},"scenario_kind":"security.dc_scheduled_task_created","source_selector":{"action_kind":"scheduled_task.created"},"strict_roles":["source_host","target_entity"],"title":"New scheduled task on a domain controller","type":"scenario_policy"}$policy$),
    ('l1-dc-service-installed','service.installed','security.dc_service_installed',
     'service.installed.fragment','service_name',
     $policy${"expected_evidence_count":1,"explanation":"An attested event records a new service on a domain controller.","merge_window_seconds":300,"result_class":"security_incident","risk":{"class":"high","display_points":60,"rationale":"Verify whether this change on a domain controller was planned.","raw_score":"60"},"scenario_kind":"security.dc_service_installed","source_selector":{"action_kind":"service.installed"},"strict_roles":["source_host","target_entity"],"title":"New service on a domain controller","type":"scenario_policy"}$policy$)
), stored as (
    insert into public.semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
    select policy_id,1,'canonical_action','draft',document::jsonb,sha256(convert_to(document,'UTF8'))
    from definitions on conflict(policy_id,policy_version) do nothing
)
insert into public.dc_catalog_policies401
select policy_id,action_kind,scenario_kind,evidence_type,object_field,sha256(convert_to(document,'UTF8'))
from definitions;

insert into public.semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256)
select p.policy_id,1,'canonical_action',pin.action_kind,p.definition_sha256
from public.semantic_risk_policies p join public.dc_catalog_policies401 pin using(policy_id)
where p.policy_version=1 and p.lifecycle_status='draft' and p.definition_sha256=pin.definition_sha256
on conflict do nothing;

update public.semantic_risk_policies p set lifecycle_status='shadow'
from public.dc_catalog_policies401 pin
where p.policy_id=pin.policy_id and p.policy_version=1 and p.definition_sha256=pin.definition_sha256
  and p.lifecycle_status in('draft','disabled')
  and exists(select 1 from public.semantic_risk_policy_subscriptions s
      where s.policy_id=p.policy_id and s.policy_version=1 and s.source_kind='canonical_action'
        and s.selector_value=pin.action_kind and s.definition_sha256=pin.definition_sha256);

-- Preserve explicit decisions, including a previous installation's task-rule opt-out.
insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
select p.policy_id,1,not exists (
    select 1 from public.semantic_policy_admission legacy
    where pin.action_kind='scheduled_task.created'
      and legacy.policy_id='l1-scheduled-task-created' and legacy.enabled is false
    ),'system:defaults'
from public.semantic_risk_policies p join public.dc_catalog_policies401 pin using(policy_id)
where p.policy_version=1 and p.lifecycle_status='shadow' and p.definition_sha256=pin.definition_sha256
on conflict(policy_id,policy_version) do nothing;

-- The packet attestation already distinguishes the two AD/DC streams. Capture
-- that distinction after verification, without changing the authenticated event.
create table if not exists public.dc_catalog_event_origins401(
    event_id bigint primary key references public.storage_v2_event_identity_allocations(id) on delete cascade,
    source_sha256 bytea not null check(octet_length(source_sha256)=32),
    module_id text not null check(module_id in('sli.windows.ad-dc','sli.windows.ad-dc-history'))
);
revoke all on public.dc_catalog_event_origins401 from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
create table public.dc_catalog_restore401(attestation text not null);
revoke all on public.dc_catalog_restore401 from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
insert into public.dc_catalog_restore401 values(pg_get_functiondef('public.attest_short_event337()'::regprocedure));
do $patch$
declare original text; patched text;
begin
    select attestation into strict original from public.dc_catalog_restore401;
    patched:=replace(original,'admission_ordinal text;','admission_ordinal text; admitted_module text;');
    if patched=original then raise exception 'dc_task_service401_attestation_shape'; end if;
    original:=patched;
    patched:=replace(patched,'a.normalized_hash,a.event_record_id','a.normalized_hash,a.event_record_id,r.module_id');
    if patched=original then raise exception 'dc_task_service401_attestation_shape'; end if;
    original:=patched;
    patched:=replace(patched,'into origin,digest,record_id','into origin,digest,record_id,admitted_module');
    if patched=original then raise exception 'dc_task_service401_attestation_shape'; end if;
    original:=patched;
    patched:=replace(patched,'new.event_record_id:=record_id; end if;',
        $body$new.event_record_id:=record_id;
        if new.event_kind in(4697,4698,7045)
           and not exists(select 1 from public.event_hot prior
               where prior.event_id=new.event_id and prior.time_created_utc=new.time_created_utc
                 and prior.source_sha256 is not null)
           and not exists(select 1 from public.event_cold_facts prior
               where prior.event_id=new.event_id and prior.time_created_utc=new.time_created_utc
                 and prior.source_sha256 is not null) then
            insert into public.dc_catalog_event_origins401(event_id,source_sha256,module_id)
            values(new.event_id,digest,admitted_module) on conflict(event_id) do nothing;
        end if;
    end if;$body$);
    if patched=original then raise exception 'dc_task_service401_attestation_shape'; end if;
    execute patched;
end $patch$;

create function public.read_dc_catalog_action401(p_policy text,p_version integer,p_action uuid)
returns jsonb language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('event_id',source.id,'domain_id',source.domain_id,
        'server_id',source.server_id,'host',source.computer,'name',n.facts_json->>pin.object_field,
        'actor',case when source.event_id in(4697,4698) then nullif(btrim(source.subject_user_name),'') end)
    from public.dc_catalog_policies401 pin
    join public.semantic_risk_policies policy on policy.policy_id=pin.policy_id and policy.policy_version=1
      and policy.definition_sha256=pin.definition_sha256 and policy.source_kind='canonical_action'
    join public.semantic_policy_admission admission on admission.policy_id=policy.policy_id
      and admission.policy_version=policy.policy_version
    join public.semantic_risk_policy_subscriptions subscription on subscription.policy_id=policy.policy_id
      and subscription.policy_version=policy.policy_version and subscription.source_kind=policy.source_kind
      and subscription.definition_sha256=policy.definition_sha256
    join public.canonical_actions action on action.canonical_action_id=p_action
      and action.action_kind=pin.action_kind and action.assembler_id='semantic-action-assembler'
      and action.semantic_contract_version=1 and action.action_status not in('contradicted','superseded','quarantined')
    join public.canonical_action_evidence link using(canonical_action_id)
    join public.normalized_events n using(normalized_event_id)
    join public.semantic_event_source355 source on source.id=n.source_event_id
      and source.normalized_hash=n.source_event_sha256 and source.time_created_utc=n.occurred_at_utc
    join public.servers host on host.id=source.server_id and host.domain_id=source.domain_id
      and host.is_active and host.role='domain_controller'
    where pin.policy_id=p_policy and p_version=1 and admission.enabled
      and public.semantic_policy_mode_v160(p_policy,p_version,policy.lifecycle_status)='enabled'
      and subscription.selector_value=pin.action_kind and n.semantic_type=pin.evidence_type
      and action.attributes_json#>>'{material_identity,source_event_id}'=source.id::text
      and action.attributes_json#>>'{material_identity,source_host}'=source.server_id::text
      and n.roles_json->>'source_host'=source.server_id::text and n.facts_json->>'domain_id'=source.domain_id::text
      and source.domain_id>0 and source.event_record_id>0
      and n.facts_json->>pin.object_field=n.roles_json->>'target_entity'
      and n.facts_json->>pin.object_field = case when source.event_id=4698
          then coalesce(nullif(btrim(source.event_data_json->>'TaskName'),''),btrim(source.event_data_json->>'TaskNamePath'))
          else btrim(source.event_data_json->>'ServiceName') end
      and length(btrim(n.facts_json->>pin.object_field)) between 1 and 512
      and ((source.event_id=4698 and pin.action_kind='scheduled_task.created'
             and source.channel='Security' and source.provider_name='Microsoft-Windows-Security-Auditing')
        or (pin.action_kind='service.installed' and
             (source.event_id=4697 and source.channel='Security' and source.provider_name='Microsoft-Windows-Security-Auditing'
              or source.event_id=7045 and source.channel='System' and source.provider_name='Service Control Manager')))
      and (select count(*) from public.canonical_action_evidence all_links
           where all_links.canonical_action_id=p_action)=1
$$;
revoke all on function public.read_dc_catalog_action401(text,integer,uuid) from public;
grant execute on function public.read_dc_catalog_action401(text,integer,uuid) to adlog_semantic_worker;

-- Restrict auxiliary operations to the standard finding and an admitted pinned
-- policy, not to an arbitrary caller-provided finding, scenario or channel.
create function public.dc_catalog_finding401(p_finding bigint,p_scenario uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists (
        select 1 from public.findings finding
        join public.semantic_security_scenarios scenario on scenario.scenario_id=p_scenario
          and finding.fingerprint='semantic:'||encode(scenario.scenario_key,'hex')
        join public.dc_catalog_policies401 pin on pin.scenario_kind=scenario.scenario_kind
          and finding.rule_code='semantic.'||pin.scenario_kind and scenario.risk_class='high'
        where finding.id=p_finding and scenario.evidence_state='ready'
          and exists(select 1 from public.semantic_risk_contributions c where c.scenario_id=p_scenario)
          and not exists (
            select 1 from public.semantic_risk_contributions c
            left join public.semantic_risk_policies policy using(policy_id,policy_version)
            left join public.semantic_policy_admission admission using(policy_id,policy_version)
            where c.scenario_id=p_scenario and (
                c.source_kind<>'canonical_action' or c.policy_id<>pin.policy_id
                or c.policy_version<>1 or c.policy_sha256<>pin.definition_sha256
                or policy.definition_sha256 is distinct from pin.definition_sha256
                or admission.enabled is not true
                or public.semantic_policy_mode_v160(c.policy_id,c.policy_version,policy.lifecycle_status)<>'enabled'
            )
          )
    )
$$;
revoke all on function public.dc_catalog_finding401(bigint,uuid) from public;

create function public.copy_dc_catalog_evidence401(p_finding bigint,p_scenario uuid)
returns boolean language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if not public.dc_catalog_finding401(p_finding,p_scenario) then return false; end if;
    with expected as materialized (
        select n.source_event_id,n.source_event_sha256,n.occurred_at_utc
        from public.semantic_scenario_evidence evidence join public.normalized_events n using(normalized_event_id)
        where evidence.scenario_id=p_scenario
    ), missing as materialized (
        select e.* from expected e
        where not exists(select 1 from public.finding_event_copies337 c
            where c.finding_id=p_finding and c.event_id=e.source_event_id and c.time_created_utc=e.occurred_at_utc
              and c.source_sha256=e.source_event_sha256 and c.evidence_role='semantic_scenario')
    )
    insert into public.finding_event_copies337
    select p_finding,c.event_id,c.time_created_utc,c.event_kind,c.domain_id,c.actor,c.target,c.source,
        c.computer,c.method,c.outcome,c.fields,c.source_sha256,'semantic_scenario','enabled semantic scenario evidence',c.event_record_id
    from missing e
    join public.semantic_event_source355 source on source.id=e.source_event_id
      and source.normalized_hash=e.source_event_sha256 and source.time_created_utc=e.occurred_at_utc
    join public.event_cold_facts c on c.event_id=e.source_event_id
      and c.time_created_utc=e.occurred_at_utc and c.source_sha256=e.source_event_sha256
    on conflict do nothing;
    return
        public.semantic_finding_in_domains_v265(p_finding,array[(
            select (s.strict_keys_json->>'domain_id')::bigint
            from public.semantic_security_scenarios s where s.scenario_id=p_scenario)])
        and not exists (
            select 1 from public.semantic_scenario_evidence e join public.normalized_events n using(normalized_event_id)
            where e.scenario_id=p_scenario and not exists(select 1 from public.finding_event_copies337 c
               where c.finding_id=p_finding and c.event_id=n.source_event_id and c.time_created_utc=n.occurred_at_utc
                 and c.source_sha256=n.source_event_sha256 and c.evidence_role='semantic_scenario')
        );
end $$;
revoke all on function public.copy_dc_catalog_evidence401(bigint,uuid) from public;
grant execute on function public.copy_dc_catalog_evidence401(bigint,uuid) to adlog_semantic_worker;

create function public.enqueue_dc_catalog_notifications401(p_scenario uuid)
returns integer language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare finding bigint; delivery_key text; reason text; event_at timestamptz; minutes integer:=0; added integer;
begin
    select p.finding_id into finding
    from public.semantic_finding_publications p
    join public.semantic_risk_evaluation_results result on result.job_id=p.first_job_id and result.scenario_id=p.scenario_id
    where p.scenario_id=p_scenario and result.evaluation_mode='enabled' and result.conclusion_state='observed';
    if not found or not public.dc_catalog_finding401(finding,p_scenario)
       or not public.copy_dc_catalog_evidence401(finding,p_scenario) then
        raise exception 'dc_task_service401_publication_unavailable';
    end if;
    select max(c.time_created_utc) filter(where origin.module_id='sli.windows.ad-dc'
            and exists(select 1 from public.semantic_processing_outbox normal
              where normal.source_event_id=c.event_id and normal.job_kind='normalize_event' and normal.status='completed'
                and normal.processor_version=n.normalizer_version)),
           case when bool_and(origin.module_id is not distinct from 'sli.windows.ad-dc-history')
             then 'history_import' else 'historical_replay' end
    into event_at,reason
    from public.semantic_scenario_evidence e join public.normalized_events n using(normalized_event_id)
    join public.finding_event_copies337 c on c.finding_id=finding and c.event_id=n.source_event_id
      and c.time_created_utc=n.occurred_at_utc and c.source_sha256=n.source_event_sha256 and c.evidence_role='semantic_scenario'
    left join public.dc_catalog_event_origins401 origin on origin.event_id=c.event_id and origin.source_sha256=c.source_sha256
    where e.scenario_id=p_scenario;
    if event_at is not null then
        if event_at<clock_timestamp()-interval '15 minutes' then
            reason:='pipeline_delay';
            minutes:=least(2147483647,floor(extract(epoch from (clock_timestamp()-event_at))/60))::integer;
        else reason:='live'; end if;
    end if;
    delivery_key:=case when event_at is null then 'initial:'||reason else 'initial' end;
    perform pg_advisory_xact_lock(hashtext('notification_outbox_admission'));
    perform 1 from public.notification_subscriptions where enabled order by id for share;
    if event_at is not null and (
        select count(*) from public.notification_outbox where state in ('pending','sending','retry')
    ) + (
        select count(distinct (s.recipient_user_id,s.channel))
        from public.notification_subscriptions s where enabled and not exists (
            select 1 from public.notification_outbox j where j.object_kind='semantic_finding'
                and j.object_id=p_scenario and j.recipient_user_id=s.recipient_user_id
                and j.channel=s.channel and j.change_key=delivery_key)
    )>10000 then raise exception 'notification_queue_full'; end if;
    insert into public.notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
        publication_scenario_id,recipient_user_id,channel,change_key,object_severity,delivery_reason,delay_minutes,state,result_code)
    select gen_random_uuid(),s.id,s.revision,'semantic_finding',p_scenario,p_scenario,s.recipient_user_id,s.channel,
        delivery_key,'high',reason,minutes,case when event_at is null then 'cancelled' else 'pending' end,
        case when event_at is null then reason end
    from (select distinct on(recipient_user_id,channel) * from public.notification_subscriptions
          where enabled order by recipient_user_id,channel,id) s
    on conflict(object_kind,object_id,recipient_user_id,channel,change_key) do nothing;
    get diagnostics added=row_count;
    return added;
end $$;
revoke all on function public.enqueue_dc_catalog_notifications401(uuid) from public;
grant execute on function public.enqueue_dc_catalog_notifications401(uuid) to adlog_semantic_worker;

create function public.dc_catalog_notification_domain401(p_job uuid,p_lease uuid,p_domains bigint[])
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists (
        select 1 from public.notification_outbox job
        join public.semantic_finding_publications publication on publication.scenario_id=job.publication_scenario_id
        join public.semantic_security_scenarios scenario on scenario.scenario_id=publication.scenario_id
        join public.dc_catalog_policies401 pin using(scenario_kind)
        where job.id=p_job and job.lease_token=p_lease and job.state='sending'
          and job.lease_until>statement_timestamp() and job.object_kind='semantic_finding'
          and public.dc_catalog_finding401(publication.finding_id,publication.scenario_id)
          and public.semantic_finding_in_domains_v265(publication.finding_id,p_domains)
    )
$$;
revoke all on function public.dc_catalog_notification_domain401(uuid,uuid,bigint[]) from public;
grant execute on function public.dc_catalog_notification_domain401(uuid,uuid,bigint[]) to adlog_notification_worker;

reset role;
insert into public.schema_migrations(version,name) values(401,'dc_task_service_catalog');
commit;
