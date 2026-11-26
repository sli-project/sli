begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_own_actions421'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=418 and name='password_threshold_rules')
       or exists(select 1 from public.schema_migrations where version>=421) then
        raise exception 'sli_own_actions421_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.sli_maintenance_catalog421(
    event_kind integer not null,
    object_name text not null,
    binary_paths text[] not null default '{}',
    primary key(event_kind,object_name)
);
revoke all on public.sli_maintenance_catalog421 from public;
insert into public.sli_maintenance_catalog421(event_kind,object_name,binary_paths)
select kind,name,array[$path$c:\program files\sli\agentnet\sliagent.exe$path$]
from unnest(array[4697,7045]) kind
cross join unnest(array['sliagentnet','sli agent .net']) name;
insert into public.sli_maintenance_catalog421(event_kind,object_name)
values(4698,$path$\microsoft\windows\updateorchestrator\ac power download$path$);

create function public.sli_catalog_maintenance421(kind integer, channel text, provider text, event_data jsonb)
returns text language sql stable set search_path=pg_catalog,pg_temp as $$
    select case when kind=4698 then 'windows_builtin_task' else 'sli_action' end
    from public.sli_maintenance_catalog421 catalog
    where catalog.event_kind=kind
      and catalog.object_name=lower(btrim(case when kind=4698
          then coalesce(nullif(btrim(event_data->>'TaskName'),''),event_data->>'TaskNamePath')
          else event_data->>'ServiceName' end))
      and case when kind=4698 then channel='Security' and provider='Microsoft-Windows-Security-Auditing'
          and event_data->>'SubjectUserSid'='S-1-5-18'
          and event_data->>'task_command' is null
      else ((kind=4697 and channel='Security' and provider='Microsoft-Windows-Security-Auditing')
          or (kind=7045 and channel='System' and provider='Service Control Manager'))
          and (select exists(select 1 from unnest(catalog.binary_paths) approved_path
                             where lower(btrim(path)) in(approved_path,'"'||approved_path||'"'))
               from (select case when kind=4697 then event_data->>'ServiceFileName'
                   else event_data->>'ImagePath' end as path) command)
      end
$$;
revoke all on function public.sli_catalog_maintenance421(integer,text,text,jsonb) from public;

-- Reuse the authenticated audit report and the event's admitted agent identity.
-- A confirmed enablement can account only for additions of that audit flag.
create function public.sli_audit_apply421(p_event bigint,p_at timestamptz)
returns timestamptz language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select min((item->>'enabled_at')::timestamptz)
    from public.semantic_event_source355 event
    join public.sli_agents agent on agent.id=(event.source_origin->>'agent_id')::uuid
    cross join lateral jsonb_array_elements(agent.windows_audit#>'{families,domain_controller,required}') item
    where event.id=p_event and event.time_created_utc=p_at and event.event_id=4719
      and event.channel='Security' and event.provider_name='Microsoft-Windows-Security-Auditing'
      and event.subject_user_sid='S-1-5-18'
      and item->>'state'='ok'
      and lower(trim(both '{}' from event.event_data_json->>'SubcategoryGuid'))=item->>'guid'
      and event.time_created_utc between (item->>'enabled_at')::timestamptz
          and (item->>'enabled_at')::timestamptz+interval '15 seconds'
      and case btrim(event.event_data_json->>'AuditPolicyChanges')
          when '%%8449' then item->'actual_success'='true'::jsonb
          when '%%8451' then item->'actual_failure'='true'::jsonb
          when '%%8449 %%8451' then item->'actual_success'='true'::jsonb and item->'actual_failure'='true'::jsonb
          when '%%8451 %%8449' then item->'actual_success'='true'::jsonb and item->'actual_failure'='true'::jsonb
          else false end
$$;
revoke all on function public.sli_audit_apply421(bigint,timestamptz) from public;
grant execute on function public.sli_audit_apply421(bigint,timestamptz) to adlog_user,adlog_semantic_worker;

create function public.sli_service_install421(p_event bigint,p_at timestamptz)
returns text language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select event.event_data_json->>'ServiceName'
    from public.semantic_event_source355 event
    where event.id=p_event and event.time_created_utc=p_at and event.event_id in(4697,7045)
      and public.sli_catalog_maintenance421(event.event_id,event.channel,event.provider_name,event.event_data_json)='sli_action'
$$;
revoke all on function public.sli_service_install421(bigint,timestamptz) from public;
grant execute on function public.sli_service_install421(bigint,timestamptz) to adlog_user;

-- Keep the existing policy, origin and host checks. Exclude known maintenance
-- at the same boundary that admits evidence for publication.
create table public.sli_catalog_restore421(definition text not null);
revoke all on public.sli_catalog_restore421 from public;
insert into public.sli_catalog_restore421 values(pg_get_functiondef('public.read_dc_catalog_action401(text,integer,uuid)'::regprocedure));
do $patch$
declare original text; patched text;
begin
    select definition into strict original from public.sli_catalog_restore421;
    patched:=replace(original,'and (select count(*) from public.canonical_action_evidence all_links',
        $body$and public.sli_catalog_maintenance421(source.event_id,source.channel,source.provider_name,source.event_data_json) is null
      and (select count(*) from public.canonical_action_evidence all_links$body$);
    if patched=original then raise exception 'sli_own_actions421_catalog_shape'; end if;
    execute patched;
end $patch$;

-- The kit and peer upgrade both connect as postgres. Restore that role for
-- the status_reason backfill and history write.
reset role;

-- Resolve only findings whose entire retained evidence has one maintenance reason.
with candidates as materialized (
    select finding.id, finding.status, finding.rule_code,
        case when finding.rule_code='semantic.security.dc_scheduled_task_created' then 'windows_builtin_task' else 'sli_action' end as reason
    from public.findings finding
    where finding.status in('new','confirmed','repeated','active','review')
      and finding.rule_code in('semantic.security.dc_service_installed','semantic.security.dc_scheduled_task_created',
                               'semantic.security.audit_controls_changed')
), evidence as (
    select finding.id, finding.status, finding.reason, copy.event_id,
        public.sli_catalog_maintenance421(copy.event_kind,copy.method->>'$channel',
            copy.method->>'$provider',coalesce(copy.method->'$principals','{}'::jsonb)||copy.fields) as observed_reason
    from candidates finding join public.finding_event_copies337 copy on copy.finding_id=finding.id
    where finding.rule_code in('semantic.security.dc_scheduled_task_created','semantic.security.dc_service_installed')
    union
    select finding.id,finding.status,finding.reason,normalized.source_event_id,
        case when public.sli_audit_apply421(normalized.source_event_id,normalized.occurred_at_utc) is not null then 'sli_action' end
    from candidates finding
    join public.semantic_finding_publications publication on publication.finding_id=finding.id
    join public.semantic_scenario_evidence link on link.scenario_id=publication.scenario_id
    join public.normalized_events normalized on normalized.normalized_event_id=link.normalized_event_id
    where finding.rule_code='semantic.security.audit_controls_changed'
), eligible as (
    select evidence.id, evidence.status, evidence.reason, count(distinct evidence.event_id) as confirmed
    from evidence group by evidence.id,evidence.status,evidence.reason
    having bool_and(evidence.observed_reason is not distinct from evidence.reason)
), closed as (
    update public.findings finding
    set status='closed',closed_at=now()::text,updated_at=now(),
        status_reason=case eligible.reason when 'sli_action' then 'Действие SLI' else 'Встроенная задача Windows' end
    from eligible where finding.id=eligible.id and finding.status=eligible.status
      and finding.evidence_count>0 and finding.evidence_count=eligible.confirmed
    returning finding.id,eligible.status as old_status,finding.status_reason
)
insert into public.finding_status_history(finding_id,old_status,new_status,changed_by,note)
select id,old_status,'closed','migration:421',status_reason from closed;

insert into public.schema_migrations(version,name) values(421,'sli_own_actions');
commit;
