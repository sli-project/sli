-- Explicit operator rollback only; never invoked by runtime.
begin;
select pg_advisory_xact_lock(hashtext('sli_attack_precursors_v302'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 302 rollback prerequisites failed';
    end if;
    if not exists(select 1 from public.schema_migrations where version=302 and name='attack_precursors')
       or exists(select 1 from public.schema_migrations where version>302) then
        raise exception 'migration 302 rollback prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

drop function public.read_t109_agent_health(jsonb);
drop function public.read_t109_recent_threats(jsonb);
drop function public.read_t109_native(jsonb,timestamptz,timestamptz);
drop function public.t109_detection_sources();
drop function public.read_t109_policy();
drop function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text);
alter function public.resolve_finding_evidence_ref_before_t109(uuid,text,text,text,text,text,text,text)
    rename to resolve_finding_evidence_ref;
grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)
    to adlog_semantic_worker;
drop table public.semantic_t109_channels;
drop table public.semantic_t109_seen;
drop table public.semantic_t109_episodes;
drop function public.t109_scope_allowed(jsonb,text);

-- Restore the pre-T109 allowlist and core/file evidence admission.
create or replace function public.ensure_default_qw_policy_v262(p_id text,p_version integer,p_document text) returns boolean
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb:=p_document::jsonb; pin jsonb:=d#>'{source_selector,execution}'; s jsonb; digest bytea;
begin
    s:=pin->'scope'; digest:=sha256(convert_to(p_document,'UTF8'));
    if p_version<>1 or octet_length(p_document)>65536 or p_id not like 'default:qw.%'
       or d->>'type' is distinct from 'scenario_policy'
       or d#>>'{source_selector,rule_id}' is distinct from pin->>'rule_id'
       or pin->>'rule_id' not in ('qw.account-decoy','qw.account-watch','qw.file-decoy','qw.file-ransom',
           'qw.nps-denials','qw.password-spray','qw.password-brute-force','qw.disabled-account-logon')
       or public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',
           s->>'source_instance_id',s->>'source_generation',s->>'collection_scope_id',
           case when s->>'plugin_id'='sli.file-audit' then 'file_audit_observation' else 'core_event' end) is not true then
        raise exception 'default_detection_policy_denied' using errcode='42501';
    end if;
    -- A prior decision for this exact execution wins, even under a custom ID.
    if exists(select 1 from public.semantic_risk_policies p
        left join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='qw_signal' and p.definition_json#>'{source_selector,execution}'=pin
          and (a.enabled is false or p.lifecycle_status in ('disabled','deprecated'))) then
        return false;
    end if;
    insert into public.semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
    values(p_id,p_version,'qw_signal','draft',d,digest) on conflict do nothing;
    perform 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version
        and definition_sha256=digest and definition_json=d for update;
    if not found then raise exception 'default_detection_policy_conflict'; end if;
    insert into public.semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256)
    select p_id,p_version,'qw_signal',pin->>'rule_id',digest
    where not exists(select 1 from public.semantic_risk_policy_subscriptions where policy_id=p_id and policy_version=p_version);
    update public.semantic_risk_policies set lifecycle_status='shadow',updated_at=now()
        where policy_id=p_id and policy_version=p_version and lifecycle_status='draft';
    insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
    select p_id,p_version,true,'system:defaults' where exists(
        select 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version
          and lifecycle_status in ('shadow','enabled'))
    on conflict(policy_id,policy_version) do nothing;
    return exists(select 1 from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.policy_id=p_id and p.policy_version=p_version and a.enabled
          and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled');
end $$;
revoke all on function public.ensure_default_qw_policy_v262(text,integer,text) from public,adlog_semantic_worker;

delete from public.schema_migrations where version=302 and name='attack_precursors';
commit;
