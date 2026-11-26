begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_threshold418'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=417 and name='password_frozen_frontier_progress')
       or exists(select 1 from public.schema_migrations where version>=418) then
        raise exception 'password_threshold418_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.semantic_identity_attack_episodes_v301
    add column password_state418 jsonb,
    add column password_finding418 bigint;
reset role;
alter table public.findings add column password_threshold_facts418 jsonb;
grant select(password_threshold_facts418,closed_at),update(password_threshold_facts418) on public.findings to adlog_storage_owner;
set local role adlog_storage_owner;

-- Reserve the all-zero entity and episode keys for the source scan cursor.
-- Actual episode keys remain scoped like the other identity thresholds.
create function public.password_threshold_scope418(s jsonb,r text) returns text
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare binding public.finding_evidence_source_bindings;
begin
    if r is null or r not in ('qw.password-brute-force','qw.password-spray') then
        raise exception 'password_threshold_rule_invalid' using errcode='22023';
    end if;
    binding:=public.password_v2_source_binding(s);
    if public.semantic_source_active320(binding.agent_id,'sli.windows.ad-dc','Security') is not true then
        raise exception 'password_threshold_source_denied' using errcode='42501';
    end if;
    return encode(sha256(convert_to(s::text,'UTF8')),'hex');
end $$;

create function public.admit_password_threshold418(p_id text,p_document text) returns boolean
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb; pin jsonb; decision text; stored record;
begin
    if p_document is null or octet_length(p_document)>65536 then
        raise exception 'password_threshold_policy_invalid' using errcode='22023';
    end if;
    d:=p_document::jsonb; pin:=d#>'{source_selector,execution}';
    perform public.password_threshold_scope418(pin->'scope',pin->>'rule_id');
    if pin->>'kind' is distinct from 'threshold' or pin->>'rule_version' is distinct from '1'
       or d->>'scenario_kind' is distinct from pin->>'rule_id' or d->>'merge_window_seconds' is distinct from '1800'
       or d#>>'{risk,class}' is distinct from 'high' or p_document is distinct from public.password_policy_json_v275(d) then
        raise exception 'password_threshold_policy_invalid' using errcode='22023';
    end if;
    perform public.password_policy_family_lock_v275(pin->'scope',pin->>'rule_id');
    decision:=public.password_policy_decision_v275(pin);
    if decision='disabled' then return false; end if;
    if decision='unknown' then raise exception 'password_policy_unconfirmed' using errcode='55000'; end if;
    if public.ensure_default_qw_policy(p_id,1,p_document) is not true then return false; end if;
    for stored in select p.policy_id,p.policy_version from public.semantic_risk_policies p
        join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='qw_signal' and p.policy_version=1 and p.definition_json=d
          and a.enabled and a.updated_by='system:defaults' and not exists (
              select 1 from public.semantic_control_audit c where c.target=p.policy_id||':'||p.policy_version
                and c.action='password_policy_managed') loop
        perform public.password_policy_provenance_v275(stored.policy_id,stored.policy_version,'seed');
    end loop;
    return true;
end $$;

create function public.password_threshold_pass418(s jsonb,r text,t timestamptz)
returns table(cursor_id bigint,end_id bigint,first_at timestamptz)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare scope_key418 text:=public.password_threshold_scope418(s,r); zero_key constant text:=repeat('0',64);
    b public.finding_evidence_source_bindings:=public.password_v2_source_binding(s);
begin
    perform pg_advisory_xact_lock(hashtextextended('password-threshold:'||scope_key418||r,0));
    select (e.password_state418->>'cursor')::bigint into cursor_id
      from public.semantic_identity_attack_episodes_v301 e
      where e.scope_key=scope_key418 and e.rule_id=r and e.entity_key=zero_key and e.episode_key=zero_key;
    -- The native AD writer serializes ID allocation and publication under
    -- its plugin lock. Capture a committed endpoint and read only through it.
    select coalesce(max(h.event_id),coalesce(cursor_id,0)),min(h.time_created_utc)
      into end_id,first_at from public.event_hot h
      where h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
        and (h.method->'$origin')-'agent_id'-'log_source_id'=s and h.source_sha256 is not null
        and h.method#>>'{$origin,agent_id}'=b.agent_id::text and h.method#>>'{$origin,log_source_id}'=b.log_source_id::text
        and h.method->>'$channel'='Security' and h.event_kind in (4624,4625,4776)
        and h.event_id>coalesce(cursor_id,0)
        and h.time_created_utc<=t and h.time_created_utc>=coalesce(
            case when cursor_id>0 then '-infinity'::timestamptz end,t-interval '10 minutes');
    cursor_id:=coalesce(cursor_id,0);
    return next;
end $$;

create function public.read_password_threshold_events418(s jsonb,r text,p_first timestamptz,p_after timestamptz,p_id bigint,
    p_end timestamptz,p_end_id bigint)
returns table(native_id bigint,event_id integer,occurred_at_utc timestamptz,sha256 text,fields jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings;
begin
    perform public.password_threshold_scope418(s,r);
    b:=public.password_v2_source_binding(s);
    return query select h.event_id,h.event_kind,h.time_created_utc,encode(h.source_sha256,'hex'),
        jsonb_build_object('TargetUserName',left(coalesce(h.method#>>'{$principals,TargetUserName}',h.fields->>'TargetUserName'),257),
            'TargetDomainName',left(coalesce(h.method#>>'{$principals,TargetDomainName}',h.fields->>'TargetDomainName'),257),
            'IpAddress',left(coalesce(h.method#>>'{$principals,IpAddress}',h.fields->>'IpAddress'),129),
            'Status',left(coalesce(h.outcome->>'Status',h.fields->>'Status',h.method->>'Status'),32),
            'SubStatus',left(coalesce(h.outcome->>'SubStatus',h.fields->>'SubStatus',h.method->>'SubStatus'),32),
            'LogonType',left(coalesce(h.method->>'LogonType',h.fields->>'LogonType'),8),
            'domain_netbios',left(d.netbios_name,257),'domain_fqdn',left(d.fqdn,257))
    from public.event_hot h left join public.domains d on d.id=h.domain_id
    where h.time_created_utc>=p_first and h.time_created_utc<=p_end and h.event_id<=p_end_id
      and (h.time_created_utc,h.event_id)>(p_after,p_id)
      and h.event_kind in (4624,4625,4776) and h.source_sha256 is not null and h.method->>'$channel'='Security'
      and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
      and (h.method->'$origin')-'agent_id'-'log_source_id'=s
      and h.method#>>'{$origin,agent_id}'=b.agent_id::text
      and h.method#>>'{$origin,log_source_id}'=b.log_source_id::text
    order by h.time_created_utc,h.event_id limit 4000;
end $$;

create function public.read_password_threshold_episodes418(s jsonb,r text,p_from timestamptz)
returns table(entity_key text,episode_key text,facts jsonb,closed_at timestamptz)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare scope_key418 text:=public.password_threshold_scope418(s,r);
begin
    return query select distinct on(e.entity_key) e.entity_key,e.episode_key,e.password_state418,
        case when f.status in ('closed','false_positive') then coalesce(f.closed_at::timestamptz,e.last_at) end
    from public.semantic_identity_attack_episodes_v301 e
    left join public.findings f on f.id=e.password_finding418
    where e.scope_key=scope_key418 and e.rule_id=r and e.entity_key<>repeat('0',64)
      and e.last_at>=p_from and e.password_state418 is not null
    order by e.entity_key,e.last_at desc,e.episode_key;
end $$;

create function public.write_password_threshold_pass418(s jsonb,r text,p_cursor bigint,p_state text,p_episodes jsonb)
returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare scope_key418 text:=public.password_threshold_scope418(s,r); zero_key constant text:=repeat('0',64); item jsonb;
begin
    if p_cursor is null or p_cursor<0 or p_state is null or p_state not in ('current','failed','disabled')
       or jsonb_typeof(p_episodes) is distinct from 'array' then
        raise exception 'password_threshold_pass_invalid' using errcode='22023';
    end if;
    perform pg_advisory_xact_lock(hashtextextended('password-threshold:'||scope_key418||r,0));
    for item in select value from jsonb_array_elements(p_episodes) loop
        if item->>'entity_key' !~ '^[a-f0-9]{64}$' or item->>'episode_key' !~ '^[a-f0-9]{64}$'
           or item->>'entity_key'=zero_key or item->>'episode_key'=zero_key or jsonb_typeof(item->'facts')<>'object' then
            raise exception 'password_threshold_episode_invalid' using errcode='22023';
        end if;
        insert into public.semantic_identity_attack_episodes_v301 as e(scope_key,rule_id,entity_key,episode_key,last_at,password_state418)
        values(scope_key418,r,item->>'entity_key',item->>'episode_key',(item#>>'{facts,last}')::timestamptz,item->'facts')
        on conflict on constraint semantic_identity_attack_episodes_v301_pkey do update
            set last_at=excluded.last_at,password_state418=excluded.password_state418;
    end loop;
    insert into public.semantic_identity_attack_episodes_v301 as e(scope_key,rule_id,entity_key,episode_key,last_at,password_state418)
    values(scope_key418,r,zero_key,zero_key,clock_timestamp(),jsonb_build_object('cursor',p_cursor,'state',p_state))
    on conflict on constraint semantic_identity_attack_episodes_v301_pkey do update
      set last_at=excluded.last_at,password_state418=jsonb_build_object('state',p_state,
        'cursor',case when p_state='current' then greatest((e.password_state418->>'cursor')::bigint,p_cursor)
                      else (e.password_state418->>'cursor')::bigint end);
end $$;

create function public.read_password_threshold_status418(allowed_domains bigint[])
returns table(rule_id text,state text,observed_at timestamptz)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    with rules(rule_id) as (values ('qw.password-brute-force'::text),('qw.password-spray'::text)),
    scopes as materialized (
        select distinct encode(sha256(convert_to(jsonb_build_object('installation_id',b.installation_id::text,
            'plugin_id',b.plugin_id,'source_instance_id',b.source_instance_id,'source_generation',b.source_generation,
            'collection_scope_id',b.collection_scope_id)::text,'UTF8')),'hex') as key
        from public.finding_evidence_source_bindings b
        join public.sli_agent_module_bindings m on m.agent_id=b.agent_id and m.module_id=b.plugin_id
        where b.plugin_id='sli.windows.ad-dc' and b.storage_kind='core_event' and b.collection_scope_id=''
          and (m.password_detection_domain_id=any(allowed_domains) or m.password_detection_domain_id is null and exists (
              select 1 from public.servers se where lower(se.hostname)=lower(m.source_name)
                and se.is_active and se.domain_id=any(allowed_domains)))
          and public.semantic_source_active320(b.agent_id,b.plugin_id,'Security')
    )
    select r.rule_id,coalesce(p.password_state418->>'state','unknown'),p.last_at
    from rules r left join lateral (
        select e.password_state418,e.last_at from public.semantic_identity_attack_episodes_v301 e
        join scopes s on s.key=e.scope_key
        where e.rule_id=r.rule_id and e.entity_key=repeat('0',64) and e.episode_key=repeat('0',64)
        order by (e.password_state418->>'state'='failed') desc,e.last_at desc limit 1
    ) p on true
$$;

-- The ordinary reference ledger is immutable. The bounded password sample
-- uses the existing finding copies, after the same scoped QW authorization.
create function public.publish_password_threshold_facts418(p_finding bigint,p_job uuid)
returns jsonb language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare doc jsonb; facts jsonb; s jsonb; current_facts jsonb; ref jsonb; keep_ids bigint[];
begin
    select q.document_json into strict doc from public.semantic_risk_evaluation_jobs j
    join public.semantic_risk_evaluation_results result on result.job_id=j.job_id
    join public.semantic_security_scenarios scenario on scenario.scenario_id=result.scenario_id
    join public.semantic_qw_signals q on q.signal_id=j.qw_signal_id
    join public.semantic_risk_policies p on (p.policy_id,p.policy_version)=(j.policy_id,j.policy_version)
    join public.semantic_policy_admission a on (a.policy_id,a.policy_version)=(j.policy_id,j.policy_version)
    join public.findings f on f.id=p_finding and f.fingerprint='semantic:'||encode(scenario.scenario_key,'hex')
    where j.job_id=p_job and result.evaluation_mode='enabled' and result.conclusion_state='observed'
      and f.rule_code='semantic.'||(q.document_json->>'rule_id') and a.enabled
      and scenario.strict_keys_json->>'entity'=q.document_json->>'entity_key'
      and scenario.strict_keys_json->>'episode'=q.document_json->>'episode_key'
      and p.definition_json#>'{source_selector,execution,scope}'=q.document_json#>'{evidence_refs,0,scope}'
      and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled'
      and f.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray');
    facts:=doc#>'{password_threshold_context,facts}'; s:=doc#>'{evidence_refs,0,scope}';
    if facts is null or jsonb_array_length(doc->'evidence_refs') not between 1 and 50
       or public.qw_signal_evidence_allowed(doc,true) is not true then
        raise exception 'password_threshold_evidence_denied' using errcode='42501';
    end if;
    for ref in select value from jsonb_array_elements(doc->'evidence_refs') loop
        perform public.copy_finding_event337(p_finding,ref->>'native_id',ref->>'sha256','semantic_scenario','enabled semantic scenario evidence');
    end loop;
    select array_agg(event_id) into keep_ids from (
        (select c.event_id from public.finding_event_copies337 c
         where c.finding_id=p_finding and c.evidence_role='semantic_scenario'
         order by c.time_created_utc,c.event_id limit 10)
        union
        (select c.event_id from public.finding_event_copies337 c
         where c.finding_id=p_finding and c.evidence_role='semantic_scenario'
         order by c.time_created_utc desc,c.event_id desc limit 40)
    ) retained;
    delete from public.finding_event_copies337 c where c.finding_id=p_finding and c.evidence_role='semantic_scenario'
      and not (c.event_id=any(keep_ids));
    select f.password_threshold_facts418 into current_facts from public.findings f where f.id=p_finding for update;
    if current_facts is null or ((facts->>'last')::timestamptz,(facts->>'attempts')::bigint, (facts->>'password_success')::boolean)
        >= ((current_facts->>'last')::timestamptz,(current_facts->>'attempts')::bigint,(current_facts->>'password_success')::boolean) then
        update public.findings set password_threshold_facts418=facts where id=p_finding;
        current_facts:=facts;
    end if;
    update public.semantic_identity_attack_episodes_v301 e set password_finding418=p_finding
      where e.scope_key=public.password_threshold_scope418(s,doc->>'rule_id') and e.rule_id=doc->>'rule_id'
        and e.entity_key=doc->>'entity_key' and e.episode_key=doc->>'episode_key';
    return current_facts;
end $$;

alter function public.password_problem_facts395(bigint,text) rename to password_problem_facts_before418;
create function public.password_problem_facts395(p_finding bigint,p_rule text) returns jsonb
language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce((select f.password_threshold_facts418||jsonb_build_object('count',
        case when p_rule='semantic.qw.password-spray' then f.password_threshold_facts418->'account_count'
             else f.password_threshold_facts418->'attempts' end,
        'cohort_key',encode(sha256(convert_to(f.fingerprint,'UTF8')),'hex'))
        from public.findings f where f.id=p_finding and f.rule_code=p_rule),
        public.password_problem_facts_before418(p_finding,p_rule))
$$;

revoke all on function public.password_threshold_scope418(jsonb,text),
    public.admit_password_threshold418(text,text),
    public.password_threshold_pass418(jsonb,text,timestamptz),
    public.read_password_threshold_events418(jsonb,text,timestamptz,timestamptz,bigint,timestamptz,bigint),
    public.read_password_threshold_episodes418(jsonb,text,timestamptz),
    public.write_password_threshold_pass418(jsonb,text,bigint,text,jsonb),
    public.publish_password_threshold_facts418(bigint,uuid),public.read_password_threshold_status418(bigint[]),
    public.password_problem_facts395(bigint,text) from public;
grant execute on function public.password_threshold_pass418(jsonb,text,timestamptz),
    public.admit_password_threshold418(text,text),
    public.read_password_threshold_events418(jsonb,text,timestamptz,timestamptz,bigint,timestamptz,bigint),
    public.read_password_threshold_episodes418(jsonb,text,timestamptz),
    public.write_password_threshold_pass418(jsonb,text,bigint,text,jsonb),
    public.publish_password_threshold_facts418(bigint,uuid) to adlog_semantic_worker;
grant execute on function public.read_password_threshold_status418(bigint[]),public.password_problem_facts395(bigint,text) to adlog_user;

insert into public.schema_migrations(version,name) values(418,'password_threshold_rules');
reset role;
commit;
