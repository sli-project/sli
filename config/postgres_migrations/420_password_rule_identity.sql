begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_threshold418'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=418 and name='password_threshold_rules')
       or (select max(version) from public.schema_migrations) not in (418,419) then
        raise exception 'password_rule_identity420_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.password_rule_functions_restore420(signature regprocedure primary key,definition text not null);
create table public.password_rule_findings_restore420(
    finding_id bigint primary key, survivor_id bigint, prior_status text not null, prior_reason text,
    prior_closed text, prior_updated timestamptz not null, prior_first text, prior_last text, prior_severity text not null,
    prior_count bigint not null, prior_event bigint, prior_facts jsonb, changed_at timestamptz not null, history_id bigint);
create table public.password_rule_scenarios_restore420(
    scenario_id uuid primary key, partition_key text not null, identity_key bytea not null,
    strict_keys jsonb not null, risk_class text not null);
create table public.password_rule_evidence_restore420(like public.finding_event_copies337 including indexes);
revoke all on public.password_rule_functions_restore420,public.password_rule_findings_restore420,
    public.password_rule_scenarios_restore420,public.password_rule_evidence_restore420 from public;

-- Match the configured DC or its unambiguous registered server. Source
-- admission is still performed by the caller before resolving this domain.
create function public.password_threshold_domain420(s jsonb) returns bigint
language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce(m.password_detection_domain_id,dc.domain_id)
    from public.password_v2_source_binding(s) b
    join public.sli_agent_module_bindings m on m.agent_id=b.agent_id and m.module_id=b.plugin_id
    left join lateral (
        select min(se.domain_id) as domain_id from public.servers se
        where se.is_active and se.role='domain_controller'
          and coalesce(se.id::text=(select details->>'server_id' from public.sli_agent_audit
              where target=m.agent_id::text and action='issue' order by id desc limit 1),
              lower(m.source_name) in (lower(se.hostname),lower(se.fqdn))
              or strpos(m.source_name,'.')=0 and lower(m.source_name)=split_part(lower(coalesce(nullif(se.fqdn,''),se.hostname)),'.',1)
              or strpos(coalesce(nullif(se.fqdn,''),se.hostname),'.')=0 and lower(se.hostname)=split_part(lower(m.source_name),'.',1))
        having count(distinct se.domain_id)=1
    ) dc on true
$$;
revoke all on function public.password_threshold_domain420(jsonb) from public;

-- Leave the immutable evidence and publication authorization in place.
-- Only the password threshold functions acquire a shared per-domain episode.
do $$
declare spec record; original text; rewritten text;
begin
    for spec in select * from (values
        ('public.password_threshold_pass418(jsonb,text,timestamptz)',
         $old$    perform pg_advisory_xact_lock(hashtextextended('password-threshold:'||scope_key418||r,0));$old$,
         $new$    if r='qw.password-brute-force' then
        if public.password_threshold_domain420(s) is null then
            raise exception 'password_threshold_collection_domain_unknown' using errcode='55000';
        end if;
        perform pg_advisory_xact_lock(hashtextextended('password-domain:'||public.password_threshold_domain420(s),0));
    end if;
    perform pg_advisory_xact_lock(hashtextextended('password-threshold:'||scope_key418||r,0));$new$),
        ('public.read_password_threshold_events418(jsonb,text,timestamptz,timestamptz,bigint,timestamptz,bigint)',
         $old$declare b public.finding_evidence_source_bindings;
begin
    perform public.password_threshold_scope418(s,r);
    b:=public.password_v2_source_binding(s);$old$,
         $new$declare b public.finding_evidence_source_bindings; trusted_domain bigint;
begin
    perform public.password_threshold_scope418(s,r);
    b:=public.password_v2_source_binding(s);
    if r='qw.password-brute-force' then trusted_domain:=public.password_threshold_domain420(s); end if;$new$),
        ('public.read_password_threshold_events418(jsonb,text,timestamptz,timestamptz,bigint,timestamptz,bigint)',
         $old$'domain_netbios',left(d.netbios_name,257),'domain_fqdn',left(d.fqdn,257))$old$,
         $new$'domain_id',h.domain_id)$new$),
        ('public.read_password_threshold_events418(jsonb,text,timestamptz,timestamptz,bigint,timestamptz,bigint)',
         $old$from public.event_hot h left join public.domains d on d.id=h.domain_id
    where h.time_created_utc>=p_first$old$,
         $new$from public.event_hot h
    where (r<>'qw.password-brute-force' or h.domain_id=trusted_domain)
      and h.time_created_utc>=p_first$new$),
        ('public.read_password_threshold_episodes418(jsonb,text,timestamptz)',
         $old$where e.scope_key=scope_key418 and e.rule_id=r$old$,
         $new$where e.scope_key=case when r='qw.password-brute-force'
        then 'password-domain:'||public.password_threshold_domain420(s) else scope_key418 end and e.rule_id=r$new$),
        ('public.read_password_threshold_episodes418(jsonb,text,timestamptz)',
         $old$and e.last_at>=p_from and e.password_state418 is not null$old$,
         $new$and (e.last_at>=p_from or r='qw.password-brute-force' and f.status in ('new','confirmed','repeated','active','review'))
      and e.password_state418 is not null$new$),
        ('public.write_password_threshold_pass418(jsonb,text,bigint,text,jsonb)',
         $old$    perform pg_advisory_xact_lock(hashtextextended('password-threshold:'||scope_key418||r,0));
    for item$old$,
         $new$    if r='qw.password-brute-force' then
        perform pg_advisory_xact_lock(hashtextextended('password-domain:'||public.password_threshold_domain420(s),0));
    end if;
    perform pg_advisory_xact_lock(hashtextextended('password-threshold:'||scope_key418||r,0));
    for item$new$),
        ('public.write_password_threshold_pass418(jsonb,text,bigint,text,jsonb)',
         $old$    for item in select value from jsonb_array_elements(p_episodes) loop$old$,
         $new$    for item in select value from jsonb_array_elements(p_episodes) loop
        if r='qw.password-brute-force' and (public.password_threshold_domain420(s) is null
            or item#>>'{facts,domain_id}' is distinct from public.password_threshold_domain420(s)::text) then
            raise exception 'password_threshold_collection_domain_denied' using errcode='42501';
        end if;$new$),
        ('public.write_password_threshold_pass418(jsonb,text,bigint,text,jsonb)',
         $old$        values(scope_key418,r,item->>'entity_key',item->>'episode_key',(item#>>'{facts,last}')::timestamptz,item->'facts')$old$,
         $new$        values(case when r='qw.password-brute-force' then 'password-domain:'||public.password_threshold_domain420(s)
            else scope_key418 end,r,item->>'entity_key',item->>'episode_key',(item#>>'{facts,last}')::timestamptz,item->'facts')$new$),
        ('public.publish_password_threshold_facts418(bigint,uuid)',
         $old$    for ref in select value from jsonb_array_elements(doc->'evidence_refs') loop$old$,
         $new$    if doc->>'rule_id'='qw.password-brute-force' and
       (facts->>'domain_id' is null or (facts->>'domain_id')::bigint is distinct from public.password_threshold_domain420(s)) then
        raise exception 'password_threshold_collection_domain_denied' using errcode='42501';
    end if;
    for ref in select value from jsonb_array_elements(doc->'evidence_refs') loop$new$),
        ('public.publish_password_threshold_facts418(bigint,uuid)',
         $old$    select array_agg(event_id) into keep_ids from ($old$,
         $new$    if doc->>'rule_id'='qw.password-brute-force' and exists (
        select 1 from public.finding_event_copies337 where finding_id=p_finding and evidence_role='semantic_scenario'
        and domain_id is distinct from (facts->>'domain_id')::bigint) then
        raise exception 'password_threshold_evidence_domain_denied' using errcode='42501';
    end if;
    select array_agg(event_id) into keep_ids from ($new$),
        ('public.publish_password_threshold_facts418(bigint,uuid)',
         $old$where e.scope_key=public.password_threshold_scope418(s,doc->>'rule_id') and e.rule_id=doc->>'rule_id'$old$,
         $new$where e.scope_key=case when doc->>'rule_id'='qw.password-brute-force' then 'password-domain:'||(facts->>'domain_id')
          else public.password_threshold_scope418(s,doc->>'rule_id') end and e.rule_id=doc->>'rule_id'$new$),
        ('public.password_queue_presentation399(bigint,text)',
         $old$    return query select c.facts,c.aliases from public.password_queue_projection399 c$old$,
         $new$    return query select public.password_problem_facts395(f.id,p_rule),null::jsonb
    from public.findings f where f.id=p_finding and f.rule_code=p_rule and f.password_threshold_facts418 is not null;
    if found then return; end if;
    return query select c.facts,c.aliases from public.password_queue_projection399 c$new$)
    ) as patches(signature,previous_fragment,next_fragment) loop
        original:=pg_get_functiondef(spec.signature::regprocedure);
        insert into public.password_rule_functions_restore420 values(spec.signature::regprocedure,original) on conflict do nothing;
        rewritten:=replace(original,spec.previous_fragment,spec.next_fragment);
        if rewritten=original then raise exception 'password_rule_identity420_function_shape: %',spec.signature; end if;
        execute rewritten;
    end loop;
end $$;

reset role;

-- Use the retained copy's authorized domain and the published account. One
-- finding with evidence from an ambiguous domain is ineligible for rekeying.
create temporary table password_rule_merge420 on commit drop as
with candidates as (
    select f.id,s.scenario_id,s.strict_keys_json->>'episode' as episode,
        'password-domain:'||e.domain_id as partition,
        encode(sha256(convert_to(e.domain_id::text,'UTF8')||decode('00','hex')||
            convert_to(casefold((f.password_threshold_facts418->>'account') collate pg_catalog.pg_unicode_fast),'UTF8')),'hex') as entity
    from public.findings f
    join public.semantic_security_scenarios s on f.fingerprint='semantic:'||encode(s.scenario_key,'hex')
    cross join lateral (
        select min(c.domain_id) as domain_id from public.finding_event_copies337 c
        where c.finding_id=f.id and c.evidence_role='semantic_scenario' having count(distinct c.domain_id)=1
    ) e
    where f.rule_code='semantic.qw.password-brute-force' and f.status in ('new','confirmed','repeated','active','review')
      and s.scenario_kind='qw.password-brute-force' and s.strict_keys_json->>'kind'='threshold'
      and length(f.password_threshold_facts418->>'account') between 1 and 256
)
select *,min(id) over(partition by partition,entity) as survivor_id from candidates;

insert into public.password_rule_findings_restore420(finding_id,survivor_id,prior_status,prior_reason,prior_closed,prior_updated,
    prior_first,prior_last,prior_severity,prior_count,prior_event,prior_facts,changed_at)
select f.id,m.survivor_id,f.status,f.status_reason,f.closed_at,f.updated_at,f.first_seen_utc,f.last_seen_utc,f.severity,
    f.evidence_count,f.last_evidence_event_id,f.password_threshold_facts418,transaction_timestamp()
from public.findings f join password_rule_merge420 m on m.id=f.id
union all
select f.id,null,f.status,f.status_reason,f.closed_at,f.updated_at,f.first_seen_utc,f.last_seen_utc,f.severity,
    f.evidence_count,f.last_evidence_event_id,f.password_threshold_facts418,transaction_timestamp()
from public.findings f
where f.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
  and f.status in ('new','confirmed','repeated','active','review') and f.password_threshold_facts418 is null
  and f.created_at <= (select applied_at from public.schema_migrations where version=418)
  and exists (
      select 1 from public.semantic_finding_publications p
      join public.semantic_risk_evaluation_jobs j on j.job_id=p.first_job_id
      join public.semantic_qw_signals q on q.signal_id=j.qw_signal_id
      where p.finding_id=f.id and f.rule_code='semantic.'||(q.document_json->>'rule_id')
        and jsonb_typeof(q.document_json->'rule_version')='number'
        and q.document_json->'rule_version'>='2'::jsonb and q.document_json ? 'password_context');

with decisions as (
    select finding_id,prior_status,changed_at,case when survivor_id is null then 'password_rule_replaced420'
        else 'password_rule_merged420:'||survivor_id end as reason
    from public.password_rule_findings_restore420 where survivor_id is distinct from finding_id
), closed as (
    update public.findings f set status='closed',status_reason=d.reason,closed_at=d.changed_at::text,updated_at=d.changed_at
    from decisions d where f.id=d.finding_id
    returning f.id,d.prior_status,d.reason,d.changed_at
), history as (
    insert into public.finding_status_history(finding_id,old_status,new_status,changed_at,changed_by,note)
    select id,prior_status,'closed',changed_at,'SLI',reason from closed returning id,finding_id
)
update public.password_rule_findings_restore420 r set history_id=h.id from history h where h.finding_id=r.finding_id;

insert into public.password_rule_scenarios_restore420
select s.scenario_id,s.partition_key,s.identity_key,s.strict_keys_json,s.risk_class
from public.semantic_security_scenarios s join password_rule_merge420 m on s.scenario_id=m.scenario_id and m.id=m.survivor_id;

insert into public.password_rule_evidence_restore420
select c.* from public.finding_event_copies337 c join password_rule_merge420 m on m.id=m.survivor_id and c.finding_id=m.id
where c.evidence_role='semantic_scenario' and exists (select 1 from password_rule_merge420 d where d.survivor_id=m.id and d.id<>m.id);

-- Keep ten earliest and forty latest distinct references on the surviving
-- finding. Retain every duplicate finding's own evidence and decision history.
create temporary table password_rule_sample420 on commit drop as
with copies as (
    select distinct on (m.survivor_id,c.time_created_utc,c.event_id)
        m.survivor_id,c.time_created_utc,c.event_id,c.event_kind,c.domain_id,c.actor,c.target,c.source,c.computer,
        c.method,c.outcome,c.fields,c.source_sha256,c.evidence_role,c.note,c.event_record_id
    from password_rule_merge420 m join public.finding_event_copies337 c on c.finding_id=m.id
    where c.evidence_role='semantic_scenario'
      and exists (select 1 from password_rule_merge420 d where d.survivor_id=m.survivor_id and d.id<>m.survivor_id)
    order by m.survivor_id,c.time_created_utc,c.event_id,c.finding_id
), numbered as (
    select *,row_number() over(partition by survivor_id order by time_created_utc,event_id) as oldest,
        row_number() over(partition by survivor_id order by time_created_utc desc,event_id desc) as newest from copies
)
select survivor_id,time_created_utc,event_id,event_kind,domain_id,actor,target,source,computer,method,outcome,
    fields,source_sha256,evidence_role,note,event_record_id from numbered where oldest<=10 or newest<=40;

with counts as (
    select m.survivor_id,sum((f.prior_facts->>'attempts')::bigint)::bigint as attempts,
        min((f.prior_facts->>'first')::timestamptz) as first_at,
        max((f.prior_facts->>'last_failure')::timestamptz) as last_failure,
        max((f.prior_facts->>'last')::timestamptz) as last_at,
        bool_or((f.prior_facts->>'password_success')::boolean) as success,
        max((f.prior_facts->>'address_count')::integer) as prior_address_count
    from password_rule_merge420 m join public.password_rule_findings_restore420 f on f.finding_id=m.id group by m.survivor_id
), addresses as (
    select m.survivor_id,count(distinct a.value) as total,
        (array_agg(distinct a.value order by a.value))[1:20] as sample
    from password_rule_merge420 m join public.password_rule_findings_restore420 f on f.finding_id=m.id
    cross join lateral jsonb_array_elements_text(f.prior_facts->'addresses') a group by m.survivor_id
), claims as (
    select m.survivor_id,(array_agg(distinct a.value order by a.value))[1:20] as sample
    from password_rule_merge420 m join public.finding_event_copies337 c on c.finding_id=m.id and c.evidence_role='semantic_scenario'
    cross join lateral (select btrim(coalesce(c.method#>>'{$principals,TargetDomainName}',c.fields->>'TargetDomainName')) as value) a
    where a.value<>'-' and length(a.value) between 1 and 256 and a.value !~ '[[:cntrl:]]'
    group by m.survivor_id
), evidence as (
    select survivor_id,count(distinct event_id) as total,max(event_id) as latest from password_rule_sample420 group by survivor_id
)
update public.findings f set password_threshold_facts418=f.password_threshold_facts418||jsonb_build_object(
        'attempts',totals.attempts,'first',totals.first_at,'last_failure',totals.last_failure,'last',totals.last_at,
        'password_success',totals.success,'domain_id',split_part(m.partition,':',2)::bigint,
        'address_count',greatest(totals.prior_address_count,coalesce(a.total,0)),
        'addresses',coalesce(to_jsonb(a.sample),'[]'::jsonb),'reported_domains',coalesce(to_jsonb(d.sample),'[]'::jsonb)),
    first_seen_utc=totals.first_at::text,last_seen_utc=totals.last_at::text,
    severity=case when totals.success then 'critical' else f.severity end,
    evidence_count=coalesce(e.total,f.evidence_count),last_evidence_event_id=coalesce(e.latest,f.last_evidence_event_id),
    updated_at=transaction_timestamp()
from counts totals join password_rule_merge420 m on m.id=totals.survivor_id
left join addresses a on a.survivor_id=totals.survivor_id left join claims d on d.survivor_id=totals.survivor_id
left join evidence e on e.survivor_id=totals.survivor_id where f.id=totals.survivor_id;

insert into public.finding_event_copies337(finding_id,time_created_utc,event_id,event_kind,domain_id,actor,target,
    source,computer,method,outcome,fields,source_sha256,evidence_role,note,event_record_id)
select * from password_rule_sample420 on conflict do nothing;
delete from public.finding_event_copies337 c
where c.evidence_role='semantic_scenario'
  and exists(select 1 from password_rule_sample420 m where m.survivor_id=c.finding_id)
  and not exists(select 1 from password_rule_sample420 m where (m.survivor_id,m.time_created_utc,m.event_id)=
      (c.finding_id,c.time_created_utc,c.event_id));

-- Reuse the scenario lookup identity. Its scenario key and finding fingerprint
-- remain stable for the immutable publication and the problem's original ID.
update public.semantic_security_scenarios s set partition_key=m.partition,strict_keys_json=strict.keys,
    identity_key=sha256(convert_to(public.password_policy_json_v275(jsonb_build_object(
        'scenario_kind',s.scenario_kind,'result_class',s.result_class,'partition_key',m.partition,
        'strict_keys',strict.keys,'merge_window_seconds',s.merge_window_seconds)),'UTF8')),
    risk_class=f.severity
from password_rule_merge420 m join public.findings f on f.id=m.id
cross join lateral (select jsonb_build_object('kind','threshold','entity',m.entity,'episode',m.episode) as keys) strict
where s.scenario_id=m.scenario_id and m.id=m.survivor_id;

insert into public.semantic_identity_attack_episodes_v301(scope_key,rule_id,entity_key,episode_key,last_at,password_state418,password_finding418)
select m.partition,'qw.password-brute-force',m.entity,m.episode,(f.password_threshold_facts418->>'last')::timestamptz,
    f.password_threshold_facts418,f.id
from password_rule_merge420 m join public.findings f on f.id=m.id and m.id=m.survivor_id;

set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(420,'password_rule_identity');
reset role;
commit;
