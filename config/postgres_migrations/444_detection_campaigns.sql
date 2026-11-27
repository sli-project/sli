begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_detection_campaigns444'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=426 and name='semantic_outbox_retention')
       or exists(select 1 from public.schema_migrations where version>=444) then
        raise exception 'detection_campaigns444_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.problem_campaigns444(
    finding_id bigint primary key references public.findings(id) on delete cascade,
    group_key text not null,
    first_at timestamptz not null,
    last_failure timestamptz not null,
    quiet_seconds integer check(quiet_seconds between 2 and 1200)
);
create index problem_campaigns_group444 on public.problem_campaigns444(group_key,last_failure desc);

-- Keep one cumulative snapshot per producer episode. Publication and risk
-- history still reference the original, immutable scenarios.
create table public.problem_campaign_sources444(
    scenario_id uuid primary key references public.semantic_security_scenarios(scenario_id) on delete cascade,
    finding_id bigint not null references public.problem_campaigns444(finding_id) on delete cascade,
    facts jsonb
);
create index problem_campaign_sources_finding444 on public.problem_campaign_sources444(finding_id);

create table public.problem_campaign_functions_restore444(signature regprocedure primary key,definition text not null);
create table public.problem_campaign_findings_restore444(
    finding_id bigint primary key,survivor_id bigint not null,status text not null,reason text,closed text,
    first_seen text,last_seen text,severity text not null,facts jsonb,updated timestamptz not null,
    changed_at timestamptz not null,history_id bigint
);
create table public.problem_campaign_episodes_restore444(
    scope_key text,rule_id text,entity_key text,episode_key text,prior_finding bigint,survivor_id bigint,
    primary key(scope_key,rule_id,entity_key,episode_key)
);
revoke all on public.problem_campaigns444,public.problem_campaign_sources444,
    public.problem_campaign_functions_restore444,public.problem_campaign_findings_restore444,
    public.problem_campaign_episodes_restore444 from public;

create function public.audit_campaign_key444(method jsonb,fields jsonb) returns text
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select 'audit:'||(method->>'$server_id')||':'||case
        when btrim(fields->>'SubcategoryGuid','{} ') ~* '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
            then lower(btrim(fields->>'SubcategoryGuid','{} '))
        when fields->>'SubcategoryId' ~ '^%%[0-9]{1,8}$' then fields->>'SubcategoryId'
    end
    where method->>'$server_id' ~ '^[1-9][0-9]{0,18}$'
$$;

create function public.password_campaign_key444(rule text,domain bigint,facts jsonb) returns text
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select case rule when 'qw.password-spray' then 'spray:'||domain
        when 'qw.password-brute-force' then 'brute:'||domain||':'||
            encode(sha256(convert_to(casefold((facts->>'account') collate pg_catalog.pg_unicode_fast),'UTF8')),'hex')
    end
    where domain>0 and facts is not null
$$;

create function public.password_campaign_facts444(p_finding bigint,p_spray boolean) returns jsonb
language sql stable set search_path=pg_catalog,pg_temp as $$
    with parts as materialized (
        select facts from public.problem_campaign_sources444 where finding_id=p_finding and facts is not null
    ), accounts as (
        select min(value) as label from parts,
            jsonb_array_elements_text(coalesce(facts->'account_members',facts->'accounts','[]')) a(value)
        group by casefold(value collate pg_catalog.pg_unicode_fast)
    ), addresses as (
        select distinct address from parts cross join lateral
            jsonb_array_elements_text(case when p_spray then jsonb_build_array(facts->>'source')
                else coalesce(facts->'address_members',facts->'addresses','[]') end) a(address)
        where address is not null
    ), totals as (
        select sum((facts->>'attempts')::bigint)::bigint as attempts,
            min((facts->>'first')::timestamptz) as first_at,max((facts->>'last')::timestamptz) as last_at,
            max((facts->>'last_failure')::timestamptz) as last_failure,
            bool_or((facts->>'password_success')::boolean) as success,
            max((facts->>'account_count')::bigint) as prior_accounts,
            max((facts->>'address_count')::bigint) as prior_addresses
        from parts
    )
    select jsonb_strip_nulls(jsonb_build_object(
        'version',1,'campaign',true,'attempts',attempts,'first',first_at,'last',last_at,'last_failure',last_failure,
        'password_success',success,
        'account',(select facts->>'account' from parts order by (facts->>'first')::timestamptz,facts->>'account' limit 1),
        'source',case when p_spray and (select count(*) from addresses)=1 then (select min(address) from addresses) end,
        'account_count',case when p_spray then greatest(prior_accounts,(select count(*) from accounts)) else 1 end,
        'address_count',greatest(prior_addresses,(select count(*) from addresses)),
        'accounts',(select jsonb_agg(label order by label) from (select label from accounts order by label limit 20) sample),
        'addresses',(select jsonb_agg(address order by address) from (select address from addresses order by address limit 20) sample),
        'reported_domains',(select jsonb_agg(value order by value) from (
            select distinct value from parts,jsonb_array_elements_text(coalesce(facts->'reported_domains','[]')) d(value)
            order by value limit 20) claims)
    ))
    from totals where attempts is not null
$$;

create function public.close_quiet_password_campaigns444(p_key text,p_at timestamptz) returns integer
language sql set search_path=pg_catalog,pg_temp as $$
    with gaps as (
        select f.id,f.status,c.last_failure+c.quiet_seconds*interval '1 second' as ended
        from public.problem_campaigns444 c join public.findings f on f.id=c.finding_id
        where c.group_key=p_key and f.status in ('new','confirmed','repeated','active','review')
          and c.last_failure+c.quiet_seconds*interval '1 second'<=p_at
        for update of f
    ), closed as (
        update public.findings f set status='closed',closed_at=g.ended,updated_at=clock_timestamp()
        from gaps g where f.id=g.id returning f.id,g.status
    ), decisions as (
        insert into public.finding_status_history(finding_id,old_status,new_status,changed_by,note)
        select id,status,'closed','semantic-worker','password_campaign_quiet444' from closed returning 1
    )
    select count(*)::integer from decisions
$$;

create function public.expire_password_campaigns444() returns integer
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare candidate text; expired integer:=0; cutoff timestamptz:=statement_timestamp();
begin
    -- A delayed risk job may carry a contribution that keeps a campaign open.
    if exists (
        select 1 from public.semantic_risk_evaluation_jobs j
        where j.policy_id like 'default:qw.password-spray:%'
          and (j.evaluation_status in ('queued','leased') or j.evaluation_status='failed' and j.attempt_count<j.max_attempts)
    ) then return 0; end if;
    for candidate in
        select distinct c.group_key from public.problem_campaigns444 c join public.findings f on f.id=c.finding_id
        where c.last_failure+c.quiet_seconds*interval '1 second'<=cutoff
          and f.status in ('new','confirmed','repeated','active','review')
        order by c.group_key
    loop
        if pg_try_advisory_xact_lock(hashtextextended('problem-campaign:'||candidate,0)) then
            expired:=expired+public.close_quiet_password_campaigns444(candidate,cutoff);
        end if;
    end loop;
    return expired;
end $$;

-- Select the canonical finding only after the worker has persisted an
-- admitted, observed risk result. Never use reported domain or host labels.
create function public.problem_campaign_route444(p_job uuid,p_finding bigint default null) returns text
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare doc jsonb; proof jsonb; facts jsonb; rule text; candidate text; key text; sid uuid;
    observed_first timestamptz; observed_last timestamptz; quiet integer; selected bigint; replay bigint; domain bigint;
    new_source boolean:=false;
begin
    select q.document_json,s.scenario_id,'semantic:'||encode(s.scenario_key,'hex')
    into doc,sid,candidate
    from public.semantic_risk_evaluation_jobs j
    join public.semantic_risk_evaluation_results r using(job_id)
    join public.semantic_security_scenarios s using(scenario_id)
    join public.semantic_qw_signals q on q.signal_id=j.qw_signal_id
    join public.semantic_risk_policies p using(policy_id,policy_version)
    join public.semantic_policy_admission a using(policy_id,policy_version)
    where j.job_id=p_job and r.evaluation_mode='enabled' and r.conclusion_state='observed'
      and s.evidence_state='ready' and s.scenario_kind=q.document_json->>'rule_id'
      and a.enabled and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled';
    if not found then return null; end if;
    rule:=doc->>'rule_id';
    if p_finding is null then
        select f.fingerprint,c.group_key into candidate,key
        from public.problem_campaign_sources444 source
        join public.problem_campaigns444 c using(finding_id) join public.findings f on f.id=c.finding_id
        where source.scenario_id=sid;
        if found then
            perform pg_advisory_xact_lock(hashtextextended('problem-campaign:'||key,0));
            return candidate;
        end if;
    end if;
    if p_finding is not null and public.qw_signal_evidence_allowed(doc,true) is not true then
        raise exception 'problem_campaign_evidence_denied' using errcode='42501';
    end if;
    proof:=doc#>'{evidence_refs,0}';
    if proof->>'storage_kind' is distinct from 'core_event'
       or proof#>>'{scope,plugin_id}' is distinct from 'sli.windows.ad-dc' then return null; end if;
    if rule='qw.audit-disabled' then
        observed_first:=(doc->>'occurred_at_utc')::timestamptz;
        observed_last:=observed_first;
        select public.audit_campaign_key444(h.method,h.fields) into key
        from public.event_hot h
        where h.event_id=(proof->>'native_id')::bigint and h.time_created_utc=observed_first
          and h.source_sha256=decode(proof->>'sha256','hex') and h.event_kind=4719;
    elsif rule in ('qw.password-spray','qw.password-brute-force') then
        facts:=doc#>'{password_threshold_context,facts}';
        if facts is null then return null; end if;
        observed_first:=(facts->>'first')::timestamptz;
        observed_last:=(facts->>'last_failure')::timestamptz;
        domain:=public.password_threshold_domain420(proof->'scope');
        key:=public.password_campaign_key444(rule,domain,facts);
        if rule='qw.password-spray' then
            quiet:=2*(doc#>>'{password_threshold_context,policy,window_seconds}')::integer;
            if quiet not between 2 and 1200 or not exists (
                select 1 from public.event_hot h where h.event_id=(proof->>'native_id')::bigint
                  and h.time_created_utc between observed_first and (facts->>'last')::timestamptz
                  and h.source_sha256=decode(proof->>'sha256','hex') and h.domain_id=domain
            ) then return null; end if;
        end if;
    end if;
    if key is null then return null; end if;
    perform pg_advisory_xact_lock(hashtextextended('problem-campaign:'||key,0));

    select c.finding_id,f.fingerprint into selected,candidate
    from public.problem_campaign_sources444 source
    join public.problem_campaigns444 c using(finding_id)
    join public.findings f on f.id=c.finding_id
    where source.scenario_id=sid and c.group_key=key;
    if not found then
        new_source:=true;
        select p.finding_id into replay from public.semantic_finding_publications p where p.scenario_id=sid;
        if replay is not null then return null; end if;
        select c.finding_id,f.fingerprint into selected,candidate
        from public.problem_campaigns444 c join public.findings f on f.id=c.finding_id
        where c.group_key=key and f.status in ('new','confirmed','repeated','active','review')
          and (quiet is null or (observed_first<c.last_failure+c.quiet_seconds*interval '1 second'
                              and observed_last>c.first_at-quiet*interval '1 second'))
        order by c.last_failure desc,c.finding_id limit 1 for update of f;
        if not found then
            select 'semantic:'||encode(s.scenario_key,'hex') into candidate
            from public.semantic_security_scenarios s where s.scenario_id=sid;
        end if;
    end if;

    if p_finding is not null then
        if (selected is not null and selected<>p_finding) or not exists(
            select 1 from public.findings f where f.id=p_finding and f.fingerprint=candidate and f.rule_code='semantic.'||rule
        ) then raise exception 'problem_campaign_publication_conflict'; end if;
        if new_source and quiet is not null then
            perform public.close_quiet_password_campaigns444(key,observed_first);
        end if;
        insert into public.problem_campaigns444 as c values(p_finding,key,observed_first,observed_last,quiet)
        on conflict(finding_id) do update set first_at=least(c.first_at,excluded.first_at),
            last_failure=greatest(c.last_failure,excluded.last_failure);
        insert into public.problem_campaign_sources444 as s values(sid,p_finding,facts)
        on conflict(scenario_id) do update set facts=excluded.facts
        where s.finding_id=excluded.finding_id and (
            (excluded.facts->>'last')::timestamptz,(excluded.facts->>'attempts')::bigint,
            (excluded.facts->>'password_success')::boolean
        )>=(
            (s.facts->>'last')::timestamptz,(s.facts->>'attempts')::bigint,(s.facts->>'password_success')::boolean
        );
    end if;
    return candidate;
end $$;

revoke all on function public.audit_campaign_key444(jsonb,jsonb),
    public.password_campaign_key444(text,bigint,jsonb),public.password_campaign_facts444(bigint,boolean),
    public.close_quiet_password_campaigns444(text,timestamptz),public.expire_password_campaigns444(),
    public.problem_campaign_route444(uuid,bigint) from public;
grant execute on function public.problem_campaign_route444(uuid,bigint),public.expire_password_campaigns444() to adlog_semantic_worker;

do $$
declare signature constant regprocedure:='public.publish_password_threshold_facts418(bigint,uuid)'::regprocedure;
    original text; patched text;
begin
    original:=pg_get_functiondef(signature);
    insert into public.problem_campaign_functions_restore444 values(signature,original);
    patched:=replace(original,$old$join public.findings f on f.id=p_finding and f.fingerprint='semantic:'||encode(scenario.scenario_key,'hex')$old$,
        $new$join public.findings f on f.id=p_finding and (f.fingerprint='semantic:'||encode(scenario.scenario_key,'hex')
        or exists(select 1 from public.problem_campaign_sources444 c where c.scenario_id=scenario.scenario_id and c.finding_id=f.id))$new$);
    if patched=original then raise exception 'detection_campaigns444_authorization_shape'; end if;
    original:=patched;
    patched:=replace(original,$old$keep_ids bigint[];
begin$old$,$new$keep_ids bigint[]; routed text; evidence_domain bigint;
begin
    routed:=public.problem_campaign_route444(p_job,p_finding);$new$);
    if patched=original then raise exception 'detection_campaigns444_route_shape'; end if;
    original:=patched;
    -- The writing route already proves the same QW evidence. Keep the
    -- existing verification for all publications outside that route.
    patched:=replace(original,$old$or public.qw_signal_evidence_allowed(doc,true) is not true then$old$,
        $new$or (routed is null and public.qw_signal_evidence_allowed(doc,true) is not true) then$new$);
    if patched=original then raise exception 'detection_campaigns444_verification_shape'; end if;
    original:=patched;
    patched:=replace(original,$old$    if doc->>'rule_id'='qw.password-brute-force' and exists (
        select 1 from public.finding_event_copies337 where finding_id=p_finding and evidence_role='semantic_scenario'
        and domain_id is distinct from (facts->>'domain_id')::bigint) then$old$,
        $new$    evidence_domain:=case when doc->>'rule_id'='qw.password-brute-force' then (facts->>'domain_id')::bigint
        when routed is not null then public.password_threshold_domain420(s) end;
    if evidence_domain is not null and exists (
        select 1 from public.finding_event_copies337 where finding_id=p_finding and evidence_role='semantic_scenario'
        and domain_id is distinct from evidence_domain) then$new$);
    if patched=original then raise exception 'detection_campaigns444_domain_shape'; end if;
    original:=patched;
    patched:=replace(original,$old$    if current_facts is null or ((facts->>'last')::timestamptz,(facts->>'attempts')::bigint, (facts->>'password_success')::boolean)$old$,
        $new$    if routed is not null then
        current_facts:=public.password_campaign_facts444(p_finding,doc->>'rule_id'='qw.password-spray');
        update public.findings set password_threshold_facts418=current_facts where id=p_finding;
    elsif current_facts is null or ((facts->>'last')::timestamptz,(facts->>'attempts')::bigint, (facts->>'password_success')::boolean)$new$);
    if patched=original then raise exception 'detection_campaigns444_facts_shape'; end if;
    execute patched;
end $$;

insert into public.problem_campaign_functions_restore444
select 'public.home_published_findings424(bigint[])'::regprocedure,
    pg_get_functiondef('public.home_published_findings424(bigint[])'::regprocedure);
create or replace function public.home_published_findings424(p_ids bigint[]) returns table(finding_id bigint)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select distinct p.finding_id from public.semantic_finding_publications p where p.finding_id=any(p_ids)
$$;

-- The bootstrap role owns the backfill. Native databases revoke TEMP from PUBLIC.
reset role;

-- Historical findings have retained, scoped evidence even after the hot
-- event expires. Require a single proven grouping key for each finding.
create temporary table problem_campaign_merge444 on commit drop as
with open_findings as (
    select f.*,replace(f.rule_code,'semantic.','') as rule
    from public.findings f
    where f.status in ('new','confirmed','repeated','active','review')
      and f.rule_code in ('semantic.qw.password-spray','semantic.qw.password-brute-force','semantic.qw.audit-disabled')
), candidates as (
    select f.id,p.scenario_id,f.rule,proof.group_key,f.password_threshold_facts418 as facts,
        coalesce((f.password_threshold_facts418->>'first')::timestamptz,f.first_seen_utc::timestamptz) as first_at,
        coalesce((f.password_threshold_facts418->>'last_failure')::timestamptz,f.last_seen_utc::timestamptz) as last_at,
        case when f.rule='qw.password-spray' then 1200 end as quiet
    from open_findings f
    join lateral (select p.scenario_id from public.semantic_finding_publications p
        where p.finding_id=f.id order by p.created_at,p.scenario_id limit 1) p on true
    join lateral (
        select min(key) as group_key
        from (
            select case when f.rule='qw.audit-disabled' and c.event_kind=4719
                and c.method#>>'{$origin,plugin_id}'='sli.windows.ad-dc'
                then public.audit_campaign_key444(c.method,c.fields)
                when f.rule<>'qw.audit-disabled'
                then public.password_campaign_key444(f.rule,c.domain_id,f.password_threshold_facts418) end as key
            from public.finding_event_copies337 c
            where c.finding_id=f.id and c.evidence_role='semantic_scenario'
        ) evidence
        having count(*)=count(key) and count(distinct key)=1
    ) proof on true
    where f.first_seen_utc is not null and f.last_seen_utc is not null
)
select *,min(id) over(partition by group_key) as survivor_id from candidates;

insert into public.problem_campaigns444
select survivor_id,group_key,min(first_at),max(last_at),max(quiet)
from problem_campaign_merge444 group by survivor_id,group_key;
insert into public.problem_campaign_sources444
select scenario_id,survivor_id,facts from problem_campaign_merge444;

insert into public.problem_campaign_episodes_restore444
select e.scope_key,e.rule_id,e.entity_key,e.episode_key,e.password_finding418,m.survivor_id
from public.semantic_identity_attack_episodes_v301 e
join problem_campaign_merge444 m on m.id=e.password_finding418 where m.id<>m.survivor_id;
update public.semantic_identity_attack_episodes_v301 e set password_finding418=r.survivor_id
from public.problem_campaign_episodes_restore444 r
where (e.scope_key,e.rule_id,e.entity_key,e.episode_key)=(r.scope_key,r.rule_id,r.entity_key,r.episode_key);

insert into public.problem_campaign_findings_restore444
select f.id,m.survivor_id,f.status,f.status_reason,f.closed_at,f.first_seen_utc,f.last_seen_utc,
    f.severity,f.password_threshold_facts418,f.updated_at,transaction_timestamp(),null
from public.findings f join problem_campaign_merge444 m on m.id=f.id;

with merged as (
    update public.findings f set status='closed',closed_at=r.changed_at,updated_at=r.changed_at,
        status_reason='problem_campaign_merged444:'||r.survivor_id
    from public.problem_campaign_findings_restore444 r
    where f.id=r.finding_id and r.finding_id<>r.survivor_id
    returning f.id,r.status,f.status_reason
), history as (
    insert into public.finding_status_history(finding_id,old_status,new_status,changed_by,note)
    select id,status,'closed','SLI',status_reason from merged returning finding_id,id
)
update public.problem_campaign_findings_restore444 r set history_id=h.id from history h where r.finding_id=h.finding_id;

with combined as (
    select c.finding_id,c.first_at,c.last_failure,
        public.password_campaign_facts444(c.finding_id,c.group_key like 'spray:%') as facts,
        bool_or(r.severity='critical') as critical
    from public.problem_campaigns444 c
    join public.problem_campaign_findings_restore444 r on r.survivor_id=c.finding_id
    group by c.finding_id
)
update public.findings f set
    first_seen_utc=coalesce(combined.facts->>'first',to_jsonb(combined.first_at)#>>'{}'),
    last_seen_utc=coalesce(combined.facts->>'last',to_jsonb(combined.last_failure)#>>'{}'),
    severity=case when combined.critical then 'critical' else f.severity end,
    password_threshold_facts418=coalesce(combined.facts,f.password_threshold_facts418),
    updated_at=transaction_timestamp()
from combined where f.id=combined.finding_id;

set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(444,'detection_campaigns');
reset role;
commit;
