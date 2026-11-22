begin;
select pg_advisory_xact_lock(hashtext('sli_problem_account_identity395'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=394 and name='notification_language')
       or exists(select 1 from public.schema_migrations where version>=395) then
        raise exception 'problem_account_identity395_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;

create or replace function public.password_definition_revision393(r text) returns integer
language sql immutable set search_path=pg_catalog,pg_temp as $$ select 395 $$;

-- A revision change can start a live pass even when the first event is
-- newer than the seam. In that case the preceding history interval is empty.
do $$ declare planner text; patched text; begin
    select pg_get_functiondef('public.password_plan388(jsonb,text)'::regprocedure) into planner;
    patched:=replace(planner,'coalesce(c.watermark,first_at,seam)','coalesce(c.watermark,least(first_at,seam))');
    if patched=planner then
        raise exception 'problem_account_identity395_planner_shape' using errcode='55000';
    end if;
    execute patched;
end $$;

-- The current password rules can use a verified successful logon to escalate.
-- Admit it through the same source, native identity, and budget gates as failures.
do $$ declare r record; original text; patched text; begin
    for r in select * from (values
        ('public.read_password_event_window362(jsonb,jsonb)',
            'e.event_id in (4625,4771,4776)',
            '(e.event_id in (4625,4771,4776) or (e.event_id=4624 and (execution->>''rule_version'')::integer>=395))'),
        ('public.read_password_retained_proof_v2_short337(jsonb,jsonb)',
            'event_id in (4625,4771,4776)','event_id in (4624,4625,4771,4776)'),
        ('public.password_v2_native_cost_short337(jsonb,jsonb)',
            'event_id in (4625,4771,4776)','event_id in (4624,4625,4771,4776)'),
        ('public.password_v2_check_state(jsonb,jsonb,text)',
            '''too_late''','''too_late'',''successful_logon''')
    ) v(signature,prev_fragment,next_fragment) loop
        select pg_get_functiondef(r.signature::regprocedure) into original;
        patched:=replace(original,r.prev_fragment,r.next_fragment);
        if patched=original then
            raise exception 'problem_account_identity395_password_shape:%',r.signature using errcode='55000';
        end if;
        execute patched;
    end loop;
end $$;

-- Resolve the retained principals as a set. Invoker rights retain the permissions
-- of the existing problem and AD readers.
create function public.password_problem_facts395(p_finding bigint,p_rule text) returns jsonb
language sql stable set search_path=pg_catalog,pg_temp as $$
    with native as (
        select e.event_db_id as id,e.event_id,e.time_created_utc,e.domain_id,
            e.target_user_name,e.target_domain_name,e.target_user_sid,e.ip_address,e.workstation_name
        from public.finding_event_details337 e
        where e.finding_id=p_finding and e.event_id in (4624,4625,4771,4776)
    ), names as (
        select n.*,nullif(btrim(n.target_user_name),'') as name,
            casefold(btrim(n.target_domain_name) collate pg_catalog.pg_unicode_fast) as realm,
            casefold(d.netbios_name collate pg_catalog.pg_unicode_fast) as netbios,casefold(d.fqdn collate pg_catalog.pg_unicode_fast) as fqdn,
            case when n.target_user_sid ~* '^S-1-5-21(-[0-9]{1,10}){4}$' then lower(n.target_user_sid) end as sid
        from native n left join public.domains d on d.id=n.domain_id
    ), qualified as (
        select *,case when strpos(name,chr(92))>0 then casefold(split_part(name,chr(92),1) collate pg_catalog.pg_unicode_fast) else realm end as qualifier,
            case when strpos(name,chr(92))>0 and casefold(split_part(name,chr(92),1) collate pg_catalog.pg_unicode_fast)=netbios
                then substr(name,strpos(name,chr(92))+1) else name end as sam
        from names
    ), account as materialized (
        select *,casefold(sam collate pg_catalog.pg_unicode_fast) as folded,
            coalesce(qualifier in ('','-','n/a',netbios,fqdn),qualifier is null) as local_name
        from qualified
    ), resolved as (
      select a.id,a.event_id,a.time_created_utc,a.domain_id,
           case when a.sid is not null then 'sid:'||a.sid
                when match.sid is not null then 'sid:'||match.sid
                when match.guid is not null then 'guid:'||match.guid
                when a.folded not in ('','-','n/a') and length(a.folded)<=256 then
                    'name:'||case when a.local_name or strpos(a.sam,chr(92))>0 then '' else coalesce(a.qualifier,'')||chr(92) end||a.folded end as account_key,
           coalesce(match.sam,case when a.folded not in ('','-','n/a') then left(a.sam,256) end) as account_name,
           case when lower(btrim(a.ip_address)) like '::ffff:%'
               then left(regexp_replace(lower(btrim(a.ip_address)),'^::ffff:([0-9]+\.)','\1'),256)
               when lower(btrim(a.ip_address)) not in ('','-','n/a','::','::1','0.0.0.0','127.0.0.1')
               then left(lower(btrim(a.ip_address)),256) end as address,
           case when lower(ltrim(btrim(a.workstation_name),chr(92))) not in ('','-','n/a')
               then left(ltrim(btrim(a.workstation_name),chr(92)),256) end as workstation
      from account a
      left join public.ad_context_entity_aliases alias on alias.domain_id=a.domain_id
        and alias.alias_type=case when a.sid is not null then 'object_sid' else 'sam_account_name' end
        and alias.normalized_value=coalesce(a.sid,case when a.local_name then a.folded end)
      left join lateral (
        select lower(nullif(v.attributes_json#>>'{identity,object_sid}','')) as sid,
               lower(nullif(v.attributes_json#>>'{identity,object_guid}','')) as guid,
               nullif(btrim(v.attributes_json#>>'{attributes,sam_account_name}'),'') as sam
        from public.ad_context_entity_versions v
        join public.ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=a.domain_id and r.status='completed'
        join public.ad_context_sections s on s.run_id=r.run_id and s.section_name=v.source_section and s.status='complete'
        where alias.entity_id is not null and v.entity_id=alias.entity_id and v.source_section='directory_accounts'
          and v.valid_from_utc<=a.time_created_utc and (v.valid_to_utc is null or v.valid_to_utc>a.time_created_utc)
          and r.observed_at_utc<=a.time_created_utc and v.attributes_json#>>'{identity,kind}' in ('ad_user','ad_computer')
          and (a.sid is not null and lower(v.attributes_json#>>'{identity,object_sid}')=a.sid
            or a.sid is null and casefold(btrim(v.attributes_json#>>'{attributes,sam_account_name}') collate pg_catalog.pg_unicode_fast)=a.folded)
        order by r.observed_at_utc desc,v.id desc limit 1
      ) match on true
    ), observed as (
        select *,max(time_created_utc) filter(where event_id=4624) over() as last_success from resolved
    ), grouped as (
        select count(distinct domain_id) as domains,min(domain_id) as domain_id,
            case when count(distinct address)=1 then min(address)
                 when count(address)=0 and count(distinct lower(workstation))=1 then min(lower(workstation)) end as source,
            case when count(distinct address)=1 then 'ip'
                 when count(address)=0 and count(distinct lower(workstation))=1 then 'host' end as source_type,
            count(distinct account_key) filter(where event_id<>4624) as accounts,
            min(account_key) filter(where event_id<>4624) as account_key,
            count(distinct id) filter(where event_id<>4624) as attempts,
            count(distinct id) filter(where event_id<>4624 and time_created_utc>=last_success-interval '600 seconds'
                and time_created_utc<last_success) as attempts_before_success,
            max(time_created_utc) filter(where event_id=4624) as success_at,min(time_created_utc) as first_at,
            (array_agg(account_name order by time_created_utc desc,id desc) filter(where event_id=4624 and account_name is not null))[1] as successful_account,
            min(account_name) filter(where event_id<>4624) as attempted_account
        from observed having count(*)>0
    )
    select jsonb_strip_nulls(jsonb_build_object(
        'account',coalesce(successful_account,case when accounts=1 then attempted_account end),
        'source',source,'account_count',accounts,'attempts',attempts,
        'count',case when success_at is not null then attempts_before_success
                     when p_rule='semantic.qw.password-spray' then accounts else attempts end,
        'password_success',success_at is not null,
        'time',regexp_replace(to_char(coalesce(success_at,first_at) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'\.000000$','')||'+00:00',
        'cohort_key',case when domains=1 and source is not null and (p_rule='semantic.qw.password-spray' or accounts=1)
            then encode(sha256(convert_to(jsonb_build_array(domain_id,source_type,source,
                case when p_rule='semantic.qw.password-brute-force' then account_key end)::text,'UTF8')),'hex') end))
    from grouped
$$;
revoke all on function public.password_problem_facts395(bigint,text) from public;
grant execute on function public.password_problem_facts395(bigint,text) to adlog_user;

create function public.notification_password_facts395(p_job uuid,p_lease uuid) returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select public.password_problem_facts395((f->>'id')::bigint,f->>'rule_code') - 'cohort_key'
    from public.notification_alert_finding(p_job,p_lease) f
    where f->>'rule_code' in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
$$;
revoke all on function public.notification_password_facts395(uuid,uuid) from public;
grant execute on function public.notification_password_facts395(uuid,uuid) to adlog_notification_worker;

create table public.problem_severity_backup395(
    finding_id bigint primary key,previous_severity text not null,applied_severity text not null,updated_at timestamptz
);
revoke all on public.problem_severity_backup395 from public;

reset role;
grant select(domain_id,entity_id,alias_type,normalized_value) on public.ad_context_entity_aliases to adlog_storage_owner;
with classified as (
    select f.id,f.severity,f.updated_at,case
        when f.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray') then
            case when f.severity='critical' or exists(select 1 from public.finding_event_details337 e where e.finding_id=f.id and e.event_id=4624)
                then 'critical' else 'medium' end
        when f.rule_code in ('semantic.qw.audit-disabled','semantic.qw.security-log-cleared','semantic.qw.agent-tamper',
            'semantic.qw.agent-silenced','semantic.qw.privileged-group-addition') then 'high'
        when f.rule_code in ('qw.ad-hardening.privileged-nonexpiring','qw.ad-hardening.machine-account-quota',
            'qw.ad-hardening.lockout-threshold') then 'low' end as classified_severity
    from public.findings f where f.status in ('new','confirmed','repeated','active','review')
), saved as (
    insert into public.problem_severity_backup395(finding_id,previous_severity,applied_severity,updated_at)
    select id,severity,classified_severity,updated_at from classified where severity<>classified_severity
    returning finding_id,applied_severity
)
update public.findings f set severity=saved.applied_severity from saved where f.id=saved.finding_id;

insert into public.schema_migrations(version,name) values(395,'problem_account_identity');
commit;
