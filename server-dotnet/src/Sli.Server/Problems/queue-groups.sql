with queue_population as materialized (
        select findings.id,cohort.key as problem_cohort,
               case when cohort.key->>0='password' then
                   first_value(findings.severity) over password_priority else findings.severity end as severity,
               first_value(password.facts) over password_priority as password_facts,
               (__STATUS__) as status,(__ACCEPTED__) as risk_accepted,
               sum(case when findings.rule_code in ('semantic.qw.privileged-group-addition','semantic.qw.security-log-cleared','semantic.qw.audit-disabled')
                   then greatest(1,(select count(distinct e.event_db_id) from finding_event_details337 e
                       where e.finding_id=findings.id and case findings.rule_code
                           when 'semantic.qw.privileged-group-addition' then e.event_id in (4728,4732,4756)
                           when 'semantic.qw.security-log-cleared' then e.event_id in (1102,104)
                           else e.event_id=4719 end))
                   when findings.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
                   then coalesce((password.facts->>'attempts')::bigint,greatest(coalesce(findings.evidence_count,0),1))
                   else 1+greatest(coalesce(findings.repeat_count,0),0) end) over(partition by cohort.key) as occurrence_count,
               min(findings.first_seen_utc::timestamptz) over(partition by cohort.key) as first_seen_utc,
               max(findings.last_seen_utc::timestamptz) over(partition by cohort.key) as last_seen_utc,
               max(findings.id) over(partition by cohort.key) as queue_cursor_id,
               row_number() over(partition by cohort.key order by
                   case (__STATUS__) when 'new' then 1 when 'repeated' then 2
                       when 'confirmed' then 3 when 'active' then 4 when 'review' then 5
                       when 'false_positive' then 6 when 'closed' then 7 else 8 end,
                   case findings.severity when 'critical' then 1 when 'high' then 2
                       when 'medium' then 3 when 'low' then 4 else 5 end,
                   findings.last_seen_utc::timestamptz desc,findings.id desc) as representative_rank
        __POPULATION____COHORT____WHERE__
        window password_priority as (partition by cohort.key order by
            case findings.severity when 'critical' then 1 when 'high' then 2
                when 'medium' then 3 when 'low' then 4 else 5 end,
            findings.last_seen_utc::timestamptz desc,findings.id desc)
    ), queue_groups as (
        select * from queue_population where representative_rank=1
    ) 
