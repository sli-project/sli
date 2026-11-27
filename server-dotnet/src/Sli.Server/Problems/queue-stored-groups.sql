with queue_group_stats as (
    select cohort.key collate "C" as problem_cohort,
        (array_agg(row(findings.id,(__STATUS__),(__ACCEPTED__),findings.severity,__ASSIGNEE__,password.aliases)
            ::public.problem_queue_representative438 order by
            case (__STATUS__) when 'new' then 1 when 'repeated' then 2
                when 'confirmed' then 3 when 'active' then 4 when 'review' then 5
                when 'false_positive' then 6 when 'closed' then 7 else 8 end,
            priority.severity,findings.last_seen_utc desc,findings.id desc))[1] as representative,
        (array_agg(row(findings.severity,password.facts)::public.problem_queue_password438
            order by priority.severity,findings.last_seen_utc desc,findings.id desc)
            filter (where findings.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')))[1] as password_priority,
        bool_or(password.facts->>'cohort_key' is not null) as password_cohort,
        sum(case findings.rule_code
            when 'semantic.qw.privileged-group-addition' then greatest(1,witnesses.group_additions)
            when 'semantic.qw.security-log-cleared' then greatest(1,witnesses.log_clears)
            when 'semantic.qw.audit-disabled' then greatest(1,witnesses.audit_changes)
            when 'semantic.qw.password-brute-force' then priority.password_attempts
            when 'semantic.qw.password-spray' then priority.password_attempts
            else 1+greatest(findings.repeat_count,0) end) as occurrence_count,
        min(findings.first_seen_utc) as first_seen_utc,
        max(findings.last_seen_utc) as last_seen_utc,
        max(findings.id) as queue_cursor_id
    __POPULATION____COHORT__
    cross join lateral (
        select case findings.severity when 'critical' then 1 when 'high' then 2
            when 'medium' then 3 when 'low' then 4 else 5 end as severity,
            coalesce((password.facts->>'attempts')::bigint,greatest(findings.evidence_count,1)) as password_attempts
    ) priority
    __WHERE__
    group by 1__PARTITION__
), queue_groups as (
    select (representative).id,problem_cohort::jsonb,
        (representative).status,(representative).risk_accepted,(representative).assignee as queue_assignee,
        case when password_cohort then (password_priority).severity else (representative).severity end as severity,
        (password_priority).facts as password_facts,(representative).password_aliases,
        occurrence_count,first_seen_utc,last_seen_utc,queue_cursor_id
    from queue_group_stats
)
