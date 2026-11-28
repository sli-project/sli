
    left join lateral (
        __PASSWORD_EVIDENCE__
        where findings.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
        offset 0
    ) password on true
    left join problem_queue_scenario_keys443 scenario
        on scenario.scenario_key=findings.scenario_key and scenario.rule_code=findings.rule_code
    cross join lateral (
        select case
            when password.facts->>'cohort_key' is not null
                then jsonb_build_array('password',findings.rule_code,password.facts->>'cohort_key')::text
            when findings.rule_code='semantic.qw.file-ransom'
                then jsonb_build_array('finding',findings.id)::text
            when scenario.scenario_key is not null
                then coalesce(scenario.cohort,jsonb_build_array('finding',findings.id)::text)
            else findings.object_key
        end as key
    ) cohort
