
    left join lateral (
        __PASSWORD_EVIDENCE__
        where findings.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
        offset 0
    ) password on true
    left join lateral (
        select s.partition_key,s.strict_keys_json->>'entity' as entity
        from semantic_security_scenarios s
        where s.scenario_key=case when findings.fingerprint ~ '^semantic:[0-9a-f]{64}$'
            then decode(substring(findings.fingerprint from 10),'hex') end
          and findings.rule_code='semantic.'||s.scenario_kind
          and nullif(s.strict_keys_json->>'entity','') is not null
          and length(s.strict_keys_json->>'entity')<=2048
          and length(s.partition_key) between 1 and 2048
        limit 1
    ) scenario_object on true
    cross join lateral (
        select case
            when password.facts->>'cohort_key' is not null
            then jsonb_build_array('password',findings.rule_code,password.facts->>'cohort_key')
            when scenario_object.entity is not null
            then jsonb_build_array('rule-entity',findings.rule_code,scenario_object.partition_key,scenario_object.entity)
            when nullif(btrim(findings.target),'') is not null and length(findings.target)<=2048
            then jsonb_build_array('rule-object',findings.rule_code,lower(btrim(findings.target)))
            when nullif(btrim(findings.source),'') is not null and length(findings.source)<=2048
            then jsonb_build_array('rule-source',findings.rule_code,lower(btrim(findings.source)))
            else jsonb_build_array('finding',findings.id)
        end as key
    ) raw_cohort
    cross join lateral (
        select case when length(raw_cohort.key::text)<=4096 then raw_cohort.key
            else jsonb_build_array('finding',findings.id) end as key
    ) cohort
