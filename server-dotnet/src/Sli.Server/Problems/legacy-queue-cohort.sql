
    cross join lateral (
        select cohort.key,cohort_config.time_zone
        from (select 1) cohort_seed
        __RETAINED_COHORT__
    ) retained_cohort
    cross join lateral (
        select case
            when retained_cohort.key->>0 <> 'finding' then retained_cohort.key
            when nullif(btrim(findings.actor),'') is not null and length(findings.actor)<=2048
                and nullif(btrim(findings.target),'') is not null and length(findings.target)<=2048
                and timezone(retained_cohort.time_zone,findings.first_seen_utc::timestamptz)::date
                    =timezone(retained_cohort.time_zone,findings.last_seen_utc::timestamptz)::date
            then jsonb_build_array('queue',findings.rule_code,findings.actor,findings.target,
                coalesce((select jsonb_agg(distinct entity.display_name order by entity.display_name)
                    from finding_entities entity where entity.finding_id=findings.id
                      and entity.entity_role='container_entity'
                      and nullif(btrim(entity.display_name),'') is not null),'[]'::jsonb),
                timezone(retained_cohort.time_zone,findings.last_seen_utc::timestamptz)::date::text)
            else jsonb_build_array('finding',findings.id)
        end as key
    ) raw_cohort
    cross join lateral (
        select case when length(raw_cohort.key::text)<=4096 then raw_cohort.key
                    else jsonb_build_array('finding',findings.id) end as key
    ) cohort
