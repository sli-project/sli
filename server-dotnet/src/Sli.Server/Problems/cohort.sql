
    cross join (select @cohort_zone::text as time_zone) cohort_config
    left join lateral (
        select count(*) as retained_count,
               count(*) filter(where e.event_id in (4728,4732,4756)) as membership_count,
               bool_and(coalesce(channel.value='Security' and provider.value='Microsoft-Windows-Security-Auditing',false)) as membership_source,
               count(distinct (e.domain_id,e.server_id,
                   timezone(cohort_config.time_zone,e.time_created_utc)::date,
                   e.target_user_sid,f.membership_member_sid)) as membership_identities,
               count(distinct (e.domain_id,e.server_id,
                   timezone(cohort_config.time_zone,e.time_created_utc)::date)) as source_days,
               bool_and(e.domain_id is not null and e.server_id is not null
                   and e.time_created_utc is not null) as source_complete,
               bool_and(e.target_user_sid ~ '^S-1-([0-9]+-)*[0-9]+$'
                   and f.membership_member_sid ~ '^S-1-([0-9]+-)*[0-9]+$'
                   and e.target_user_sid is not null and f.membership_member_sid is not null) as identities_complete,
               min(e.domain_id) as domain_id,min(e.server_id) as server_id,
               min(timezone(cohort_config.time_zone,e.time_created_utc)::date)::text as day,
               min(e.target_user_sid) as group_sid,min(f.membership_member_sid) as member_sid,
               case when count(distinct e.domain_id)=1 then min(d.fqdn) end as domain_name
        from finding_event_details337 e
        left join lateral (select e.membership_member_sid) f on true
        left join lateral (select e.channel as value) channel on true
        left join lateral (select e.identity_provider as value) provider on true
        left join domains d on d.id=e.domain_id
        where e.finding_id=findings.id
    ) witness on true
    cross join lateral (
        select case
            when witness.retained_count=findings.evidence_count and witness.retained_count>0
                and witness.source_complete and witness.identities_complete and witness.membership_source
                and witness.membership_count=witness.retained_count and witness.membership_identities=1
            then jsonb_build_array('membership',findings.rule_code,witness.domain_id,witness.server_id,
                witness.member_sid,witness.group_sid,witness.day)
            when witness.retained_count=findings.evidence_count and witness.retained_count>0
                and witness.source_complete and witness.membership_count=0 and witness.source_days=1
                and nullif(btrim(findings.target),'') is not null and length(findings.target)<=2048
            then jsonb_build_array('object',findings.rule_code,witness.domain_id,witness.server_id,
                findings.target,witness.day)
            else jsonb_build_array('finding',findings.id)
        end as key
    ) raw_cohort
    cross join lateral (
        select case when length(raw_cohort.key::text)<=4096 then raw_cohort.key
                    else jsonb_build_array('finding',findings.id) end as key
    ) cohort
