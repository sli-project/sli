(
    with samples as materialized (
        select event_id,event_kind,domain_id,time_created_utc,
            method#>>'{$principals,SubjectUserSid}' as subject_sid,
            method#>>'{$principals,SubjectUserName}' as subject_name,
            coalesce(fields->>'ProcessName',method->>'ProcessName') as process_name,
            method->>'$server_id' as server_id,
            method->>'$correlation_id' as correlation_id,
            coalesce(fields->>'SubjectLogonId',method->>'SubjectLogonId',fields->>'TargetLogonId',method->>'TargetLogonId') as logon_id
        from finding_event_copies337 where finding_id=findings.id
        order by time_created_utc desc,event_id desc limit 21
    ), review_samples as (
        select * from samples order by time_created_utc desc,event_id desc limit 20
    )
    -- Only an audit-change sample with one of these inputs can leave the
    -- unknown bucket in the authoritative review classifier.
    select case when bool_or(event_kind=4719 and (
        (server_id is not null and (nullif(correlation_id,'') is not null or nullif(logon_id,'') is not null))
        or subject_sid in ('S-1-5-18','S-1-5-19','S-1-5-20')
        or (subject_sid is not null and right(subject_name,1)='$')))
    then semantic_finding_review_v160(findings.id)
    else jsonb_build_object('kind','hint','verdict',false,'bucket','unknown',
        'sample_count',count(*),'truncated',(select count(*)>20 from samples),
        'process_observed',coalesce(bool_or(process_name is not null),false),
        'has_audit_change',coalesce(bool_or(event_kind=4719),false),'mixed',false,'gpo_correlated',false,
        'machine_account',false,'interactive_session',false,'privileged_session',false,
        'domain_id',case when count(distinct domain_id)=1 then min(domain_id) end,
        'subject_sid',case when count(subject_sid)=count(*) and count(distinct subject_sid)=1 then min(subject_sid) end)
    end
    from review_samples
)
