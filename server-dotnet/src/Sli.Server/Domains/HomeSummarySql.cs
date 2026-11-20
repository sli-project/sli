namespace Sli.Server.Domains;

internal static class HomeSummarySql
{
    internal const string EffectiveStatus = """
        case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end
        """;
    internal const string Population = """
        from findings_active findings
        left join lateral (select s.*,u.username as responsible_username from semantic_suppressions s
            join auth_users u on u.id=s.responsible_user_id
            where s.finding_id=findings.id and s.kind='risk_acceptance'
            order by s.id desc limit 1) risk on true
        """;
    internal static string ScopeWhere => $"""
        where is_semantic_finding_published_v1(findings.id)
          and (findings.rule_code<>'semantic.qw.file-acl-broad-write' or semantic_finding_in_domains_v265(findings.id,null))
          and not coalesce(risk.state='active' and risk.expires_at>statement_timestamp(),false)
          and not ({Sli.Server.Problems.ProblemRepository.Suppressed})
          and semantic_finding_in_domains_v265(findings.id,cast(@ids as bigint[]))
          and (cast(@from as timestamptz) is null or findings.last_seen_utc::timestamptz>=cast(@from as timestamptz))
          and (cast(@to as timestamptz) is null or findings.last_seen_utc::timestamptz<cast(@to as timestamptz))
        """;
    internal static string Where => ScopeWhere + $" and ({EffectiveStatus}) in ('new','confirmed','repeated')";
    internal static string Problems => $"""
        select findings.id,findings.rule_code,findings.title,findings.summary,findings.why_it_matters,findings.recommended_action,
               findings.severity,({EffectiveStatus}) as status,findings.repeat_count,findings.last_seen_utc,
               findings.actor,findings.target,findings.assigned_to,{Sli.Server.Problems.ProblemCohorts.PasswordFacts("findings")} as presentation_facts
        {Population} {Where}
        order by case when findings.severity in ('critical','high') then 0 else 2 end,
                 case findings.severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'low' then 4 else 5 end,
                 (({EffectiveStatus})='repeated' or coalesce(findings.repeat_count,0)>0) desc,
                 coalesce(findings.repeat_count,0) desc,
                 coalesce(findings.last_seen_utc,findings.updated_at::text)::timestamptz desc,findings.id desc limit 6
        """;
    internal static string Counts => $"""
        select findings.severity,({EffectiveStatus}) as status,count(*) as count
        {Population} {ScopeWhere} and (@all_statuses or ({EffectiveStatus}) in ('new','confirmed','repeated'))
        group by findings.severity,({EffectiveStatus})
        """;
    internal const string Heartbeat = "select status,phase,heartbeat_at,expected_interval_seconds,details_json from runtime_worker_heartbeats where worker_name='semantic' limit 1";
    internal const string PreviousLogin = "select previous_login_at from auth_users where id=@user";
    internal const string PasswordCoverage = "select public.read_password_detection_coverage(cast(@ids as bigint[])) as coverage";

    internal const string Sections = """
        with expected_domains as (select id as domain_id,fqdn as domain_name from domains where id=any(@ids)),
        required_sections(section_name) as (select unnest(string_to_array(@sections,','))),
        latest_section as (
            select distinct on (run.domain_id,section.section_name) run.domain_id,section.section_name,
                run.status as run_status,section.status as section_status,section.record_count,run.observed_at_utc
            from ad_context_runs run join expected_domains d on d.domain_id=run.domain_id
            join ad_context_sections section on section.run_id=run.run_id
            where section.section_name=any(string_to_array(@sections,','))
            order by run.domain_id,section.section_name,run.observed_at_utc desc,run.created_at desc,run.run_id desc)
        select expected.domain_id,expected.domain_name,required.section_name,latest.run_status,latest.section_status,
            latest.record_count,latest.observed_at_utc
        from expected_domains expected cross join required_sections required
        left join latest_section latest on latest.domain_id=expected.domain_id and latest.section_name=required.section_name
        order by expected.domain_id,required.section_name
        """;
    internal const string Entities = """
        select entity.id as entity_id,entity.domain_id,d.fqdn as domain_name,et.value as entity_type,
               entity.display_name,entity.natural_key,version.source_section,
               version.last_observed_at_utc as observed_at_utc,version.attributes_json as attributes
        from entities_v2_active entity join storage_v2_entity_type et on et.id=entity.entity_type_id
        join domains d on d.id=entity.domain_id
        join ad_context_entity_versions version on version.entity_id=entity.id and version.valid_to_utc is null
        where entity.domain_id=any(@ids) and version.source_section=any(string_to_array(@sections,','))
          and et.value in ('domain','ad_computer','replication_link','password_policy','domain_trust')
        order by entity.domain_id,entity.id limit (case when @sections='directory_accounts' then 10001 else 5001 end)
        """;
    internal const string Changes = """
        select count(*) filter(where change.at>=@current) as current_count,
               count(*) filter(where change.at<@current) as previous_count
        from ad_context_relation_versions relation
        cross join lateral (values (relation.valid_from_utc,'added'),(relation.valid_to_utc,'removed')) change(at,kind)
        where relation.domain_id=any(@ids) and relation.source_section='privileged_membership'
          and relation.relation_kind='member_of' and change.at>=@before and change.at<@end
          and not exists (select 1 from ad_context_relation_versions adjacent
              where adjacent.domain_id=relation.domain_id and adjacent.relation_key=relation.relation_key
                and adjacent.source_section=relation.source_section and adjacent.id<>relation.id
                and ((change.kind='added' and adjacent.valid_to_utc=change.at)
                     or (change.kind='removed' and adjacent.valid_from_utc=change.at)))
          and (change.kind='removed' or exists (select 1 from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id
              where run.domain_id=relation.domain_id and run.status='completed'
                and section.section_name='privileged_membership' and section.status='complete'
                and run.observed_at_utc<relation.valid_from_utc))
        """;
    internal const string ChangeHistory = """
        select run.domain_id,min(run.observed_at_utc) as history_from,max(run.observed_at_utc) as observed_at_utc
        from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id
        where run.domain_id=any(@ids) and run.status='completed' and section.section_name='privileged_membership'
          and section.status='complete' and run.observed_at_utc<=@end group by run.domain_id order by run.domain_id
        """;
    internal const string VpnCoverage = "select * from radius_vpn_session_coverage_v1 where domain_id=@domain";
    internal const string VpnCounts = """
        select count(*) filter(where started_at_utc<@end and stopped_at_utc>@current) as current_count,
               count(*) filter(where started_at_utc<@current and stopped_at_utc>@before) as previous_count
        from radius_vpn_session_rows_v1 where domain_id=@domain and entity_id is not null
          and stopped_at_utc is not null and started_at_utc is not null and stopped_at_utc>started_at_utc
          and started_at_utc<@end and stopped_at_utc>@before
        """;
}
