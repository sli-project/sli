using Sli.Server.Problems;

namespace Sli.Server.Domains;

internal static class HomeDecisionSql
{
    internal static string Groups(bool identity, bool allDomains = false)
    {
        // The queue owns both the admitted population and the rule/object grouping.
        var query = new FindingQuery(null, null, null, "from", "to", null, null, allDomains ? null : [], 8, false) {
            GroupQueue = true, Population = "open"
        };
        string prefix = ProblemRepository.FindingsQueries(query, populationOnly: true, shortEvents: true).Page
            .Replace("@domains", "@ids")
            .Replace("findings.last_seen_utc::timestamptz>=@from::timestamptz", "(@from::timestamptz is null or findings.last_seen_utc::timestamptz>=@from::timestamptz)")
            .Replace("findings.last_seen_utc::timestamptz<@to::timestamptz", "(@to::timestamptz is null or findings.last_seen_utc::timestamptz<@to::timestamptz)");
        return prefix + $"""
            , population as materialized (
                select findings.*,g.problem_cohort as cohort,g.occurrence_count,
                    g.last_seen_utc as group_last_seen_utc
                from queue_findings findings join queue_groups g on g.id=findings.id
            )
            select p.id,p.rule_code,p.title,p.cohort,p.occurrence_count,p.actor,p.target,{ProblemCohorts.PasswordFacts("p", true)} as presentation_facts,
                case p.severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end as importance,
                1::bigint as total,
                case when @since::timestamptz is null then null else (p.created_at>@since::timestamptz)::int end as new_count,
                p.group_last_seen_utc as last_seen_utc,p.assigned_to,
                (nullif(btrim(p.assigned_to),'') is null)::int as unassigned_count,
                null::text as day,
                {(identity ? "jsonb_build_array(p.target)" : "null::jsonb")} as object_names,
                null::text as domain_name,
                jsonb_build_object('id',p.id,'actor',p.actor,'target',p.target,'evidence_count',p.evidence_count) as representative,
                count(*) over() as total_problems,count(*) over() as total_groups,
                case when @since::timestamptz is null then null else count(*) filter(where p.created_at>@since::timestamptz) over() end as total_new
            from population p
            order by importance,group_last_seen_utc desc nulls last,p.id desc
            limit 8
            """;
    }
}
