using System.Text.Json.Nodes;
using Sli.Server.Agents.Registry;
using static Sli.Server.Domains.HomeJson;

namespace Sli.Server.Domains;

internal static class HomeAgentLinkWarning
{
    internal const string Sql = """
        select a.id::text, a.last_seen, a.collection_policy, a.created_at,
               ack.occurred_at as policy_applied_at
        from sli_agents a
        left join lateral (
            select occurred_at from sli_agent_audit where target=a.id::text and action='policy_ack'
            order by id desc limit 1
        ) ack on true
        where a.status='active' and coalesce(a.collection_policy->>'state','active')='active'
          and a.applied_collection_state='active' and a.policy_revision=a.applied_policy_revision
          and a.last_seen is not null
          and (@all_agents or exists (
            select 1 from domains d where d.id=any(@ids) and (
                exists (select 1 from jsonb_array_elements(a.assigned_modules) m
                    where m->>'enabled'='true' and coalesce(m->'config'->>'paused','false')='false'
                      and lower(m->'config'->>'domain_dns')=lower(d.fqdn))
                or exists (
                    select 1 from sli_agent_audit issued
                    join sli_agent_group_approval_links c on issued.actor='enrollment:' || c.enrollment_token_id::text
                    join sli_agent_group_requests r on r.id=c.request_id
                    join sli_agent_group_tokens t on t.id=r.token_id
                    where issued.target=a.id::text and issued.action='issue' and t.domain_id=d.id))))
        """;

    internal static async Task<JsonObject?> Read(HomeSummaryReaders reads, AgentLinkHistory? history, HomeReport report,
        long[] ids, bool allAgents, DateTimeOffset now, CancellationToken ct)
    {
        if (!report.Fields(ids, "technical")) return null;
        try
        {
            var agents = await reads.Read(Sql, ct, ("ids", ids), ("all_agents", allAgents));
            if (history is null) throw new InvalidOperationException("agent_link_history_unavailable");
            long count = 0;
            DateTimeOffset? latest = null;
            foreach (var agent in agents)
            {
                if (!Guid.TryParse(agent.Text("id"), out var id) || agent.Stamp("last_seen") is not {} seen) continue;
                var interval = agent["collection_policy"].Number("interval_seconds");
                var since = new[] { now.AddHours(-1), agent.Stamp("created_at") ?? now.AddHours(-1),
                    agent.Stamp("policy_applied_at") ?? now.AddHours(-1) }.Max();
                var gap = history.Check(id, seen, interval > 0 ? interval : 60, since, now);
                if (gap is null) continue;
                count++;
                if (latest is null || gap > latest) latest = gap;
            }
            return count == 0 ? null : Object(new { reason_code = "home.queue.warning.agent_link_unstable", agent_count = count,
                window_from_utc = HomeSummaryQuery.Iso(now.AddHours(-1)), window_to_utc = HomeSummaryQuery.Iso(now),
                observed_at_utc = HomeSummaryQuery.Iso(latest!.Value), href = "/app/operations" });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return Object(new { reason_code = "home.queue.warning.agent_link_unknown", observed_at_utc = HomeSummaryQuery.Iso(now), href = "/app/operations" }); }
    }
}
