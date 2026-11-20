using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    private (string Id, int Version, string Sha)[]? DispatchRulePins() => mode == SemanticRuntimeSettings.InvestigationMode
        ? InvestigationRules.Select(x => (x.Key, x.Value.Version, x.Value.Sha)).ToArray() : null;

    private static string DispatchRuleFilter(List<object?> values, IReadOnlyList<string>? ids,
        IReadOnlyList<(string Id, int Version, string Sha)>? identities)
    {
        if (ids is not null && identities is not null) throw new ArgumentException("Choose allowed_rule_ids or allowed_rule_identities");
        if (ids is not null)
        {
            var exact = ids.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct().Order(StringComparer.Ordinal).ToArray();
            if (exact.Length == 0 || exact.Any(x => x.Length > 200)) throw new ArgumentException("Invalid allowed_rule_ids");
            values.Add(exact); return $"and rule.rule_id=any(${values.Count})";
        }
        if (identities is null) return "";
        if (identities.Count == 0) throw new ArgumentException("Invalid allowed_rule_identities");
        var arms = new List<string>();
        foreach (var (id, version, sha) in identities.Distinct().OrderBy(x => x.Id, StringComparer.Ordinal).ThenBy(x => x.Version).ThenBy(x => x.Sha, StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(id) || id.Trim().Length > 200 || version <= 0 || sha.Length != 64 || !sha.All(Uri.IsHexDigit))
                throw new ArgumentException("Invalid allowed_rule_identities");
            int n = values.Count; values.Add(id.Trim()); values.Add(version); values.Add(Convert.FromHexString(sha));
            arms.Add($"(rule.rule_id=${n + 1} and rule.rule_version=${n + 2} and rule.definition_sha256=${n + 3})");
        }
        return "and (" + string.Join(" or ", arms) + ")";
    }

    internal static Task<JsonArray> ClaimDispatchJobs(ISemanticSession session, CancellationToken ct, int limit = 1, int leaseSeconds = 300,
        IReadOnlyList<string>? allowedRuleIds = null, IReadOnlyList<(string Id, int Version, string Sha)>? allowedRuleIdentities = null,
        IReadOnlyList<Guid>? allowedJobIds = null)
    {
        var values = new List<object?>(); string filter = DispatchRuleFilter(values, allowedRuleIds, allowedRuleIdentities);
        if (allowedJobIds is { Count: 0 }) return Task.FromResult(new JsonArray());
        if (allowedJobIds is not null) { values.Add(allowedJobIds.Distinct().ToArray()); filter += $" and job.job_id=any(${values.Count}::uuid[])"; }
        int n = values.Count; values.Add(Math.Max(1, limit)); values.Add(Guid.NewGuid()); values.Add(Math.Max(60, leaseSeconds));
        return session.QueryAsync($"""
            with candidates as(select job.job_id from semantic_correlation_dispatch_jobs job join semantic_correlation_rules rule on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
              where job.attempt_count<job.max_attempts and job.available_at<=now() and(job.dispatch_status in('queued','failed') or(job.dispatch_status='leased' and job.lease_until<now())) {filter}
              order by job.available_at,job.created_at,job.job_id for update of job skip locked limit ${n + 1}),
            leased as(update semantic_correlation_dispatch_jobs job set dispatch_status='leased',attempt_count=attempt_count+1,lease_token=${n + 2},lease_until=now()+(${n + 3} * interval '1 second'),heartbeat_at=now(),updated_at=now(),last_error_code=null,last_error_detail=null
              from candidates where job.job_id=candidates.job_id returning job.*) select * from leased
            """, ct, values.ToArray());
    }

    internal static (string Predicate, JsonObject[] Parameters) CrossDcContextPredicate(string kind, string partition)
    {
        InvalidDataException Invalid() => new("Cross-DC dispatch partition is not an exact SID key");
        var pieces = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string component in partition.Split('|'))
        {
            var pair = component.Split(':', 2);
            if (pair.Length != 2 || !pieces.TryAdd(pair[0], pair[1])) throw Invalid();
        }
        string[] keys = kind switch { "domain_account_sid" => ["domain", "account_sid"], "domain_member_group_sid" => ["domain", "member_sid", "group_sid"], "domain_account_member_sid" => ["domain", "account_member_sid"], _ => throw Invalid() };
        if (pieces.Count != keys.Length || keys.Any(x => !pieces.ContainsKey(x))
            || !Regex.IsMatch(pieces["domain"], @"\A[1-9][0-9]*\z") || !long.TryParse(pieces["domain"], NumberStyles.None, CultureInfo.InvariantCulture, out long domain)
            || keys.Skip(1).Any(x => pieces[x].Length > 184 || !Regex.IsMatch(pieces[x], @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z"))) throw Invalid();
        var domainFilter = new JsonObject { ["domain_id"] = domain };
        return kind switch
        {
            "domain_account_sid" => ("facts_json @> $7::jsonb and roles_json @> $8::jsonb", [domainFilter, new() { ["affected_entity"] = "sid:" + pieces["account_sid"] }]),
            "domain_member_group_sid" => ("facts_json @> $7::jsonb and facts_json @> $8::jsonb", [domainFilter, new() { ["relation_member_sid"] = pieces["member_sid"], ["relation_group_sid"] = pieces["group_sid"] }]),
            _ => ("facts_json @> $7::jsonb and (roles_json @> $8::jsonb or facts_json @> $9::jsonb)", [domainFilter, new() { ["affected_entity"] = "sid:" + pieces["account_member_sid"] }, new() { ["relation_member_sid"] = pieces["account_member_sid"] }])
        };
    }

    internal static Task<JsonArray> ExpireCorrelationCandidates(ISemanticSession session, DateTime beforeUtc, CancellationToken ct, int limit = 100)
    {
        if (beforeUtc.Kind == DateTimeKind.Unspecified) throw new ArgumentException("Correlation expiry boundary must be timezone-aware", nameof(beforeUtc));
        return session.QueryAsync("""
            with expiring as(select candidate_id from semantic_correlation_candidates
              where candidate_status='matched' and window_end_utc < $1 order by window_end_utc,candidate_id for update skip locked limit $2)
            update semantic_correlation_candidates candidate set candidate_status='expired',closed_at=now(),updated_at=now()
              from expiring where candidate.candidate_id=expiring.candidate_id returning candidate.candidate_id
            """, ct, beforeUtc.ToUniversalTime(), Math.Max(1, limit));
    }
}
