using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

public sealed partial class FileAuditReportReader
{
    internal static bool ResourceMatches(JsonNode root, string? search, bool nested)
    {
        if (string.IsNullOrWhiteSpace(search)) return true;
        string term = search.Trim().Replace('/', '\\').TrimEnd('\\');
        string path = (Text(root, "path") ?? "").Replace('/', '\\').TrimEnd('\\');
        if (term.StartsWith(@"\\", StringComparison.Ordinal))
            path = $@"\\{SourceName(root)}\{Text(root, "share_name")}";
        if (term.StartsWith(@"\\", StringComparison.Ordinal) || term.Length >= 2 && term[1] == ':')
            return path.Equals(term, StringComparison.OrdinalIgnoreCase)
                || nested && path.StartsWith(term + "\\", StringComparison.OrdinalIgnoreCase);
        return (Text(root, "share_name") ?? "").Contains(term, StringComparison.OrdinalIgnoreCase)
            || path.Contains(term, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<Dictionary<string, JsonObject>> OverviewFactsAsync(ISemanticSession session,
        JsonArray roots, DateTime from, DateTime to, CancellationToken ct)
    {
        var facts = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        var configured = roots.OfType<JsonObject>().Where(r => r["catalog_configured"]?.GetValue<bool>() != false).ToArray();
        foreach (string tab in new[] { "mass-operations", "permissions" })
        {
            // Newest-first cursors let us stop reading a root once its newest
            // critical finding is known, since no later page can outrank it.
            var remaining = configured.ToDictionary(ShareKey, StringComparer.Ordinal);
            JsonNode? after = null;
            while (remaining.Count > 0)
            {
                var result = (await session.QueryAsync("""
                    select sli_plugin_file_audit.report_rows($1::jsonb,$2,$3,$4,null,true,null,null,$5::jsonb,200) as data
                    """, ct, new JsonArray(remaining.Values.Select(r => r.DeepClone()).ToArray()),
                    tab, from, to, after ?? new JsonObject()))[0]!["data"]!.AsObject();
                if (result["service_filter_version"]?.GetValue<int>() != 1)
                    throw new ReportRequestException("file_audit_source_unreadable");
                var items = Array(result["items"]).OfType<JsonObject>().ToArray();
                await RuleSeveritiesAsync(session, items, ct);
                foreach (var row in items)
                {
                    string key = ShareKey(row);
                    if (!remaining.ContainsKey(key)) continue;
                    var fact = RuleFact(tab, row, Text(row, "severity"));
                    if (fact is not null && (!facts.TryGetValue(key, out var previous) || IsPreferredFact(fact, previous)))
                        facts[key] = fact;
                    if (Text(row, "severity") == "critical") remaining.Remove(key);
                }
                if (!result.Flag("has_more") || result["after"] is not { } next || JsonNode.DeepEquals(after, next)) break;
                after = next;
            }
        }
        foreach (var root in roots.OfType<JsonObject>())
        {
            string? state = Text(root, "audit_state");
            if (state is "disabled" or "error")
                facts.TryAdd(ShareKey(root), new JsonObject { ["kind"] = state == "disabled" ? "audit_disabled" : "audit_error" });
        }
        return facts;
    }

    private static async Task RuleSeveritiesAsync(ISemanticSession session, JsonObject[] rows, CancellationToken ct)
    {
        var ids = new JsonArray(rows.Select(r => Text(r, "result_id")).OfType<string>().Distinct()
            .Select(id => JsonValue.Create("file-audit:" + id)).ToArray());
        if (ids.Count == 0) return;
        var severities = await session.QueryAsync("""
            select f.fingerprint,f.severity from jsonb_array_elements_text($1::jsonb) ids(fingerprint)
            join public.findings f using(fingerprint)
            """, ct, ids);
        var byId = severities.OfType<JsonObject>().ToDictionary(r => Text(r, "fingerprint")!, r => Text(r, "severity"));
        foreach (var row in rows)
            if (byId.TryGetValue("file-audit:" + Text(row, "result_id"), out var severity)) row["severity"] = severity;
    }

    private static JsonObject? RuleFact(string tab, JsonObject row, string? severity)
    {
        string? code = Text(row, "rule_code");
        if (code is not ("file-audit.mass-read" or "file-audit.mass-write" or "file-audit.mass-delete"
            or "file-audit.broad-write" or "file-audit.direct-user-rights" or "file-audit.disabled-account-rights" or "file-audit.acl-review"))
            return null;
        var details = row["details"];
        return new JsonObject
        {
            ["kind"] = tab == "mass-operations" ? "mass" : "acl",
            ["rule"] = code,
            ["severity"] = severity,
            ["at"] = row["observed_at"]?.DeepClone(),
            ["id"] = row["id"]?.DeepClone(),
            ["paths"] = details?["distinct_files"]?.DeepClone(),
            ["layer"] = details?["layer"]?.DeepClone(),
            ["subject"] = row["subject_sid"]?.DeepClone(),
            ["path"] = row["path"]?.DeepClone(),
            ["snapshot"] = row["snapshot_id"]?.DeepClone(),
        };
    }

    private static bool IsPreferredFact(JsonObject candidate, JsonObject current)
    {
        static int Rank(string? severity) => severity switch { "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0 };
        int bySeverity = Rank(Text(candidate, "severity")).CompareTo(Rank(Text(current, "severity")));
        if (bySeverity != 0) return bySeverity > 0;
        DateTimeOffset.TryParse(Text(candidate, "at"), out var candidateAt);
        DateTimeOffset.TryParse(Text(current, "at"), out var currentAt);
        return candidateAt > currentAt || candidateAt == currentAt && string.CompareOrdinal(Text(candidate, "id"), Text(current, "id")) > 0;
    }
}
