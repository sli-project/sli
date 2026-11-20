using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
namespace Sli.Server.Reporting.V2;

public static class ReportResult
{
    public static readonly IReadOnlySet<string> States = new HashSet<string>(["ok", "empty", "denied", "not_collected", "partial", "processing", "stale", "error"], StringComparer.Ordinal);
    public static string SourceState(string? state) => state switch
    {
        "available" => "ok", "not_authorized" => "denied", "unavailable" or "failed" => "error",
        "empty_unverified" or "coverage_unverified" or "identity_incomplete" => "partial",
        _ => state is not null && States.Contains(state) ? state : "error"
    };
    public static JsonObject Create(string key, string state, JsonArray? items = null, JsonObject? coverage = null,
        JsonObject? collections = null, JsonArray? limitations = null, DateTimeOffset? now = null)
    {
        if (!States.Contains(state)) throw new ReportRequestException("report_state_invalid");
        coverage = coverage?.Copy() ?? []; items = (JsonArray?)items?.DeepClone() ?? [];
        collections = collections?.Copy() ?? []; limitations = (JsonArray?)limitations?.DeepClone() ?? [];
        var issues = (JsonArray?)coverage["source_issues"]?.DeepClone() ?? [];
        var missingSources = (JsonArray?)coverage["missing_sources"]?.DeepClone() ?? [];
        var missingDomains = (JsonArray?)coverage["missing_domains"]?.DeepClone() ?? [];
        foreach (var domain in coverage.Objects("domains"))
        {
            var statuses = new[] { domain.Text("run_status"), domain.Text("section_status"), domain.Text("state") };
            if (!statuses.Intersect(["failed", "cancelled", "error", "unavailable", "timeout", "denied", "partial", "skipped", "not_collected"]).Any() && !(domain.ContainsKey("run_status") && string.IsNullOrEmpty(domain.Text("run_status")))) continue;
            AddUnique(missingDomains, domain["domain_id"]); AddUnique(missingSources, domain["section_name"]);
            string source = string.Join(":", new[] { domain["domain_id"], domain["section_name"] }.Where(n => n is not null).Select(n => n!.ToString()));
            if (source.Length > 0)
            {
                string reason = domain.Text("reason_code");
                if (reason.Length == 0) reason = statuses.Contains("denied") ? "access_denied" : statuses.Intersect(["failed", "cancelled", "error", "unavailable", "timeout"]).Any() ? "source_failed" : statuses.Contains("partial") ? "source_partial" : "source_missing";
                var issue = new JsonObject { ["source"] = source, ["reason"] = reason, ["since_utc"] = (domain["since_utc"] ?? domain["failed_since_utc"])?.DeepClone() };
                if (domain.Text("domain_name").Length > 0) issue["source_name"] = domain.Text("domain_name");
                issues.Add(issue);
            }
        }
        foreach (var (name, reason) in new[] { ("failed", "source_failed"), ("partial", "source_partial"), ("missing", "source_missing"), ("stale", "snapshot_old") })
            foreach (var entry in coverage[name] as JsonArray ?? [])
                if (entry is JsonValue value && value.TryGetValue<string>(out var source) && !issues.OfType<JsonObject>().Any(i => i.Text("source") == source))
                    issues.Add(new JsonObject { ["source"] = source, ["reason"] = reason, ["since_utc"] = coverage["since_utc"]?.DeepClone() });
        foreach (var source in missingSources)
            if (source is JsonValue value && value.TryGetValue<string>(out var text) && !issues.OfType<JsonObject>().Any(i => i.Text("source") == text || i.Text("source").Split(':')[^1] == text))
                issues.Add(new JsonObject { ["source"] = text, ["reason"] = "source_missing", ["since_utc"] = coverage["since_utc"]?.DeepClone() });
        var observed = coverage["observed_at_utc"] ?? coverage["latest_observed_at_utc"];
        var staleSince = coverage["stale_since_utc"]?.DeepClone();
        if (observed is not null && coverage["freshness_threshold_seconds"] is JsonValue threshold && double.TryParse(threshold.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out double seconds) && seconds > 0
            && System.Text.RegularExpressions.Regex.IsMatch(observed.ToString(), @"(?:Z|[+-]\d{2}:?\d{2})$")
            && DateTimeOffset.TryParse(observed.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp))
        {
            try { var expiry = stamp.AddSeconds(seconds); if (expiry < (now ?? DateTimeOffset.UtcNow)) staleSince = expiry.ToString("yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture); }
            catch (ArgumentOutOfRangeException) { }
        }
        if (state is not ("denied" or "error" or "not_collected"))
        {
            string cs = coverage.Text("state");
            if (cs is "failed" or "error" or "unavailable") state = "error";
            else if (cs == "not_collected") state = items.Count > 0 || collections.Any(c => c.Value is JsonArray { Count: > 0 }) ? "partial" : "not_collected";
            else if (cs == "processing" || Truthy(coverage["unprocessed_events"]) || Truthy((coverage["activity"] as JsonObject)?["unprocessed_events"])) state = "processing";
            else if ((cs == "stale" || Truthy(staleSince)) && state is "ok" or "empty" or "stale") state = "stale";
            else if (state is "ok" or "empty" && (missingSources.Count > 0 || missingDomains.Count > 0 || coverage.Text("completeness") == "not_proven" || cs is "partial" or "unknown" or "inactive" or "empty_unverified" or "coverage_unverified")) state = "partial";
        }
        string reasonCode = state switch { "ok" => "query_completed", "empty" => "query_completed_zero_rows", "denied" => "access_denied", "not_collected" => "collection_not_confirmed", "partial" => "coverage_incomplete", "processing" => "import_or_projection_pending", "stale" => "freshness_exceeded", _ => "source_or_storage_error" };
        string reasonText = coverage.Text("reason");
        if (reasonText.Length == 0) reasonText = state == "partial" && Truthy(coverage["truncated"]) ? "result_truncated" : reasonCode;
        return new()
        {
            ["contract_id"] = "sli.report-result.v2", ["report_key"] = key, ["state"] = state,
            ["state_message"] = Message("reports.state." + state),
            ["state_details"] = new JsonObject { ["reason"] = reasonText, ["source"] = coverage["source"]?.DeepClone(), ["stage"] = coverage.Text("stage", "query"),
                ["limitations"] = limitations.DeepClone(), ["missing_sources"] = missingSources, ["missing_domains"] = missingDomains,
                ["observed_at_utc"] = observed?.DeepClone(), ["stale_since_utc"] = staleSince, ["source_issues"] = issues },
            ["items"] = items, ["has_more"] = false, ["next_cursor"] = null, ["filtered_count"] = null,
            ["metrics"] = new JsonArray(), ["series"] = new JsonObject(), ["coverage"] = coverage,
            ["filter_options"] = new JsonObject(), ["limitations"] = limitations, ["window"] = new JsonObject(), ["collections"] = collections
        };
    }
    private static bool Truthy(JsonNode? node) => node is not null && node.ToJsonString() is not ("0" or "false" or "null" or "\"\"" or "[]" or "{}");
    private static void AddUnique(JsonArray array, JsonNode? value) { if (value is not null && !array.Any(n => JsonNode.DeepEquals(n, value))) array.Add(value.DeepClone()); }
    private static readonly Lazy<IReadOnlyDictionary<string,string>> Russian = new(() => Catalog("ru"));
    private static readonly Lazy<IReadOnlyDictionary<string,string>> English = new(() => Catalog("en"));
    private static IReadOnlyDictionary<string,string> Catalog(string locale)
    {
        using var stream = typeof(ReportResult).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server." + locale + ".json")!;
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
    }
    public static JsonObject Message(string code, bool english = false)
    {
        var catalog = english ? English.Value : Russian.Value;
        return new() { ["code"] = code, ["params"] = new JsonObject(), ["text"] = catalog.GetValueOrDefault(code, code) };
    }
}
