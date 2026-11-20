using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Storage.Lifecycle;

internal sealed record ResolvedRetentionPeriod(int Days, string Source, bool Defaulted, string? PolicyField = null);
internal sealed record EventRetentionResolution(ResolvedRetentionPeriod RawPayload, ResolvedRetentionPeriod Record,
    ResolvedRetentionPeriod WarmRecord, string? Rollup);

internal sealed partial record LifecyclePolicy
{
    static int ConfiguredDays(string? value, int fallback) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int days) ? days : fallback;

    internal static ResolvedRetentionPeriod ReadOperationalRetention(Func<string, string?> get) =>
        ResolveOperationalRetention("post_collection_jobs", Default with {
            PostCollectionDays = ConfiguredDays(get("ADLOG_POST_COLLECTION_RETENTION_DAYS"), Default.PostCollectionDays)
        });

    internal static ResolvedRetentionPeriod ResolveOperationalRetention(string kind, LifecyclePolicy? policy = null) =>
        kind == "post_collection_jobs" ? new((policy ?? Default).PostCollectionDays, "configuration", false, "post_collection_retention_days") :
        throw new ArgumentException("unknown operational retention kind", nameof(kind));

    // Catalogue periods always win over configuration, including predicate rules.
    internal static EventRetentionResolution ResolveCatalogueRetention(JsonObject? entry, JsonObject? eventRow = null, LifecyclePolicy? policy = null)
    {
        policy ??= Default;
        if (entry?["lifecycle"] is not JsonObject lifecycle)
            return new(new(policy.RawDays, "configuration", true, "raw_retention_days"),
                new(policy.HotDays, "configuration", true, "db_retention_days"),
                new(policy.WarmDays, "configuration", true, "warm_retention_days"), null);
        var raw = new ResolvedRetentionPeriod(CatalogueDays(lifecycle["raw_payload_days"], eventRow), "catalogue", false);
        var record = new ResolvedRetentionPeriod(CatalogueDays(lifecycle["record_days"], eventRow), "catalogue", false);
        var warm = lifecycle["warm_record_days"] is { } value
            ? new ResolvedRetentionPeriod(CatalogueDays(value, eventRow), "catalogue", false)
            : new ResolvedRetentionPeriod(policy.WarmDays, "configuration", true, "warm_retention_days");
        if (lifecycle["rollup"] is { } rollup && (rollup is not JsonValue scalar || !scalar.TryGetValue<string>(out _)))
            throw new ArgumentException("lifecycle rollup must be a string or null");
        return new(raw, record, warm, lifecycle["rollup"]?.GetValue<string>());
    }

    static int CatalogueDays(JsonNode? value, JsonObject? eventRow)
    {
        if (value is JsonValue scalar && scalar.TryGetValue<int>(out int days)) return days;
        if (value is not JsonObject predicate || !predicate.ContainsKey("default"))
            throw new ArgumentException("lifecycle period must be an integer or predicate with default");
        JsonNode? selected = predicate["default"];
        if (predicate["rules"] is { } rules) foreach (var ruleNode in rules.AsArray()) {
            if (ruleNode is not JsonObject rule) throw new ArgumentException("lifecycle predicate rule must be an object");
            if (PredicateMatches(eventRow?[rule["field"]?.ToString() ?? ""], rule["op"]?.ToString() ?? "", rule["value"])) {
                selected = rule["then"]; break;
            }
        }
        return selected is JsonValue result && result.TryGetValue<int>(out days) ? days :
            throw new ArgumentException("lifecycle predicate must resolve to an integer");
    }

    static bool PredicateMatches(JsonNode? actual, string op, JsonNode? expected)
    {
        IEnumerable<JsonNode?> values = expected is JsonArray array ? array : new[] { expected };
        string text = actual?.ToString() ?? "";
        return op switch {
            "equals" or "one_of" => values.Any(v => JsonNode.DeepEquals(actual, v) || actual?.ToString() == v?.ToString()),
            "prefix" => values.Any(v => text.StartsWith(v?.ToString() ?? "None", StringComparison.Ordinal)),
            "suffix" => values.Any(v => text.EndsWith(v?.ToString() ?? "None", StringComparison.Ordinal)),
            "contains" => values.Any(v => text.Contains(v?.ToString() ?? "None", StringComparison.Ordinal)),
            "regex" => values.Any(v => Regex.IsMatch(text, v?.ToString() ?? "None")),
            _ => throw new ArgumentException("unsupported lifecycle predicate operator")
        };
    }
}
