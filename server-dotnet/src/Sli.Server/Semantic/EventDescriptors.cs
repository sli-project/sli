using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Storage.Lifecycle;
using static Sli.Server.Semantic.EventCatalogQuality;

namespace Sli.Server.Semantic;

// Source-neutral descriptor lookup and storage_policy.py retention resolution.
internal sealed class EventDescriptors(JsonObject data, string legacySource = "sli.windows.ad-dc")
{
    internal static JsonObject Load()
    {
        using var stream = typeof(EventDescriptors).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    internal JsonObject? Lookup(string source, string stream, string eventKey, string? provider = null, bool semantic = false)
    {
        static string Norm(string s) => UnicodeLower.Lower(s.Trim());
        var entry = Entries(data).LastOrDefault(e =>
        {
            bool v2 = new[] { "source", "stream", "event_key" }.Any(e.ContainsKey);
            return Norm(v2 ? Text(e["source"]) : legacySource) == Norm(source) &&
                Norm(Text(e[v2 ? "stream" : "channel"])) == Norm(stream) && Norm(Text(e[v2 ? "event_key" : "event_id"])) == Norm(eventKey);
        });
        if (entry is null || semantic && (Text(entry["provider_name"]).Trim().Length == 0 || Norm(Text(entry["provider_name"])) != Norm(provider ?? ""))) return null;
        return (JsonObject)entry.DeepClone();
    }
    internal JsonObject Resolve(string source, string stream, string eventKey, LifecyclePolicy? policy = null, JsonObject? eventData = null) =>
        ResolveRetention(Lookup(source, stream, eventKey), policy, eventData);

    internal static JsonObject ResolveRetention(JsonObject? entry, LifecyclePolicy? policy = null, JsonObject? eventData = null)
    {
        JsonObject? lifecycle = entry?["lifecycle"] as JsonObject;
        int hot = policy?.HotDays ?? 7, warm = policy?.WarmDays ?? 365;
        JsonObject Period(string key, int fallback, string policyField)
        {
            bool declared = lifecycle is not null && (key != "warm_record_days" || lifecycle[key] is not null);
            return new() { ["days"] = declared ? Days(lifecycle![key], eventData ?? new()) : fallback,
                ["source"] = declared ? "catalogue" : "configuration", ["defaulted"] = !declared, ["policy_field"] = declared ? null : policyField };
        }
        JsonObject promotion;
        if (lifecycle?["promotion"] is null)
            promotion = new() { ["version"] = "legacy-safe-default", ["archive_requirement"] = "archive_required", ["post_promotion_disposition"] = "preserve_source",
                ["read_representation"] = "archived_atomic", ["high_volume"] = false, ["semantic_role"] = null, ["hot_need"] = null, ["warm_value"] = null, ["executable_lifecycle"] = null, ["budget"] = null };
        else
        {
            var errors = new List<string>();
            PromotionErrors(lifecycle, (code, _) => errors.Add(code));
            if (errors.Contains("lifecycle_direct_retention_requires_no_archive")) throw new ArgumentException("direct retention requires no_archive");
            if (errors.Count > 0) throw new ArgumentException(errors[0]);
            promotion = new();
            foreach (string key in PromotionFields) promotion[key] = lifecycle["promotion"]![key]?.DeepClone();
        }
        if (lifecycle?["rollup"] is { } rollup && !IsString(rollup)) throw new ArgumentException("lifecycle rollup must be a string or null");
        if (lifecycle?["rollup_role"] is { } role && Text(role) is not ("open" or "close" or "boot_scope")) throw new ArgumentException("lifecycle rollup_role is invalid");
        var result = new JsonObject { ["raw_payload"] = Period("raw_payload_days", 2, "raw_retention_days"), ["record"] = Period("record_days", hot, "db_retention_days"),
            ["warm_record"] = Period("warm_record_days", warm, "warm_retention_days"), ["rollup"] = lifecycle?["rollup"]?.DeepClone(),
            ["rollup_role"] = lifecycle?["rollup_role"]?.DeepClone(), ["promotion"] = promotion };
        result["policy_fingerprint"] = Fingerprint(result);
        result["catalogue_entry_found"] = entry is not null;
        return result;
    }
    private static long Days(JsonNode? value, JsonObject eventData)
    {
        if (Integer(value, out long days)) return days;
        if (value is not JsonObject p || !p.ContainsKey("default")) throw new ArgumentException("lifecycle period must be an integer or predicate with default");
        JsonNode? selected = p["default"];
        foreach (var node in p["rules"] as JsonArray ?? [])
        {
            if (node is not JsonObject rule) throw new ArgumentException("lifecycle predicate rule must be an object");
            var actual = eventData[Text(rule["field"])];
            var expected = rule["value"] is JsonArray array ? array.ToArray() : new[] { rule["value"] };
            bool Match(JsonNode? v) => Text(rule["op"]) switch
            {
                "equals" or "one_of" => JsonNode.DeepEquals(actual, v) || Text(actual) == Text(v),
                "prefix" => Text(actual).StartsWith(Text(v), StringComparison.Ordinal),
                "suffix" => Text(actual).EndsWith(Text(v), StringComparison.Ordinal),
                "contains" => Text(actual).Contains(Text(v), StringComparison.Ordinal),
                "regex" => Regex.IsMatch(Text(actual), Text(v), RegexOptions.CultureInvariant),
                _ => throw new ArgumentException("unsupported lifecycle predicate operator")
            };
            if (expected.Any(Match)) { selected = rule["then"]; break; }
        }
        return Integer(selected, out days) ? days : throw new ArgumentException("lifecycle predicate must resolve to an integer");
    }
}
