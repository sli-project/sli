using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Compatibility;

namespace Sli.Server.Workspace;

internal sealed record DashboardRiskSql(string Sql, object[] Parameters, bool Exact);

// dashboard_fast: cache the current semantic catalogue, excluding presentation fields.
internal sealed class DashboardRiskProjection(Func<JsonObject[]> entries)
{
    static readonly Lazy<JsonObject[]> Catalog = new(() =>
    {
        using var stream = typeof(DashboardRiskProjection).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        return JsonNode.Parse(stream)!["entries"]!.AsArray().OfType<JsonObject>().ToArray();
    });
    internal static readonly DashboardRiskProjection Bundled = new(() => Catalog.Value);
    readonly object sync = new();
    string? fingerprint;
    DashboardRiskSql? compiled;
    static string Text(JsonNode? value) => value?.ToString() ?? "";
    static string Fold(JsonNode? value) => UnicodeLower.Lower(PythonText.Strip(Text(value)));
    static string First(params JsonNode?[] values) => values.Select(Text).FirstOrDefault(s => s.Length > 0) ?? "";
    static int Id(JsonObject entry) => int.Parse(First(entry["event_id"], JsonValue.Create(0)), System.Globalization.CultureInfo.InvariantCulture);

    internal static string Fingerprint(IEnumerable<JsonObject> entries)
    {
        var rules = entries.Select(e => new JsonObject
        {
            ["event_id"] = Id(e), ["provider_name"] = Fold(e["provider_name"]), ["channel"] = Fold(e["channel"]),
            ["base_risk"] = Fold(JsonValue.Create(First(e["base_risk"], e["severity"], JsonValue.Create("info")))),
            ["risk_rules"] = new JsonArray((e["card"]?["risk_rules"] as JsonArray ?? []).OfType<JsonObject>().Select(r => (JsonNode)new JsonObject
            {
                ["severity"] = Fold(r["severity"]), ["all"] = r["all"]?.DeepClone() ?? new JsonArray()
            }).ToArray())
        }).OrderBy(e => Id(e)).ThenBy(e => Text(e["provider_name"]), StringComparer.Ordinal)
            .ThenBy(e => Text(e["channel"]), StringComparer.Ordinal)
            .ThenBy(e => CanonicalJson.Serialize(e["risk_rules"]), StringComparer.Ordinal).ToArray();
        var payload = new JsonObject { ["catalog_schema_version"] = 1, ["compiler_version"] = 2, ["rules"] = new JsonArray(rules.Cast<JsonNode>().ToArray()) };
        return Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(payload)));
    }

    internal DashboardRiskSql Get()
    {
        lock (sync)
        {
            var snapshot = entries().Select(e => e.DeepClone().AsObject()).ToArray();
            string next = Fingerprint(snapshot);
            if (compiled is not null && next == fingerprint) return compiled;
            var result = Compile(snapshot);
            fingerprint = next;
            return compiled = result;
        }
    }

    static string Risk(string value, string fallback) => Fold(JsonValue.Create(value)) switch
    {
        "important" or "warning" or "warn" => "medium",
        "critical" => "critical", "high" => "high", "medium" => "medium", "low" => "low", "info" => "info", "unknown" => "unknown", _ => fallback
    };

    internal static DashboardRiskSql Compile(IEnumerable<JsonObject> entries)
    {
        var cases = new List<string>();
        var parameters = new List<object>();
        bool exact = true;
        foreach (var entry in entries.OrderByDescending(e => (Fold(e["channel"]).Length > 0 ? 1 : 0) + (Fold(e["provider_name"]).Length > 0 ? 1 : 0)).ThenByDescending(Id))
        {
            var match = new List<string> { "e.event_id = ?" };
            parameters.Add(Id(entry));
            foreach (string key in new[] { "channel", "provider_name" })
                if (Fold(entry[key]) is { Length: > 0 } value)
                { match.Add($"lower(coalesce(e.{key}, '')) = ?"); parameters.Add(value); }
            string baseRisk = Risk(First(entry["base_risk"], entry["severity"]), "info");
            string riskSql = "?";
            var riskParameters = new List<object> { baseRisk };
            foreach (var rule in (entry["card"]?["risk_rules"] as JsonArray ?? []).OfType<JsonObject>().Reverse())
            {
                string severity = Risk(First(rule["severity"], JsonValue.Create(baseRisk)), baseRisk);
                if (severity == baseRisk) continue;
                var checks = new List<string>();
                var values = new List<object>();
                bool supported = true;
                foreach (var condition in (rule["all"] as JsonArray ?? []).OfType<JsonObject>())
                {
                    bool Truth(string key) => condition[key] is { } v && v.ToString() is not ("" or "false" or "0");
                    if (Truth("dc")) { checks.Add("lower(coalesce(s.hostname, '')) like ?"); values.Add("dc%"); }
                    var tokens = (condition["contains_any"] as JsonArray ?? []).Select(v => UnicodeLower.Lower(Text(v))).ToArray();
                    if (tokens.Length > 0)
                    {
                        checks.Add("(" + string.Join(" or ", tokens.Select(_ => "lower(coalesce(e.event_data_json, '')) like ?")) + ")");
                        values.AddRange(tokens.Select(t => (object)("%" + CanonicalJson.Serialize(JsonValue.Create(t), ensureAscii: false)[1..^1] + "%")));
                    }
                    if (Truth("microsoft_namespace") || Truth("machine_or_system") || condition.Any(p => p.Key is not ("dc" or "contains_any" or "role" or "fields" or "microsoft_namespace" or "machine_or_system"))) supported = false;
                }
                if (!supported) { exact = false; continue; }
                string conditionSql = checks.Count == 0 ? "(1 = 1)" : "(" + string.Join(" and ", checks) + ")";
                riskSql = $"case when {conditionSql} then ? else {riskSql} end";
                riskParameters = [.. values, severity, .. riskParameters];
            }
            cases.Add("when (" + string.Join(" and ", match) + ") then " + riskSql);
            parameters.AddRange(riskParameters);
        }
        string sql = cases.Count == 0 ? "?" : "case " + string.Join(" ", cases) + " else ? end";
        parameters.Add("unknown");
        int index = 0;
        sql = System.Text.RegularExpressions.Regex.Replace(sql, "\\?", _ => "@risk" + index++);
        return new(sql, parameters.ToArray(), exact);
    }
}
