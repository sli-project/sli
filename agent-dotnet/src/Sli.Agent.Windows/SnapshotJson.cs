using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

internal static class SnapshotJson
{
    public static JsonNode? Copy(JsonNode? n) => n?.DeepClone();
    public static string Text(JsonNode? n, string fallback = "") => JsonRead.TryString(n, out var s) ? s : fallback;
    public static long Int(JsonNode? n, long fallback = 0) => n is null ? fallback : long.Parse(n.ToString(), CultureInfo.InvariantCulture);
    public static bool Flag(JsonNode? n) => n is JsonValue v && v.TryGetValue<bool>(out var b) && b;
    public static IEnumerable<JsonNode> Rows(JsonNode? n) => n is JsonArray a ? a.Where(x => x is not null).Select(x => x!) : [];
    public static IEnumerable<JsonNode> Values(JsonNode? n) => n is null ? [] : n is JsonArray ? Rows(n) : [n];
    public static JsonArray Array(IEnumerable<string> values) => new(values.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
    public static JsonArray Array(IEnumerable<JsonNode> values) => new(values.Select(n => n.DeepClone()).ToArray());
    public static string Stamp(DateTimeOffset now) => Iso8601.Format(now).Replace("+00:00", "Z", StringComparison.Ordinal);
    public static string? Utc(JsonNode? n)
    {
        var value = n?.ToString();
        if (value is null or "" or "0" or "9223372036854775807") return null;
        if (long.TryParse(value, out var ticks)) return Stamp(DateTimeOffset.FromFileTime(ticks / 10 * 10));
        if (!System.Text.RegularExpressions.Regex.IsMatch(value, @"(?:Z|[+-]\d{2}:\d{2})\z")
            || !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date)) throw new FormatException();
        return Stamp(date);
    }
    public static string Hash(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    public static string StableGuid(string s)
    {
        var b = SHA256.HashData(Encoding.UTF8.GetBytes(s.ToLowerInvariant()))[..16]; b[7] = (byte)((b[7] & 15) | 64); b[8] = (byte)((b[8] & 63) | 128);
        return new Guid(b).ToString();
    }
    public static JsonObject Bundle(JsonObject config, string observed, string runId, JsonObject scope, JsonArray records, JsonArray sections) => new()
    {
        ["schema_version"] = "ad-context-bundle/v1", ["source_pack_id"] = "sli.windows.ad-context", ["source_pack_version"] = "0.9.0",
        ["run_id"] = runId, ["mode"] = config["search_bases"]!.AsArray().Count == 0 ? "full" : "targeted",
        ["domain"] = new JsonObject { ["sid"] = Copy(config["domain_sid"]), ["dns_name"] = Copy(config["domain_dns"]) },
        ["scope"] = scope, ["observed_at_utc"] = observed, ["records"] = records, ["sections"] = sections
    };
}
