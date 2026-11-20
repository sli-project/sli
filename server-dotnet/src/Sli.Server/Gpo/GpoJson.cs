using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using System.Text;
using Sli.Agent.Protocol;

namespace Sli.Server.Gpo;

internal static class GpoJson
{
    internal static JsonObject Metadata { get; } = ReadMetadata();
    static JsonObject ReadMetadata()
    {
        using var stream = typeof(GpoJson).Assembly.GetManifestResourceStream("Sli.Server.Gpo.declaration.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    internal static string Text(this JsonNode? node, string key = "") => (key.Length == 0 ? node : node?[key])?.ToString() ?? "";
    internal static IEnumerable<JsonObject> Rows(this JsonNode? node, string key = "") => (key.Length == 0 ? node : node?[key]) is JsonArray a ? a.OfType<JsonObject>() : [];
    internal static JsonArray Array(IEnumerable<JsonNode> rows) => new(rows.Select(r => r.DeepClone()).ToArray());
    internal static string Hash(JsonNode? node) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(node, ensureAscii:false))));
    internal static long Number(this JsonNode? node, string key = "") => long.TryParse(node.Text(key), NumberStyles.Integer, CultureInfo.InvariantCulture, out long n) ? n : 0;
    internal static bool True(this JsonNode? node, string key) => node?[key]?.GetValueKind() == JsonValueKind.True;
    internal static JsonObject Copy(this JsonObject node) => (JsonObject)node.DeepClone();
    internal static bool Contains(JsonNode? node, string query) => query.Length == 0 || Fold(CanonicalJson.Serialize(node, ensureAscii:false)).Contains(Fold(query), StringComparison.Ordinal);
    internal static string Fold(string text)=>Sli.Server.Agents.Registry.UnicodeCaseFold.Fold(text);
    internal static DateTimeOffset Stamp(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime();
    internal static string Iso(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + (value.Ticks % TimeSpan.TicksPerSecond == 0 ? "" : value.ToString(".ffffff", CultureInfo.InvariantCulture)) + "+00:00";
}
