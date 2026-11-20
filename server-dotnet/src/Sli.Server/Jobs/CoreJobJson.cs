using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;

namespace Sli.Server.Jobs;

public sealed class CoreJobContractException(string code) : Exception(code);
public sealed class CoreJobLeaseLost() : Exception("job_lease_lost");
public sealed class CoreJobConflict() : Exception("job_identity_conflict");

public static class CoreJobJson
{
    public static string Digest(JsonNode? value) => Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(value)));
    public static string Text(this JsonNode node, string field) => node[field]?.GetValueKind() == JsonValueKind.String
        ? node[field]!.GetValue<string>() : throw new CoreJobContractException("manifest_shape_invalid");
    public static long Integer(this JsonNode node) => node.Deserialize<long>();
    public static double Number(this JsonNode node) => node.Deserialize<double>();
    public static JsonObject Pick(JsonObject value, params string[] fields)
    {
        var result = new JsonObject();
        foreach (var field in fields) result[field] = value[field]?.DeepClone();
        return result;
    }
    internal static JsonObject Resource(string name)
    {
        using var stream = typeof(CoreJobJson).Assembly.GetManifestResourceStream("Sli.Server.Jobs." + name)
            ?? throw new CoreJobContractException("handler_version_unavailable");
        return JsonNode.Parse(stream)!.AsObject();
    }

    // The vocabulary used by plugin_architecture_v3.json, matching plugin_validation.validate_shape.
    public static void Validate(JsonNode? value, JsonObject node, JsonObject schema)
    {
        void Invalid() => throw new CoreJobContractException("manifest_shape_invalid");
        if (node["$ref"] is JsonNode reference)
        { Validate(value, schema["$defs"]![reference.GetValue<string>().Split('/')[^1]]!.AsObject(), schema); return; }
        if (node["oneOf"] is JsonArray options)
        {
            int count = 0;
            foreach (var option in options)
                try { Validate(value, option!.AsObject(), schema); count++; } catch (CoreJobContractException) { }
            if (count != 1) Invalid();
        }
        if (node["type"] is JsonNode declared)
        {
            var types = declared is JsonArray list ? list.Select(x => x!.GetValue<string>()) : [declared.GetValue<string>()];
            bool Matches(string type) => type switch
            {
                "object" => value is JsonObject, "array" => value is JsonArray, "null" => value is null,
                "string" => value?.GetValueKind() == JsonValueKind.String,
                "boolean" => value?.GetValueKind() is JsonValueKind.True or JsonValueKind.False,
                "integer" => value?.GetValueKind() == JsonValueKind.Number && Regex.IsMatch(value.ToJsonString(), @"^-?[0-9]+$"),
                _ => false
            };
            if (!types.Any(Matches)) Invalid();
        }
        if (node.ContainsKey("const") && !JsonNode.DeepEquals(value, node["const"])) Invalid();
        if (node["enum"] is JsonArray values && !values.Any(x => JsonNode.DeepEquals(value, x))) Invalid();
        if (value is null) return;
        if (value is JsonObject obj)
        {
            var properties = node["properties"] as JsonObject ?? new();
            if (node["required"] is JsonArray required && required.Any(x => !obj.ContainsKey(x!.GetValue<string>()))) Invalid();
            foreach (var (key, item) in obj)
            {
                if (node["propertyNames"] is JsonObject names) Validate(JsonValue.Create(key), names, schema);
                if (properties[key] is JsonObject definition) Validate(item, definition, schema);
                else if (node["additionalProperties"] is JsonObject additional) Validate(item, additional, schema);
                else if (node["additionalProperties"]?.GetValueKind() == JsonValueKind.False) Invalid();
            }
        }
        if (value is JsonArray array)
        {
            if (array.Count < (node["minItems"]?.GetValue<int>() ?? 0) || array.Count > (node["maxItems"]?.GetValue<int>() ?? int.MaxValue)) Invalid();
            if (node["uniqueItems"]?.GetValue<bool>() == true && array.Select(Digest).Distinct().Count() != array.Count) Invalid();
            foreach (var item in array) Validate(item, node["items"] as JsonObject ?? new(), schema);
        }
        if (value.GetValueKind() == JsonValueKind.String)
        {
            string text = value.GetValue<string>();
            int length = text.EnumerateRunes().Count();
            if (length < (node["minLength"]?.GetValue<int>() ?? 0) || length > (node["maxLength"]?.GetValue<int>() ?? int.MaxValue)) Invalid();
            if (node["pattern"] is JsonNode pattern && !Regex.IsMatch(text, pattern.GetValue<string>(), RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1))) Invalid();
        }
        if (value.GetValueKind() == JsonValueKind.Number)
        {
            var number = System.Numerics.BigInteger.Parse(value.ToJsonString(), System.Globalization.CultureInfo.InvariantCulture);
            if (node["minimum"] is JsonNode min && number < min.GetValue<long>() || node["maximum"] is JsonNode max && number > max.GetValue<long>()) Invalid();
        }
    }
}
