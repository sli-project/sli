using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Access.Requests;

internal static class RequestJson
{
    internal static long SessionId(Principal actor) => actor.Type == "session" ? actor.Id : throw new AccessRequestException("authenticated_user_required", 403);
    internal static AssignmentActor Actor(Principal principal) => new(principal.Type, principal.Id);
    internal static bool True(JsonElement value, string key) => value.Get(key).ValueKind == JsonValueKind.True;
    internal static string Text(JsonElement value, string key, string fallback = "") => AssignmentValidation.Text(value, key, fallback);
    internal static string Strip(string value) => AssignmentValidation.Strip(value);
    internal static JsonElement Empty => JsonSerializer.SerializeToElement(new { });
    internal static string Iso(DateTimeOffset time) => AssignmentAudit.Stamp(time).Replace(' ', 'T');
    internal static IEnumerable<string> Strings(JsonElement value, string[] fallback)
    {
        if (value.ValueKind == JsonValueKind.Undefined) return fallback;
        return value.ValueKind switch
        {
            JsonValueKind.Array => value.EnumerateArray().Select(AssignmentValidation.String).ToArray(),
            JsonValueKind.Object => value.EnumerateObject().Select(p => p.Name).ToArray(),
            JsonValueKind.String => value.GetString()!.EnumerateRunes().Select(r => r.ToString()).ToArray(),
            _ => throw new IterableTypeException(value.ValueKind switch
            {
                JsonValueKind.Null => "NoneType",
                JsonValueKind.True or JsonValueKind.False => "bool",
                _ => value.GetRawText().IndexOfAny(['.', 'e', 'E']) >= 0 ? "float" : "int"
            })
        };
    }
    // Source TypeError is a 400 only where the route explicitly catches it.
    internal sealed class IterableTypeException(string type) : Exception("'" + type + "' object is not iterable");
    internal static string[] Sorted(JsonElement value, string[] fallback) => Strings(value, fallback).Where(s => s.Length > 0).Distinct().Order(StringComparer.Ordinal).ToArray();

    internal static JsonElement NormalizeScope(JsonElement value, IReadOnlySet<string> allowed)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new AccessRequestException("request_scope_not_supported");
        var raw = value.EnumerateObject().Any() ? value : JsonSerializer.SerializeToElement(new { kind = "all" });
        string kind = Strip(Text(raw, "kind")).ToLowerInvariant();
        if (!allowed.Contains(kind)) throw new AccessRequestException("request_scope_not_supported");
        if (kind == "all") return JsonSerializer.SerializeToElement(new { kind = "all" });
        string key = kind == "channel" ? "values" : "ids";
        var values = raw.Get(key);
        if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() is < 1 or > 100
            || values.Items().Any(v => v.ValueKind != JsonValueKind.String || Strip(v.GetString()!).Length == 0 || v.GetString()!.EnumerateRunes().Count() > 255))
            throw new AccessRequestException("invalid_request_scope");
        return JsonSerializer.SerializeToElement(new Dictionary<string, object> { ["kind"] = kind,
            [key] = values.Items().Select(v => Strip(v.GetString()!)).Distinct().Order(StringComparer.Ordinal).ToArray() });
    }

    internal static bool Subset(JsonElement granted, JsonElement requested)
    {
        string kind = requested.Text("kind"), grantedKind = granted.Text("kind");
        if (kind == "all") return grantedKind is "all" or "domain" or "server" or "channel";
        if (kind != grantedKind) return false;
        string key = kind == "channel" ? "values" : "ids";
        return granted.Get(key).Strings().IsSubsetOf(requested.Get(key).Strings());
    }

    internal static JsonElement Row(string json)
    {
        var row = JsonNode.Parse(json)!.AsObject();
        Format(row, "requested_valid_until", "granted_valid_until", "decided_at", "created_at", "updated_at");
        return JsonSerializer.SerializeToElement(row);
    }
    internal static JsonElement RawReport(JsonElement value)
    {
        var report = JsonNode.Parse(value.GetRawText())!.AsObject();
        Format(report, "access_valid_until", "preference_updated_at");
        if (report["request"] is JsonObject request) Format(request, "created_at", "updated_at");
        foreach (string field in new[] { "sources", "grants" })
            if (report[field] is JsonArray rows) foreach (var row in rows.OfType<JsonObject>()) Format(row, "valid_from", "valid_until");
        return JsonSerializer.SerializeToElement(report);
    }
    private static void Format(JsonObject row, params string[] fields)
    {
        foreach (string key in fields)
            if (row[key] is JsonValue value && value.TryGetValue<string>(out var stamp)) row[key] = AssignmentAudit.Stamp(DateTimeOffset.Parse(stamp, CultureInfo.InvariantCulture));
    }

    internal static object Present(JsonElement payload, string language)
    {
        // Reuse builtin metadata translation without another catalogue. Source
        // request rows identify versions/names using report_version/report_name.
        var body = JsonNode.Parse(payload.GetRawText())!.AsObject();
        if (body["items"] is not JsonArray rows) return body;
        foreach (var row in rows.OfType<JsonObject>())
        { row["version"] = row["report_version"]?.DeepClone(); row["name"] = row["report_name"]?.DeepClone(); }
        var rendered = JsonSerializer.SerializeToNode(AccessReadPresentation.Apply(body, "grant-options", language))!.AsObject();
        foreach (var row in rendered["items"]!.AsArray().OfType<JsonObject>())
        {
            row["report_name"] = row["name"]?.DeepClone(); row.Remove("name"); row.Remove("version");
            if (row["presentation_messages"] is JsonObject messages && messages["name"] is { } name)
            { messages["report_name"] = name.DeepClone(); messages.Remove("name"); }
        }
        return rendered;
    }
}
