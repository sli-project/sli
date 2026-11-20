using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Reporting.V2;

// Mirrors core.messages: only declared vocabulary is presentation; observations remain data.
internal static class ReportPresentation
{
    internal static readonly IReadOnlyDictionary<string, string> Russian = Catalog("ru");
    internal static readonly IReadOnlyDictionary<string, string> English = Catalog("en");
    static readonly JsonObject DateParams = Resource("Sli.Server.Reporting.V2.date-params.json");
    static readonly HashSet<string> Coded = ["ad.users.v2", "ad.computers.v6", "ad.infrastructure", "security.problems"];
    static JsonObject Resource(string name)
    {
        using var stream = typeof(ReportPresentation).Assembly.GetManifestResourceStream(name)!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    static IReadOnlyDictionary<string, string> Catalog(string locale) => Resource("Sli.Server.Access.Administration.server." + locale + ".json")
        .ToDictionary(p => p.Key, p => p.Value!.GetValue<string>(), StringComparer.Ordinal);
    static string? Text(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
    internal static JsonObject? Message(string code, bool english, JsonObject? parameters = null)
    {
        if (!(english ? English : Russian).TryGetValue(code, out var template)) return null;
        parameters = parameters?.DeepClone().AsObject() ?? new();
        var display = parameters.DeepClone().AsObject();
        foreach (var (name, kind) in DateParams[code] as JsonObject ?? new())
            if (parameters.ContainsKey(name)) display[name] = Date(Text(parameters[name]), english, kind!.ToString());
        string text = Regex.Replace(template, @"\{(\w+)\}", m => display.ContainsKey(m.Groups[1].Value)
            ? Scalar(display[m.Groups[1].Value]) : m.Value);
        return new() { ["code"] = code, ["params"] = parameters, ["text"] = text };
    }
    static string Scalar(JsonNode? node) => node is null ? "None" : node.GetValueKind() == JsonValueKind.True ? "True" : node.GetValueKind() == JsonValueKind.False ? "False" : node.ToString();
    static string Date(string? value, bool english, string kind)
    {
        DateTime instant;
        if (kind == "date")
        {
            if (!DateTime.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out instant)) return "—";
        }
        else
        {
            if (value is null || !Regex.IsMatch(value, @"(?:Z|[+-]\d{2}:?\d{2})$") || !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp)) return "—";
            instant = kind == "local_datetime" ? stamp.DateTime : stamp.UtcDateTime;
        }
        return instant.ToString(english ? kind == "date" ? "MMM d, yyyy" : "MMM d, yyyy, h:mm tt" : kind == "date" ? "dd.MM.yyyy" : "dd.MM.yyyy, HH:mm", CultureInfo.GetCultureInfo("en-US"));
    }
    internal static JsonObject Apply(JsonObject payload, bool english)
    {
        var result = payload.DeepClone().AsObject();
        if (Text(result["state"]) is {} state && (result["contract_id"]?.ToString() == "sli.report-result.v2" || result.ContainsKey("report_key")))
            if (Message("reports.state." + state, english) is {} message) result["state_message"] = message;
        string? key = new[] { Text(result["report_key"]), Text(result["key"]) }.FirstOrDefault(k => k is not null && Coded.Contains(k));
        if (Text(result["report_key"]) == "security.events.chains") Localize(result, english);
        if (key is null) return result;
        string prefix = "reports.v2." + key;
        Metadata(result, prefix, english);
        var shared = new JsonObject();
        var coverage = result["coverage"] as JsonObject;
        if (coverage?["hygiene_policy"] is JsonObject policy && policy.Count > 0)
        {
            shared["password_days"] = policy["password_age"]?.DeepClone() ?? JsonValue.Create("");
            shared["inactivity_days"] = policy["inactivity"]?.DeepClone() ?? JsonValue.Create("");
        }
        if (key == "ad.users.v2")
        {
            shared["count"] = coverage?["unknown_accounts"]?.DeepClone() ?? JsonValue.Create("");
            foreach (string field in new[] { "password_age", "inactivity" }) shared[field] = coverage?["hygiene_policy"]?[field]?.DeepClone() ?? JsonValue.Create("");
        }
        Limitations(result, prefix, shared, english);
        if (result["state_details"] is JsonObject details) Limitations(details, prefix, shared, english);
        if (result["branches"] is JsonObject branches) foreach (var branch in branches.Select(p => p.Value).OfType<JsonObject>()) Limitations(branch, prefix, shared, english);
        Localize(result, english);
        if (key == "ad.computers.v6") foreach (var row in (result["items"] as JsonArray ?? []).OfType<JsonObject>())
            if (row["reasons"] is JsonArray reasons && reasons.OfType<JsonObject>().Any(r => r["presentation_messages"] is JsonObject fields && fields.ContainsKey("label")))
                row["reason_text"] = reasons.Count == 0 ? null : string.Join(", ", reasons.Select(r => r?["label"]?.ToString()));
        return result;
    }
    static void Set(JsonObject value, string field, string code, bool english, JsonObject? parameters = null)
    {
        if (Message(code, english, parameters) is not {} message) return;
        if (value["presentation_messages"] is not JsonObject) value["presentation_messages"] = new JsonObject();
        value["presentation_messages"]![field] = message;
        value[field] = message["text"]!.DeepClone();
    }
    static void Metadata(JsonObject value, string prefix, bool english)
    {
        foreach (string field in new[] { "title", "description", "label", "note", "question", "denominator", "freshness_expectation", "caption" })
            if (Text(value[field]) is not null) Set(value, field, field == "label" && new[] { ".row_links.", ".options.", ".series." }.Any(prefix.Contains) ? prefix : prefix + "." + field, english);
        if (value["labels"] is JsonObject labels)
        {
            var messages = new JsonObject();
            foreach (string label in labels.Select(p => p.Key).ToArray()) if (Message(prefix + ".labels." + label, english) is {} message) { messages[label] = message; labels[label] = message["text"]!.DeepClone(); }
            if (messages.Count > 0) value["labels_messages"] = messages;
        }
        foreach (var (field, identity) in new[] { ("columns", "key"), ("params", "key"), ("metrics", "key"), ("options", "value"), ("row_links", "href"), ("views", "key"), ("series", "path") })
            foreach (var item in (value[field] as JsonArray ?? []).OfType<JsonObject>()) if (Text(item[identity]) is {} id) Metadata(item, prefix + "." + field + "." + id, english);
        if (value["filter_options"] is JsonObject filters) foreach (var (param, options) in filters)
            foreach (var option in (options as JsonArray ?? []).OfType<JsonObject>()) if (Text(option["value"]) is {} id) Metadata(option, prefix + ".params." + param + ".options." + id, english);
        foreach (string field in new[] { "detail", "intent" }) if (value[field] is JsonObject child) Metadata(child, prefix + "." + field, english);
        if (value["presets"] is JsonArray presets) foreach (var item in presets.OfType<JsonObject>())
            if (item["params"] is JsonObject parameters) Set(item, "label", prefix + ".presets." + Sli.Agent.Protocol.CanonicalJson.Serialize(parameters, false), english);
    }
    static void Limitations(JsonObject value, string prefix, JsonObject shared, bool english)
    {
        foreach (var item in (value["limitations"] as JsonArray ?? []).OfType<JsonObject>())
        {
            string code = prefix + ".limitations." + Text(item["code"]);
            if (!(english ? English : Russian).TryGetValue(code, out var template)) continue;
            var parameters = shared.DeepClone().AsObject();
            foreach (var (name, parameter) in item["params"] as JsonObject ?? new()) parameters[name] = parameter?.DeepClone() ?? JsonValue.Create("");
            if (Regex.Matches(template, @"\{(\w+)\}").All(m => parameters.ContainsKey(m.Groups[1].Value))) Set(item, "text", code, english, parameters);
        }
    }
    static void Localize(JsonNode? value, bool english)
    {
        if (value is JsonArray array) { foreach (var item in array) Localize(item, english); return; }
        if (value is not JsonObject obj) return;
        foreach (var child in obj.Select(p => p.Value).ToArray()) Localize(child, english);
        JsonObject? Resolve(JsonNode? envelope) => envelope is JsonObject e && Text(e["code"]) is {} code
            ? e["rendered"]?.ToString() == "true" ? e.DeepClone().AsObject() : Message(code, english, e["params"] as JsonObject) : null;
        if (obj["presentation_messages"] is JsonObject fields) foreach (var (field, envelope) in fields.ToArray())
            if (Resolve(envelope) is {} message) { fields[field] = message; obj[field] = message["text"]!.DeepClone(); }
        foreach (string field in new[] { "status_message", "severity_message" }) if (Resolve(obj[field]) is {} message) obj[field] = message;
        if (obj["labels_messages"] is JsonObject labels)
        {
            if (obj["labels"] is not JsonObject) obj["labels"] = new JsonObject();
            foreach (var (field, envelope) in labels.ToArray()) if (Resolve(envelope) is {} message) { labels[field] = message; obj["labels"]![field] = message["text"]!.DeepClone(); }
        }
        if (obj["entity_messages"] is JsonArray entities)
        {
            for (int i = 0; i < entities.Count; i++) if (Resolve(entities[i]) is {} message) entities[i] = message;
            obj["entity_text"] = entities.Count == 0 ? null : string.Join(", ", entities.Select(e => e is JsonObject entity ? entity["text"]?.ToString() : e?.ToString()));
        }
    }
}
