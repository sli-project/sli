using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Globalization;
using Sli.Server.Domains;

namespace Sli.Server.Access.Administration;

// Only the frozen response_messages declared access metadata slots are visited.
// Owner-authored names, later versions, audit reasons and scope values remain data.
public static class AccessReadPresentation
{
    private static readonly Lazy<Dictionary<string, string>> Russian = new(() => Catalog("ru"));
    private static readonly Lazy<Dictionary<string, string>> English = new(() => Catalog("en"));
    private static Dictionary<string, string> Catalog(string locale)
    {
        using var stream = typeof(AccessReadPresentation).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server." + locale + ".json")
            ?? throw new InvalidOperationException("Access presentation catalog is missing.");
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream) ?? throw new InvalidOperationException("Invalid presentation catalog.");
    }
    public static object Apply(object payload, string leaf, string acceptLanguage)
    {
        var body = JsonSerializer.SerializeToNode(payload)!.AsObject();
        FormatTimestamps(body, leaf);
        var destination = DomainHttp.SelectEnglish(acceptLanguage) ? English.Value : Russian.Value;
        void Fields(JsonObject value, string identity, string prefix, params (string Field, string Suffix)[] fields)
        {
            string? key = value[identity]?.GetValue<string>();
            if (key is null) return;
            foreach (var (field, suffix) in fields)
            {
                string code = "access.builtin." + prefix + "." + key + "." + suffix;
                if (value[field] is not JsonValue raw || !raw.TryGetValue<string>(out var text)
                    || !Russian.Value.ContainsKey(code) || !English.Value.ContainsKey(code)) continue;
                foreach (string candidate in new[] { code }.Concat(Russian.Value.Keys.Where(k => k.StartsWith(code + ".alias.", StringComparison.Ordinal)).Order(StringComparer.Ordinal)))
                {
                    if (!Russian.Value.TryGetValue(candidate, out string? ru) || !English.Value.TryGetValue(candidate, out string? en)) continue;
                    Dictionary<string, string>? parameters = Match(ru, text) ?? Match(en, text);
                    if (parameters is null && !(prefix == "report" && suffix == "name" && key.StartsWith("file-audit.", StringComparison.Ordinal) && text == key)) continue;
                    parameters ??= [];
                    string translated = destination[candidate];
                    foreach (var p in parameters) translated = translated.Replace("{" + p.Key + "}", p.Value, StringComparison.Ordinal);
                    var messages = value["presentation_messages"] as JsonObject;
                    if (messages is null) value["presentation_messages"] = messages = new JsonObject();
                    messages[field] = JsonSerializer.SerializeToNode(new { code = candidate, @params = parameters, text = translated });
                    value[field] = translated;
                    break;
                }
            }
        }
        void Packages(string field, string identity, params (string Field, string Suffix)[] fields)
        {
            if (body[field] is JsonArray values) foreach (var value in values.OfType<JsonObject>()) Fields(value, identity, "package", fields);
        }
        string? reportList = null;
        if (leaf == "subjects")
        {
            Packages("packages", "package_key", ("name", "name"), ("description", "description"));
            Packages("package_assignments", "package_key", ("package_name", "name"));
        }
        else if (leaf == "effective") { Packages("packages", "key", ("name", "name")); reportList = "reports"; }
        else if (leaf == "grant-options") reportList = "items";
        if (reportList is not null && body[reportList] is JsonArray reports)
            foreach (var report in reports.OfType<JsonObject>())
                if (report["version"]?.GetValue<long>() == 1) Fields(report, "report_key", "report", ("name", "name"), ("purpose", "purpose"));
        return body;
    }

    private static void FormatTimestamps(JsonObject body, string leaf)
    {
        bool effective = leaf == "effective";
        void Format(JsonObject value, params string[] fields)
        {
            foreach (string field in fields)
            {
                if (value[field] is not JsonValue node || !node.TryGetValue<string>(out var text)
                    || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var instant)) continue;
                // pydantic serializes Any datetimes with six fractional digits;
                // the raw Python read routes use datetime.__str__ instead.
                string stamp = instant.ToString(effective ? "yyyy-MM-dd'T'HH:mm:ss" : "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                if (instant.Ticks % TimeSpan.TicksPerSecond != 0) stamp += "." + instant.ToString("ffffff", CultureInfo.InvariantCulture);
                stamp += effective && instant.Offset == TimeSpan.Zero ? "Z" : instant.ToString("zzz", CultureInfo.InvariantCulture);
                value[field] = stamp;
            }
        }
        void Each(JsonObject parent, string field, Action<JsonObject> action)
        { if (parent[field] is JsonArray rows) foreach (var row in rows.OfType<JsonObject>()) action(row); }
        if (effective)
        {
            Format(body, "evaluated_at_utc");
            Each(body, "groups", r => Format(r, "valid_until"));
            Each(body, "package_explain", r => Format(r, "valid_from", "valid_until"));
            if (body["capability_explain"] is JsonObject capabilities)
                foreach (var value in capabilities.Select(p => p.Value).OfType<JsonArray>())
                    foreach (var source in value.OfType<JsonObject>()) Format(source, "valid_until");
            Each(body, "reports", report =>
            {
                Format(report, "access_valid_until", "preference_updated_at");
                if (report["request"] is JsonObject request) Format(request, "created_at", "updated_at");
                Each(report, "sources", r => Format(r, "valid_from", "valid_until"));
                Each(report, "grants", r => Format(r, "valid_from", "valid_until"));
            });
        }
        else if (leaf == "subjects")
        {
            Each(body, "users", r => Format(r, "last_login_at"));
            foreach (string field in new[] { "assignments", "package_assignments" })
                Each(body, field, r => Format(r, "valid_from", "valid_until", "created_at"));
        }
        else if (leaf == "audit") Each(body, "items", r => Format(r, "created_at"));
    }
    private static Dictionary<string, string>? Match(string template, string text)
    {
        if (!template.Contains("{domain}", StringComparison.Ordinal)) return template == text ? [] : null;
        string[] pieces = template.Split("{domain}", StringSplitOptions.None);
        if (pieces.Length != 2 || !text.StartsWith(pieces[0], StringComparison.Ordinal) || !text.EndsWith(pieces[1], StringComparison.Ordinal)
            || text.Length < pieces[0].Length + pieces[1].Length) return null;
        string domain = text[pieces[0].Length..(text.Length - pieces[1].Length)];
        return Regex.IsMatch(domain, @"\A(?=.{1,253}\z)[\w-]+(?:\.[\w-]+)+\.?\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))
            ? new() { ["domain"] = domain } : null;
    }
}
