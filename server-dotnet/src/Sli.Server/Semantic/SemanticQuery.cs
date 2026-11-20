using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Semantic;

public sealed class SemanticQuery
{
    public Dictionary<string, string[]> Values { get; }
    public SemanticQuery(string? query, bool keepBlank = false)
    {
        Values = (query ?? "").TrimStart('?').Split('&').Select(x => x.Split('=', 2)).Where(x => x[0].Length > 0)
            .Select(x => (Key: WebUtility.UrlDecode(x[0]), Value: x.Length == 2 ? WebUtility.UrlDecode(x[1]) : ""))
            .Where(x => keepBlank || x.Value.Length > 0).GroupBy(x => x.Key).ToDictionary(x => x.Key, x => x.Select(y => y.Value).ToArray());
    }
    public string? Get(string key) => Values.TryGetValue(key, out var values) ? values[0].Trim() : null;
    internal long? ExactEventId()
    {
        if (!Values.TryGetValue("event_db_id", out var ids)) return null;
        if (ids.Length != 1) throw new SemanticInputException("invalid_event_db_id");
        long id = Positive(ids[0].Trim(), "invalid_event_db_id");
        foreach (string key in new[] { "time_from", "time_to", "timezone" })
            if (Values.TryGetValue(key, out var values) && values.Length != 1) throw new SemanticInputException("invalid_semantic_context");
        return id;
    }
    public void Only(string code, params string[] keys)
    { if (Values.Keys.Except(keys).Any() || Values.Any(p => p.Value.Length != 1)) throw new SemanticInputException(code); }
    public static long Positive(string? raw, string code)
    {
        if (!long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out long n) || n < 1 || n.ToString(CultureInfo.InvariantCulture) != raw)
            throw new SemanticInputException(code);
        return n;
    }
    public int Integer(string key, int fallback, string code)
    { if (Get(key) is not { Length: > 0 } text) return fallback; if (!int.TryParse(text, out int n)) throw new SemanticInputException(code); return n; }
    internal string? Filter(string key, string code, params string[] allowed)
    { string? value = Get(key)?.ToLowerInvariant(); if (string.IsNullOrEmpty(value)) return null; if (!allowed.Contains(value)) throw new SemanticInputException(code); return value; }
    internal static string Uuid(string? value, string code)
    {
        string? digits = value?.Replace("urn:", "", StringComparison.Ordinal).Replace("uuid:", "", StringComparison.Ordinal).Trim('{', '}').Replace("-", "", StringComparison.Ordinal);
        if (!Guid.TryParseExact(digits, "N", out var id)) throw new SemanticInputException(code);
        return id.ToString();
    }
    internal static DateTimeOffset Time(string value, string zone, string code, bool exclusiveDateEnd = false)
    {
        try
        {
            // Offset-less wall times are interpreted in the explicitly selected timezone.
            var timezone = TimeZoneInfo.FindSystemTimeZoneById(zone);
            // The inclusive calendar day ends at the next local midnight, before conversion to UTC.
            if (exclusiveDateEnd && DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
                value = day.AddDays(1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            if (System.Text.RegularExpressions.Regex.IsMatch(value, @"(?:Z|[+-]\d{2}:?\d{2})$"))
                return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture).ToUniversalTime();
            var wall = DateTime.SpecifyKind(DateTime.Parse(value, CultureInfo.InvariantCulture), DateTimeKind.Unspecified);
            if (timezone.IsInvalidTime(wall) || timezone.IsAmbiguousTime(wall)) throw new FormatException();
            return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(wall, timezone));
        }
        catch (Exception e) when (e is FormatException or ArgumentException or TimeZoneNotFoundException or InvalidTimeZoneException)
        { throw new SemanticInputException(code); }
    }
    internal (DateTimeOffset? Start, DateTimeOffset? End) Bounds(string code, bool exclusiveDateEnd = false)
    {
        string zone = Get("timezone") ?? "UTC";
        DateTimeOffset? start = Get("time_from") is { } s ? Time(s, zone, code) : null;
        DateTimeOffset? end = Get("time_to") is { } e ? Time(e, zone, code, exclusiveDateEnd) : null;
        if (start is not null && end is not null && start >= end) throw new SemanticInputException(code);
        return (start, end);
    }
}

internal static class SemanticJson
{
    internal static string? Text(this JsonNode? node, string key) => node?[key]?.GetValue<string>();
    internal static long Number(this JsonNode? node, string key) => node?[key] is { } value && long.TryParse(value.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long number) ? number : 0;
    internal static bool Flag(this JsonNode? node, string key) => node?[key]?.GetValue<bool>() ?? false;
    internal static JsonNode? Copy(this JsonNode? node) => node?.DeepClone();
    internal static string Stamp(DateTimeOffset time) => Password.PasswordJson.Stamp(time);
    internal static string Hash(JsonNode? node) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(node, ensureAscii: false))));
    internal static JsonArray Array(IEnumerable<JsonNode?> values) => new(values.Select(x => x.Copy()).ToArray());
    internal static string Cursor(JsonArray context, JsonObject position)
    {
        var body = new JsonObject { ["binding"] = Binding(context), ["position"] = position.Copy() };
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(body.ToJsonString())).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
    internal static JsonObject? Position(string? token, JsonArray context)
    {
        if (token is null) return null;
        try
        {
            if (token.Length is < 1 or > 2048 || token.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '+' or '/' or '='))) throw new FormatException();
            var body = JsonNode.Parse(Convert.FromBase64String(token.Replace('-', '+').Replace('_', '/') + new string('=', (4 - token.Length % 4) % 4)))!.AsObject();
            if (body.Text("binding") != Binding(context) || body["position"] is not JsonObject position) throw new FormatException();
            return position;
        }
        catch (Exception e) when (e is FormatException or System.Text.Json.JsonException or InvalidOperationException or ArgumentException or NullReferenceException)
        { throw new SemanticInputException("invalid_cursor"); }
    }
    private static string Binding(JsonNode context)
    {
        // Python json.dumps(sort_keys=True) uses ASCII escapes and spaces after separators.
        string compact = CanonicalJson.Serialize(context, ensureAscii: true);
        var spaced = new StringBuilder(); bool quoted = false, escaped = false;
        foreach (char c in compact) { spaced.Append(c); if (!quoted && c is ',' or ':') spaced.Append(' '); if (!escaped && c == '"') quoted = !quoted; escaped = !escaped && c == '\\'; }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(spaced.ToString())));
    }
}
