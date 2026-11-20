using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Agents.Control;

internal static class AgentControlJson
{
    internal static JsonElement Get(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var found) ? found : default;
    internal static string? String(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    internal static bool Matches(string? value, string pattern) => value is not null && Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    internal static Guid Id(JsonElement value) => Id(value.ValueKind == JsonValueKind.Number
        ? Sli.Server.Auth.Lifecycle.AuthJsonBody.CredentialString(JsonSerializer.SerializeToElement(new { v = value }), "v") : String(value));
    internal static Guid Id(string? value)
    {
        // uuid.UUID(str(value)): optional urn:/uuid: text, outer braces and
        // hyphens are removed before requiring exactly 32 hexadecimal digits.
        string text = (value ?? "").Replace("urn:", "", StringComparison.Ordinal).Replace("uuid:", "", StringComparison.Ordinal).Trim('{', '}').Replace("-", "", StringComparison.Ordinal);
        if (!Matches(text, @"\A[0-9a-fA-F]{32}\z") || !Guid.TryParseExact(text, "N", out var id)) throw new AgentControlException("invalid_agent_identity");
        return id;
    }
    internal static DateTimeOffset Now() => new(DateTimeOffset.UtcNow.Ticks / 10 * 10, TimeSpan.Zero);
    internal static string Stamp(DateTimeOffset value, bool iso = false)
    {
        string result = value.ToString(iso ? "yyyy-MM-dd'T'HH:mm:ss" : "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        if (value.Ticks % TimeSpan.TicksPerSecond != 0) result += "." + value.ToString("ffffff", CultureInfo.InvariantCulture);
        return result + value.ToString("zzz", CultureInfo.InvariantCulture);
    }
    internal static JsonObject Row(string json)
    {
        var row = JsonNode.Parse(json)!.AsObject();
        foreach (string key in new[] { "created_at", "expires_at", "used_at", "revoked_at", "last_seen", "not_after", "requested_at", "reported_at", "occurred_at" })
            if (row[key] is JsonValue value && value.TryGetValue<string>(out var text)) row[key] = Stamp(DateTimeOffset.Parse(text, CultureInfo.InvariantCulture));
        return row;
    }
    internal static JsonElement Element(JsonNode value) => JsonSerializer.SerializeToElement(value);
    internal static string? HumanName(string? value)
    {
        if (value is null) return null;
        string text = Strip(value);
        if (text.Length == 0) return null;
        if (text.ToLowerInvariant() is "localhost" or "unknown") return null;
        try { _ = Id(text); return null; } catch (AgentControlException) { return text; }
    }
    internal static string Strip(string value)
    {
        static bool Space(char c) => char.IsWhiteSpace(c) || c is >= '\x1c' and <= '\x1f';
        int start = 0, end = value.Length; while (start < end && Space(value[start])) start++; while (end > start && Space(value[end - 1])) end--;
        return value[start..end];
    }
    internal static string? ReportedName(JsonElement value) => ReportedName(String(value));
    internal static string? ReportedName(string? value)
    {
        if (value is null || value.Length is < 1 or > 253 || value.ToLowerInvariant() is "localhost" or "localhost.localdomain" or "unknown"
            || Matches(value, @"\A[0-9]+(?:\.[0-9]+){3}\z") || value.Split('.').Any(label => !Matches(label, @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z"))) return null;
        try { _ = Id(value); return null; } catch (AgentControlException) { return value; }
    }
}
