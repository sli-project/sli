using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Compatibility;

internal sealed class LegacyInputException(string code, int status = 400) : Exception(code)
{ internal int Status { get; } = status; }

public sealed class LegacyQuery(JsonObject filters)
{
    public JsonObject Filters { get; } = filters;
    public string? Text(string key) => Filters[key]?.ToString();
    public int Number(string key, int fallback = 0) => int.TryParse(Text(key), out int n) ? n : fallback;
    internal static string? First(IQueryCollection query, params string[] names)
    {
        foreach (string name in names)
        {
            // Python parse_qs drops blank values and then takes the first.
            string? value = query[name].FirstOrDefault(x => !string.IsNullOrEmpty(x));
            if (!string.IsNullOrEmpty(value)) return value;
        }
        return null;
    }
    internal static LegacyQuery Parse(string path, IQueryCollection query)
    {
        string? F(params string[] names) => First(query, names);
        bool search = path.Contains("/search") || path.EndsWith("/timeline");
        bool entity = path == "/api/entities/details", detail = path == "/api/events/details";
        bool monitor = path.Contains("events-monitor");
        int Integer(string key, int fallback)
        {
            string? raw = F(key);
            if (raw is null) return fallback;
            if (int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result)) return result;
            if (search) return fallback;
            // Python int() escapes the route handler and becomes a 500.
            throw new FormatException("legacy_integer_invalid");
        }
        if (path.EndsWith("/summary")) return new(new());
        if (path is "/api/ai/runs" or "/reports/ai-reports.html")
            return new(new() { ["limit"] = Math.Clamp(Integer("limit", 50) is 0 ? 50 : Integer("limit", 50), 1, 200) });
        if (path == "/reports/ai-analysis.html")
            return new(new() { ["run_id"] = long.TryParse(F("run_id", "id"), out long id) ? id : null });
        if (path.Contains("preview"))
        {
            if (F("limit") is {} raw && !int.TryParse(raw, out _)) throw new LegacyInputException("ai_preview_limit_invalid");
            var preview = new JsonObject();
            foreach (string key in new[] { "q", "event_id", "channel", "time_from", "time_to" }) preview[key] = F(key);
            preview["account"] = F("account", "user");
            preview["servers"] = new JsonArray((F("server", "servers") ?? "").Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
            preview["limit"] = Math.Clamp(Integer("limit", 50) is 0 ? 50 : Integer("limit", 50), 1, 200);
            string level = (F("redaction_level", "level") ?? "strict").Trim().ToLowerInvariant();
            preview["redaction_level"] = level is "strict" or "balanced" or "off" ? level : "strict";
            if (path.Contains("prompt-preview")) {
                preview["provider"] = F("provider") ?? "openai_api"; preview["model"] = F("model") ?? "gpt-5.5";
                preview["allow_unsafe_redaction"] = Truth(F("allow_unsafe_redaction"));
            }
            return new(preview);
        }
        var filters = new JsonObject();
        if (monitor)
        {
            foreach (string key in new[] { "group", "event_id", "target", "server", "period", "time_from", "time_to" }) filters[key] = F(key);
            filters["account"] = F("account", "user"); filters["source"] = F("source", "ip", "host");
            string? risk = F("risk", "severity")?.Trim().ToLowerInvariant();
            filters["risk"] = risk is "high" or "medium" or "info" or "low" ? risk : null;
            filters["only_privileged"] = Truth(F("only_privileged", "privileged")); filters["only_service"] = Truth(F("only_service", "service"));
            int limit = Integer("limit", 300); filters["limit"] = Math.Clamp(limit == 0 ? 300 : limit, 1, 2000);
            string period = F("period")?.Trim().ToLowerInvariant() ?? "";
            int days = period switch { "24h" => 1, "7d" => 7, "30d" => 30, _ => 0 };
            if (F("time_from") is null) { filters["period"] = days == 0 ? "" : period; if (days > 0) filters["time_from"] = Iso(DateTimeOffset.UtcNow.AddDays(-days)); }
            filters["period"] ??= JsonValue.Create("");
            filters["period_label"] = filters["period"]!.ToString() switch { "24h" => "последние 24 часа", "7d" => "последние 7 дней", "30d" => "последние 30 дней", _ => "весь импортированный период" };
            return new(filters);
        }
        filters["q"] = Clean(F("q"));
        filters["channel"] = Clean(F("channel"));
        filters["servers"] = new JsonArray((F("server", "servers") ?? "").Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        var ids = query["event_id"].SelectMany(x => (x ?? "").Replace(';', ',').Split(',')).Select(s => int.TryParse(s.Trim(), out int n) ? (int?)n : null).Where(n => n is not null).Distinct().ToArray();
        filters["event_ids"] = new JsonArray(ids.Select(n => (JsonNode?)JsonValue.Create(n!.Value)).ToArray());
        filters["limit"] = Math.Clamp(Integer("limit", 200), 1, path.EndsWith("/deep") ? 200 : 1000);
        filters["offset"] = Math.Max(0, Integer("offset", 0));
        filters["order"] = F("order")?.Trim().ToLowerInvariant() == "asc" ? "asc" : "desc";
        if (entity || detail)
        {
            filters["event_id"] = ids.Length == 1 ? ids[0] : null;
            string key = entity ? "entity_id" : "event_db_id";
            filters[key] = long.TryParse(F(key, entity ? key : "id"), out long id) && (!detail || id > 0) ? id : null;
            if (entity) filters["role"] = Clean(F("role"));
            else foreach (string field in new[] { "user", "ip", "logon_id" }) filters[field] = Clean(F(field));
        }
        if (detail)
        {
            filters.Remove("q");
            foreach (string field in new[] { "time_from", "time_to" }) filters[field] = Clean(F(field));
            return new(filters);
        }
        string timezone = F("timezone") ?? "UTC";
        var range = Range(F("time_from"), F("time_to"), timezone);
        filters["time_from"] = range.From; filters["time_to"] = range.To; filters["timezone"] = timezone;
        if (entity) return new(filters);
        filters["account"] = Clean(F("account", "user"));
        filters["provider"] = Clean(F("provider", "source")); filters["subject"] = Clean(F("subject", "initiator")); filters["target"] = Clean(F("target", "object"));
        string view = F("view")?.Trim().ToLowerInvariant() ?? "";
        filters["risk"] = Clean(F("risk") ?? (view == "attention" ? "high" : null))?.ToLowerInvariant();
        filters["tier"] = Clean(F("tier"))?.ToLowerInvariant();
        filters["category"] = Clean(F("category") ?? (view switch { "authentication" => "authentication", "accounts" => "account_management", "tasks" => "service_task", _ => null }))?.ToLowerInvariant();
        filters["offset_ignored"] = filters["offset"]!.GetValue<int>() > 0;
        filters["cursor"] = Clean(F("cursor")); filters["cursor_values"] = Decode(F("cursor"));
        bool deep = path.EndsWith("/deep");
        bool defaultWindow = range.From is null && range.To is null && (deep || (filters["q"] is null && filters["account"] is null));
        filters["default_window_hours"] = deep ? 1 : 24; filters["default_window_applied"] = defaultWindow;
        if (defaultWindow) filters["time_from"] = Iso(DateTimeOffset.UtcNow.AddHours(deep ? -1 : -24));
        filters["include_internal_evidence"] = false;
        return new(filters);
    }
    internal static string? Clean(string? text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();
    internal static Dictionary<string, string?> MonitorParameters(JsonObject filters)
    {
        var result = new Dictionary<string, string?>();
        foreach (string key in new[] { "group", "event_id", "account", "source", "target", "server", "risk", "period", "time_from", "time_to", "limit" })
            if (filters[key]?.ToString() is { Length: > 0 } value && value != "false") result[key] = value;
        foreach (string key in new[] { "only_privileged", "only_service" })
            if (filters[key]?.GetValue<bool>() == true) result[key] = "1";
        // Effective timestamps belong to this read, not to future rolling links.
        if (result.GetValueOrDefault("period") is "24h" or "7d" or "30d")
        { result.Remove("time_from"); result.Remove("time_to"); }
        return result;
    }
    internal static bool Truth(string? text) => text?.ToLowerInvariant() is "1" or "true" or "yes" or "on";
    internal static string Iso(DateTimeOffset value) => value.UtcDateTime.ToString(value.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:ss'Z'" : "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
    internal static (string? From, string? To) Range(string? from, string? to, string timezone)
    {
        TimeZoneInfo zone;
        try { zone = TimeZoneInfo.FindSystemTimeZoneById(timezone.Trim()); }
        catch (Exception error) when (error is TimeZoneNotFoundException or InvalidTimeZoneException) { throw new LegacyInputException("invalid_timezone"); }
        string? Instant(string? raw, bool end)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            bool date = Regex.IsMatch(raw, @"^\d{4}-\d{2}-\d{2}$");
            if (!DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.None, out var wall)) throw new LegacyInputException("invalid_datetime");
            if (!date && Regex.IsMatch(raw, @"(Z|[+-]\d{2}:?\d{2})$"))
            {
                if (!DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.None, out var offset)) throw new LegacyInputException("invalid_datetime");
                return Iso(offset);
            }
            wall = DateTime.SpecifyKind(wall, DateTimeKind.Unspecified);
            if (date && end) wall = wall.AddDays(1);
            if (!date && zone.IsInvalidTime(wall)) throw new LegacyInputException("nonexistent_local_datetime");
            if (!date && zone.IsAmbiguousTime(wall)) throw new LegacyInputException("ambiguous_local_datetime_requires_offset");
            return Iso(new DateTimeOffset(wall, zone.GetUtcOffset(wall)));
        }
        string? start = Instant(from, false), finish = Instant(to, true);
        if (start is not null && finish is not null && DateTimeOffset.Parse(start,CultureInfo.InvariantCulture) >= DateTimeOffset.Parse(finish,CultureInfo.InvariantCulture)) throw new LegacyInputException("empty_or_reversed_time_range");
        return (start, finish);
    }
    internal static JsonObject? Decode(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try
        {
            string padded = raw.Replace('-', '+').Replace('_', '/'); padded = padded.PadRight((padded.Length + 3) / 4 * 4, '=');
            var obj = JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(padded))) as JsonObject;
            if (obj is null || string.IsNullOrWhiteSpace(obj["time"]?.ToString()) || !long.TryParse(obj["id"]?.ToString(), out long id) || id <= 0) return null;
            return new() { ["time"] = obj["time"]!.ToString(), ["id"] = id, ["record"] = long.TryParse(obj["record"]?.ToString(), out long record) ? record : -1 };
        }
        catch (Exception error) when (error is FormatException or System.Text.Json.JsonException or InvalidOperationException) { return null; }
    }
}
