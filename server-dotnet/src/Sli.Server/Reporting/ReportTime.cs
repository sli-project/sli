using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Storage.History;

namespace Sli.Server.Reporting;

// Human-facing timestamps follow server/sli/core/time_format.py. Raw UTC stays
// available as technical context rather than being converted to a local instant.
internal static class ReportTime
{
    internal static DateTimeOffset? Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Trim() == "—") return null;
        try { return SourceTimestamp.Parse(value, false); }
        catch (InvalidDataException) { return null; }
    }

    private static (TimeZoneInfo Zone, string Label) Zone(string? name)
    {
        name = (string.IsNullOrEmpty(name) ? Environment.GetEnvironmentVariable("ADLOG_DISPLAY_TIMEZONE") ?? "UTC" : name).Trim();
        if (name.Equals("UTC", StringComparison.OrdinalIgnoreCase) || name.Equals("Z", StringComparison.OrdinalIgnoreCase))
            return (TimeZoneInfo.Utc, "UTC");
        try { return (TimeZoneInfo.FindSystemTimeZoneById(name), name); }
        catch (Exception error) when (error is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            int? hours = name switch { "Europe/Moscow" => 3, "Asia/Novosibirsk" => 7, _ => null };
            return hours is {} offset ? (TimeZoneInfo.CreateCustomTimeZone(name, TimeSpan.FromHours(offset), name, name), name)
                : (TimeZoneInfo.Utc, "UTC");
        }
    }

    internal static string Event(string? value, string? timezoneName = null, string mode = "utc", string? suffix = "UTC", string empty = "—")
    {
        if (Parse(value) is not {} time) return string.IsNullOrEmpty(value) ? empty : value;
        if (mode == "local") { var zone = Zone(timezoneName); time = TimeZoneInfo.ConvertTime(time, zone.Zone); suffix ??= zone.Label; }
        string label = time.ToString("dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture);
        return string.IsNullOrEmpty(suffix) ? label : label + " " + suffix;
    }

    internal static string Report(string? value, string? timezoneName = null) => Event(value, timezoneName, "local", null);

    internal static JsonObject WithContext(string? value, string? timezoneName = null, string mode = "utc")
    {
        var parsed = Parse(value);
        return new() {
            ["display"] = Event(value, timezoneName, mode, mode == "local" ? null : "UTC"),
            ["tooltip"] = parsed?.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) ?? value ?? "",
            ["timezone"] = parsed is null ? "unknown" : mode == "local" ? Zone(timezoneName).Label : "UTC"
        };
    }
}
