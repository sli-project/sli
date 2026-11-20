using Sli.Server.Infrastructure;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Ad;

internal static class AdJson
{
    public static JsonObject Obj(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();
    public static JsonArray Array<T>(IEnumerable<T> rows) => JsonSerializer.SerializeToNode(rows)!.AsArray();
    public static string? Text(this JsonNode? row, string key)
    {
        string? value = row?[key]?.ToString().Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }
    public static long Int(this JsonNode? row, string key) => long.TryParse(row?[key]?.ToString(), out long n) ? n : 0;
    public static string? WindowsText(this JsonNode? row, string key)
    {
        string? value = row.Text(key);
        return value is "-" or "—" || value is not null && value.StartsWith("%%", StringComparison.Ordinal)
            && value.Length > 2 && value[2..].All(char.IsAsciiDigit) ? null : value;
    }
    public static string Iso(DateTimeOffset value) => value.UtcDateTime.ToString(value.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:ss'Z'" : "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
    public static DateTimeOffset Time(this JsonNode? row, string key)
    {
        string? text = row.Text(key);
        if (text is null || !System.Text.RegularExpressions.Regex.IsMatch(text, @"[Tt ].*(?:Z|[+-]\d{2}:\d{2})\z", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            throw new FormatException("ad_timestamp_requires_timezone");
        return DateTimeOffset.Parse(text, CultureInfo.InvariantCulture).ToUniversalTime();
    }
    public static JsonObject Unknown(string? reason = null) => reason is null ? Obj(new { state = "unknown" }) : Obj(new { state = "unknown", reason });
    public static JsonObject Principal(JsonNode row, string sidKey, string nameKey, bool native = false,bool cleanSid=false)
    {
        string? sid = row.WindowsText(sidKey), name = row.WindowsText(nameKey);
        if ((cleanSid||sidKey is "membership_member_sid") && sid == "-") sid = null;
        if (sid is null && name is null) return Unknown();
        return new JsonObject { ["state"] = "observed", [native ? sidKey : "sid"] = sid, [native ? nameKey : "name"] = name };
    }
    public static JsonObject Evidence(JsonNode row, bool complete = false)
    {
        var value = new JsonObject();
        foreach (string key in new[] { "event_db_id", "event_record_id", "source_core_sha256", "source_facts_sha256" }) value[key] = row[key]?.DeepClone();
        if (complete)
        {
            var missing = value.Where(p => p.Value is null).Select(p => p.Key).ToArray();
            value["state"] = missing.Length > 0 ? "partial" : "complete"; value["missing_fields"] = Array(missing);
        }
        return value;
    }
    public static async Task<List<JsonObject>> ReadAsync(NpgsqlConnection db, string sql, CancellationToken ct, params object?[] args)
    {
        SqlArguments.Validate(args);
        await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
        foreach (object? arg in args) command.Parameters.Add(new() { Value = arg ?? DBNull.Value });
        await using var reader = await command.ExecuteReaderAsync(ct);
        var rows = new List<JsonObject>();
        while (await reader.ReadAsync(ct))
        {
            var row = new JsonObject();
            for (int i = 0; i < reader.FieldCount; i++)
            {
                object? value = reader.IsDBNull(i) ? null : reader.GetValue(i);
                row[reader.GetName(i)] = value switch
                {
                    byte[] bytes => JsonValue.Create(Convert.ToHexStringLower(bytes)),
                    DateTime time => JsonValue.Create(Iso(new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Utc)))),
                    DateTimeOffset time => JsonValue.Create(Iso(time)),
                    _ => JsonSerializer.SerializeToNode(value)
                };
            }
            rows.Add(row);
        }
        return rows;
    }
}

public sealed class AdInputException(string code) : Exception(code);

public sealed record AdPeriod(DateTimeOffset Start, DateTimeOffset End)
{
    public JsonObject Bounds => AdJson.Obj(new { from_utc = AdJson.Iso(Start), to_utc_exclusive = AdJson.Iso(End) });
    public static AdPeriod Parse(string? from, string? to, string? timezone, string prefix, int maxDays = 31)
    {
        if (string.IsNullOrEmpty(from) || string.IsNullOrEmpty(to)) throw new AdInputException(prefix + "_requires_time_bounds");
        TimeZoneInfo zone;
        try { zone = TimeZoneInfo.FindSystemTimeZoneById(string.IsNullOrWhiteSpace(timezone) ? "UTC" : timezone.Trim()); }
        catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException) { throw new AdInputException("invalid_timezone"); }
        DateTimeOffset Instant(string raw, bool upper)
        {
            try
            {
                raw = raw.Trim();
                bool date = System.Text.RegularExpressions.Regex.IsMatch(raw, @"\A\d{4}-\d{2}-\d{2}\z");
                if (!date && System.Text.RegularExpressions.Regex.IsMatch(raw, @"(?:Z|[+-]\d\d:\d\d)\z")) return DateTimeOffset.Parse(raw, CultureInfo.InvariantCulture).ToUniversalTime();
                var wall = DateTime.SpecifyKind(DateTime.Parse(raw, CultureInfo.InvariantCulture), DateTimeKind.Unspecified);
                if (date && upper) wall = wall.AddDays(1);
                if (!date && zone.IsInvalidTime(wall)) throw new AdInputException("nonexistent_local_datetime");
                if (!date && zone.IsAmbiguousTime(wall)) throw new AdInputException("ambiguous_local_datetime_requires_offset");
                return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(wall, zone));
            }
            catch (Exception e) when (e is FormatException or ArgumentException) { throw new AdInputException("invalid_datetime"); }
        }
        var period = new AdPeriod(Instant(from, false), Instant(to, true));
        if (period.Start >= period.End) throw new AdInputException("empty_or_reversed_time_range");
        if (period.End - period.Start > TimeSpan.FromDays(maxDays)) throw new AdInputException(prefix + "_period_too_wide");
        return period;
    }
}
