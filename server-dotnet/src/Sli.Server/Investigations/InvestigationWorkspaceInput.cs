using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Investigations;

public sealed record InvestigationWorkspaceInput(long? Event, long? Entity, string Query, string? Scope, string? From, string? To, string Zone, string? Cursor)
{
    internal static long? Exact(string? value, string error)
    {
        if (value is null) return null;
        string text = value.Trim();
        if (text.Length == 0 || text.Any(c => c is < '0' or > '9') || !long.TryParse(text, out long n) || n is <= 0 or > 9007199254740991)
            throw new InvestigationException(error, error);
        return n;
    }
    internal static InvestigationWorkspaceInput Parse(HttpRequest request)
    {
        string? First(string key) => request.Query.TryGetValue(key, out var values) ? values.FirstOrDefault() : null;
        return new(Exact(First("event_db_id"), "invalid_event_db_id"), Exact(First("entity_id"), "invalid_entity_id"), (First("q") ?? "").Trim(), First("scope"), First("time_from"), First("time_to"), First("timezone") ?? "UTC", First("cursor"));
    }
    internal InvestigationWorkspaceInput Normalize()
    {
        TimeZoneInfo zone;
        try
        {
            zone = TimeZoneInfo.FindSystemTimeZoneById(Zone.Trim());
            if (!zone.HasIanaId && Zone.Trim() != "UTC") throw new TimeZoneNotFoundException();
        }
        catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException or ArgumentException) { throw new InvestigationException("invalid_timezone", "invalid_timezone"); }
        string? Instant(string? value, bool upper)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            string raw = value.Trim();
            try
            {
                DateTimeOffset time;
                if (Regex.IsMatch(raw, @"\A\d{4}-\d{2}-\d{2}\z"))
                {
                    var day = DateTime.ParseExact(raw, "yyyy-MM-dd", CultureInfo.InvariantCulture);
                    if (upper) day = day.AddDays(1);
                    time = new(day, zone.GetUtcOffset(day));
                }
                else
                {
                    if (!Regex.IsMatch(raw, @"\A[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}")) throw new FormatException();
                    if (raw.EndsWith('Z') || Regex.IsMatch(raw, @"[+-]\d{2}:?\d{2}$")) time = DateTimeOffset.Parse(raw, CultureInfo.InvariantCulture);
                    else
                    {
                        var wall = DateTime.SpecifyKind(DateTime.Parse(raw, CultureInfo.InvariantCulture), DateTimeKind.Unspecified);
                        if (zone.IsInvalidTime(wall)) throw new InvestigationException("nonexistent_local_datetime", "nonexistent_local_datetime");
                        if (zone.IsAmbiguousTime(wall)) throw new InvestigationException("ambiguous_local_datetime_requires_offset", "ambiguous_local_datetime_requires_offset");
                        time = new(wall, zone.GetUtcOffset(wall));
                    }
                }
                time = time.ToUniversalTime();
                return time.ToString(time.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:ss'Z'" : "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
            }
            catch (Exception e) when (e is FormatException or ArgumentException or OverflowException) { throw new InvestigationException("invalid_datetime", "invalid_datetime"); }
        }
        string? start = Instant(From, false), end = Instant(To, true);
        if (start is not null && end is not null && DateTimeOffset.Parse(start, CultureInfo.InvariantCulture) >= DateTimeOffset.Parse(end, CultureInfo.InvariantCulture))
            throw new InvestigationException("empty_or_reversed_time_range", "empty_or_reversed_time_range");
        return this with { From = start, To = end };
    }
    string Binding()
    {
        // Python json.dumps defaults: ASCII escapes and spaces after separators.
        object?[] values = ["investigation", Event, Entity, Query, Scope, From, To, Zone];
        string json = "[" + string.Join(", ", values.Select(v => JsonSerializer.Serialize(v, new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))) + "]";
        var ascii = new StringBuilder();
        foreach (char c in json) { if (c > 127) ascii.Append("\\u").Append(((int)c).ToString("x4")); else ascii.Append(c); }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ascii.ToString())));
    }
    internal string? DecodeCursor()
    {
        if (Cursor is null) return null;
        try
        {
            if (Cursor.Length is < 1 or > 2048 || Cursor.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '+' or '/' or '='))) throw new FormatException();
            string text = Cursor.Replace('-', '+').Replace('_', '/'); text += new string('=', (4 - text.Length % 4) % 4);
            var root = JsonNode.Parse(Convert.FromBase64String(text))!;
            if (root["binding"]?.ToString() != Binding() || root["position"]?["relations"] is not JsonValue v || !v.TryGetValue<string>(out var relation) || relation.Length == 0) throw new FormatException();
            return relation;
        }
        catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException) { throw new InvestigationException("invalid_cursor", "invalid_cursor"); }
    }
    internal string? EncodeCursor(string? relation) => relation is null ? null : Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { binding = Binding(), position = new { relations = relation } })).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
