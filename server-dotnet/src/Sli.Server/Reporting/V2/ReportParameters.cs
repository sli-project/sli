using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Access.Administration;
namespace Sli.Server.Reporting.V2;

public sealed record ReportPaging(string? Cursor, int Limit, string Timezone, string? Sort, string Direction, string? Tab);
public static class ReportParameters
{
    private static readonly HashSet<string> Reserved = ["cursor", "limit", "sort", "direction", "tz", "tab"];
    public static string? First(IQueryCollection query, string key) => query.TryGetValue(key, out var values) && values.Count > 0 ? AssignmentValidation.Strip(values[0] ?? "") : null;
    public static (JsonObject Params, ReportPaging Paging) Parse(ReportDefinition definition, IQueryCollection query, DateTimeOffset? now = null)
    {
        var declared = definition.Params.Select(p => p.Text("key")).ToHashSet(StringComparer.Ordinal);
        var unknown = query.Keys.Except(declared).Except(Reserved).Except(declared.Contains("period") ? ["from", "to"] : Array.Empty<string>()).Order(StringComparer.Ordinal).FirstOrDefault();
        if (unknown is not null) throw new ReportRequestException("report_parameter_unknown:" + unknown);
        string tz = First(query, "tz") is { Length: > 0 } zone ? zone : "UTC";
        TimeZoneInfo timezone;
        try { timezone = TimeZoneInfo.FindSystemTimeZoneById(tz); if (!timezone.HasIanaId && tz != "UTC") throw new TimeZoneNotFoundException(); }
        catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException or ArgumentException) { throw new ReportRequestException("report_timezone_invalid"); }
        var result = new JsonObject();
        foreach (var param in definition.Params)
        {
            string key = param.Text("key"), kind = param.Text("kind");
            var options = param.Objects("options").Select(o => o.Text("value")).ToHashSet(StringComparer.Ordinal);
            if (kind == "period")
            {
                string preset = First(query, key) is { Length: > 0 } period ? period : param.Text("default");
                result[key] = Period(preset, First(query, "from"), First(query, "to"), timezone, param["max_days"]?.GetValue<int>(), now ?? DateTimeOffset.UtcNow);
                continue;
            }
            if (kind == "multichoice")
            {
                var values = query[key].Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => AssignmentValidation.Strip(v!)).ToArray();
                if (options.Count > 0 && values.Any(v => !options.Contains(v))) throw new ReportRequestException("report_parameter_invalid:" + key);
                result[key] = new JsonArray(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
                continue;
            }
            string? value = First(query, key);
            if (string.IsNullOrEmpty(value)) value = param["default"] is JsonValue d ? d.ToString() : null;
            if (string.IsNullOrEmpty(value))
            {
                if (param.Flag("required")) throw new ReportRequestException("report_parameter_required:" + key);
                continue;
            }
            if (value.EnumerateRunes().Count() > (param["max_length"]?.GetValue<int>() ?? 256)) throw new ReportRequestException("report_parameter_invalid:" + key);
            if (kind is "domain" or "int")
            {
                if (!Integer(value, out var number) || number <= 0) throw new ReportRequestException("report_parameter_invalid:" + key);
                result[key] = JsonNode.Parse(number.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                if (kind == "choice" && options.Count > 0 && !options.Contains(value)) throw new ReportRequestException("report_parameter_invalid:" + key);
                result[key] = value;
            }
        }
        string? limitText = First(query, "limit");
        BigInteger limit = definition.DefaultLimit;
        if (!string.IsNullOrEmpty(limitText) && !Integer(limitText, out limit) || limit < 1 || limit > definition.MaxLimit) throw new ReportRequestException("report_limit_invalid");
        string direction = First(query, "direction") is { Length: > 0 } dir ? dir : "asc";
        string? sort = First(query, "sort"), tab = First(query, "tab");
        if (direction is not ("asc" or "desc") || !string.IsNullOrEmpty(sort) && !definition.Columns.Any(c => c.Text("key") == sort && c.Flag("sortable"))) throw new ReportRequestException("report_sort_invalid");
        if (!string.IsNullOrEmpty(tab) && !definition.Views.Any(v => v.Text("key") == tab)) throw new ReportRequestException("report_tab_invalid");
        return (result, new(First(query, "cursor"), (int)limit, tz, sort, direction, tab));
    }
    internal static bool Integer(string text, out BigInteger number)
    {
        var normalized = new StringBuilder(); bool digit = false;
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value is '+' or '-' && normalized.Length == 0) { normalized.Append((char)rune.Value); continue; }
            if (rune.Value == '_' && digit) { normalized.Append('_'); digit = false; continue; }
            if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.DecimalDigitNumber) { number = 0; return false; }
            normalized.Append((char)('0' + (int)Rune.GetNumericValue(rune))); digit = true;
        }
        number = 0;
        return digit && normalized.Length <= 4300 && BigInteger.TryParse(normalized.ToString().Replace("_", ""), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out number);
    }
    internal static JsonObject Period(string preset, string? from, string? to, TimeZoneInfo zone, int? maxDays, DateTimeOffset now)
    {
        DateTimeOffset start, end;
        try
        {
            int days = preset switch { "24h" => 1, "7d" => 7, "30d" => 30, "90d" => 90, _ => 0 };
            if (preset == "2h") { end = now; start = end.AddHours(-2); }
            else if (days > 0) { end = now; start = end.AddDays(-days); }
            else if (preset == "custom" && ((from ?? "") + to).Contains('T'))
            {
                start = Instant(from); end = Instant(to);
                if (start >= end) throw new FormatException();
            }
            else if (preset == "custom")
            {
                var first = DateOnly.ParseExact(from ?? "", "yyyy-MM-dd", CultureInfo.InvariantCulture);
                var last = DateOnly.ParseExact(to ?? "", "yyyy-MM-dd", CultureInfo.InvariantCulture);
                if (first > last) throw new FormatException();
                // Python zoneinfo assigns the pre-transition offset for a nonexistent midnight.
                var a = first.ToDateTime(TimeOnly.MinValue); var b = last.AddDays(1).ToDateTime(TimeOnly.MinValue);
                start = new DateTimeOffset(a, zone.IsAmbiguousTime(a) ? zone.GetAmbiguousTimeOffsets(a).Max() : zone.GetUtcOffset(a));
                end = new DateTimeOffset(b, zone.IsAmbiguousTime(b) ? zone.GetAmbiguousTimeOffsets(b).Max() : zone.GetUtcOffset(b));
            }
            else throw new FormatException();
        }
        catch (Exception e) when (e is FormatException or ArgumentException or OverflowException) { throw new ReportRequestException("report_period_invalid"); }
        if (maxDays is > 0 && end - start > TimeSpan.FromDays(maxDays.Value)) throw new ReportRequestException("report_period_too_wide");
        return new() { ["preset"] = preset, ["from_utc"] = Stamp(start), ["to_utc"] = Stamp(end) };
    }
    private static DateTimeOffset Instant(string? value)
    {
        if (value is null || !System.Text.RegularExpressions.Regex.IsMatch(value, @"T.*(?:Z|[+-]\d{2}:?\d{2})$")) throw new FormatException();
        return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.None).ToUniversalTime();
    }
    private static string Stamp(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
