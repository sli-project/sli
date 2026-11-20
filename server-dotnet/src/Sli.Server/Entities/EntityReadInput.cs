using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using Sli.Server.Compatibility;

namespace Sli.Server.Entities;

public static partial class EntityReadInput
{
    public static string? First(IQueryCollection query, string key, string? fallback = null) => query.TryGetValue(key, out var values) && values.Count > 0 ? values[0] : fallback;
    public static long Integer(string? raw, string error)
    {
        if (!TryInteger(raw, out var result)) throw new EntityInputException(error);
        return (long)BigInteger.Clamp(result, long.MinValue, long.MaxValue);
    }
    static bool TryInteger(string? raw, out BigInteger number)
    {
        number = default; if (raw is null) return false;
        var text = new StringBuilder(); bool previous = false; int count = 0;
        foreach (var rune in PythonText.Strip(raw).EnumerateRunes())
        {
            if (rune.Value is '+' or '-' && text.Length == 0) { text.Append((char)rune.Value); continue; }
            if (rune.Value == '_' && previous) { text.Append('_'); previous = false; continue; }
            if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.DecimalDigitNumber || ++count > 4300) return false;
            text.Append((char)('0' + (int)Rune.GetNumericValue(rune))); previous = true;
        }
        return previous && BigInteger.TryParse(text.ToString().Replace("_", "", StringComparison.Ordinal), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out number);
    }
    public static int Limit(string? raw, int fallback, string error, bool tolerate = false, bool emptyDefault = true)
    {
        if (raw is null || emptyDefault && raw.Length == 0) return fallback;
        if (!TryInteger(raw, out var value))
        {
            if (tolerate) return fallback;
            throw new EntityInputException(error);
        }
        return (int)BigInteger.Clamp(value, int.MinValue, int.MaxValue);
    }
    public static EntityReadOptions Detail(IQueryCollection query, bool vpn)
    {
        if (vpn && (query.Keys.Any(key => key is not ("time_from" or "time_to" or "timezone" or "limit")) || query.Any(pair => pair.Value.Count != 1)))
            throw new EntityInputException("invalid_entity_vpn_context");
        foreach (string key in new[] { "time_from", "time_to", "timezone" })
            if (query[key].Count > 1) throw new EntityInputException("duplicate_" + key);
        string? from = First(query, "time_from"), to = First(query, "time_to");
        if (vpn && (string.IsNullOrEmpty(from) || string.IsNullOrEmpty(to))) throw new EntityInputException("entity_vpn_time_bounds_required");
        string zone = First(query, "timezone") is { Length: > 0 } z ? z : "UTC";
        if (vpn)
        {
            var range = Range(from, to, zone); string rawLimit = First(query, "limit") ?? "50";
            return new(Limit(rawLimit, 50, $"invalid literal for int() with base 10: '{rawLimit}'"), From: range.Start, To: range.End, Timezone: zone);
        }
        int limit = Limit(First(query, "limit"), 50, "invalid_entity_limit");
        string? before = First(query, "before_time_utc"), idText = First(query, "before_event_db_id");
        if ((before is null) != (idText is null)) throw new EntityInputException("entity_cursor_requires_time_and_event_id");
        long? id = idText is null ? null : Integer(idText, "invalid_before_event_db_id");
        string? summary = First(query,"before_summary_key");
        if(summary is not null && (id!=0 || summary.Length!=64 || !summary.All(char.IsAsciiHexDigit))) throw new EntityInputException("invalid_entity_cursor");
        if (id.HasValue && (id < 0 || id==0 && summary is null || string.IsNullOrEmpty(before))) throw new EntityInputException("invalid_entity_cursor");
        if (string.IsNullOrEmpty(from) != string.IsNullOrEmpty(to)) throw new EntityInputException("entity_time_context_requires_both_bounds");
        var (start, end) = Range(from, to, zone);
        if (!vpn && start is not null && end is not null && DateTimeOffset.Parse(end, CultureInfo.InvariantCulture) - DateTimeOffset.Parse(start, CultureInfo.InvariantCulture) > TimeSpan.FromDays(31))
            throw new EntityInputException("entity_time_context_period_too_wide");
        return new(limit, before, id, start, end, zone, summary);
    }
    public static (string? Start, string? End) Range(string? from, string? to, string timezone)
    {
        TimeZoneInfo zone;
        try { zone = TimeZoneInfo.FindSystemTimeZoneById(timezone.Trim().Length == 0 ? "UTC" : timezone.Trim()); }
        catch (TimeZoneNotFoundException) { throw new EntityInputException("invalid_timezone"); }
        catch (InvalidTimeZoneException) { throw new EntityInputException("invalid_timezone"); }
        string? start = Instant(from, zone, false), end = Instant(to, zone, true);
        if (start is not null && end is not null && DateTimeOffset.Parse(start, CultureInfo.InvariantCulture) >= DateTimeOffset.Parse(end, CultureInfo.InvariantCulture))
            throw new EntityInputException("empty_or_reversed_time_range");
        return (start, end);
    }
    static string? Instant(string? raw, TimeZoneInfo zone, bool end)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        raw = raw.Trim();
        try
        {
            DateTimeOffset instant;
            if (DateOnlyRegex().IsMatch(raw))
            {
                var local = DateTime.ParseExact(raw, "yyyy-MM-dd", CultureInfo.InvariantCulture);
                if (end) local = local.AddDays(1);
                instant = new(local, zone.GetUtcOffset(local));
            }
            else if (OffsetRegex().IsMatch(raw)) instant = DateTimeOffset.Parse(raw, CultureInfo.InvariantCulture);
            else
            {
                var local = DateTime.SpecifyKind(DateTime.Parse(raw, CultureInfo.InvariantCulture), DateTimeKind.Unspecified);
                if (zone.IsInvalidTime(local)) throw new EntityInputException("nonexistent_local_datetime");
                if (zone.IsAmbiguousTime(local)) throw new EntityInputException("ambiguous_local_datetime_requires_offset");
                instant = new(local, zone.GetUtcOffset(local));
            }
            return instant.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'", CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException) { throw new EntityInputException("invalid_datetime"); }
    }
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}$")] private static partial Regex DateOnlyRegex();
    [GeneratedRegex(@"[Tt ].*(?:[Zz]|[+-]\d{2}:?\d{2})$")] private static partial Regex OffsetRegex();
}
