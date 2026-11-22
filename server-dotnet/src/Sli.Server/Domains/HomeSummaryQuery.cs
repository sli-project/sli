using System.Globalization;

namespace Sli.Server.Domains;

public sealed class HomeQueryException(string code, int status = 400) : Exception(code)
{
    public int Status { get; } = status;
}

public sealed record HomeWindow(DateTimeOffset From, DateTimeOffset To)
{
    public static string Iso(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    public object Json() => new { from_utc = Iso(From), to_utc = Iso(To) };
}

public sealed record HomeSummaryQuery(string Contract, long? Domain, string TimeZone, string Preset,
    DateTimeOffset Now, HomeWindow? Period, HomeWindow Current, HomeWindow Previous, bool WindowComplete)
{
    public string Language { get; init; } = "";
    public static string Iso(DateTimeOffset value)
    {
        value = value.ToUniversalTime();
        var micros = value.Ticks % TimeSpan.TicksPerSecond / 10;
        return value.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture)
            + (micros == 0 ? "" : "." + micros.ToString("D6", CultureInfo.InvariantCulture)) + "+00:00";
    }
    public object Context(long[] domains) => new
    {
        scope = Domain.HasValue ? "domain" : "accessible", domain_id = Domain, domain_ids = domains,
        time_zone = TimeZone,
        period = Period is null ? (object)new { preset = Preset, kind = "snapshot", as_of_utc = Iso(Now) }
            : new { preset = Preset, kind = "observations", from_utc = HomeWindow.Iso(Period.From), to_utc = HomeWindow.Iso(Period.To) }
    };

    public static HomeSummaryQuery Parse(IQueryCollection query, DateTimeOffset now)
    {
        if (query.TryGetValue("domain_id", out var selection) && (selection.Count != 1 || string.IsNullOrEmpty(selection[0])))
            throw new HomeQueryException("domain_scope_invalid");
        // Python's parse_qs drops blank values before the home handler sees them.
        query = new QueryCollection(query.Select(p => KeyValuePair.Create(p.Key,
            new Microsoft.Extensions.Primitives.StringValues(p.Value.Where(v => !string.IsNullOrEmpty(v)).ToArray())))
            .Where(p => p.Value.Count > 0).ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal));
        string[] allowed = ["contract", "scope", "domain", "domain_id", "period", "from", "to", "tz"];
        if (query.Keys.Except(allowed, StringComparer.Ordinal).Any()) throw new HomeQueryException("home_parameter_unknown");
        var selectedDomain = DomainQuery.ParseDomainId(query);
        if (query.Any(p => p.Value.Count != 1)) throw new HomeQueryException("home_parameter_invalid");
        string First(string key, string fallback = "") => query.TryGetValue(key, out var values) ? values[0] ?? "" : fallback;
        var contract = First("contract", "v1");
        if (contract is not ("v1" or "v2" or "v3" or "v4")) throw new HomeQueryException("home_contract_invalid");
        long? domain = selectedDomain;
        var scope = First("scope", "accessible");
        var rawDomain = First("domain");
        if (query.ContainsKey("domain_id"))
        {
            if (query.ContainsKey("scope") || query.ContainsKey("domain")) throw new HomeQueryException("domain_scope_invalid");
            rawDomain = First("domain_id"); scope = "domain";
        }
        if (scope is not ("accessible" or "domain") || (scope == "domain") != (rawDomain.Length > 0))
            throw new HomeQueryException("home_scope_invalid");
        if (scope == "domain" && domain is null)
        {
            if (!long.TryParse(rawDomain, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id) || id <= 0)
                throw new HomeQueryException(query.ContainsKey("domain_id") ? "domain_scope_invalid" : "home_scope_invalid");
            domain = id;
        }
        var zoneName = First("tz", "UTC");
        TimeZoneInfo zone;
        try { zone = TimeZoneInfo.FindSystemTimeZoneById(zoneName); }
        catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException or ArgumentException)
        { throw new HomeQueryException("home_timezone_invalid"); }
        // ZoneInfo accepts IANA names, not Windows registry aliases.
        if (zoneName != "UTC" && !TimeZoneInfo.TryConvertIanaIdToWindowsId(zoneName, out _))
            throw new HomeQueryException("home_timezone_invalid");
        var preset = First("period", contract == "v4" ? "24h" : "current");
        HomeWindow? period = null;
        var days = preset switch { "current" or "24h" => 1, "7d" => 7, "30d" => 30, "90d" => 90, _ => 0 };
        if (preset == "current")
        {
            if (query.ContainsKey("from") || query.ContainsKey("to")) throw new HomeQueryException("home_period_invalid");
        }
        else if (days > 0) period = new(now.AddDays(-days), now);
        else if (preset == "custom")
        {
            bool calendar = !First("from").Contains('T') && !First("to").Contains('T');
            DateTimeOffset Bound(string key)
            {
                var text = First(key);
                if (calendar && DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                {
                    var local = date.AddDays(calendar && key == "to" ? 1 : 0).ToDateTime(TimeOnly.MinValue);
                    return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(local, zone));
                }
                if (calendar || !(text.EndsWith('Z') || System.Text.RegularExpressions.Regex.IsMatch(text, @"[+-]\d\d:\d\d$"))
                    || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var value))
                    throw new HomeQueryException("report_period_invalid");
                return value.ToUniversalTime();
            }
            period = new(Bound("from"), Bound("to"));
            if (period.From >= period.To) throw new HomeQueryException("report_period_invalid");
            if (period.To - period.From > TimeSpan.FromDays(90)) throw new HomeQueryException("report_period_too_wide");
        }
        else throw new HomeQueryException("report_period_invalid");
        if (period is not null) period = new(DateTimeOffset.FromUnixTimeSeconds(period.From.ToUnixTimeSeconds()), DateTimeOffset.FromUnixTimeSeconds(period.To.ToUnixTimeSeconds()));
        if (contract == "v4" && (period is null || period.From >= period.To || period.To > now || period.To - period.From > TimeSpan.FromDays(7)))
            throw new HomeQueryException("report_period_invalid");
        HomeWindow current, previous;
        if (days > 0)
        {
            var end = TimeZoneInfo.ConvertTime(now, zone).Date;
            DateTimeOffset Utc(DateTime local) => new(TimeZoneInfo.ConvertTimeToUtc(local, zone));
            current = new(Utc(end.AddDays(-days)), Utc(end));
            previous = new(Utc(end.AddDays(-2 * days)), current.From);
        }
        else
        {
            current = period!; previous = new(current.From - (current.To - current.From), current.From);
        }
        return new(contract, domain, zoneName, preset, now, period, current, previous, current.To <= now);
    }

    public Dictionary<string, object?> Filters(string key)
    {
        var filters = new Dictionary<string, object?> { ["tz"] = TimeZone };
        if (Domain.HasValue) filters["domain"] = Domain.Value;
        if (key == "security.problems" && Period is not null)
        { filters["time_from"] = HomeWindow.Iso(Period.From); filters["time_to"] = HomeWindow.Iso(Period.To); }
        return filters;
    }

    public static string Href(string key, IDictionary<string, object?>? filters = null) => "/app/report/" + key
        + (filters is null || filters.Count == 0 ? "" : "?" + string.Join("&", filters.Select(p =>
            Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(Convert.ToString(p.Value, CultureInfo.InvariantCulture) ?? "").Replace("%20", "+", StringComparison.Ordinal))));
}
