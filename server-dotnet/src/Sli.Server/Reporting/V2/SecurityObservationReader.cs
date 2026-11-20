using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

internal sealed partial class SecurityObservationReader(ISemanticDatabase database,IConfiguration? configuration=null)
{
    static long N(JsonNode? row, string key) => long.TryParse(row?[key]?.ToString(), out long n) ? n : 0;
    static string? T(JsonNode? row, string key) => row?[key]?.ToString().Trim() is { Length: > 0 } text && text != "-" ? text : null;
    static DateTimeOffset Time(JsonNode row, string key = "time_created_utc") => DateTimeOffset.Parse(row[key]!.ToString(), CultureInfo.InvariantCulture).ToUniversalTime();
    static JsonArray Array<TValue>(IEnumerable<TValue> rows) => JsonSerializer.SerializeToNode(rows)!.AsArray();
    static JsonObject Obj(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();
    static string? Sid(JsonNode row, bool revocation = false)
    {
        string? sid = T(row, revocation && N(row, "event_id") == 6272 ? "subject_user_sid" : "target_user_sid")?.ToLowerInvariant();
        return sid is not null && (revocation ? System.Text.RegularExpressions.Regex.IsMatch(sid, @"\As-1-5-21-\d+-\d+-\d+-\d+\z") : sid.StartsWith("s-1-", StringComparison.Ordinal) && sid != "s-1-0-0") ? sid : null;
    }
    static string[] Codes(JsonObject row) => new[] { T(row["facts_json"], "failure_status"), T(row["facts_json"], "result_code"), T(row, "result_code") }.OfType<string>().Select(s => s.ToLowerInvariant()).Distinct().Order(StringComparer.Ordinal).ToArray();
    internal static bool HasMeaning(JsonObject row) => row["short_event"]?.GetValue<bool>() == true || row["normalized_event_id"] is not null;
    static bool Failure(JsonObject row) => N(row, "event_id") is 4625 or 4771 || N(row, "event_id") == 4776 && Codes(row) is { Length: > 0 } codes && codes.All(code => ulong.TryParse(code.StartsWith("0x", StringComparison.Ordinal) ? code[2..] : code, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong value) && value != 0);
    public async Task<JsonObject> Read(ReportQueryContext c, CancellationToken ct)
    {
        long domain = long.Parse(c.Params["domain"]!.ToString(), CultureInfo.InvariantCulture);
        int minimum = 2, window = 15;
        if (c.Paging.Tab != "account-revocation")
        {
            minimum = checked((int)(c.Params["min_repeats"] is null ? 2 : N(c.Params, "min_repeats")));
            window = checked((int)(c.Params["failure_window"] is null ? 15 : N(c.Params, "failure_window")));
            if (domain <= 0 || c.Paging.Limit is < 1 or > 500 || c.Action is not ("view" or "export") || minimum < 1 || window is < 1 or > 1440)
                throw new ReportRequestException("security_events_filter_invalid");
        }
        if (!AdReportEndpoints.Allowed(c.Access, "security", domain, c.Action == "export")) return ReportResult.Create(c.Definition.Key, "denied");
        var start = DateTimeOffset.Parse(c.Params["period"]!["from_utc"]!.ToString(), CultureInfo.InvariantCulture).ToUniversalTime();
        var end = DateTimeOffset.Parse(c.Params["period"]!["to_utc"]!.ToString(), CultureInfo.InvariantCulture).ToUniversalTime();
        if (start >= end || end - start > TimeSpan.FromDays(31)) throw new ReportRequestException("security_events_period_too_wide");
        if (c.Paging.Tab == "account-revocation")
        {
            long follow = c.Params["revocation_window"] is null ? 1440 : N(c.Params, "revocation_window");
            if (domain <= 0 || c.Paging.Limit is < 1 or > 500 || c.Action is not ("view" or "export")
                || follow is < 1 or > 1440 || N(c.Params, "minimum_delay") < 0
                || T(c.Params, "activity_type") is not (null or "logon" or "nps_allow" or "vpn_continuation" or "insufficient"))
                throw new ReportRequestException("security_events_filter_invalid");
        }
        await using var db = await database.OpenAsync(false, ct);
        if (c.Paging.Tab == "account-revocation") return await Revocation(c, db, domain, start, end, ct);
        Task<JsonArray> Read(int[] codes, DateTimeOffset from) => ShortEvents(db, domain, codes, from, end, configuration, ct);
        var locks = await Read([4740], start); var unlocks = await Read([4767], start); var failures = await Read([4625, 4771, 4776], start.AddMinutes(-window));
        var events = locks.Concat(unlocks).Concat(failures).OfType<JsonObject>().Where(e => e["day"] is null).ToArray();
        bool dailyFailures = failures.Any(e => e?["day"] is not null);
        var rows = Lockouts(events, window, minimum, T(c.Params, "target"), T(c.Params, "caller"), T(c.Params, "failure_code"), dailyFailures);
        var coverage = Obj(new { state = "coverage_unverified", completeness = "not_proven", source_truncated = false, accounts_truncated = rows.Length > c.Paging.Limit,
            unknown_sid_lockouts = locks.Count(e => Sid(e!) is null), unmatched_identity_failures = failures.OfType<JsonObject>().Count(e => Sid(e) is null && Failure(e)), missing_current_semantics = events.Count(e => !HasMeaning(e)) });
        var result = ReportResult.Create(c.Definition.Key, rows.Length > c.Paging.Limit ? "partial" : rows.Length > 0 ? "ok" : "empty", coverage: coverage,
            collections: new JsonObject { ["lockout_recurring"] = Array(rows.Take(c.Paging.Limit)) }, limitations: new JsonArray(SecurityEventsReader.Note("recurring_correlation", "Точный SID и близость времени связывают наблюдения, но не доказывают причину блокировки. События без SID не объединяются по имени; автоматическое снятие блокировки может не создавать 4767."), SecurityEventsReader.Note("recurring_coverage", "Полнота источника не подтверждена. Используется только текущая версия семантики; недостающие факты не восстанавливаются из старых версий.")));
        long lockCount = rows.Sum(r => N(r, "lockouts"));
        result["metrics"] = Array(new[] { Obj(new { key = "recurring_accounts", label = "Аккаунты с повторными блокировками", value = (double?)rows.Count(r => N(r, "lockouts") >= 2 && r["sid"] is not null) }), Obj(new { key = "recurring_lockouts", label = "Блокировки", value = (double?)lockCount }), Obj(new { key = "recurring_relocked", label = "Аккаунты с повтором после разблокировки", value = (double?)rows.Count(r => N(r, "relocks") > 0) }), Obj(new { key = "recurring_caller", label = "Блокировки с Caller, %", value = lockCount > 0 ? (double?)Math.Round(100.0 * rows.Sum(r => N(r, "caller_lockouts")) / lockCount, 1) : null }), Obj(new { key = "recurring_sources", label = "Наблюдаемые источники", value = (double?)rows.SelectMany(r => new[] { "callers", "ips", "workstations" }.SelectMany(k => r[k]!.AsArray().Select(v => (k, v!.ToString().ToLowerInvariant())))).Distinct().Count() }) });
        result["filtered_count"] = rows.Length; result["window"] = Obj(new { from_utc = AdJson.Iso(start), to_utc_exclusive = AdJson.Iso(end), failure_window_minutes = window, idea_key = "security.lockout-recurring", source_row_limits = new { lockouts = (int?)null, unlocks = (int?)null, failures = (int?)null } }); return result;
    }
    internal static JsonObject[] Lockouts(IEnumerable<JsonObject> input, int window, int minimum, string? account = null, string? caller = null, string? code = null, bool truncated = false)
    {
        var events = input.DistinctBy(e => N(e, "event_db_id")).OrderBy(e => Time(e)).ThenBy(e => N(e, "event_db_id")).ToArray(); var output = new List<JsonObject>();
        foreach (var group in events.Where(e => N(e, "event_id") == 4740).GroupBy(e => Sid(e) ?? "unknown:" + N(e, "event_db_id")))
        {
            var episodes = group.ToArray(); string? sid = Sid(episodes[0]); if (episodes.Length < minimum || account is not null && !new[] { group.Key }.Concat(episodes.Select(e => T(e, "target_user_name") ?? "")).Contains(account, StringComparer.OrdinalIgnoreCase)) continue;
            var failures = events.Where(e => Sid(e) == group.Key && Failure(e)).ToArray(); var unlocks = events.Where(e => Sid(e) == group.Key && N(e, "event_id") == 4767).ToArray();
            var matched = new List<JsonObject>(); int matchedCount = 0, relocks = 0; var intervals = new List<double>(); DateTimeOffset? previous = null;
            foreach (var episode in episodes)
            {
                var at = Time(episode); var associated = failures.Where(e => Time(e) >= at.AddMinutes(-window) && (previous is null || Time(e) > previous) && Time(e) < at).ToArray();
                if (previous is not null) { intervals.Add((at - previous.Value).TotalSeconds); if (unlocks.Any(e => Time(e) > previous && Time(e) < at)) relocks++; }
                matched.AddRange(associated); if (associated.Length > 0) matchedCount++; previous = at;
            }
            var observedUnlocks = unlocks.Where(e => Time(e) > Time(episodes[0])).ToArray();
            string[] Values(IEnumerable<string?> values) => values.OfType<string>().Distinct().Order(StringComparer.Ordinal).ToArray();
            var callers = Values(episodes.Select(e => T(e["facts_json"], "caller_computer"))); var ips = Values(episodes.Concat(matched).Select(e => T(e, "ip_address"))); var stations = Values(episodes.Concat(matched).Select(e => T(e, "workstation_name") ?? T(e["facts_json"], "workstation"))); var codes = Values(matched.SelectMany(Codes));
            if (caller is not null && !callers.Concat(ips).Concat(stations).Contains(caller, StringComparer.OrdinalIgnoreCase) || code is not null && !codes.Contains(code, StringComparer.OrdinalIgnoreCase)) continue;
            bool missing = episodes.Concat(matched).Concat(observedUnlocks).Any(e => !HasMeaning(e));
            output.Add(Obj(new { account_key = group.Key, account = T(episodes[^1], "target_user_name") ?? sid, sid = sid is null ? null : T(episodes[0], "target_user_sid"), first_lockout = AdJson.Iso(Time(episodes[0])), last_lockout = AdJson.Iso(Time(episodes[^1])), lockouts = episodes.Length, relocks, unlocks = observedUnlocks.Length, callers, ips, workstations = stations, failure_codes = codes, failures = matched.Count, matched_lockouts = matchedCount, intervals_seconds = intervals, last_interval_seconds = intervals.Count > 0 ? (double?)intervals[^1] : null,
                matching = sid is null ? "unknown_sid" : truncated || missing ? "partial" : matchedCount == episodes.Length ? "all_with_failures" : matchedCount > 0 ? "some_with_failures" : "no_failures", caller_lockouts = episodes.Count(e => T(e["facts_json"], "caller_computer") is not null), first_event = N(episodes[0], "event_db_id"), last_event = N(episodes[^1], "event_db_id"), unlock_event = observedUnlocks.Length > 0 ? (long?)N(observedUnlocks[^1], "event_db_id") : null, failure_event = matched.Count > 0 ? (long?)N(matched[^1], "event_db_id") : null, event_ids = episodes.Concat(observedUnlocks).Concat(matched).Select(e => N(e, "event_db_id")) }));
        }
        return output.OrderByDescending(r => N(r, "lockouts")).ThenBy(r => T(r, "account_key"), StringComparer.Ordinal).ToArray();
    }
}
