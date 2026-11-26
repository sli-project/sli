using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

public sealed class SecurityEventsReader(IAdReportStore store, ISemanticDatabase database, BuiltinReportExports exports, IConfiguration? configuration = null) : IReportV2Reader
{
    public string OwnerId => "sli.core";
    public bool Handles(string key) => key == "security.events.chains";
    internal async Task<long[]> Authorized(AccessDecision access, bool export, CancellationToken ct)
    {
        var permitted = new List<long>(); long after = 0;
        while (true)
        {
            var batch = await store.DomainsAsync(after, ct); if (batch.Count == 0) break;
            permitted.AddRange(batch.Where(id => AdReportEndpoints.Allowed(access, "security", id, export)));
            after = batch[^1]; if (batch.Count < 256) break;
        }
        return permitted.ToArray();
    }
    public async Task<JsonObject> OptionsAsync(ReportDefinition definition, AccessDecision access, CancellationToken ct)
    {
        var ids = await Authorized(access, false, ct);
        var names = new Dictionary<long, string>();
        if (ids.Length > 0)
        {
            // Selector labels are metadata, independent of retained events and AD snapshots.
            await using var db = await database.OpenAsync(false, ct);
            var rows = await db.QueryAsync("select id, fqdn from domains where id=any($1) order by fqdn", ct, ids);
            foreach (var row in rows.OfType<JsonObject>())
                names.Add(long.Parse(row["id"]!.ToString(), CultureInfo.InvariantCulture), row["fqdn"]!.GetValue<string>());
        }
        return new JsonObject
        {
            ["domain"] = JsonSerializer.SerializeToNode(ids.Select(id => new { value = id.ToString(CultureInfo.InvariantCulture), label = names.GetValueOrDefault(id, "Домен " + id) })),
            ["change_operation"] = JsonSerializer.SerializeToNode(AdSecurity.ChangeEventIds()
                .Select(id => new { value = id.ToString(CultureInfo.InvariantCulture), label = id.ToString(CultureInfo.InvariantCulture) }))
        };
    }
    public Task<ReportExport> ExportAsync(ReportQueryContext c, CancellationToken ct) => exports.ExportAsync(c, ct);
    public async Task<JsonObject> QueryAsync(ReportQueryContext c, CancellationToken ct)
    {
        try { return await Read(c, ct); }
        catch (AdInputException e) { throw new ReportRequestException(e.Message); }
    }
    async Task<JsonObject> Read(ReportQueryContext c, CancellationToken ct)
    {
        if (c.Paging.Tab is "persistence-changes" or "account-revocation" or "lockout-recurring")
        {
            if (c.Params["domain"] is null) throw new ReportRequestException("report_parameter_required:domain");
            var data = c.Paging.Tab == "persistence-changes" ? await exports.PersistenceData(c, ct) : await new SecurityObservationReader(database,configuration).Read(c, ct);
            if (data.Text("state") != "denied") data["filter_options"] = await OptionsAsync(c.Definition, c.Access, ct);
            return data;
        }
        var period = AdPeriod.Parse(c.Params["period"]!["from_utc"]!.ToString(), c.Params["period"]!["to_utc"]!.ToString(), "UTC", "security_events",365);
        var cutoff = Sli.Server.Storage.EventReports.EventReadService.ShortBoundary(configuration);
        var filters = AdSecurity.Normalize(new QueryCollection(c.Params.Where(p => p.Value is JsonValue).ToDictionary(p => p.Key, p => new StringValues(p.Value!.ToString()))), domainChanges: true);
        long[] ids = c.Params["domain"] is {} selected ? [long.Parse(selected.ToString(), CultureInfo.InvariantCulture)] : await Authorized(c.Access, c.Action == "export", ct);
        if (ids.Any(id => id <= 0)) throw new ReportRequestException("security_events_domain_invalid");
        if (ids.Length == 0 || ids.Any(id => !AdReportEndpoints.Allowed(c.Access, "security", id, c.Action == "export"))) return ReportResult.Create(c.Definition.Key, "denied");
        var binding = new JsonObject { ["report"] = c.Definition.Key, ["filters"] = filters.DeepClone(), ["domains"] = JsonSerializer.SerializeToNode(ids), ["period"] = c.Params["period"]!.DeepClone(), ["principal"] = JsonSerializer.SerializeToNode(c.Principal), ["access"] = JsonSerializer.SerializeToNode(c.Access) };
        JsonObject? after = null;
        if (c.Paging.Cursor is not null)
        {
            try { after = JsonNode.Parse(ReportCursor.Decode(c.Paging.Cursor, binding)!)!.AsObject(); if (after.Int("id") < 0 || after.Int("id") == 0 && after.Text("group")?.Length != 64) throw new FormatException(); }
            catch (Exception e) when (e is FormatException or System.Text.Json.JsonException or InvalidOperationException or NullReferenceException) { throw new ReportRequestException("invalid_cursor"); }
        }
        var rows = new List<JsonObject>(); var categories = new JsonObject(); var sources = new List<JsonObject>(); bool more = false, history = false;
        foreach (long id in ids)
        {
            string? cursor = after is null ? null : AdSecurity.EncodeCursor(id, period, filters, DateTimeOffset.Parse(after.Text("time"), CultureInfo.InvariantCulture), after.Int("id"), after.Text("group") ?? "");
            bool snapshotValues = filters["changes_view"] is not null && c.Action == "view"
                && ResourceAccessDecisions.ReportAction(c.Access, "ad.users.v2", "view", [[new("domain", id)]],
                    new HashSet<string> { "identity_basic", "technical" }).Allowed;
            var raw = await store.ReadAsync(new("security", false, c.Action == "export", id, period, c.Paging.Limit, filters, cursor)
                { AuthenticationCutoff = cutoff, IncludeChangeSnapshotValues = snapshotValues }, false, ct);
            if (ReportResult.SourceState(raw.Text("state")) == "denied") return ReportResult.Create(c.Definition.Key, "denied");
            sources.Add(raw);
            rows.AddRange(raw.Objects("items").Select(r => r.Copy())); more |= raw.Flag("has_more"); history |= raw["collection_coverage"]?["history_event_present"]?.GetValue<bool>() == true;
            foreach (var (family, state) in raw["category_coverage"] as JsonObject ?? new())
            {
                int Rank(JsonNode? n) => n?["state"]?.ToString() switch { "processing_unfinished" => 3, "retained_match_present" => 2, "no_retained_match" => 1, _ => 0 };
                if (!categories.ContainsKey(family) || Rank(state) > Rank(categories[family])) categories[family] = state?.DeepClone();
            }
        }
        DateTimeOffset Time(JsonObject row) => DateTimeOffset.Parse(row.Text("time_created_utc"), CultureInfo.InvariantCulture);
        var ordered = filters.Text("changes_order") == "asc"
            ? rows.OrderBy(Time).ThenBy(r => r.Int("event_db_id"))
            : rows.OrderByDescending(Time).ThenByDescending(r => r.Int("event_db_id")).ThenByDescending(r => r.Text("summary_key"), StringComparer.Ordinal);
        var page = ordered.Take(c.Paging.Limit).ToArray();
        more |= rows.Count > page.Length;
        foreach (var row in page) Derived(row);
        var renderedSources = sources.Select(s => Render(c.Definition.Key, s)).ToArray();
        var states = renderedSources.Select(s => s.Text("state")).ToArray();
        string stateCode = states.Contains("error") ? "error" : states.Contains("processing") ? "processing"
            : states.Contains("partial") || states.Contains("not_collected") && !states.All(s => s == "not_collected") ? "partial"
            : states.Contains("stale") ? "stale" : states.All(s => s == "not_collected") ? "not_collected" : page.Length > 0 ? "ok" : "empty";
        var coverage = renderedSources[0]["coverage"]!.AsObject().Copy();
        foreach (string key in new[] { "missing_sources", "missing_domains", "domains", "source_issues" })
        {
            var values = renderedSources.SelectMany(s => s["coverage"]?[key] as JsonArray ?? []).DistinctBy(n => n?.ToJsonString()).ToArray();
            if (values.Length > 0) coverage[key] = new JsonArray(values.Select(n => n?.DeepClone()).ToArray());
        }
        if (sources.Count > 1) coverage["state"] = stateCode;
        string coverageState = coverage.Text("state", sources.Count == 1 ? sources[0].Text("state") : stateCode);
        if (states.All(s => s == "ok") && page.Length > 0 && coverageState == "empty_unverified") coverageState = "available";
        coverage["state"] = coverageState; coverage["history_event_present"] = history;
        if (sources.Any(s => s.Text("state") == "empty_unverified")) coverage["completeness"] ??= "not_proven";
        coverage["categories"] = categories;
        if (renderedSources.Any(s => s["coverage"]?["source_truncated"]?.GetValue<bool>() == true))
            coverage["source_truncated"] = true;
        var limitations = new JsonArray();
        foreach (string text in sources.SelectMany(s => s["limitations"] as JsonArray ?? []).Select(n => n?.ToString() ?? "").Distinct(StringComparer.Ordinal))
            limitations.Add(text switch
            {
                "Rows are source-event observations, not reconstructed account, membership, or audit state." => Note("observations_only", "Строки — наблюдения событий источника, а не восстановленное состояние учётных записей, членства или аудита."),
                "Unknown identity and outcome fields were not present in the scoped Storage V2 contract." => Note("unknown_fields", "Поля «не определён» отсутствовали в сохранённых данных события."),
                "An empty window does not prove complete source coverage." => Note("empty_not_proof", "Пустой результат не доказывает, что источник собран полностью."),
                _ => Note("engine_note", text)
            });
        var collections = new JsonObject();
        if (c.Paging.Tab == "daily")
        {
            var daily = await Daily(c, ids, period, filters, cutoff, ct);
            collections["daily"] = daily.Rows;
            if (daily.Truncated)
            {
                stateCode = "partial";
                coverage["state"] = "bounded_slice";
                coverage["source_truncated"] = true;
            }
        }
        var result = ReportResult.Create(c.Definition.Key, stateCode, JsonSerializer.SerializeToNode(page)!.AsArray(), coverage, collections, limitations);
        if (filters["changes_view"] is not null && stateCode != "not_collected")
        {
            result["change_counts"] = new JsonObject(AdSecurity.ChangeViews.Select(key =>
                KeyValuePair.Create(key, (JsonNode?)JsonValue.Create(sources.Sum(s => s["change_counts"].Int(key))))));
            result["filtered_count"] = sources.Sum(s => s.Int("filtered_count"));
        }
        result["has_more"] = more; result["next_cursor"] = more && page.Length > 0 ? ReportCursor.Encode(binding, new JsonObject { ["time"] = page[^1]["time_created_utc"]!.DeepClone(), ["id"] = page[^1]["event_db_id"]?.DeepClone() ?? JsonValue.Create(0), ["group"] = page[^1]["summary_key"]?.DeepClone() }.ToJsonString()) : null;
        result["window"] = new JsonObject { ["from_utc"] = c.Params["period"]!["from_utc"]!.DeepClone(), ["to_utc_exclusive"] = c.Params["period"]!["to_utc"]!.DeepClone() };
        result["filter_options"] = await OptionsAsync(c.Definition, c.Access, ct); return result;
    }
    internal static JsonObject Render(string key, JsonObject raw)
    {
        var rows = new JsonArray(raw.Objects("items").Select(r => (JsonNode?)r.DeepClone()).ToArray());
        string engine = raw.Text("state"), state = ReportResult.SourceState(engine);
        if (state == "ok" && rows.Count == 0) state = "empty";
        var coverage = (raw["collection_coverage"] as JsonObject)?.Copy() ?? new();
        string source = coverage.Text("state", engine);
        if (engine == "available" && rows.Count > 0 && source == "empty_unverified") source = engine;
        coverage["state"] = source;
        coverage["completeness"] ??= engine == "empty_unverified" ? coverage["source_completeness"]?.DeepClone() : null;
        return ReportResult.Create(key, state, rows, coverage);
    }
    internal static void Derived(JsonObject row)
    {
        var outcome = row["outcome"] as JsonObject;
        row["outcome_code"] = outcome?["state"]?.ToString() == "observed" && outcome["value"]?.ToString() is "success" or "failure" ? outcome["value"]!.DeepClone() : JsonValue.Create("unknown");
        row["member_text"] = row["member"]?["state"]?.ToString() == "observed" ? (row["member"]?["name"] ?? row["member"]?["sid"])?.DeepClone() : null;
        string code = "reports.v2.security.events.chains.actions." + row["event_id"];
        if (row["event_id"]?.ToString() == "4776") code += "." + row["outcome_code"];
        if (row.Flag("sli_service_install")) code = "reports.v2.security.events.chains.actions.sli_service";
        JsonObject? parameters = null;
        if (row.Int("sli_audit_subcategories") is > 0 and var subcategories)
        {
            code = "reports.v2.security.events.chains.actions.sli_audit." + (subcategories % 100 is >= 11 and <= 14
                ? "many" : (subcategories % 10) switch { 1 => subcategories == 1 ? "one" : "ending_one", >= 2 and <= 4 => "few", _ => "many" });
            parameters = new JsonObject { ["count"] = subcategories };
        }
        var message = ReportPresentation.Message(code, false, parameters);
        row["change_text"] = message?["text"]?.DeepClone();
        if (message is not null)
        {
            if (row["presentation_messages"] is not JsonObject) row["presentation_messages"] = new JsonObject();
            row["presentation_messages"]!["change_text"] = message;
        }
    }
    async Task<(JsonArray Rows, bool Truncated)> Daily(ReportQueryContext c, long[] ids, AdPeriod period, JsonObject filters, DateTimeOffset cutoff, CancellationToken ct)
    {
        var counts = new Dictionary<string, Dictionary<string, long>>();
        bool truncated = false;
        await using var db = await database.OpenAsync(false, ct);
        foreach (long id in ids)
        {
            var dailyFilters = filters.Copy(); dailyFilters.Remove("event_db_id");
            var query = AdSecurityQuery.Create(new("security", false, false, id, period, c.Paging.Limit, dailyFilters, null),cutoff:cutoff,useColdFacts:true,config:configuration);
            var rows = await db.QueryAsync(query.DailySql, ct, query.DailyArgs.Concat(new object?[] { c.Paging.Timezone }).ToArray());
            foreach (var row in rows.OfType<JsonObject>())
            {
                string date = row.Text("date"), family = AdSecurity.Family(long.Parse(row["event_id"]!.ToString(), CultureInfo.InvariantCulture))!;
                if (!counts.TryGetValue(date, out var values)) counts[date] = values = new(); values[family] = values.GetValueOrDefault(family) + long.Parse(row["count"]!.ToString(), CultureInfo.InvariantCulture);
            }
        }
        var output = new JsonArray(); var zone = TimeZoneInfo.FindSystemTimeZoneById(c.Paging.Timezone);
        for (var date = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(period.Start, zone).DateTime); date <= DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(period.End.AddSeconds(-1), zone).DateTime); date = date.AddDays(1))
        {
            string key = date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture); var values = counts.GetValueOrDefault(key) ?? new(); var row = new JsonObject { ["date"] = key, ["total"] = values.Values.Sum() };
            foreach (string family in new[] { "authentication", "account_lock", "password_operation", "account_lifecycle", "account_change", "group_membership", "group_lifecycle", "audit_configuration" }) row[family] = values.GetValueOrDefault(family); output.Add(row);
        }
        return (output, truncated);
    }
    internal static JsonObject Note(string code, string text) => new() { ["code"] = code, ["text"] = text };
}
