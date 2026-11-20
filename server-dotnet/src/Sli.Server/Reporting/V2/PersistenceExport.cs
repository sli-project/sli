using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;
using Sli.Server.Ad;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

public sealed partial class BuiltinReportExports
{
    async Task<ReportExport> Persistence(ReportQueryContext c, AdPeriod period, CancellationToken ct)
    {
        var data = await PersistenceData(c with { Action = "export", Paging = c.Paging with { Limit = c.Definition.MaxLimit } }, ct);
        var rows = data["collections"]!.AsObject().Objects("persistence_changes");
        var columns = c.Definition.Views.Single(v => v.Text("key") == "persistence-changes").Objects("columns");
        return new(ReportCsv.FromColumns(columns, rows), rows.Length, data.Text("state") == "partial");
    }
    internal async Task<JsonObject> PersistenceData(ReportQueryContext c, CancellationToken ct)
    {
        if (c.Action is not ("view" or "export")) throw new ReportRequestException("security_events_filter_invalid");
        AdPeriod period;
        try { period = AdPeriod.Parse(c.Params["period"]!["from_utc"]!.ToString(), c.Params["period"]!["to_utc"]!.ToString(), "UTC", "security_events"); }
        catch (AdInputException e) { throw new ReportRequestException(e.Message); }
        if (c.Params["domain"] is not {} domain) throw new ReportRequestException("report_parameter_required:domain");
        long id = long.Parse(domain.ToString(), System.Globalization.CultureInfo.InvariantCulture);
        if (!AdReportEndpoints.Allowed(c.Access, "security", id, c.Action == "export")) {
            if (c.Action == "export") throw new ReportRequestException("report_export_not_authorized", 403);
            return ReportResult.Create(c.Definition.Key, "denied");
        }
        await using var db = await database.OpenAsync(false, ct);
        var events = await SecurityObservationReader.ShortEvents(db, id, [4697,4698,4699,4700,4701,4702,7045], period.Start, period.End, configuration, ct, 10001);
        bool cut = events.Count > 10000;
        var retained = events.OfType<JsonObject>().Take(10000).ToArray();
        var rows = PersistenceRows(retained, cut);
        string? P(string key) => c.Params[key]?.ToString();
        bool Has(string? value, string? term) => string.IsNullOrEmpty(term) || (value ?? "").Contains(term, StringComparison.OrdinalIgnoreCase);
        int? max = int.TryParse(P("persistence_rarity"), out int rarity) ? rarity : null;
        var selected = rows.Where(r => Has(T(r, "dc"), P("source")) && (P("persistence_type") is not {} type || T(r, "object_type") == type)
            && Has(T(r, "action"), P("persistence_path")) && (P("persistence_change") is not {} change || T(r, "change") == change)
            && (max is null || N(r, "frequency") <= max) && (P("actor") is not {} actor || r["observations"]!.AsArray().Any(o => Has(T(o, "initiator_sid"), actor) || Has(T(o, "initiator_name"), actor)))).ToArray();
        var page = selected.Take(c.Paging.Limit).ToArray(); bool rowsCut = selected.Length > page.Length;
        var result = ReportResult.Create(c.Definition.Key, cut || rowsCut ? "partial" : selected.Length > 0 ? "ok" : "empty",
            coverage: new JsonObject { ["state"] = cut ? "bounded_slice" : "coverage_unverified", ["completeness"] = "not_proven", ["source_truncated"] = cut, ["rows_truncated"] = rowsCut, ["missing_current_semantics"] = retained.Count(e => !SecurityObservationReader.HasMeaning(e)) },
            collections: new JsonObject { ["persistence_changes"] = new JsonArray(page.Select(r => (JsonNode?)r).ToArray()) },
            limitations: new JsonArray(SecurityEventsReader.Note("persistence_observations", "История содержит наблюдения в выбранном окне, а не восстановленное состояние или доказательство закрепления. Предыдущее значение — только предыдущее наблюдение; при неоднозначном порядке оно неизвестно. Обновления ПО могут быть легитимными."), SecurityEventsReader.Note("persistence_linking", "4697 и 7045 связаны только при точном совпадении DC, времени, имени, файла, RunAs и типа запуска и единственной паре. Связь не доказывает одну установку. Полнота источников не подтверждена.")));
        long Objects(Func<JsonObject, bool> predicate) => selected.Where(r => r["object_key"]?[0]?.ToString() != "unknown" && predicate(r)).Select(r => r["object_key"]!.ToJsonString()).Distinct().LongCount();
        var metrics = new JsonArray();
        void Metric(string key, string label, long value) => metrics.Add(new JsonObject { ["key"] = key, ["label"] = label, ["value"] = value });
        Metric("persistence_services", "Службы с наблюдаемой установкой", Objects(r => T(r, "object_type") == "service" && T(r, "change") == "installed"));
        Metric("persistence_tasks", "Задачи с наблюдаемым созданием", Objects(r => T(r, "object_type") == "task" && T(r, "change") == "created"));
        Metric("persistence_actions", "Объекты с изменённым action", Objects(r => r["action"] is not null && r["previous_value"] is not null && !JsonNode.DeepEquals(r["previous_value"], r["action"])));
        Metric("persistence_paths", "Редкие пути / action в срезе", selected.Where(r => T(r, "action") is not null).GroupBy(r => T(r, "action")).LongCount(g => g.Count() <= (max ?? 1)));
        Metric("persistence_repeated", "Объекты с повторными наблюдениями", Objects(r => N(r, "frequency") > 1));
        Metric("persistence_unknown", "Исходные события без SID инициатора", selected.SelectMany(r => r["observations"]!.AsArray()).Count(o => o?["initiator_sid"] is null));
        result["metrics"] = metrics; result["filtered_count"] = selected.Length;
        result["window"] = new JsonObject { ["from_utc"] = AdJson.Iso(period.Start), ["to_utc_exclusive"] = AdJson.Iso(period.End), ["idea_key"] = "security.persistence-changes", ["source_row_limit"] = 10000 };
        return result;
    }
    static string? T(JsonNode? row, string key) => row?[key]?.ToString().Trim() is { Length: > 0 } text && text != "-" ? text : null;
    static long N(JsonNode? row, string key) => long.TryParse(row?[key]?.ToString(), out long n) ? n : 0;
    static (string? Action, string? RunAs) TaskValues(JsonObject ev)
    {
        string? runAs = T(ev, "run_as"), content = T(ev, "task_content"), action = T(ev, "task_action");
        if (content is null) return (action?.Contains('<') == true ? null : action, runAs);
        try {
            if (Encoding.UTF8.GetByteCount(content) > 8192) return (null, runAs);
            using var reader = XmlReader.Create(new StringReader(content), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8192 });
            var root = XElement.Load(reader);
            if (root.DescendantsAndSelf().Count() > 2048 || root.DescendantsAndSelf().Any(n => n.Ancestors().Count() >= 32)) return (null, runAs);
            XElement[] Children(XElement node, string name) => node.Elements().Where(n => n.Name.LocalName == name).ToArray();
            string? Text(XElement node, string name) => Children(node, name).FirstOrDefault()?.Value.Trim() is { Length: > 0 } value ? value : null;
            var principals = Children(root, "Principals").SelectMany(p => Children(p, "Principal")).ToArray();
            if (runAs is null && principals.Length == 1) runAs = Text(principals[0], "UserId") ?? Text(principals[0], "GroupId");
            var actions = new List<string>();
            foreach (var node in Children(root, "Actions").SelectMany(a => a.Elements())) {
                if (node.Name.LocalName == "Exec") {
                    if (Text(node, "Command") is {} command) actions.Add(string.Join(' ', new[] { command, Text(node, "Arguments") }.OfType<string>()) + (Text(node, "WorkingDirectory") is {} dir ? " (" + dir + ")" : ""));
                }
                else actions.Add(node.Name.LocalName + ": " + string.Join("; ", node.Elements().Select(n => n.Name.LocalName + "=" + n.Value)));
            }
            return (actions.Count > 0 ? string.Join("; ", actions) : null, runAs);
        }
        catch (Exception e) when (e is XmlException or ArgumentException) { return (null, runAs); }
    }
    static JsonObject Observation(JsonObject ev)
    {
        string? sid = T(ev, "process_user_sid"); if (sid?.StartsWith("s-1-", StringComparison.OrdinalIgnoreCase) != true || sid.Equals("S-1-0-0", StringComparison.OrdinalIgnoreCase)) sid = null;
        return new() { ["event_db_id"] = ev["event_db_id"]!.DeepClone(), ["event_id"] = ev["event_id"]!.DeepClone(), ["initiator_sid"] = sid,
            ["initiator_name"] = T(ev, "process_user_name"), ["initiator_domain"] = T(ev, "process_user_domain"), ["href"] = "/app/events/" + ev["event_db_id"] };
    }
    internal static JsonObject[] PersistenceRows(IEnumerable<JsonObject> input, bool truncated)
    {
        var events = input.DistinctBy(e => N(e, "event_db_id")).OrderBy(e => e["time_created_utc"]!.ToString(), StringComparer.Ordinal).ThenBy(e => N(e, "event_db_id")).ToArray();
        string Key(params object?[] parts) => System.Text.Json.JsonSerializer.Serialize(parts);
        var linked = new Dictionary<long, JsonObject>(); var consumed = new HashSet<long>();
        if (!truncated) foreach (var pair in events.Where(e => N(e, "event_id") is 4697 or 7045 && SecurityObservationReader.HasMeaning(e) && N(e, "server_id") > 0 && new[] { "service_name", "service_file", "service_account", "service_start_type" }.All(k => T(e, k) is not null))
            .GroupBy(e => Key(e["domain_id"]?.ToString(), e["server_id"]?.ToString(), e["time_created_utc"]?.ToString(), T(e, "service_name"), T(e, "service_file"), T(e, "service_account"), T(e, "service_start_type")))) {
            var list = pair.ToArray(); if (list.Length != 2 || list.Select(e => N(e, "event_id")).Distinct().Count() != 2) continue;
            var primary = list.Single(e => N(e, "event_id") == 4697); var secondary = list.Single(e => N(e, "event_id") == 7045);
            linked[N(primary, "event_db_id")] = secondary; consumed.Add(N(secondary, "event_db_id"));
        }
        var histories = new Dictionary<string, List<JsonObject>>();
        foreach (var ev in events.Where(e => !consumed.Contains(N(e, "event_db_id")))) {
            long code = N(ev, "event_id"), id = N(ev, "event_db_id"); bool service = code is 4697 or 7045;
            string? name = T(ev, service ? "service_name" : "task_name"); bool known = name is not null && N(ev, "server_id") > 0 && SecurityObservationReader.HasMeaning(ev);
            string key = known ? Key(N(ev,"domain_id"), N(ev,"server_id"), service ? "service" : "task", name) : Key("unknown", id);
            var (action, runAs) = service ? (T(ev, "service_file"), T(ev, "service_account")) : TaskValues(ev);
            var observations = new JsonArray(Observation(ev)); linked.TryGetValue(id, out var other); if (other is not null) observations.Add(Observation(other));
            var row = new JsonObject { ["event_db_id"] = id, ["linked_event"] = other?["event_db_id"]?.DeepClone(), ["dc"] = T(ev, "dc"), ["object"] = name, ["object_type"] = service ? "service" : "task", ["object_key"] = JsonNode.Parse(key),
                ["change"] = T(ev, "task_change") ?? (code switch { 4697 or 7045 => "installed", 4698 => "created", 4699 => "deleted", 4700 => "enabled", 4701 => "disabled", _ => "updated" }),
                ["action"] = action, ["run_as"] = runAs, ["service_start_type"] = service ? T(ev, "service_start_type") : null,
                ["initiator"] = observations[0]!["initiator_sid"]?.DeepClone() ?? observations[0]!["initiator_name"]?.DeepClone(),
                ["initiator_sid"] = observations[0]!["initiator_sid"]?.DeepClone(), ["event_ids"] = new JsonArray(observations.Select(o => o!["event_db_id"]!.DeepClone()).ToArray()), ["task_content"] = null,
                ["initiator_quality"] = observations.All(o => o?["initiator_sid"] is not null) ? "exact_sid" : observations.Any(o => o?["initiator_sid"] is not null) ? "partially_known" : "unknown_sid",
                ["observed_at"] = ev["time_created_utc"]!.DeepClone(), ["quality"] = !SecurityObservationReader.HasMeaning(ev) ? "missing_semantics" : !known ? "unknown_object" : other is not null ? "exact_link" : "exact_object",
                ["observations"] = observations, ["evidence"] = new JsonArray(observations.Select(o => (JsonNode?)JsonValue.Create(o!["event_id"] + ": " + o["href"])).ToArray()) };
            if (!histories.TryGetValue(key, out var history)) histories[key] = history = []; history.Add(row);
        }
        foreach (var history in histories.Values) {
            JsonObject? previous = null;
            foreach (var group in history.GroupBy(r => r["observed_at"]!.ToString())) {
                var values = group.Select(r => new JsonObject(new[] { "action", "run_as", "service_start_type", "change" }.Select(k => KeyValuePair.Create(k, r[k]?.DeepClone())))).ToArray();
                foreach (var row in group) {
                    row["first_seen"] = history[0]["observed_at"]!.DeepClone(); row["last_seen"] = history[^1]["observed_at"]!.DeepClone(); row["frequency"] = history.Count;
                    row["previous_value"] = previous?["action"]?.DeepClone();
                    row["previous"] = previous?.DeepClone();
                    if (group.Count() > 1) row["quality"] = "ambiguous_order"; if (truncated) row["quality"] = "partial";
                }
                previous = values.All(v => JsonNode.DeepEquals(v, values[0])) ? values[0] : null;
            }
        }
        return histories.Values.SelectMany(h => h).OrderByDescending(r => r["observed_at"]!.ToString(), StringComparer.Ordinal).ThenByDescending(r => N(r, "event_db_id")).ToArray();
    }
}
