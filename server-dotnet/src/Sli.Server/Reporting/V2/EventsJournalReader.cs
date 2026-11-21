using System.Text.Json;
using System.Text.Json.Nodes;
using System.Globalization;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Semantic;
using Sli.Server.Storage.EventReports;
using Sli.Server.Entities;
using Sli.Server.Problems;

namespace Sli.Server.Reporting.V2;

public sealed class EventsJournalReader(ReportRunner runner, IAccessFactsRepository facts, ISemanticDatabase database, BuiltinReportExports exports, IProblemRepository? problems = null) : IReportV2Reader
{
    public string OwnerId => "sli.core";
    public bool Handles(string key) => key == "events.journal";
    public Task<ReportExport> ExportAsync(ReportQueryContext c, CancellationToken ct) => c.Params["problem_id"] is null
        ? exports.ExportAsync(c, ct) : throw new ReportRequestException("report_export_denied", 403);
    public async Task<JsonObject> QueryAsync(ReportQueryContext c, CancellationToken ct)
    {
        var subject = await facts.LoadAsync(c.Principal, ct);
        var projection = JsonSerializer.SerializeToNode(AccessReadProjection.Compose(c.Principal, subject, c.Access.Capabilities, c.Access, false))!.AsObject();
        var filters = new Dictionary<string, string> { ["time_from"] = c.Params["period"]!["from_utc"]!.ToString(), ["time_to"] = c.Params["period"]!["to_utc"]!.ToString() };
        foreach (string key in new[] { "view", "q", "server" }) if (c.Params[key]?.ToString() is { Length: > 0 } value && (key != "view" || value != "all")) filters[key] = value;
        long? problemId = null;
        if (c.Params["problem_id"] is {} requested) {
            if (!Integer(requested, out long id) || id <= 0) throw new ReportRequestException("report_parameter_invalid:problem_id");
            var access = new ProblemAccess(c.Access);
            try {
                access.Capability("evidence.exact");
                if (!access.Fields("raw_evidence", "technical") || !c.FieldAccess(["security", "raw_evidence", "technical"]))
                    throw new ProblemException("report_field_categories_not_allowed", 403);
                var domains = access.Scope("security.queue").Domains();
                var input = new FindingQuery(null, null, null, null, null, null, null, domains, 1, false) { FindingId = id, Compact = true, PageQueue = true };
                var admitted = await (problems ?? throw new ReportRequestException("report_reader_unavailable", 503)).FindingsAsync(input, access, ct);
                if (admitted["items"] is not JsonArray { Count: 1 }) throw new ReportRequestException("report_row_not_found", 404);
            }
            catch (ProblemException error) { throw new ReportRequestException(error.Code, error.Status); }
            problemId = id;
        }
        if (!string.IsNullOrEmpty(c.Paging.Cursor)) filters["cursor"] = c.Paging.Cursor;
        JsonObject raw;
        try { raw = await runner.ExecuteAsync(new(c.Principal, subject, c.Access.Capabilities, projection), "events.explorer", Math.Min(c.Paging.Limit, 200), null, "view", filters, ct, problemId); }
        catch (ReportException e) { throw new ReportRequestException(e.Message, e.Status); }
        var rows = raw.Objects("items");
        // Dependencies belong to one projected row, never a union of grant branches.
        var identities = rows.Select(Identity).Where(i => i.HasValue).Select(i => i!.Value).ToHashSet();
        var titles = new Dictionary<(string Key, long EventId, string Channel), JsonObject>();
        long[] ids = identities.Where(i => !i.Key.Contains(':')).Select(i => long.Parse(i.Key,CultureInfo.InvariantCulture)).Distinct().Order().ToArray();
        string[] groups = identities.Where(i => i.Key.Contains(':')).Select(i => i.Key).ToArray();
        if (ids.Length > 0 || groups.Length > 0)
        {
            try
            {
                await using var db = await database.OpenAsync(false, ct);
                var sources = await db.QueryAsync("with short_events as ("+EntityShortSql.Source("$3")+") select e.id,e.event_id,e.server_id,e.domain_id,e.channel,e.provider_name,e.day,e.summary_key "+EventReadService.ShortJoins+" where s.id is not null and (e.id=any($1) or (e.day::text || ':' || e.summary_key)=any($4)) limit $2", ct, ids, identities.Count, runner.ShortRetentionBoundary, groups);
                foreach (var source in sources.OfType<JsonObject>())
                {
                    if (Identity(source) is not {} identity || !identities.Contains(identity)
                        || !Integer(source["domain_id"], out long domain) || !Integer(source["server_id"], out long server) || domain <= 0 || server <= 0) continue;
                    IReadOnlyList<IReadOnlyList<AccessResource>> resources = [[new("server", server), new("domain", domain), new("channel", Value: source["channel"]!.ToString())]];
                    if (!ResourceAccessDecisions.ReportAction(c.Access, "events.explorer", "view", resources, new HashSet<string> { "security", "technical", "raw_evidence" }).Allowed || new[] { "field.security", "field.technical", "field.raw_evidence", "evidence.exact" }.Any(cap => !ResourceAccessDecisions.Capability(c.Access.Capabilities, cap, resources).Allowed)) continue;
                    string provider = source["provider_name"]?.ToString().Trim() ?? "";
                    if (provider.Length == 0) continue;
                    var lookup = source.Copy(); lookup["provider_name"] = provider; lookup["channel"] = identity.Channel.Trim();
                    if (EventListProjection.ExactTitleEntry(lookup) is not {} entry) continue;
                    string code = $"events.semantic.{entry["channel"]}:{entry["provider_name"]}:{identity.EventId}.title";
                    string english = ReportResult.Message(code, true).Text("text");
                    if (english == code) english = ReportResult.Message("events.unknown_type", true).Text("text");
                    var title = ReportResult.Message("events.catalog_title");
                    title["params"] = new JsonObject { ["ru"] = entry["title"]!.DeepClone(), ["en"] = english };
                    title["text"] = entry["title"]!.DeepClone();
                    titles[identity] = title;
                }
            }
            catch (Npgsql.PostgresException e) when (e.SqlState == "57014") { }
            catch (TimeoutException) { }
        }
        foreach (var row in rows)
        {
            string? Clean(string key) => row[key]?.ToString().Trim() is { Length: > 0 } s && s is not ("-" or "—") ? s : null;
            string? target = Clean("target_user_name"), actor = Clean("subject_user_name");
            if(target is null && actor is null)
                actor=Clean("actor")??Clean("target");
            var title = Identity(row) is {} identity && titles.TryGetValue(identity, out var admitted) ? admitted.Copy() : ReportResult.Message("events.unknown_type");
            row["title_text"] = title["text"]!.DeepClone(); row["participant"] = target ?? actor ?? ReportResult.Message("events.participant_unknown").Text("text");
            row["on_behalf"] = actor is not null && actor != (target ?? actor) ? actor : null;
            row["presentation_messages"] = new JsonObject { ["title_text"] = title };
            if (target is null && actor is null) row["presentation_messages"]!["participant"] = ReportResult.Message("events.participant_unknown");
        }
        return Render(c, raw, rows);
    }
    internal static JsonObject Render(ReportQueryContext c, JsonObject raw, JsonObject[] rows)
    {
        string state = ReportResult.SourceState(raw.Text("state")); if (state == "ok" && rows.Length == 0) state = "empty";
        var result = ReportResult.Create(c.Definition.Key, state, new JsonArray(rows.Select(r => (JsonNode?)r.DeepClone()).ToArray()), raw["coverage"] as JsonObject,
            limitations: new JsonArray(new JsonObject { ["code"] = "no_risk_in_slice", ["text"] = "Оценка риска не входит в этот срез. Название показывается только при точном совпадении источника и разрешённом доступе к доказательству; неизвестный участник не восстанавливается." }));
        result["has_more"] = raw["has_more"]?.DeepClone() ?? JsonValue.Create(false); result["next_cursor"] = raw["next_cursor"]?.DeepClone();
        result["window"] = new JsonObject { ["from_utc"] = c.Params["period"]!["from_utc"]!.DeepClone(), ["to_utc_exclusive"] = c.Params["period"]!["to_utc"]!.DeepClone() };
        return result;
    }
    static bool Integer(JsonNode? node, out long value)
    {
        value = 0;
        return node is JsonValue && node.GetValueKind() == JsonValueKind.Number
            && long.TryParse(node.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }
    static (string Key, long EventId, string Channel)? Identity(JsonObject row) =>
        Integer(row["event_id"], out long eventId)
        && row["channel"] is JsonValue channel && channel.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text)
        && (Integer(row["id"], out long id) && id > 0 ? id.ToString(CultureInfo.InvariantCulture) : DateTimeOffset.TryParse(row["day"]?.ToString(),CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal,out var day) && row["summary_key"]?.ToString() is { Length:64 } key && key.All(Uri.IsHexDigit) ? day.ToString("yyyy-MM-dd",CultureInfo.InvariantCulture)+":"+key : null) is {} identity
            ? (identity, eventId, text) : null;

    internal static void Localize(JsonObject payload, bool english)
    {
        foreach (var row in payload.Objects("items"))
        {
            if (row["presentation_messages"] is not JsonObject messages) continue;
            foreach (string field in new[] { "title_text", "participant" })
            {
                if (messages[field] is not JsonObject envelope) continue;
                string code = envelope.Text("code");
                if (code == "events.catalog_title" && field == "title_text")
                    envelope["text"] = envelope["params"]?[english ? "en" : "ru"]?.DeepClone();
                else if (code is "events.unknown_type" or "events.participant_unknown")
                    envelope["text"] = ReportResult.Message(code, english)["text"]!.DeepClone();
                else continue;
                row[field] = envelope["text"]?.DeepClone();
            }
        }
    }
}
