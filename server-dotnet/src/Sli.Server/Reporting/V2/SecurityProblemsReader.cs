using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Problems;

namespace Sli.Server.Reporting.V2;

public sealed class SecurityProblemsReader(IProblemRepository repository, ISecurityProblemEvidence evidence) : IReportV2Reader
{
    public string OwnerId => "sli.core";
    public bool Handles(string key) => key == "security.problems";
    internal static JsonObject Binding(ReportQueryContext c) => new() {
        ["report"] = c.Definition.Key, ["params"] = c.Params.DeepClone(), ["domains"] = JsonSerializer.SerializeToNode(c.DomainIds),
        ["timezone"] = c.Paging.Timezone, ["action"] = c.Action, ["scope"] = c.Scope.Fingerprint,
        ["access"] = JsonSerializer.SerializeToNode(c.Access), ["principal"] = JsonSerializer.SerializeToNode(c.Principal)
    };
    internal static FindingQuery Input(ReportQueryContext c, string? rowId = null)
    {
        var domains = CoverageDomains(c);
        string? S(string key) => c.Params[key]?.ToString();
        long? Id(string key) => S(key) is {} s && long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out long id) && id > 0 ? id : S(key) is null ? null : throw new ReportRequestException("report_parameter_invalid:" + key);
        foreach (string key in new[] { "created_from", "created_to" })
            if (S(key) is {} raw && !ProblemJson.Stamp(JsonValue.Create(raw), out _)) throw new ReportRequestException("report_period_invalid");
        if (S("time_from") is not null || S("time_to") is not null) {
            _ = ReportParameters.Period("custom", S("time_from"), S("time_to"), TimeZoneInfo.FindSystemTimeZoneById(c.Paging.Timezone), 90, DateTimeOffset.UtcNow);
        }
        if (S("cohort") is {} cohort) { if (!c.FieldAccess(["security", "identity_basic"])) throw new ReportRequestException("report_field_categories_not_allowed", 403); _ = ProblemCohorts.Parse(cohort); }
        long? before = null;
        string? workplace = S("queue_tab");
        (int, DateTimeOffset, long)? position = null;
        if (rowId is null && c.Paging.Cursor is {} cursor) {
            string? value = ReportCursor.Decode(cursor, Binding(c));
            if (workplace is not null) {
                string[] parts = value?.Split('|') ?? [];
                if (parts.Length != 3 || !int.TryParse(parts[0], out int rank) || rank is < 1 or > 5 ||
                    !ProblemJson.Stamp(JsonValue.Create(parts[1]), out var stamp) ||
                    !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out long id) || id <= 0)
                    throw new ReportRequestException("invalid_cursor");
                position = (rank, stamp, id);
            }
            else {
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long id) || id <= 0) throw new ReportRequestException("invalid_cursor");
                before = id;
            }
        }
        // Python's open queue depends on the original id filter, not the detail row id.
        if (workplace is not null && (rowId is not null || S("id") is not null)) workplace = "detail";
        string? population = workplace is null ? S("population") ?? "open" : null;
        if (population == "open" && S("id") is not null) population = null;
        return new(S("status"), S("severity"), S("q"), S("time_from"), S("time_to"), S("risk"), Id("entity_id"), domains, c.Paging.Limit, S("show_suppressed") == "true") {
            FindingId = rowId is null ? Id("id") : long.TryParse(rowId, out long finding) && finding > 0 ? finding : throw new ReportRequestException("report_row_not_found", 404),
            RuleCode = S("rule_code"), CreatedFrom = S("created_from"), CreatedTo = S("created_to"), Cohort = S("cohort"),
            Population = population, BeforeId = before, PageQueue = true,
            GroupQueue = workplace is null && rowId is null && S("cohort") is null && S("id") is null, Timezone = c.Paging.Timezone,
            WorkplaceTab = workplace, WorkplacePosition = position, SearchTechnical = c.FieldAccess(["security", "identity_basic", "technical"]) &&
                new ProblemAccess(c.Access).Fields("identity_basic", "technical")
        };
    }
    private static long[]? CoverageDomains(ReportQueryContext c)
    {
        var allowed = new ProblemAccess(c.Access).Scope("security.queue", c.Action).Domains();
        return allowed is null ? c.DomainIds : c.DomainIds is null ? allowed : c.DomainIds.Intersect(allowed).Order().ToArray();
    }
    public async Task<JsonObject> QueryAsync(ReportQueryContext c, CancellationToken ct)
    {
        try {
            var input = Input(c);
            var raw = await repository.FindingsAsync(input with { QueueList = input.FindingId is null }, new(c.Access), ct);
            return Render(c, raw, input);
        }
        catch (ProblemException e) { throw new ReportRequestException(e.Code, e.Status); }
    }
    internal async Task<JsonObject> PasswordCoverageAsync(ReportQueryContext c, CancellationToken ct)
    {
        try {
            var password = await repository.ReadQueuePasswordCoverageAsync(CoverageDomains(c), ct);
            return RenderPasswordCoverage(c, password);
        }
        catch (ProblemException e) { throw new ReportRequestException(e.Code, e.Status); }
    }
    internal static JsonObject RenderPasswordCoverage(ReportQueryContext c, JsonObject? password)
    {
        var coverage = new JsonObject(); var limitations = new JsonArray();
        if (password is null) return ReportResult.Create(c.Definition.Key, "ok", coverage: coverage);
        coverage["password_detection"] = password.DeepClone();
        bool incomplete = password.Text("availability") != "observed" || password.Flag("has_more")
            || password["rows"] is not JsonArray list || list.Count == 0 || list.Any(r =>
                r?["policy_state"]?.ToString() is "unknown" or "disabled_last_known" || r?["frozen_episode_count"]?.ToString() != "0"
                || r?["policy_state"]?.ToString() == "enabled" && r?["status"]?.ToString() != "healthy");
        if (incomplete) AddLimitation(c, limitations, "password_coverage_incomplete");
        return ReportResult.Create(c.Definition.Key, incomplete ? "partial" : "ok", coverage: coverage, limitations: limitations);
    }
    private static void AddLimitation(ReportQueryContext c, JsonArray limitations, string code)
    {
        var message = ProblemPresentation.Message("reports.v2.security.problems.limitations." + code, c.Language);
        limitations.Add(new JsonObject { ["code"] = code, ["text"] = message["text"]!.DeepClone(), ["presentation_messages"] = new JsonObject { ["text"] = message } });
    }
    public async Task<JsonObject> DetailAsync(ReportQueryContext c, string rowId, CancellationToken ct)
    {
        try {
            var membership = await repository.FindingsAsync(Input(c, rowId) with { Limit = 1, Compact = true }, new(c.Access), ct);
            long id = long.Parse(rowId, CultureInfo.InvariantCulture);
            if (!(membership["items"] as JsonArray ?? []).Any(r => r?["id"]?.ToString() == rowId)) throw new ReportRequestException("report_row_not_found", 404);
            var binding = Binding(c); binding["row"] = rowId;
            JsonObject? position = null;
            if (c.Paging.Cursor is {} cursor) {
                try { position = JsonNode.Parse(ReportCursor.Decode(cursor, binding)!) as JsonObject ?? throw new FormatException(); }
                catch (Exception e) when (e is System.Text.Json.JsonException or FormatException) { throw new ReportRequestException("invalid_cursor"); }
            }
            var page = await evidence.PageAsync(c, id, position, ct);
            var rows = page["items"]!.AsArray(); var native = rows.Where(r => r?["storage_kind"]?.ToString() == "file_audit_snapshot").ToArray();
            int missing = rows.Count(r => r?["storage_kind"]?.ToString() == "file_audit_snapshot" ? r?["availability"]?.ToString() == "unavailable" : r?["event_db_id"] is null);
            bool partial = missing > 0 || native.Any(r => r?["grants_has_more"]?.GetValue<bool>() == true || r?["coverage"]?["state"]?.ToString() != "complete");
            var coverage = new JsonObject { ["evidence_total_lower_bound"] = page["total_lower_bound"]?.DeepClone(), ["evidence_missing_sources"] = missing, ["evidence_native_snapshots"] = native.Length };
            if (native.Length > 0) coverage["evidence_historical"] = true;
            var result = ReportResult.Create(c.Definition.Key, partial ? "partial" : rows.Count > 0 ? "ok" : "empty", rows, coverage);
            result["filtered_count"] = page["total"]?.DeepClone(); result["has_more"] = page["has_more"]?.DeepClone();
            JsonObject? nextCursor = page["next_position"] is {} next
                ? new() { ["version"] = 2, ["position"] = next.DeepClone(), ["watermark"] = page["watermark"]?.DeepClone() }
                : rows.LastOrDefault()?["evidence_id"] is {} after ? new() { ["after_id"] = after.DeepClone() } : null;
            result["next_cursor"] = page.Flag("has_more") && nextCursor is not null ? ReportCursor.Encode(binding, nextCursor.ToJsonString()) : null;
            return result;
        }
        catch (ProblemException e) { throw new ReportRequestException(e.Code, e.Status); }
    }
    internal static JsonObject Render(ReportQueryContext c, JsonObject raw, FindingQuery? input = null)
    {
        var rows = new JsonArray(); var access = new ProblemAccess(c.Access);
        bool includeDescription = c.Params["id"] is not null;
        foreach (var finding in (raw["items"] as JsonArray ?? []).OfType<JsonObject>()) {
            if (input?.WorkplaceTab is not null) {
                rows.Add(ProblemPresentation.Workplace(finding, access, c.Language, includeDescription,
                    c.FieldAccess(["security", "identity_basic"]), c.FieldAccess(["security", "technical"]),
                    c.FieldAccess(["security", "technical", "raw_evidence"])));
                continue;
            }
            var row = ProblemPresentation.Finding(finding, access, c.Language, queue: true, includeDescription: includeDescription);
            string status = row.Text("status");
            var transitions = raw["lifecycle"]?["allowed_transitions"]?[status] as JsonArray ?? [];
            row["allowed_statuses"] = new JsonArray(new[] { status }.Concat(transitions.Select(s => s!.ToString())).Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
            rows.Add(row);
        }
        var runtime = raw["semantic_runtime"] as JsonObject ?? new(); var limitations = new JsonArray();
        foreach (var text in raw["limitations"] as JsonArray ?? []) limitations.Add(new JsonObject { ["code"] = "problems_" + limitations.Count, ["text"] = text?.ToString() });
        string state = ReportResult.SourceState(raw["state"]?.ToString()); if (state == "ok" && rows.Count == 0) state = "empty";
        if (runtime.Text("findings_state") != "active") {
            AddLimitation(c, limitations, "zero_is_not_safe");
            if (state is "ok" or "empty") state = "partial";
        }
        long Count(params string[] statuses) => (raw["summary"] as JsonArray ?? []).OfType<JsonObject>().Where(r => statuses.Contains(r.Text("status")) && !r.Flag("risk_accepted")).Sum(r => long.TryParse(r["count"]?.ToString(), out long n) ? n : 0);
        long attention = Count("new", "confirmed", "repeated"), progress = Count("active", "review");
        if (input?.WorkplaceTab is {} tab) {
            long open = attention + progress, closed = Count("closed", "false_positive");
            var workplace = ReportResult.Create(c.Definition.Key, rows.Count == 0 ? "empty" : "ok", rows);
            workplace["queue_counts"] = new JsonObject { ["open"] = open, ["closed"] = closed };
            workplace["filtered_count"] = tab == "closed" ? closed : tab == "open" ? open : rows.Count;
            workplace["has_more"] = raw["has_more"]?.DeepClone() ?? JsonValue.Create(false);
            if (workplace.Flag("has_more") && ProblemJson.Array(raw["items"]).LastOrDefault() is JsonObject lastFinding) {
                int rank = lastFinding.Text("severity") switch { "critical" => 1, "high" => 2, "medium" => 3, "low" => 4, _ => 5 };
                workplace["next_cursor"] = ReportCursor.Encode(Binding(c), FormattableString.Invariant($"{rank}|{lastFinding["last_seen_utc"] ?? lastFinding["updated_at"]}|{lastFinding["id"]}"));
            }
            return workplace;
        }
        var metrics = new JsonArray();
        foreach (var (key, count, tone, filter) in new (string, long, string, JsonObject?)[] { ("open", attention + progress, attention + progress > 0 ? "warning" : "neutral", null), ("attention", attention, attention > 0 ? "danger" : "neutral", new() { ["population"] = "attention" }), ("progress", progress, progress > 0 ? "accent" : "neutral", new() { ["status"] = "active" }), ("closed", Count("false_positive", "closed"), "success", new() { ["status"] = "closed" }) }) {
            var label = ProblemPresentation.Message($"reports.v2.security.problems.metrics.{key}.label", c.Language);
            var metric = new JsonObject { ["key"] = key, ["label"] = label["text"]!.DeepClone(), ["presentation_messages"] = new JsonObject { ["label"] = label }, ["value"] = count, ["tone"] = key == "progress" ? "accent" : tone };
            if (filter is not null) metric["filter"] = filter; metrics.Add(metric);
        }
        string? Latest(string key) => rows.OfType<JsonObject>().Select(r => r[key]?.ToString()).Where(s => s is not null).Order(StringComparer.Ordinal).LastOrDefault();
        var coverage = new JsonObject { ["state"] = runtime["findings_state"]?.DeepClone(), ["event_at_utc"] = Latest("last_seen_utc"), ["published_at_utc"] = Latest("published_at_utc"), ["worker_checked_at_utc"] = runtime["heartbeat_at"]?.DeepClone() };
        var result = ReportResult.Create(c.Definition.Key, state, rows, coverage, limitations: limitations);
        result["metrics"] = metrics; result["has_more"] = raw["has_more"]?.DeepClone() ?? JsonValue.Create(false);
        var last = (raw["items"] as JsonArray)?.LastOrDefault();
        result["next_cursor"] = result.Flag("has_more") && last is not null ? ReportCursor.Encode(Binding(c), (last["queue_cursor_id"] ?? last["id"])!.ToString()) : null;
        result["filtered_count"] = (raw["summary"] as JsonArray ?? []).Sum(r => long.TryParse(r?["count"]?.ToString(), out long n) ? n : 0);
        return result;
    }

    // Only registered presentation slots are translated. Source observations,
    // identifiers, filter values and analyst text remain data.
    internal static void Localize(JsonObject body, string language, bool declaration = false)
    {
        JsonObject M(string code, JsonObject? args = null) => ProblemPresentation.Message(code, language, args);
        void Field(JsonObject obj, string field, string code) {
            if (!obj.ContainsKey(field)) return;
            var message = M(code); obj[field] = message["text"]!.DeepClone();
            if (obj["presentation_messages"] is not JsonObject) obj["presentation_messages"] = new JsonObject();
            obj["presentation_messages"]![field] = message;
        }
        void Envelopes(JsonObject obj) {
            if (obj["presentation_messages"] is JsonObject messages)
                foreach (var (field, value) in messages.ToArray())
                    if (value is JsonObject envelope && envelope["code"] is {} code) {
                        var message = M(code.ToString(), envelope["params"]?.DeepClone() as JsonObject);
                        obj[field] = message["text"]!.DeepClone(); messages[field] = message;
                    }
        }
        const string prefix = "reports.v2.security.problems.";
        if (declaration && body["views"] is JsonArray views)
            views.Insert(0, new JsonObject { ["kind"] = "custom", ["key"] = "queue", ["component"] = "problems.workplace" });
        if (declaration) {
            Field(body, "title", prefix + "title");
            if (body["intent"] is JsonObject intent)
                foreach (string field in new[] { "question", "denominator", "freshness_expectation" }) Field(intent, field, prefix + "intent." + field);
            void Columns(JsonObject parent, string path) {
                foreach (var column in parent.Objects("columns")) {
                    string key = column.Text("key"); Field(column, "label", prefix + path + key + ".label");
                    if (column["labels"] is JsonObject labels) {
                        var messages = new JsonObject();
                        foreach (string value in labels.Select(p => p.Key).ToArray()) {
                            var message = M(prefix + path + key + ".labels." + value);
                            labels[value] = message["text"]!.DeepClone(); messages[value] = message;
                        }
                        column["labels_messages"] = messages;
                    }
                }
            }
            Columns(body, "columns.");
            foreach (var param in body.Objects("params")) {
                string key = param.Text("key"); Field(param, "label", prefix + "params." + key + ".label");
                foreach (var option in param.Objects("options")) Field(option, "label", prefix + "params." + key + ".options." + option["value"]);
            }
            foreach (var preset in body.Objects("presets")) Field(preset, "label", prefix + "presets." + preset["params"]!.ToJsonString());
            if (body["detail"] is JsonObject detail) {
                Field(detail, "title", prefix + "detail.title"); Columns(detail, "detail.columns.");
                foreach (var link in detail.Objects("row_links")) Field(link, "label", prefix + "detail.row_links." + link["href"]);
            }
            return;
        }
        foreach (var row in body.Objects("items")) {
            Envelopes(row);
            foreach (string field in new[] { "status_message", "severity_message" })
                if (row[field] is JsonObject message) row[field] = M(message.Text("code"), message["params"]?.DeepClone() as JsonObject);
            if (row["linked_case"] is JsonObject linked && linked["status"] is {} status) linked["status_message"] = M("investigations.caseStatus." + status);
            if (row["entity_messages"] is JsonArray entities) {
                for (int i = 0; i < entities.Count; i++)
                    if (entities[i] is JsonObject message) entities[i] = M(message.Text("code"), message["params"]?.DeepClone() as JsonObject);
                row["entity_text"] = entities.Count > 0 ? string.Join(", ", entities.Select(e => e is JsonObject message ? message.Text("text") : e?.ToString())) : null;
            }
        }
        foreach (var metric in body.Objects("metrics")) Envelopes(metric);
        foreach (var limitation in body.Objects("limitations")) Envelopes(limitation);
    }
}
