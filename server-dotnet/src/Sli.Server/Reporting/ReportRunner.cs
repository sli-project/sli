using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Storage.EventReports;
using Sli.Server.Entities;
using static Sli.Server.Reporting.ReportJson;
using static Sli.Server.Reporting.ReportStudioService;

namespace Sli.Server.Reporting;

public sealed class ReportRunner(IReportDatabase database, IConfiguration? configuration = null)
{
    internal DateTimeOffset ShortRetentionBoundary => EventReadService.ShortBoundary(configuration);
    private const string ProjectionLimitation = "Каждая строка содержит только проекцию одного неделимого назначения доступа.";
    public async Task<JsonObject> ExecuteAsync(ReportCaller caller, string key, int limit, string[]? fields, string action, IReadOnlyDictionary<string, string> query, CancellationToken ct, long? problemId = null)
    {
        var report = caller.Access.Array("reports").OfType<JsonObject>().FirstOrDefault(r => r.Text("report_key") == key);
        Require(report is not null, "report_not_found"); Require(report!.Flag("allowed"), "report_access_denied", 403);
        report = RawReport(report);
        await using var db = await database.OpenAsync(false, ct);
        if (key == "ad.users.v2") await ReportDomain.ResolveIdAsync(db, ct);
        var definition = First(await Query(db, "select r.definition_json,d.dataset_key,d.fields_json from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id where r.report_key=@p0 and r.version=@p1", ct, key, report.Number("version")));
        Require(definition.Count > 0, "report_definition_not_found");
        var result = await RunAsync(db, caller, report, definition, Math.Clamp(limit, 1, 200), fields, action, query, ct, problemId);
        if (action == "view" && key is "vpn.audit" or "vpn.accounts" or "vpn.connections")
        {
            string state = "unknown";
            try
            {
                var plugin = First(await Query(db, "select enabled from read_plugin_states_v1() where plugin_id='sli.remote-access'", ct));
                if (plugin.Count > 0) state = plugin.Flag("enabled") ? "enabled" : "disabled";
            }
            catch (Exception e) when (e is Npgsql.NpgsqlException or InvalidOperationException) { }
            result["plugin"] = new JsonObject { ["plugin_id"] = "sli.remote-access", ["state"] = state, ["read_only"] = state != "enabled" };
            if (state == "disabled" && result.Text("state") == "empty" && result.Array("items").Count == 0) { result["state"] = "not_collected"; result["reason"] = "not_collected"; }
        }
        return result;
    }

    public async Task SampleAsync(JsonObject preview, ReportCaller caller, CancellationToken ct)
    {
        preview["sample_rows"] = new JsonArray(); preview["sample_columns"] = new JsonArray(); preview["sample_limit"] = 20;
        if (preview.Text("status") != "accepted" || preview.Array("missing_capabilities").Count > 0)
        { preview["sample_state"] = "gated"; preview["sample_missing_capabilities"] = preview["missing_capabilities"]!.DeepClone(); return; }
        string dataset = preview["dataset"].Text("key");
        await using var db = await database.OpenAsync(false, ct);
        var datasetRow = First(await Query(db, "select fields_json from report_datasets_v4 where dataset_key=@p0 and version=@p1 and status='published'", ct, dataset, preview["dataset"].Number("version")));
        var grants = caller.Facts.IsOwner ? new JsonArray(new JsonObject { ["source_type"] = "platform_owner", ["source"] = "owner:primary",
            ["scope"] = new JsonObject { ["kind"] = "all" }, ["field_categories"] = Nodes(Sorted(datasetRow.Array("fields_json").Select(f => f.Text("category", "identity_basic")))), ["allowed_actions"] = new JsonArray("view") })
            : Nodes(caller.Access.Array("reports").OfType<JsonObject>().Where(r => r.Flag("allowed") && r.Text("dataset_key") == dataset)
                .SelectMany(r => r.Array("grants").OfType<JsonObject>()).Where(g => g.Strings("allowed_actions").Contains("view")));
        if (grants.Count == 0) { Gate(); return; }
        var runtime = Definition(preview, "builder.preview"); runtime["actions"] = new JsonArray("view"); runtime["export_policy"] = "disabled";
        var definition = new JsonObject { ["dataset_key"] = dataset, ["fields_json"] = datasetRow["fields_json"]?.DeepClone(), ["definition_json"] = runtime };
        var report = new JsonObject { ["report_key"] = "builder.preview", ["version"] = 0, ["allowed"] = true, ["grants"] = grants };
        try
        {
            var result = await RunAsync(db, caller, report, definition, 20, null, "view", new Dictionary<string, string>(), ct);
            preview["sample_rows"] = result["items"]!.DeepClone(); preview["sample_columns"] = result["fields"]!.DeepClone();
            preview["sample_state"] = result.Array("items").Count > 0 ? "rows" : "empty";
        }
        catch (ReportException e) when (e.Status == 403) { Gate(); }
        void Gate() { preview["sample_state"] = "gated"; preview["sample_missing_capabilities"] = new JsonArray(); preview["sample_gate_reason"] = "no_dataset_access"; }
    }

    private async Task<JsonObject> RunAsync(IReportSession db, ReportCaller caller, JsonObject report, JsonObject definition, int limit, string[]? fields, string action, IReadOnlyDictionary<string, string> query, CancellationToken ct, long? problemId = null)
    {
        string dataset = definition.Text("dataset_key"); Require(ReportBuilder.Executable.Contains(dataset), "report_dataset_not_executable");
        var runtime = definition["definition_json"] as JsonObject ?? new();
        var fieldDefs = definition.Array("fields_json").OfType<JsonObject>().ToDictionary(f => f.Text("key"));
        Require(runtime["columns"] is JsonArray, "invalid_report_definition_columns");
        string[] columns = runtime.Array("columns").Select(c => c is JsonObject ? c.Text("key") : c?.ToString() ?? "").ToArray();
        Require(columns.Length > 0 && columns.Distinct().Count() == columns.Length && columns.All(fieldDefs.ContainsKey), "invalid_report_definition_columns");
        Require(action is "view" or "export", "report_action_not_executable");
        string[] actions = runtime["actions"] is null ? ["view"] : runtime.Strings("actions");
        Require(actions.Contains(action), "report_action_denied", 403);
        bool export = caller.Caps.Contains("reports.export") && runtime.Text("export_policy", "disabled") == "controlled";
        Require(action != "export" || export, "report_export_denied", 403);
        var grants = report.Array("grants").OfType<JsonObject>().Where(g => g.Strings("allowed_actions").Contains(action)).ToArray();
        Require(grants.Length > 0, "report_access_denied", 403);
        if (fields is null)
        {
            var branchQuery = query.ToDictionary(p => p.Key, p => p.Value);
            string requestedBranch = branchQuery.GetValueOrDefault("grant_branch", "").Trim().ToLowerInvariant();
            branchQuery.Remove("grant_branch");
            Require(requestedBranch.Length == 0 || requestedBranch.Length == 64 && requestedBranch.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'), "invalid_report_grant_branch");
            var unique = grants.GroupBy(BranchKey).Select(g => g.First()).ToArray();
            unique = unique.Where((candidate, i) => !unique.Where((_, j) => i != j).Any(other => Covers(other, candidate) && (!Covers(candidate, other) || System.Array.IndexOf(unique, other) < i))).ToArray();
            if (requestedBranch.Length > 0)
            {
                unique = unique.Where(g => BranchKey(g) == requestedBranch).ToArray();
                Require(unique.Length > 0, "report_grant_branch_access_denied", 403);
            }
            Require(unique.Length <= 32, "report_grant_branch_limit_exceeded", 403);
            var branches = new List<JsonObject>();
            foreach (var grant in unique)
            {
                var projection = columns.Where(c => grant.Strings("field_categories").Contains(fieldDefs[c].Text("category"))).ToArray();
                if (projection.Length == 0) continue;
                var branchReport = report.Copy(); branchReport["grants"] = new JsonArray(grant.DeepClone());
                branchReport["field_categories"] = grant["field_categories"]?.DeepClone(); branchReport["allowed_actions"] = grant["allowed_actions"]?.DeepClone(); branchReport["scopes"] = new JsonArray(grant["scope"]?.DeepClone());
                var branch = await RunAsync(db, caller, branchReport, definition, limit, projection, action, branchQuery, ct, problemId);
                branch["grant_branch"] = BranchKey(grant); branch["grant_branch_fields"] = Nodes(projection); branches.Add(branch);
            }
            Require(branches.Count > 0, "report_field_access_denied", 403);
            if (branches.Count == 1)
            {
                var single = branches[0]; single["field_visibility"] = "per_grant"; single["limitations"] = new JsonArray(ProjectionLimitation);
                single["limits"]!["grant_branches"] = 1; single["limits"]!["grant_branch_max"] = 32; return single;
            }
            var combined = branches.SelectMany(b => b.Array("items").OfType<JsonObject>()).ToList();
            if (query.TryGetValue("sort", out string? sort))
            {
                bool descending = query.GetValueOrDefault("direction") == "desc";
                combined.Sort((a, b) => Compare(a[sort], b[sort], descending));
            }
            var publicReport = report.Copy(); publicReport.Remove("grants");
            publicReport["allowed_actions"] = Nodes(Sorted(unique.SelectMany(g => g.Strings("allowed_actions")).Where(a => actions.Contains(a) && (a != "export" || export))));
            var visible = branches.SelectMany(b => b.Array("fields").Select(f => f.Text("key"))).ToHashSet();
            var states = Nodes(branches.Select(b => new JsonObject { ["grant_branch"] = b["grant_branch"]!.DeepClone(), ["state"] = b.Text("state"), ["has_more"] = b.Flag("has_more"),
                ["next_cursor"] = b["next_cursor"]?.DeepClone(), ["fields"] = b["grant_branch_fields"]!.DeepClone(), ["field_count"] = b.Array("fields").Count, ["summary_available"] = b["summary"] is JsonObject }));
            var limitations = new JsonArray(ProjectionLimitation, "При нескольких независимых назначениях каждая ветвь читается отдельно по grant_branch и имеет собственный cursor.");
            var result = new JsonObject { ["api_version"] = "v4", ["report"] = publicReport, ["dataset_key"] = dataset, ["state"] = combined.Count > 0 ? "available" : "empty", ["items"] = Nodes(combined.Take(limit)),
                ["fields"] = Nodes(columns.Where(visible.Contains).Select(c => fieldDefs[c])), ["field_visibility"] = "per_grant", ["limitations"] = limitations, ["branch_states"] = states,
                ["branch_continuations"] = states.DeepClone(), ["has_more"] = combined.Count > limit || branches.Any(b => b.Flag("has_more")), ["next_cursor"] = null,
                ["limits"] = new JsonObject { ["rows"] = limit, ["grant_branches"] = branches.Count, ["grant_branch_max"] = 32, ["total_count"] = "not_calculated" } };
            if (branches[0]["summary"] is JsonObject && branches.All(b => JsonNode.DeepEquals(b["summary"], branches[0]["summary"]))) result["summary"] = branches[0]["summary"]!.DeepClone();
            else limitations.Add("Сводка веток не объединяется арифметически: области назначений могут пересекаться.");
            return result;
        }
        Require(fields.Length > 0 && fields.All(columns.Contains), "report_field_access_denied", 403);
        string[] categories = Sorted(fields.Select(f => fieldDefs[f].Text("category")));
        var eligible = grants.Where(g => !categories.Except(g.Strings("field_categories")).Any()).ToArray();
        Require(eligible.Length > 0, "report_field_access_denied", 403);
        var sql = new ReportQuery();
        bool unrestricted = eligible.Any(g => g["scope"].Text("kind") == "all");
        string alias = dataset == "events.v2" ? "event" : dataset is "ad.accounts.vpn" or "ad.accounts.privileged" ? "source_entity" : "entity";
        var scopes = new List<string>();
        if (!unrestricted)
        {
            foreach (var grant in eligible)
            {
                var scope = grant["scope"]; string kind = scope.Text("kind");
                if (kind is "server" or "domain")
                {
                    var ids = scope.Array("ids").Take(100).Select(v => long.TryParse(v?.ToString(), out long n) ? n : throw new ReportException("invalid_report_scope", 403)).ToArray();
                    if (ids.Length > 0) scopes.Add(alias + "." + (kind == "server" ? "server_id" : "domain_id") + "=any(" + sql.Parameter(ids) + ")");
                }
                if (kind == "channel" && dataset == "events.v2")
                {
                    string[] values = scope.Strings("values").Take(100).ToArray(); if (values.Length > 0) scopes.Add("channel.value=any(" + sql.Parameter(values) + ")");
                }
            }
            Require(scopes.Count > 0 && dataset != "security.problems", "report_scope_not_executable", 403);
        }
        string summaryWhere = unrestricted ? "" : " where (" + string.Join(" or ", scopes) + ")";
        var scopeValues = sql.Values.ToArray();
        long days = 90;
        if (dataset.StartsWith("ad."))
        {
            var policy = First(await Query(db, "select value from platform_settings where key='ad.inactivity_days'", ct));
            Require(long.TryParse(policy.Text("value", "90"), out days) && days is >= 1 and <= 3650, "value_must_be_days_1_3650");
        }
        bool eventDataset = dataset == "events.v2";
        sql.Definition(dataset, runtime, days); sql.Interactive(dataset, query, days);
        if (problemId is {} problem) {
            Require(eventDataset && action == "view", "report_action_denied", 403);
            sql.Predicates.Add("exists(select 1 from finding_event_details337 copy where copy.finding_id=" + sql.Parameter(problem) +
                " and copy.event_db_id=event.id and copy.time_created_utc=event.time_created_utc and copy.domain_id=event.domain_id and copy.channel=event.channel)");
        }
        string where = summaryWhere + (sql.Predicates.Count == 0 ? "" : (summaryWhere.Length > 0 ? " and " : " where ") + string.Join(" and ", sql.Predicates.Select(p => "(" + p + ")")));
        JsonObject? summary = problemId is null ? await ReportSummaries.ReadAsync(db, dataset, summaryWhere, scopeValues, categories.ToHashSet(), days, where, sql.Values, ct) : null;
        string template = dataset switch { "entities.v2" => "_execute_definition_0", "ad.audit.snapshot" => "_execute_definition_1", "security.problems" => "_execute_definition_3", "ad.accounts.privileged" => "_execute_definition_5", "ad.gpo.governance" => "_execute_definition_6", _ => "read_accounts_1" };
        long? count = null; string from = "";
        if (dataset == "ad.accounts.vpn")
        {
            from = Template("vpn_from", where, sql.Order, days);
            count = First(await Query(db, "select count(distinct source_entity.id) as filtered_count " + from, ct, sql.Values.ToArray())).Number("filtered_count");
            if (query.TryGetValue("cursor", out string? cursor) && cursor.Length > 0) from += " and source_entity.id>" + sql.Parameter(long.Parse(ReportQuery.DecodeCursor(cursor).Text("object_id"), CultureInfo.InvariantCulture));
        }
        string statement = eventDataset ? "" : Template(template, where, sql.Order, days).Replace("{from_sql}", from);
        if (eventDataset)
        {
            string source = EntityShortSql.Source(sql.Parameter(EventReadService.ShortBoundary(configuration)));
            string order = sql.Order == ReportQuery.DefaultOrder(dataset)
                ? "event.time_created_utc desc,coalesce(event.id,0) desc,event.summary_key desc" : sql.Order;
            statement = "with short_events as ("+source+") select event.* "+
                "from (select e.*,e.actor as subject_user_name,e.target as target_user_name,e.source as ip_address,e.source as workstation_name,e.fields->>'TargetLogonId' as logon_id from short_events e) event "+
                "join servers server on server.id=event.server_id and server.domain_id=event.domain_id "+
                "cross join lateral (select event.channel as value) channel "+where+" order by "+order+" limit ?";
        }
        statement = statement.Replace("?", sql.Parameter(limit + 1));
        var rows = await db.QueryAsync(statement, sql.Values, ct);
        if(eventDataset) rows=rows.Select(EventReadService.ShortRow).ToArray();
        bool hasMore = rows.Count > limit;
        JsonObject? next = hasMore && dataset == "events.v2" && sql.Order == ReportQuery.DefaultOrder(dataset)
            ? EventReadService.ShortCursor(rows[limit-1])
            : hasMore && dataset == "ad.accounts.vpn" && sql.Order == "source_entity.id asc" ? new() { ["object_id"] = rows[limit - 1].Text("object_id") } : null;
        var pub = report.Copy(); pub.Remove("grants");
        pub["allowed_actions"] = Nodes(Sorted(report.Array("grants").OfType<JsonObject>().Where(g => !categories.Except(g.Strings("field_categories")).Any())
            .SelectMany(g => g.Strings("allowed_actions")).Where(a => actions.Contains(a) && (a != "export" || export))));
        var safe = Nodes(rows.Take(limit).Select(r => {
            var row = new JsonObject(); foreach (string f in fields) row[f] = r[f]?.DeepClone();
            if(eventDataset) {
                if(fields.Contains("time_created_utc")) foreach(string f in new[]{"day","event_count","first_seen_utc","last_seen_utc","summary_key"}) row[f]=r[f]?.DeepClone();
                if(fields.Contains("subject_user_name")) row["actor"]=r["actor"]?.DeepClone();
                if(fields.Contains("target_user_name")) row["target"]=r["target"]?.DeepClone();
                if(fields.Contains("subject_user_name") && fields.Contains("target_user_name")) row["source"]=r["source"]?.DeepClone();
            }
            return row;
        }));
        var output = new JsonObject { ["api_version"] = "v4", ["report"] = pub, ["dataset_key"] = dataset, ["state"] = safe.Count > 0 ? "available" : "empty", ["items"] = safe,
            ["fields"] = Nodes(fields.Select(f => fieldDefs[f])), ["has_more"] = hasMore, ["next_cursor"] = next is null ? null : ReportQuery.Cursor(next),
            ["limits"] = new JsonObject { ["rows"] = limit, ["total_count"] = count is { } n ? JsonValue.Create(n) : JsonValue.Create("not_calculated") } };
        if (summary is not null) output["summary"] = summary;
        if (count is { } filtered) output["filtered_count"] = filtered;
        return output;
    }

    internal static string Template(string name, string where, string order, long days) => ReportQuery.Resolve(ReportDatasetCatalog.Data["queries"].Text(name), days)
        .Replace("{scoped_where}", where).Replace("{filtered_where}", where).Replace("{connector}", where.Length > 0 ? " and " : " where ").Replace("{order_sql}", order);

    private static int Compare(JsonNode? a, JsonNode? b, bool descending)
    {
        if (a is null) return b is null ? 0 : 1; if (b is null) return -1;
        int value = double.TryParse(a.ToString(), CultureInfo.InvariantCulture, out double x) && double.TryParse(b.ToString(), CultureInfo.InvariantCulture, out double y) ? x.CompareTo(y)
            : StringComparer.OrdinalIgnoreCase.Compare(a.ToString(), b.ToString()); return descending ? -value : value;
    }
    private static JsonObject RawReport(JsonObject report)
    {
        var result = report.Copy();
        static void Dates(JsonNode value, params string[] keys)
        {
            foreach (string key in keys)
                if (value[key] is not null && DateTimeOffset.TryParse(value[key]!.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp))
                    value[key] = Sli.Server.Access.Administration.AssignmentAudit.Stamp(stamp);
        }
        Dates(result, "access_valid_until", "preference_updated_at");
        foreach (string key in new[] { "grants", "sources" }) foreach (var item in result.Array(key).OfType<JsonObject>()) Dates(item, "valid_from", "valid_until");
        if (result["request"] is JsonObject request) Dates(request, "created_at", "updated_at");
        return result;
    }
    private static bool Covers(JsonObject broad, JsonObject narrow)
    {
        if (narrow.Strings("field_categories").Except(broad.Strings("field_categories")).Any() || narrow.Strings("allowed_actions").Except(broad.Strings("allowed_actions")).Any()) return false;
        string kind = broad["scope"].Text("kind"); if (kind == "all") return true;
        return kind is "domain" or "server" or "channel" && kind == narrow["scope"].Text("kind")
            && !narrow["scope"].Strings(kind == "channel" ? "values" : "ids").Except(broad["scope"].Strings(kind == "channel" ? "values" : "ids")).Any();
    }
    internal static string BranchKey(JsonObject grant)
    {
        var identity = new JsonObject { ["scope"] = grant["scope"]?.DeepClone() ?? new JsonObject(), ["field_categories"] = Nodes(Sorted(grant.Strings("field_categories"))), ["allowed_actions"] = Nodes(Sorted(grant.Strings("allowed_actions"))) };
        foreach (string key in new[] { "source_type", "source", "valid_from", "valid_until" }) identity[key] = grant[key]?.DeepClone();
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(identity))));
    }
    private static string Canonical(JsonNode? node) => node switch
    {
        null => "null", JsonObject obj => "{" + string.Join(',', obj.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => Quote(p.Key) + ":" + Canonical(p.Value))) + "}",
        JsonArray array => "[" + string.Join(',', array.Select(Canonical)) + "]", JsonValue v when v.TryGetValue<string>(out var text) => Quote(text), _ => node.ToJsonString()
    };
    private static string Quote(string text)
    {
        var output = new StringBuilder("\"");
        foreach (char c in text) output.Append(c switch { '"' => "\\\"", '\\' => "\\\\", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t", '\b' => "\\b", '\f' => "\\f", _ when c < 32 || c > 127 => "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture), _ => c.ToString() });
        return output.Append('"').ToString();
    }
}
