using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Semantic;
using Sli.Agent.Protocol;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Reporting.V2;

// Admission, rows, counts and episode metadata share a read-only repeatable-read snapshot.
public sealed partial class FileAuditReportReader : IReportV2Reader
{
    readonly ISemanticDatabase database;
    readonly Func<FileAuditHistory?> history;
    public FileAuditReportReader(ISemanticDatabase database, IConfiguration? config = null)
        : this(database,() => FileAuditHistory.Configured(config)) { }
    internal FileAuditReportReader(ISemanticDatabase database, Func<FileAuditHistory?> history)
    { this.database = database; this.history = history; }
    internal static readonly string[] Tabs = ["overview", "actions", "mass-operations", "permission-changes", "access-denials", "out-of-hours", "permissions", "audit-state"];
    public string OwnerId => "sli.file-audit";
    public bool Handles(string key) => Tabs.Any(t => key == "file-audit." + t);
    private static string? Text(JsonNode? node, string key) => node?[key]?.GetValue<string>();
    private static JsonArray Array(JsonNode? node) => node as JsonArray ?? [];
    internal static string ShareKey(JsonNode root) => CanonicalJson.Serialize(new JsonArray(root["agent_id"]?.DeepClone(), root["source_instance_id"]?.DeepClone(), root["collection_scope_id"]?.DeepClone()));
    internal static bool Admitted(ReportQueryContext context, JsonNode root, ReportScope? scope = null)
    {
        string? agent = Text(root, "agent_id"), source = Text(root, "source_instance_id"), collection = Text(root, "collection_scope_id");
        if (new[] { agent, source, collection }.Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 256)) return false;
        var target = new ReportScope("restricted", [new() { ["plugin_ids"] = new JsonArray("sli.file-audit"), ["device_ids"] = new JsonArray(agent), ["source_instance_ids"] = new JsonArray(source), ["collection_scope_ids"] = new JsonArray(collection) }]);
        if (!(scope ?? context.Scope).Covers(target)) return false;
        IReadOnlyList<IReadOnlyList<AccessResource>> groups = [new AccessResource[] { new("plugin") { PluginId = "sli.file-audit", DeviceId = agent, SourceInstanceId = source, CollectionScopeId = collection } }];
        return context.Access.Capabilities.DecideForResourceGroups(context.Action == "export" ? "file-audit.export" : "file-audit.view", groups).Allowed;
    }
    private static JsonObject? Cursor(string? cursor)
    {
        if (string.IsNullOrEmpty(cursor)) return null;
        try
        {
            var obj = JsonNode.Parse(cursor)!.AsObject();
            if (obj.Count != 2 || obj["at"] is not JsonValue at || !at.TryGetValue<string>(out var stamp) || obj["id"] is not JsonValue id || !id.TryGetValue<string>(out _)
                || !System.Text.RegularExpressions.Regex.IsMatch(stamp, @"(?:Z|[+-]\d{2}:?\d{2})$") || !DateTimeOffset.TryParse(stamp, CultureInfo.InvariantCulture, DateTimeStyles.None, out _)) throw new FormatException();
            return obj;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException or ArgumentException or NullReferenceException) { throw new ReportRequestException("report_cursor_invalid"); }
    }
    public async Task<JsonObject> QueryAsync(ReportQueryContext context, CancellationToken ct)
    {
        string tab = context.Definition.Key["file-audit.".Length..]; if (!Tabs.Contains(tab)) throw new ReportRequestException("report_not_found", 404);
        var after = Cursor(context.Paging.Cursor); JsonArray roots; JsonObject data;
        try
        {
            await using var session = await database.OpenAsync(false, ct);
            var discovered = Array((await session.QueryAsync("select sli_plugin_file_audit.report_roots() as roots", ct))[0]!["roots"]);
            if (discovered.Count > 1000) return ReportResult.Create(context.Definition.Key, "partial", coverage: new() { ["state"] = "unknown", ["reason"] = "result_truncated" }, limitations: [new JsonObject { ["code"] = "root_limit", ["text"] = "Область превышает 1000 шар. Уточните назначенную область доступа." }]);
            roots = new JsonArray(discovered.Where(r => Admitted(context, r!) && (context.Params["source_kind"] is null || (Text(r, "source_kind") ?? "server") == context.Params.Text("source_kind"))).Select(r => r!.DeepClone()).ToArray());
            var selected = Array(context.Params["share"]);
            if (context.Params["file_server_domain"] is { } domain && roots.Count > 0)
            {
                var match = (await session.QueryAsync(DomainRootsSql, ct, roots, domain.GetValue<long>()))[0];
                roots = Array(match!["roots"]).DeepClone().AsArray();
            }
            var readRoots = new JsonArray(roots.Where(r =>
                (context.Params["source_instance_id"] is null || Text(r, "source_instance_id") == Text(context.Params, "source_instance_id"))
                && (context.Params["device_id"] is null || Text(r, "agent_id") == Text(context.Params, "device_id"))
                && (selected.Count == 0 || selected.Any(x => x!.GetValue<string>() == ShareKey(r!))))
                .Select(r => r!.DeepClone()).ToArray());
            if (readRoots.Count == 0) data = new() { ["items"] = new JsonArray(), ["filtered_count"] = 0, ["has_more"] = false, ["after"] = null };
            else
            {
                var options = after?.Copy() ?? new JsonObject(); options["show_service"] = context.Params.Text("show_service", "false") == "true";
                if (context.Params["record_unit"] is { } unit) options["record_unit"] = unit.DeepClone();
                string? operation = context.Params["operation"]?.GetValue<string>();
                bool objectView = tab == "permissions" && context.Params.Text("view") == "objects";
                bool actionRows = tab is "actions" or "permission-changes" or "access-denials" or "out-of-hours";
                var sql = tab == "overview" ? PermissionOverviewSql : actionRows && tab != "out-of-hours" ? PermissionChangesSql
                    : "select sli_plugin_file_audit.report_rows($1::jsonb,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10) as data";
                var from = DateTimeOffset.Parse(context.Params["period"]!["from_utc"]!.GetValue<string>(), CultureInfo.InvariantCulture).UtcDateTime;
                var to = WindowEnd(context);
                if (context.Params["activity"] is { } activity) options["activity"] = activity.DeepClone();
                Task<JsonArray> Read(JsonObject paging, int size) => session.QueryAsync(sql, ct, readRoots, tab, from, to,
                    Text(context.Params, "path"), context.Params.Text("include_nested", "true") == "true",
                    Text(context.Params, "employee"), operation, paging, size);
                data = objectView ? await ObjectRows(session, context, readRoots, after, ct)
                    : actionRows ? await ReadScreenActions(session, context, tab, options, Read, ct)
                    : (await Read(options, context.Paging.Limit))[0]!["data"]!.AsObject();
                if (data["service_filter_version"]?.GetValue<int>() != 1) return Unreadable(context);
                if (tab == "overview") await ResourceAuditAsync(session, Array(data["items"]), ct);
                if (actionRows) await LinkActionProblemsAsync(session, context, Array(data["items"]), tab, ct);
            }
            await RestoreEvidenceAsync(context, readRoots, Array(data["items"]), ct);
            if (tab == "mass-operations") await RansomDetails(session, context, roots, Array(data["items"]), ct);
            await session.CommitAsync(ct);
        }
        catch (PostgresException e) when (e.SqlState == "57014")
        { return ReportResult.Create(context.Definition.Key, "error", coverage: new() { ["state"] = "unavailable", ["reason"] = "source_timeout" }, limitations: [new JsonObject { ["code"] = "source_timeout", ["text"] = ReportResult.Message("reports.file-audit.source_timeout")["text"]!.DeepClone() }]); }
        catch (PostgresException e) when (e.SqlState is "42883" or "42P01" or "42501") { return Unreadable(context); }
        catch (NpgsqlException) { return Unreadable(context); }
        catch (Exception e) when (e is LifecycleBlocked or HttpRequestException or IOException or System.Text.Json.JsonException or Sli.Server.Storage.EventReports.EventReadConfigurationException)
        { return ReportResult.Create(context.Definition.Key,"error",coverage: new() { ["state"] = "unavailable", ["reason"] = "file_audit_history_unavailable" }, limitations: [new JsonObject { ["code"] = "file_audit_history_unavailable", ["text"] = "История доказательств аудита файлов недоступна. Повторите запрос после восстановления хранилища." }]); }
        return Present(context, roots, data, tab);
    }
    internal async Task RestoreEvidenceAsync(ReportQueryContext context, JsonArray roots, JsonArray items, CancellationToken ct)
    {
        FileAuditHistory? archive = null;
        try {
            foreach (var row in items.OfType<JsonObject>()) {
                var references = Array(row["evidence"]).OfType<JsonObject>().Where(e => Text(e,"reference")?.StartsWith(FileAuditHistory.ReferencePrefix,StringComparison.Ordinal) == true).ToArray();
                if (references.Length == 0) continue;
                var root = roots.OfType<JsonObject>().SingleOrDefault(r => ShareKey(r) == ShareKey(row));
                if (root is null || !Admitted(context,root)) throw new LifecycleBlocked("file_audit_history_scope_mismatch");
                archive ??= history() ?? throw new LifecycleBlocked("file_audit_history_unavailable");
                string[] keys = references.Select(e => Text(e,"reference")![FileAuditHistory.ReferencePrefix.Length..]).Distinct().ToArray();
                if (keys.Any(k => !System.Text.RegularExpressions.Regex.IsMatch(k,"^[a-f0-9]{64}$"))) throw new LifecycleBlocked("file_audit_history_reference_invalid");
                var payloads = await archive.ReadAsync(root,keys,ct);
                foreach (var evidence in references) {
                    string key = Text(evidence,"reference")![FileAuditHistory.ReferencePrefix.Length..];
                    var payload = payloads.Single(p => Text(p["observation"],"evidence_key") == key);
                    // Validate the original edge too, not only the observation hash.
                    string action = Text(evidence,"action_id") ?? Text(row,"action_id") ?? Text(row,"id")!;
                    var link = payload["links"]!.AsArray().OfType<JsonObject>().SingleOrDefault(l => Text(l,"action_id") == action && (evidence["role"] is null || Text(l,"role") == Text(evidence,"role")))
                        ?? throw new LifecycleBlocked("file_audit_history_link_mismatch");
                    var observation = payload["observation"]!;
                    evidence["reference"] = link["core_evidence_ref"]!.DeepClone();
                    foreach (string field in new[] { "event_id","record_id","generation","payload_sha256" }) evidence[field] = observation[field]!.DeepClone();
                    evidence["path"] = observation["normalized"]?["path"]?.DeepClone();
                }
            }
        } finally { archive?.Dispose(); }
    }
    private static JsonObject Unreadable(ReportQueryContext c) => ReportResult.Create(c.Definition.Key, "error", coverage: new() { ["state"] = "unavailable", ["reason"] = "source_unreadable" });
    private static async Task RansomDetails(ISemanticSession session, ReportQueryContext context, JsonArray roots, JsonArray items, CancellationToken ct)
    {
        var queueRule = new JsonObject { ["report_key"] = "security.queue", ["required_fields"] = new JsonArray("security"), ["scope"] = "generic" };
        ReportScope queue;
        try { queue = new ReportAccess(new ReportDefinition(new() { ["key"] = "security.queue", ["access_rule"] = queueRule }), context.Access, context.Action).Scope; }
        catch (ReportRequestException e) when (e.Status == 403) { queue = ReportScope.None; }
        var allowed = new JsonArray(roots.Where(r => Admitted(context, r!, queue)).Select(r => r!.DeepClone()).ToArray());
        var decisions = new JsonObject();
        if (allowed.Count > 0 && items.Count > 0) decisions = (await session.QueryAsync("select public.read_file_ransom_details($1::jsonb,$2::jsonb) as decisions", ct, allowed, new JsonArray(items.Select(r => r!["id"]!.DeepClone()).ToArray())))[0]!["decisions"]!.AsObject();
        foreach (var row in items.OfType<JsonObject>()) row["ransom"] = Text(row, "rule_code") is not ("file-audit.mass-write" or "file-audit.mass-delete") ? new JsonObject { ["state"] = "not_applicable" }
            : !allowed.Any(r => ShareKey(r!) == ShareKey(row)) ? new JsonObject { ["state"] = "denied" } : decisions[Text(row, "id")!]?.DeepClone() ?? new JsonObject { ["state"] = "not_evaluated" };
    }
    internal static JsonObject Present(ReportQueryContext context, JsonArray roots, JsonObject data, string tab)
    {
        var items = Array(data["items"]).DeepClone().AsArray();
        bool rootObservationFilter = tab == "overview" && (context.Params["employee"] is not null || context.Params["operation"] is not null);
        foreach (var row in items.OfType<JsonObject>())
        {
            var root = roots.FirstOrDefault(r => ShareKey(r!) == ShareKey(row)); row["share_label"] = Label(root);
            foreach (string field in new[] { "source_name", "share_name", "source_kind" })
                if (root?[field] is { } value) row[field] = field == "source_name" ? JsonValue.Create(SourceName(root)) : value.DeepClone();
            row["operation"] = (row["operation"] ?? row["details"]?["operation"])?.DeepClone();
            if (tab == "mass-operations") { row["operation"] = row.Text("rule_code")["file-audit.mass-".Length..]; row["files_per_minute"] = Math.Round(double.Parse(row["details"]!["distinct_files"]!.ToJsonString(), CultureInfo.InvariantCulture) * 60 / double.Parse(row["details"]!["window_seconds"]!.ToJsonString(), CultureInfo.InvariantCulture), 1, MidpointRounding.ToEven); }
            if (tab is "overview" or "audit-state" && row["snapshot_id"] is null) row["folders_with_read_audit"] = null;
            if (tab == "audit-state") row["delivery_state"] = !row.ContainsKey("delivery_received_at") ? "unknown" : row["delivery_received_at"] is null ? "not_received" : row["delivery_imported_at"] is not null ? "imported" : "pending_import";
            if (rootObservationFilter) row["actions"] = null;
            row["employee"] = (row["subject_name"] ?? row["subject_sid"])?.DeepClone();
            if (tab == "out-of-hours" && row["path"] is null) row["path"] = Array(row["evidence"]).FirstOrDefault(e => !string.IsNullOrEmpty(Text(e, "path")))?["path"]?.DeepClone();
        }
        var coverage = new JsonObject { ["state"] = "unknown", ["reason"] = "coverage_incomplete", ["completeness"] = "not_proven" };
        bool serverSource = context.Params.Text("source_kind") == "server"
            || roots.Count > 0 && roots.All(r => (Text(r, "source_kind") ?? "server") == "server");
        if (serverSource)
        {
            // This describes the supported server collector, not a live-agent
            // or completeness claim. Older activity remains readable as evidence.
            coverage["supported_collection_mode"] = "server_permissions_only";
            coverage["activity_scope"] = "retained_observations";
            if (items.Count == 0)
                coverage["reason"] = tab is "mass-operations" or "access-denials" or "out-of-hours"
                    || tab == "actions" && context.Params["operation"] is not null && context.Params.Text("operation") != "permissions"
                    ? "full_activity_not_collected" : "no_saved_observations";
        }
        if (tab is "overview" or "audit-state" or "permissions" && items.Count > 0)
        {
            string? observed = items.Select(r => Text(r, "observed_at")).Where(t => t is not null).Order(StringComparer.Ordinal).LastOrDefault();
            if (observed is not null) { coverage["observed_at_utc"] = observed; coverage["freshness_threshold_seconds"] = 86400; }
        }
        bool objectView = tab == "permissions" && context.Params.Text("view") == "objects";
        if (objectView) { coverage["inventory_scope"] = "retained_snapshot_pages"; coverage["record_unit"] = "observed_object"; }
        if (data["native_group_count"] is { } nativeGroups) coverage["native_group_count"] = nativeGroups.DeepClone();
        if (data.ContainsKey("native_event_count")) coverage["native_event_count"] = data["native_event_count"]?.DeepClone();
        var collections = tab == "overview" ? new JsonObject { ["timeline"] = rootObservationFilter ? new JsonArray() : data["timeline"]?.DeepClone() ?? new JsonArray() } : tab == "permissions" && !objectView ? new JsonObject { ["groups"] = Groups(Array(data["inventory"]), Text(context.Params, "employee")) } : new JsonObject();
        var result = ReportResult.Create(context.Definition.Key, roots.Count > 0 ? "partial" : "not_collected", items, coverage, collections, [new JsonObject { ["code"] = "coverage_unverified", ["text"] = "Полнота сбора за выбранный период не подтверждена." }]);
        result["filtered_count"] = roots.Count > 0 ? data["filtered_count"]?.DeepClone() : null; result["has_more"] = data["has_more"]?.DeepClone() ?? JsonValue.Create(false);
        result["next_cursor"] = data.Flag("has_more") ? data["after"]!.ToJsonString() : null;
        result["filter_options"] = new JsonObject
        {
            ["share"] = new JsonArray(roots.Select(r => (JsonNode)new JsonObject { ["value"] = ShareKey(r!), ["label"] = Label(r), ["important"] = r!["important"]?.DeepClone() ?? JsonValue.Create(false) }).ToArray()),
            ["source_instance_id"] = new JsonArray(roots.OfType<JsonObject>().GroupBy(r => Text(r, "source_instance_id")).Select(g => (JsonNode)new JsonObject { ["value"] = g.Key, ["label"] = SourceName(g.First()) ?? "—" }).ToArray()),
            ["device_id"] = new JsonArray(roots.OfType<JsonObject>().GroupBy(r => Text(r, "agent_id")).Select(g => (JsonNode)new JsonObject { ["value"] = g.Key, ["label"] = SourceName(g.First()) ?? "—" }).ToArray())
        };
        result["window"] = context.Params["period"]!.DeepClone(); result["window"]!["timezone"] = context.Paging.Timezone;
        result["window"]!["export_row_limit"] = 10000;
        if (tab == "overview" && roots.Count > 0 && !rootObservationFilter) result["metrics"] = new JsonArray(new[] { ("read", "Чтения"), ("write", "Записи"), ("delete", "Удаления"), ("denials", "Отказы") }.Select(p => (JsonNode)new JsonObject { ["key"] = p.Item1, ["label"] = p.Item2, ["value"] = data["summary"]?[p.Item1]?.DeepClone(), ["quality"] = data["summary"]?[p.Item1] is null ? "unknown" : "observed", ["filter"] = p.Item1 == "denials" ? new JsonObject() : new JsonObject { ["operation"] = p.Item1 } }).ToArray());
        return result;
    }
    private static string Label(JsonNode? root) => (SourceName(root) ?? "—") + " · " + (Text(root, "share_name") is { Length: > 0 } share ? share : Text(root, "path") ?? "—");
    internal static JsonArray Groups(JsonArray inventory, string? employee)
    {
        var rows = new JsonArray();
        foreach (var root in inventory)
        {
            var smb = FileAuditAcl.Parse(Text(root, "share_dacl")); var ntfs = FileAuditAcl.Parse(Text(root, "root_dacl"));
            var known = Array(root?["group_sids"]).Select(s => s!.GetValue<string>()).Concat(["S-1-1-0", "S-1-5-11", "S-1-5-32-544", "S-1-5-32-545"]).ToHashSet();
            foreach (string sid in smb.Aces.Concat(ntfs.Aces).Where(a => a.Kind == "A" && !a.InheritOnly && (known.Contains(a.Sid) || a.Sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && a.Sid.EndsWith("-513", StringComparison.Ordinal))).Select(a => a.Sid).Distinct().Order(StringComparer.Ordinal))
            {
                if (employee is not null && employee != sid) continue;
                if (rows.Count == 1000) return rows;
                rows.Add(new JsonObject { ["share_label"] = root!["share_label"]?.DeepClone(), ["subject_sid"] = sid, ["smb_mask"] = smb.Complete && root["share_complete"]?.GetValue<bool>() == true ? JsonValue.Create(FileAuditAcl.AccessMask(smb.Aces, new HashSet<string> { sid })) : null, ["ntfs_mask"] = ntfs.Complete ? JsonValue.Create(FileAuditAcl.AccessMask(ntfs.Aces, new HashSet<string> { sid })) : null, ["observed_at"] = root["observed_at"]?.DeepClone() });
            }
        }
        return rows;
    }
    public async Task<ReportExport> ExportAsync(ReportQueryContext context, CancellationToken ct)
    {
        if (!context.Access.Capabilities.Capabilities.Contains("file-audit.export")) throw new ReportRequestException("report_access_denied", 403);
        var projection = new ReportAccess(context.Definition, context.Access, "export"); var rows = new JsonArray(); string? cursor = null; bool more;
        do
        {
            var data = projection.Project(await QueryAsync(context with { Action = "export", Paging = context.Paging with { Cursor = cursor, Limit = 100 } }, ct));
            if (data.Text("state") is "error" or "denied" or "not_collected") throw new ReportRequestException("report_export_unavailable");
            foreach (var row in Array(data["items"])) rows.Add(row!.DeepClone()); more = data.Flag("has_more"); string? next = Text(data, "next_cursor");
            if (more && (string.IsNullOrEmpty(next) || next == cursor)) throw new ReportRequestException("report_export_unavailable"); cursor = next;
        } while (more && rows.Count < 10000);
        var columns = context.Definition.Columns;
        if (context.Definition.Key == "file-audit.permissions" && context.Params.Text("view") == "objects")
            columns = columns.Where(c => new[] { "source_name", "share_name", "path", "object_type", "owner_sid", "snapshot_id", "observed_at", "completeness", "record_unit" }.Contains(c.Text("key"))).ToArray();
        return new(ReportCsv.FromColumns(columns, rows.OfType<JsonObject>()), rows.Count, more);
    }
}
