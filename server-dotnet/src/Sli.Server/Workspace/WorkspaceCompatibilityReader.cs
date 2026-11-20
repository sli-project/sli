using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Compatibility;
using Sli.Server.Reporting;

namespace Sli.Server.Workspace;

public sealed class WorkspaceCompatibilityReader(IWorkspaceRows rows, IConfiguration configuration, ReportRunner runner,
    DashboardSnapshotReader dashboard, LegacyInvestigationReader investigation) : IWorkspaceCompatibilityReader
{
    public Task<JsonObject> ReadAsync(string path, IQueryCollection query, Principal principal, AccessReadEvaluation access, CancellationToken ct) => path switch {
        "/api/ui/navigation" => Task.FromResult(LegacyWorkspaceModels.Navigation(configuration)),
        "/api/v1/ui/route-parity" => Task.FromResult(LegacyWorkspaceModels.Parity()),
        "/api/v1/workspace" => Workspace(principal, access, ct),
        "/api/dashboard/snapshot" => dashboard.ReadAsync(LegacyQuery.First(query, "force")?.ToLowerInvariant() is "1" or "true" or "yes", ct),
        "/api/role-views" => RoleViews(ct),
        "/api/investigation/workspace" => investigation.ReadAsync(query, ct),
        _ => throw new LegacyInputException("not_found", 404)
    };
    private Task<JsonObject> RoleViews(CancellationToken ct) => dashboard.ReadRoleViewsAsync(ct);
    private async Task<JsonObject> Workspace(Principal principal, AccessReadEvaluation access, CancellationToken ct) {
        var projection = JsonSerializer.SerializeToNode(AccessReadProjection.Compose(principal, access.Facts, access.Capabilities, access.Reports, false))!.AsObject();
        // The optional-auth local operator has no persisted identity in the Python contract.
        if (principal.Type.Length == 0)
            projection["subject"] = new JsonObject { ["type"] = "local", ["id"] = null, ["username"] = "local-operator", ["coarse_role"] = access.Facts.Role };
        var reports = projection["reports"]!.AsArray().OfType<JsonObject>().Where(r => r["allowed"]?.GetValue<bool>() == true).ToArray();
        var pinned = reports.OrderByDescending(r => r["pinned"]?.GetValue<bool>() == true).ThenBy(r => r["name"]?.ToString(), StringComparer.Ordinal);
        var recent = new JsonArray(); string recentState = "available";
        if (access.Facts.IsOwner || access.Capabilities.Capabilities.Contains("objects.view") || access.Capabilities.ResourceCapabilities.Contains("objects.view")) {
            IReadOnlyList<JsonElement> objects;
            try { objects = await rows.ReadAsync("""
                select entity.id,entity_type.value as object_type,entity.display_name,entity.natural_key,
                       entity.last_seen_utc,entity.domain_id,entity.server_id
                from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
                order by entity.last_seen_utc desc nulls last,entity.id desc limit 8
                """, ct); }
            catch (Npgsql.PostgresException e) when (e.SqlState == "57014") { objects = []; recentState = "temporarily_unavailable"; }
            foreach (var row in objects) {
                if (!row.TryGetProperty("domain_id", out var domain) || !row.TryGetProperty("server_id", out var server)) continue;
                long? D(JsonElement e) => e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out long n) && n > 0 ? n : null;
                long? domainId = D(domain), serverId = D(server);
                if (domain.ValueKind != JsonValueKind.Null && domainId is null || server.ValueKind != JsonValueKind.Null && serverId is null || domainId is null && serverId is null) continue;
                var resources = new List<AccessResource>(); if (domainId is {} d) resources.Add(new("domain", d)); if (serverId is {} s) resources.Add(new("server", s));
                if (!access.Capabilities.DecideForResourceGroups("objects.view", [resources]).Allowed) continue;
                string? natural = access.Capabilities.DecideForResourceGroups("field.technical", [resources]).Allowed ? row.Text("natural_key") : null;
                string id = row.GetProperty("id").ToString();
                recent.Add(new JsonObject { ["object_type"] = row.Text("object_type"), ["object_id"] = id, ["display_name"] = row.Text("display_name") is { Length: > 0 } name ? name : natural is { Length: > 0 } ? natural : id,
                    ["natural_key"] = natural, ["observed_at_utc"] = row.Get("last_seen_utc").ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ? null : row.Get("last_seen_utc").ToString(), ["source"] = "Storage V2" });
            }
        }
        var focus = new List<JsonObject>();
        foreach (var report in reports) {
            var selected = (report["selected_optional_metric_keys"] as JsonArray ?? []).Select(n => n!.ToString()).ToHashSet();
            JsonArray definitions;
            try { definitions = ReportBuilder.Metrics(report["dashboard_metrics"]); } catch (ReportException) { continue; }
            var metrics = definitions.OfType<JsonObject>().Where(m => m["kind"]?.ToString() == "required" || selected.Contains(m["key"]?.ToString() ?? "") || report["focus_preference_configured"]?.GetValue<bool>() != true && m["default_selected"]?.GetValue<bool>() == true).ToArray();
            if (metrics.Length == 0) continue;
            JsonObject payload;
            try { payload = await runner.ExecuteAsync(new(principal, access.Facts, access.Capabilities, projection), report["report_key"]!.ToString(), 1, null, "view", new Dictionary<string, string>(), ct); }
            catch (Exception e) when (e is ReportException or InvalidOperationException or Npgsql.NpgsqlException) { payload = new() { ["state"] = "unavailable" }; }
            JsonNode? Value(string? path) { if (path == "items.count") return JsonValue.Create((payload["items"] as JsonArray)?.Count ?? 0); JsonNode? node = payload; foreach (var part in (path ?? "").Split('.')) node = node is JsonObject o ? o[part] : null; return node?.DeepClone(); }
            var collectionStates = (payload["summary"]?["collection"] as JsonObject ?? new()).Select(p => p.Value?["state"]?.ToString() ?? "").ToHashSet();
            string state = collectionStates.Contains("failed") ? "failed" : collectionStates.Overlaps(["partial", "skipped"]) ? "partial" : collectionStates.Count > 0 && collectionStates.IsSubsetOf(["not_collected", "scope_not_applicable"]) ? "not_collected" : payload["state"]?.ToString() ?? "unknown";
            foreach (var metric in metrics) {
                var item = metric.DeepClone().AsObject(); item.Remove("value_path"); item.Remove("freshness_path"); item.Remove("default_selected");
                item["value"] = Value(metric["value_path"]?.ToString()); item["freshness"] = Value(metric["freshness_path"]?.ToString());
                item["state"] = state; item["source"] = report["dataset_key"]?.DeepClone(); item["report_key"] = report["report_key"]!.DeepClone(); focus.Add(item);
            }
        }
        int Denies() => projection["explicit_denies"]!.AsObject().Sum(p => (p.Value as JsonArray)?.Count ?? 0);
        return new() { ["api_version"] = "v4", ["state"] = reports.Length > 0 ? "available" : "empty", ["subject"] = projection["subject"]!.DeepClone(), ["packages"] = projection["packages"]!.DeepClone(), ["groups"] = projection["groups"]!.DeepClone(), ["capabilities"] = projection["capabilities"]!.DeepClone(),
            ["reports"] = new JsonArray(pinned.Select(r => r.DeepClone()).ToArray()), ["focus_metrics"] = new JsonArray(focus.OrderBy(m => m["priority"]?.GetValue<int>() ?? 0).ThenBy(m => Agents.Registry.UnicodeCaseFold.Fold(m["label"]?.ToString() ?? ""), StringComparer.Ordinal).ThenBy(m => m["key"]?.ToString(), StringComparer.Ordinal).Select(m => (JsonNode)m).ToArray()),
            ["recent_objects"] = recent, ["recent_objects_state"] = recentState,
            ["composition"] = new JsonObject { ["package_count"] = projection["packages"]!.AsArray().Count, ["group_count"] = projection["groups"]!.AsArray().Count,
                ["direct_report_count"] = reports.Sum(r => (r["sources"] as JsonArray ?? []).Count(s => s?["source_type"]?.ToString() is "direct" or "temporary")), ["allowed_report_count"] = reports.Length, ["explicit_deny_count"] = Denies() },
            ["limits"] = new JsonObject { ["recent_objects"] = 8, ["reports"] = reports.Length } };
    }
}
