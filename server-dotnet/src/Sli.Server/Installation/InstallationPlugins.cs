using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Agents.Radius;
using Sli.Server.Workspace;

namespace Sli.Server.InstallationSetup;

public sealed partial class InstallationService
{
    static readonly string[] StateFields = ["plugin_id", "package_version", "installed", "configured", "enabled", "receiving_data", "component_runtime", "queue_state", "revision", "last_data_at_utc"];
    static JsonObject PluginState(JsonObject row) => new(StateFields.Select(f => new KeyValuePair<string, JsonNode?>(f, row[f]?.DeepClone())));
    async Task<JsonObject> ToggleAsync(string id, JsonObject body, Principal actor, CancellationToken ct)
    {
        if (!InstallationPackages.Keys(body, "enabled", "expected_revision") || body["enabled"] is not JsonValue b || !b.TryGetValue<bool>(out bool enabled)
            || body["expected_revision"] is not JsonValue revision || !revision.TryGetValue<long>(out long expected) || expected < 1)
            throw new InstallationException("plugin_state_request_invalid");
        bool? configured = id == "sli.remote-access" ? RemoteConfigured() : null;
        if (enabled && configured == false) throw new InstallationException("plugin_not_configured", 409);
        try
        {
            return await database.WriteAsync(async s =>
            {
                if (id=="sli.remote-access" && enabled && Environment.GetEnvironmentVariable("SLI_DEPLOYMENT_MODE")=="native")
                {
                    if (RadiusAccountingMode.Effective() is not { } mode)
                        throw new InstallationException("plugin_not_configured",409);
                    await s.QueryAsync("select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))",ct);
                    var exists=First(await s.QueryAsync("select to_regprocedure('public.radius_accounting_source_ready406(text,text,text,text,boolean)') is not null as ready",ct));
                    if (exists?["ready"]?.GetValue<bool>() != true ||
                        First(await s.QueryAsync("select public.radius_accounting_source_ready406(@p0,@p1,@p2,@p3,false) as ready",
                            ct,mode.SourceId,mode.Subscription,mode.TransportBinding,mode.EndpointIdentity))?["ready"]?.GetValue<bool>() != true)
                        throw new InstallationException("plugin_not_configured",409);
                }
                var row = First(await s.QueryAsync("select * from set_plugin_enabled_v1(@p0,@p1,@p2,@p3,@p4,@p5::boolean)", ct,
                    id, enabled, expected, actor.Type, actor.Id, configured.HasValue ? configured.Value : null));
                return row is null ? throw new InstallationException("plugin_state_conflict", 409) : PluginState(row);
            }, ct);
        }
        catch (PostgresException e) when (e.SqlState == PostgresErrorCodes.InsufficientPrivilege)
        { throw new InstallationException("plugin_management_owner_or_admin_required", 403); }
        catch (PostgresException e) when (e.SqlState == PostgresErrorCodes.RaiseException)
        {
            string reason = e.MessageText;
            if (reason == "plugin_not_found") throw new InstallationException(reason, 404);
            if (reason == "plugin_state_request_invalid") throw new InstallationException(reason);
            if (reason is "plugin enable precondition failed" or "plugin drain precondition failed" or "plugin disable precondition failed") reason = "plugin_runtime_precondition_failed";
            string[] allowed = ["plugin_state_conflict", "plugin_revision_conflict", "plugin_not_installed", "plugin_not_configured", "plugin_runtime_not_stopped",
                "plugin_runtime_not_running", "plugin_queue_not_drained", "plugin_active_leases", "plugin_runtime_transition_unsupported", "plugin_runtime_precondition_failed"];
            throw new InstallationException(allowed.Contains(reason, StringComparer.Ordinal) ? reason : "plugin_state_conflict", 409);
        }
    }
    async Task<JsonArray> PluginStatesAsync(bool preview, AccessFacts? facts, CancellationToken ct)
    {
        var rows = await database.ReadAsync(s => s.QueryAsync("select * from read_plugin_states_v1()", ct), ct);
        var items = new JsonArray(rows.OfType<JsonObject>()
            .Where(r => preview || !NavigationRegistry.IsPreviewPlugin(Text(r["plugin_id"])))
            .Select(r => (JsonNode)PluginState(r)).ToArray());
        var moduleReceipts = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        var receipts = await ReceiptsAsync(items.OfType<JsonObject>().Select(i => Text(i["plugin_id"])).ToArray(), ct, moduleReceipts);
        var sources = await PluginSourcesAsync(items, ct);
        var workstationSources = facts is not null && items.OfType<JsonObject>().Any(i => Text(i["plugin_id"]) == "sli.workstations")
            ? await WorkstationStatusSourcesAsync(facts, ct) : sources;
        var now = DateTimeOffset.UtcNow;
        foreach (var item in items.OfType<JsonObject>())
        {
            string id = Text(item["plugin_id"]);
            item["data_receipts"] = receipts[id];
            if (id == "sli.remote-access") item["configured"] = RemoteConfigured();
            var sigma = id == "sli.sigma" && Bool(item["enabled"]) ? await SigmaStatusAsync(ct) : null;
            var radius = id == "sli.remote-access" && Bool(item["enabled"]) ? await RadiusStatusSourcesAsync(ct) : null;
            item["status"] = PluginPresentation(item, receipts[id], moduleReceipts, id == "sli.workstations" ? workstationSources : sources, radius, sigma, now);
        }
        return items;
    }
    bool RemoteConfigured()
    {
        using var admission = Admission("sli.remote-access");
        if (Environment.GetEnvironmentVariable("SLI_DEPLOYMENT_MODE")=="native")
            return RadiusAccountingMode.Effective() is not null;
        return Bool(packages.RadiusRoute()?["accounting_ready"]);
    }
    static readonly IReadOnlyDictionary<string, string[]> PluginModules = new Dictionary<string, string[]> {
        ["sli.ad"] = ["sli.windows.ad-dc", "sli.windows.ad-dc-history", "sli.ad-snapshot"], ["sli.gpo"] = ["sli.gpo-snapshot"],
        ["sli.file-audit"] = ["sli.file-audit"], ["sli.workstations"] = ["sli.workstations"], ["sli.remote-access"] = ["sli.vpn-nps", "sli.radius-accounting"] };
    internal async Task<Dictionary<string, JsonObject>> ReceiptsAsync(string[] ids, CancellationToken ct,
        Dictionary<string, JsonObject>? moduleReceipts = null)
    {
        string[] fields = ["last_received_at", "last_imported_at", "last_snapshot_completed_at"];
        var result = ids.Distinct().ToDictionary(id => id, id => new JsonObject { ["state"] = PluginModules.ContainsKey(id) ? "no_receipts" : "not_supported",
            [fields[0]] = null, [fields[1]] = null, [fields[2]] = null });
        string[] modules = ids.Where(PluginModules.ContainsKey).SelectMany(id => PluginModules[id]).Distinct().ToArray();
        if (modules.Length == 0) return result;
        JsonArray rows;
        try
        {
            rows = await database.ReadAsync(s => s.QueryAsync(Sql("plugin-receipts.sql"), ct, modules, modules), ct);
        }
        catch (Exception e) when (e is NpgsqlException or InvalidOperationException)
        {
            foreach (string id in ids.Where(PluginModules.ContainsKey)) result[id]["state"] = "unavailable";
            return result;
        }
        if (moduleReceipts is not null)
            foreach (var row in rows.OfType<JsonObject>()) moduleReceipts[Text(row["module_id"])] = row;
        foreach (string id in ids.Where(PluginModules.ContainsKey))
            foreach (string field in fields)
            {
                var stamps = rows.OfType<JsonObject>().Where(r => PluginModules[id].Contains(Text(r["module_id"]))).Select(r => Text(r[field])).Where(v => v.Length > 0)
                    .Select(v => DateTimeOffset.Parse(v)).OrderDescending().ToArray();
                if (stamps.Length == 0) continue;
                string format = stamps[0].Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-ddTHH:mm:sszzz" : "yyyy-MM-ddTHH:mm:ss.ffffffzzz";
                result[id][field] = stamps[0].ToString(format, System.Globalization.CultureInfo.InvariantCulture); result[id]["state"] = "observed";
            }
        return result;
    }
    public static string Sql(string name)
    {
        using var stream = typeof(InstallationService).Assembly.GetManifestResourceStream("Sli.Installation." + name) ?? throw new InvalidOperationException("installation_sql_unavailable");
        using var reader = new StreamReader(stream); return reader.ReadToEnd();
    }
    async Task<JsonObject> PluginCatalogAsync(CancellationToken ct)
    {
        _ = PluginPackageManifest.LoadAndValidateRemoteAccess();
        var registry = InstallationPackages.Contract("stage10_plugin_management_v1.json");
        var architecture = InstallationPackages.Contract("plugin_architecture_v2.json");
        var ad = AdDcCompatibilityRegistration.Load();
        if (Text(registry["contract_id"]) != "sli.plugin-management.v1" || Number(registry["schema_version"]) != 2
            || Text(registry["status"]) != "runtime_state_management_enabled" || !Bool(registry["mutation_api_enabled"])
            || Bool(registry["production_read_path_cutover"]) || Bool(registry["destructive_purge_allowed"])
            || Text(architecture["decision_id"]) != Text(registry["architecture_decision_id"]) || Text(architecture["status"]) != "owner_accepted_design_boundary")
            throw new InstallationException("plugin_management_architecture_mismatch");
        var items = new JsonArray();
        foreach (var item in registry["plugins"]!.AsArray().OfType<JsonObject>())
        {
            var plugin = item.DeepClone().AsObject();
            plugin["sections"] = registry["sections"]!.DeepClone(); plugin["lifecycle_actions"] = registry["lifecycle_actions"]!.DeepClone();
            if (Text(plugin["plugin_id"]) == "sli.remote-access") plugin["observed"] = await RemoteObservationAsync(ct);
            else
            {
                foreach (var action in plugin["lifecycle_actions"]!.AsObject()) action.Value!["available"] = false;
                plugin["observed"] = new JsonObject { ["status"] = "compatibility_registered_not_live_asserted", ["state"] = ad["state"]!.DeepClone(), ["source_count"] = 0, ["sources"] = new JsonArray() };
            }
            items.Add(plugin);
        }
        return new() { ["contract_id"] = registry["contract_id"]!.DeepClone(), ["status"] = registry["status"]!.DeepClone(), ["read_only"] = true,
            ["mutation_api_enabled"] = true, ["runtime_changed"] = false, ["source_contact"] = false, ["items"] = items,
            ["limits"] = registry["limits"]!.DeepClone(), ["explicitly_out_of_scope"] = registry["explicitly_out_of_scope"]!.DeepClone() };
    }
    async Task<JsonObject> RemoteObservationAsync(CancellationToken ct)
    {
        try
        {
            using var admission = Admission("sli.remote-access");
            var rows = await database.ReadAsync(s => s.QueryAsync("select * from radius_vpn_operations_v1 order by source_instance_id limit 20", ct), ct);
            var sources = new JsonArray();
            foreach (var row in rows.OfType<JsonObject>())
            {
                long failed = Number(row["failed_delivery_count"]), leased = Number(row["leased_delivery_count"]), quarantined = Number(row["quarantined_delivery_count"]), projected = Number(row["projected_session_count"]);
                long unresolved = Number(row["identity_unresolved_count"]) + Number(row["timestamp_unresolved_count"]) + quarantined;
                sources.Add(new JsonObject { ["source_instance_id"] = row["source_instance_id"]?.DeepClone(), ["plugin_state"] = "bundled_supervised_production",
                    ["source_state"] = Text(row["source_activation"]) == "disabled" ? "disabled" : Text(row["subscription_activation"]) == "disabled" ? "subscription_disabled" : "manual_enabled",
                    ["worker_state"] = Bool(row["manual_worker_session_exists"]) ? "active_manual" : Bool(row["ephemeral_login_exists"]) ? "attention" : "manual_idle",
                    ["queue_state"] = failed > 0 || leased > 0 || quarantined > 0 ? "attention" : Number(row["queued_delivery_count"]) > 0 ? "pending_manual" : "drained",
                    ["dataset_state"] = projected == 0 && unresolved > 0 ? "identity_incomplete" : projected > 0 && unresolved > 0 ? "partial" : projected > 0 ? "available" : "not_collected",
                    ["access_state"] = Number(row["direct_capability_assignment_count"]) == 0 && Number(row["package_capability_mapping_count"]) == 0 ? "owner_only" : "assigned",
                    ["resource_profile"] = ResourceProfile(Text(row["resource_profile_id"])) });
            }
            return new() { ["status"] = "ok", ["source_count"] = sources.Count, ["sources"] = sources, ["contains_identity_or_event_payload"] = false };
        }
        catch (Exception e) when (e is NpgsqlException or InvalidOperationException or IOException or InstallationException)
        {
            string errorType = e is PostgresException postgres ? postgres.SqlState switch {
                "42P01" => "UndefinedTable", "42501" => "InsufficientPrivilege", "57014" => "QueryCanceled", "42883" => "UndefinedFunction", _ => "Error" }
                : e is NpgsqlException ? "OperationalError" : "RuntimeError";
            return new() { ["status"] = "unavailable", ["source_count"] = 0, ["sources"] = new JsonArray(), ["contains_identity_or_event_payload"] = false, ["error_type"] = errorType };
        }
    }
    static JsonObject ResourceProfile(string id) => PluginResourceProfiles.View(id);
}
