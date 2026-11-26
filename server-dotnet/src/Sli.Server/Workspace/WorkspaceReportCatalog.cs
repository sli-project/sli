using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Access.Administration;

namespace Sli.Server.Workspace;

public sealed class WorkspaceReportCatalog(IWorkspaceRows rows, IReportCatalogProvider catalog, IConfiguration? configuration = null)
{
    public async Task<object> ReadAsync(AccessReadEvaluation access, CancellationToken ct)
    {
        var snapshot = catalog.Capture();
        IReadOnlyList<JsonElement> states;
        try { states = await rows.ReadAsync("select plugin_id,enabled from read_plugin_states_v1()", ct); }
        catch (Exception error) when (error is Npgsql.NpgsqlException or TimeoutException or InvalidOperationException) { states = []; }
        return Compose(access, catalog.Recheck(snapshot).Rules, states, NavigationRegistry.PreviewEnabled(configuration));
    }

    public static object Compose(AccessReadEvaluation access, IReadOnlyList<ReportRule> rules, IReadOnlyList<JsonElement> states, bool preview = false)
    {
        var declarations = WorkspaceJson.Declarations;
        var owners = NavigationRegistry.Owners();
        var items = new List<JsonObject>();
        foreach (var definition in declarations.Get("reports").Items())
        {
            var rule = rules.FirstOrDefault(r => r.RegistryKey == definition.Text("key"));
            if (rule is null || !rule.RequiredCapabilities.IsSubsetOf(access.Capabilities.Capabilities)) continue;
            var grant = access.Reports.Reports.FirstOrDefault(r => r.ReportKey == rule.ReportKey && r.Allowed);
            if (grant is null) continue;
            var item = JsonNode.Parse(definition.GetRawText())!.AsObject();
            var owner = owners[definition.Text("key")];
            item["owner_id"] = owner["owner_id"]!.DeepClone();
            item["navigation_section"] = owner["section_id"]!.DeepClone();
            item["executable"] = Executable(access.Reports, rule, grant);
            items.Add(item);
        }
        return new { contract_id = "sli.report-catalog.v2", items, navigation = Navigation(access, rules, states, preview: preview) };
    }

    private static bool Executable(AccessDecision access, ReportRule rule, ReportDecision report)
    {
        if (rule.DeclarationOnly) return false;
        if (rule.RequiredRole is not null && rule.RequiredRole != access.CoarseRole) return false;
        if (rule.GlobalScopeOnly && rule.RequiredCapabilities.Any(c => !access.Capabilities.Decide(c).Allowed)) return false;
        if (!report.Grants.Any(g => g.AllowedActions.Contains("view"))) return false;
        if (rule.Scope == "delegated")
            return rule.AcceptsGenericScope || !report.Grants.Any(g => g.Scope.ValueKind == JsonValueKind.Object && g.Scope.TryGetProperty("mode", out _));
        if (rule.Scope == "domain")
        {
            try
            {
                var domains = new ReportScopeResolver().PermittedDomains(access, [rule]);
                return domains.Kind == DomainGrantKind.All || domains.DomainIds.Count > 0;
            }
            catch (DomainScopeCompositionException) { return false; }
        }
        var scopes = report.Grants.Where(g => g.AllowedActions.Contains("view") && rule.RequiredFields.IsSubsetOf(g.FieldCategories))
            .Select(g => ReportScopeResolver.ParseScope(g.Scope)).Where(s => !s.Invalid).ToArray();
        return scopes.Any(s => s.All) || !rule.GlobalScopeOnly && scopes.Any(s => s.Clauses.Count > 0);
    }

    internal static JsonObject Navigation(AccessReadEvaluation access, IReadOnlyList<ReportRule> rules, IReadOnlyList<JsonElement> states, JsonObject? configuration = null, bool preview = false)
    {
        var registry = configuration is null ? NavigationRegistry.Configuration() : (JsonObject)configuration.DeepClone();
        var previewEntries = registry["preview_entries"]!.AsArray().Select(entry => entry!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        registry["modules_preview"] = preview;
        var enabled = registry["enabled_plugins"]!.AsArray().Select(p => p!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        foreach (var state in states)
            if (state.Get("enabled").ValueKind != JsonValueKind.True) enabled.Remove(state.Text("plugin_id"));
        if (!states.Any(s => s.Text("plugin_id") == "sli.remote-access")) enabled.Remove("sli.remote-access");
        // The compiled provider already fences unavailable/unsupported plugin generations.
        foreach (string owner in new[] { "sli.ad", "sli.gpo", "sli.remote-access", "sli.file-audit" })
            if (!rules.Any(r => r.OwnerId == owner)) enabled.Remove(owner);
        var reports = access.Reports.Reports.Where(r => r.Allowed).Select(r => r.ReportKey).ToHashSet(StringComparer.Ordinal);
        bool Visible(JsonNode entry) => (entry["plugin_id"] is null || enabled.Contains(entry["plugin_id"]!.GetValue<string>()))
            && (entry["always"]?.GetValue<bool>() == true
                || entry["reports"]?.AsArray().Any(r => reports.Contains(r!.GetValue<string>())) == true
                || entry["capabilities"]?.AsArray().Any(c => access.Capabilities.Capabilities.Contains(c!.GetValue<string>())) == true);
        foreach (var section in registry["sections"]!.AsArray().ToArray())
        {
            foreach (var group in section!["groups"]!.AsArray().ToArray())
            {
                foreach (var entry in group!["entries"]!.AsArray().ToArray())
                {
                    if ((!preview && previewEntries.Contains(entry!["id"]!.GetValue<string>())) || !Visible(entry!))
                    { group["entries"]!.AsArray().Remove(entry); continue; }
                    if (entry!["views"] is JsonArray views)
                        foreach (var view in views.ToArray()) if (!Visible(view!)) views.Remove(view);
                }
                if (group["entries"]!.AsArray().Count == 0) section["groups"]!.AsArray().Remove(group);
            }
            if (section["groups"]!.AsArray().Count == 0) registry["sections"]!.AsArray().Remove(section);
        }
        registry.Remove("core_reports");
        registry["enabled_plugins"] = JsonSerializer.SerializeToNode(enabled.Order(StringComparer.Ordinal));
        return registry;
    }
}
