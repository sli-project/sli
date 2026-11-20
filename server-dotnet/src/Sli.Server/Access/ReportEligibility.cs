using System.Text.Json;

namespace Sli.Server.Access;

public sealed record AtomicReportGrant(JsonElement Scope, IReadOnlySet<string> FieldCategories,
    IReadOnlySet<string> AllowedActions, long ReportVersion, long DatasetVersion);
public sealed record ReportDecision(string ReportKey, bool Allowed, IReadOnlyList<AtomicReportGrant> Grants);
public sealed record AccessDecision(string CoarseRole, CapabilityDecisionSet Capabilities, IReadOnlyList<ReportDecision> Reports);
public interface IReportEligibility { AccessDecision Compose(AccessFacts facts, CapabilityDecisionSet capabilities); }

public sealed class ReportEligibility : IReportEligibility
{
    private static readonly IReadOnlyDictionary<string, string> ActionCapabilities = new Dictionary<string, string>
    {
        ["export"] = "reports.export", ["create_task"] = "tasks.create", ["start_case"] = "investigations.manage",
        ["grant_access"] = "access.manage", ["configure_channel"] = "access.manage",
        ["manage_decoy"] = "decoys.manage", ["manage_watch"] = "watch.manage"
    };

    public AccessDecision Compose(AccessFacts facts, CapabilityDecisionSet capabilities)
    {
        var available = capabilities.Capabilities.Concat(capabilities.ResourceCapabilities).ToHashSet(StringComparer.Ordinal);
        var denied = facts.ReportAssignments.Where(r => r.Text("effect") == "deny").Select(r => r.Text("report_key")).ToHashSet();
        var sources = facts.PackageReports.Where(r => capabilities.AllowedPackages.ContainsKey(r.Text("package_key")))
            .Concat(facts.ReportAssignments.Where(r => r.Text("effect") == "allow"))
            .Where(r => !denied.Contains(r.Text("report_key"))).GroupBy(r => r.Text("report_key"))
            .ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.Ordinal);
        var reports = new List<ReportDecision>();
        foreach (var definition in facts.Definitions)
        {
            var key = definition.Text("report_key");
            var json = definition.Get("definition_json").Object();
            var datasetFields = definition.Get("fields_json").Items().Select(i => i.Text("category")).Where(s => s.Length > 0).ToHashSet();
            var declaredFields = json.Get("field_categories").Strings();
            if (declaredFields.Count > 0) datasetFields.IntersectWith(declaredFields);
            var actions = definition.Get("actions_json").Strings();
            actions.IntersectWith(json.Get("actions").Strings());
            var version = definition.Get("version").GetInt64();
            var datasetVersion = definition.Get("dataset_version").GetInt64();
            var grants = new List<AtomicReportGrant>();
            if (facts.IsOwner)
            {
                if (actions.Contains("view")) grants.Add(new(JsonSerializer.SerializeToElement(new { kind = "all" }), datasetFields, actions, version, datasetVersion));
            }
            else if (sources.TryGetValue(key, out var rows))
            {
                foreach (var row in rows)
                {
                    var fields = row.Get("field_categories").Strings();
                    fields.RemoveWhere(f => !available.Contains("field." + f) || f == "raw_evidence" && !available.Contains("evidence.exact"));
                    fields.IntersectWith(datasetFields);
                    var grantActions = row.Get("allowed_actions").Strings();
                    grantActions.RemoveWhere(a => a != "view" && (!ActionCapabilities.TryGetValue(a, out var cap) || !available.Contains(cap)));
                    grantActions.IntersectWith(actions);
                    if (grantActions.Contains("view"))
                    {
                        JsonElement scope;
                        try { scope = row.Get("scope_json").Object(); }
                        catch (JsonException) { continue; }
                        if (scope.ValueKind == JsonValueKind.Object)
                            grants.Add(new(scope, fields, grantActions, version, datasetVersion));
                    }
                }
            }
            var allowed = grants.Count > 0 && json.Get("required_capabilities").Strings().IsSubsetOf(available)
                && (facts.IsOwner || !denied.Contains(key));
            reports.Add(new(key, allowed, grants));
        }
        return new(facts.Role, capabilities, reports);
    }
}
