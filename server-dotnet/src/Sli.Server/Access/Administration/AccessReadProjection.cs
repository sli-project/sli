using System.Text.Json;
using Sli.Server.Auth;

namespace Sli.Server.Access.Administration;

// Presentation of the existing capability/atomic-report decisions. This does not
// resolve execution scopes or grant authority independently of the access core.
public static class AccessReadProjection
{
    private static readonly JsonElement All = JsonSerializer.SerializeToElement(new { kind = "all" });
    private static string[] Sorted(IEnumerable<string> values) => values.Distinct().Order(StringComparer.Ordinal).ToArray();
    private static object? Value(JsonElement row, string key) => row.Get(key).ValueKind == JsonValueKind.Undefined ? null : row.Get(key);
    private static bool Flag(JsonElement row, string key) => row.Get(key).ValueKind == JsonValueKind.True;
    private static string SubjectSource(JsonElement row) => row.Text("subject_type") + ":" + row.Get("subject_id").ToString();
    private static Dictionary<string, object?> Source(JsonElement row, bool package, bool grant)
    {
        var result = new Dictionary<string, object?> { ["source_type"] = package ? "package" : row.Text("source_type"), ["source"] = package ? row.Text("package_key") : SubjectSource(row) };
        if (!package)
        {
            result["valid_from"] = Value(row, "valid_from"); result["valid_until"] = Value(row, "valid_until");
            if (!grant) result["business_reason"] = row.Text("business_reason");
        }
        return result;
    }

    public static object Compose(Principal principal, AccessFacts facts, CapabilityDecisionSet capabilities, AccessDecision access, bool preview)
    {
        var packageDenies = facts.Packages.Where(r => r.Text("effect") == "deny").Select(r => r.Text("package_key")).ToHashSet();
        var reportDenies = facts.ReportAssignments.Where(r => r.Text("effect") == "deny").Select(r => r.Text("report_key")).ToHashSet();
        var globalDenies = capabilities.Policies.Where(p => p.Valid && p.Global && p.Effect == "deny").Select(p => p.CapabilityKey).ToHashSet();
        var invalidDenies = capabilities.Policies.Where(p => !p.Valid && p.Effect == "deny").Select(p => p.CapabilityKey).ToHashSet();
        var policies = facts.DirectCapabilities.Select((row, index) =>
        {
            var policy = capabilities.Policies[index];
            JsonElement? scope = null;
            if (policy.Valid)
            {
                scope = policy.Global ? All : row.Get("scope_json").Object();
                if (!policy.Global && scope.Value.Text("kind") == "channel")
                    scope = JsonSerializer.SerializeToElement(new { kind = "channel", values = scope.Value.Get("values").Items().Select(i => i.GetString()!.Trim()).ToArray() });
            }
            return new { capability_key = policy.CapabilityKey, effect = policy.Effect, scope, valid = policy.Valid,
                diagnostic = policy.Valid ? null : "invalid_scope", source_type = row.Text("source_type", row.Text("subject_type", "assignment")), source = SubjectSource(row) };
        }).ToArray();
        var explanations = new Dictionary<string, List<object>>(StringComparer.Ordinal);
        void Explain(string key, object source)
        { if (!explanations.TryGetValue(key, out var list)) explanations[key] = list = []; list.Add(source); }
        foreach (var row in facts.PackageCapabilities)
        {
            string key = row.Text("capability_key"), packageKey = row.Text("package_key");
            if (!capabilities.Capabilities.Contains(key) || !capabilities.AllowedPackages.TryGetValue(packageKey, out var package)) continue;
            // The core already filtered viewer starter capabilities. A direct
            // source of the same key must not reintroduce a restricted role source.
            var single = facts with { Packages = [package], PackageCapabilities = [row], DirectCapabilities = [], AllCapabilities = [], IsOwner = false };
            if (!new CapabilityComposer().Compose(single).Capabilities.Contains(key)) continue;
            Explain(key, new { source_type = "package", source = packageKey, source_origin = package.Text("source_kind", "role") });
        }
        for (int i = 0; i < facts.DirectCapabilities.Count; i++)
        {
            var row = facts.DirectCapabilities[i]; var policy = capabilities.Policies[i];
            if (policy.Valid && policy.Global && policy.Effect == "allow" && capabilities.Capabilities.Contains(policy.CapabilityKey))
                Explain(policy.CapabilityKey, new { source_type = row.Text("source_type"), source = SubjectSource(row),
                    source_origin = row.Text("subject_type", row.Text("source_type", "direct")), scope = All, valid_until = Value(row, "valid_until") });
        }
        if (facts.IsOwner)
        {
            explanations.Clear();
            foreach (string key in Sorted(capabilities.Capabilities))
                Explain(key, new { source_type = "platform_owner", source = "owner:primary", source_origin = "platform_owner", scope = All });
        }
        var reports = new List<Dictionary<string, object?>>();
        foreach (var row in facts.Definitions)
        {
            string key = row.Text("report_key");
            var decision = access.Reports.Single(r => r.ReportKey == key);
            bool allowed = decision.Allowed;
            bool discoverable = Flag(row, "discoverable") || allowed || facts.IsOwner;
            if (!discoverable) continue;
            var definition = row.Get("definition_json").Object();
            var available = capabilities.Capabilities.Concat(capabilities.ResourceCapabilities).ToHashSet();
            var required = definition.Get("required_capabilities").Strings();
            string[] missing = Sorted(required.Except(available));
            bool resource = !required.IsSubsetOf(capabilities.Capabilities) && missing.Length == 0;
            bool denied = reportDenies.Contains(key) && !facts.IsOwner;
            var rawSources = facts.PackageReports.Where(r => r.Text("report_key") == key && capabilities.AllowedPackages.ContainsKey(r.Text("package_key")))
                .Select(r => (Row: r, Package: true)).Concat(facts.ReportAssignments.Where(r => r.Text("report_key") == key && r.Text("effect") == "allow")
                    .Select(r => (Row: r, Package: false))).ToArray();
            if (reportDenies.Contains(key)) rawSources = [];
            var sources = rawSources.Select(r => Source(r.Row, r.Package, false)).ToList();
            bool hasSource = sources.Count > 0 || facts.IsOwner;
            if (facts.IsOwner) sources = [new() { ["source_type"] = "platform_owner", ["source"] = "owner:primary" }];
            var sourceGrants = rawSources.Where(r => r.Row.Get("allowed_actions").Strings().Contains("view")).ToArray();
            var grants = new List<Dictionary<string, object?>>();
            for (int i = 0; i < decision.Grants.Count; i++)
            {
                var atomic = decision.Grants[i];
                var grant = facts.IsOwner ? new Dictionary<string, object?> { ["source_type"] = "platform_owner", ["source"] = "owner:primary" }
                    : Source(sourceGrants[i].Row, sourceGrants[i].Package, true);
                grant["scope"] = atomic.Scope.ValueKind == JsonValueKind.Undefined ? new { } : atomic.Scope;
                grant["field_categories"] = Sorted(atomic.FieldCategories); grant["allowed_actions"] = Sorted(atomic.AllowedActions);
                grant["validated_report_version"] = atomic.ReportVersion; grant["validated_dataset_version"] = atomic.DatasetVersion;
                grants.Add(grant);
            }
            bool assigned = grants.Count > 0;
            bool requestable = Flag(row, "requestable") && missing.Length == 0 && !denied;
            var request = facts.Requests.FirstOrDefault(r => r.Text("report_key") == key);
            var preference = facts.Preferences.FirstOrDefault(r => r.Text("report_key") == key);
            var view = preference.Get("view_json").Object();
            var until = (facts.IsOwner ? [] : rawSources).Where(s => !s.Package).Select(s => s.Row.Get("valid_until")).Where(v => v.ValueKind == JsonValueKind.String)
                .OrderBy(v => DateTimeOffset.Parse(v.GetString()!, System.Globalization.CultureInfo.InvariantCulture)).ToArray();
            string code = allowed ? facts.IsOwner ? "platform_owner" : resource ? "resource_context" : "assignment_policy"
                : denied ? "explicit_deny" : missing.Length > 0 ? "missing_capabilities" : hasSource && !assigned ? "version_review" : "not_assigned";
            string explanation = code switch
            {
                "platform_owner" => "Полный доступ владельца платформы",
                "resource_context" => "Доступ назначен; строки проверяются по области ресурса",
                "assignment_policy" => "Доступ разрешён назначением и политикой возможностей",
                "explicit_deny" => "Явный запрет имеет приоритет",
                "missing_capabilities" => "Не хватает возможностей: " + string.Join(", ", missing),
                "version_review" => "Назначение требует пересмотра для текущей версии отчёта",
                _ => "Отчёт не назначен пользователю или его группам"
            };
            string state = allowed ? until.Length > 0 ? "available_until" : "available"
                : request.Text("status") is "submitted" or "reviewing" ? "request_pending"
                : request.Text("status") == "rejected" ? "request_rejected" : requestable ? "requestable" : "request_unavailable";
            reports.Add(new()
            {
                ["report_key"] = key, ["version"] = row.Get("version"), ["name"] = row.Text("name"), ["owner"] = row.Text("owner_name"),
                ["purpose"] = row.Text("purpose"), ["dataset_key"] = row.Text("dataset_key"), ["dataset_version"] = row.Get("dataset_version"),
                ["sensitivity"] = row.Text("sensitivity"), ["status"] = row.Text("status"), ["target_path"] = definition.Text("target_path") is { Length: > 0 } target ? target : "/reports",
                ["allowed"] = allowed, ["explanation"] = explanation, ["explanation_code"] = code, ["missing_capabilities"] = missing,
                ["resource_context_required"] = resource, ["discoverable"] = discoverable, ["requestable"] = requestable,
                ["access_state"] = state, ["access_valid_until"] = until.Length > 0 ? until[0] : null,
                ["request"] = request.ValueKind == JsonValueKind.Undefined ? null : request,
                ["request_profile"] = requestable ? ObjectOrEmpty(row.Get("request_profile_json")) : new { },
                ["assignment_version_state"] = facts.IsOwner ? "owner" : assigned ? "compatible" : hasSource ? "requires_review" : "not_assigned",
                ["field_categories"] = allowed ? Sorted(decision.Grants.SelectMany(g => g.FieldCategories)) : [],
                ["allowed_actions"] = allowed ? Sorted(decision.Grants.SelectMany(g => g.AllowedActions)) : [],
                ["scopes"] = allowed ? decision.Grants.Select(g => ObjectOrEmpty(g.Scope)).ToArray() : [],
                ["sources"] = allowed ? sources : [], ["grants"] = allowed ? grants : [],
                ["pinned"] = Flag(preference, "pinned"), ["preference_updated_at"] = Value(preference, "updated_at"),
                ["dashboard_metrics"] = allowed ? definition.Get("dashboard_metrics").Items().Where(i => i.ValueKind == JsonValueKind.Object).ToArray() : [],
                ["selected_optional_metric_keys"] = view.Get("focus_metric_keys").Items().Where(i => i.ValueKind == JsonValueKind.String && i.GetString() != "").Select(i => i.GetString()).ToArray(),
                ["focus_preference_configured"] = view.Get("focus_metric_keys").ValueKind != JsonValueKind.Undefined
            });
        }
        var navigation = new[]
        {
            ("workspace", "Моё рабочее пространство", "/", "workspace.view"), ("reports", "Каталог отчётов", "/reports", "reports.catalog"),
            ("objects", "Объекты и сущности", "/objects", "objects.view"), ("events", "События", "/events", "events.view"),
            ("investigations", "Расследования", "/investigations", "investigations.view"), ("scenarios", "Сценарии · SHADOW", "/scenarios", "semantic.review"),
            ("operations", "Эксплуатация", "/operations", "operations.view"), ("access", "Доступы пользователей", "/access", "access.manage"),
            ("report-builder", "Конструктор отчёта", "/report-builder", "reports.design")
        }.Where(n => capabilities.Capabilities.Contains(n.Item4) || n.Item1 == "investigations" && reports.Any(r => r["allowed"] is true && r["report_key"] is "investigations.workspace" or "cases.workspace"))
            .Select(n => new { id = n.Item1, label = n.Item2, path = n.Item3 }).ToArray();
        object Denies(bool owner) => new { packages = owner ? Sorted(packageDenies) : [], capabilities = owner ? Sorted(globalDenies.Concat(invalidDenies)) : [], reports = owner ? Sorted(reportDenies) : [] };
        return new
        {
            api_version = "v4", evaluated_at_utc = facts.EvaluatedAt, preview, platform_owner = facts.IsOwner,
            owner_policy = new { key = "primary", full_product_access = facts.IsOwner, surveyed_system_write_access = false },
            subject = new { type = principal.Type, id = principal.Id, username = !string.IsNullOrEmpty(principal.Username) ? principal.Username : !string.IsNullOrEmpty(principal.Label) ? principal.Label : "local-operator", coarse_role = facts.Role },
            groups = facts.Groups.Select(g => new { id = g.Get("id"), key = g.Text("group_key"), name = g.Text("name"), source = g.Text("source"), valid_until = Value(g, "valid_until") }).ToArray(),
            packages = capabilities.AllowedPackages.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new { key = p.Key, name = p.Value.Text("name") }).ToArray(),
            package_explain = facts.Packages.Select(p => new { package_key = p.Text("package_key"), name = p.Text("name"), effect = p.Text("effect"), source_type = p.Text("source_kind"), source = p.Text("source_key"), valid_from = Value(p, "valid_from"), valid_until = Value(p, "valid_until") }).ToArray(),
            capabilities = Sorted(capabilities.Capabilities), resource_bound_capabilities = Sorted(capabilities.ResourceCapabilities), capability_explain = explanations,
            capability_policies = policies,
            quarantined_capability_assignments = policies.Where(p => !p.valid).Select(p => new { p.capability_key, p.effect, reason = "invalid_scope" }).ToArray(),
            resource_bound_capability_assignments = policies.Where(p => p.valid && p.scope is JsonElement scope && scope.Text("kind") != "all").Select(p => new { p.capability_key, p.effect, p.scope, reason = "resource_context_required" }).ToArray(),
            reports, allowed_report_count = reports.Count(r => r["allowed"] is true), navigation,
            explicit_denies = new { packages = facts.IsOwner ? [] : Sorted(packageDenies), capabilities = facts.IsOwner ? [] : Sorted(globalDenies), reports = facts.IsOwner ? [] : Sorted(reportDenies) },
            ignored_denies = Denies(facts.IsOwner)
        };
    }
    private static object ObjectOrEmpty(JsonElement value)
    { var obj = value.Object(); return obj.ValueKind == JsonValueKind.Object ? obj : new { }; }
}
