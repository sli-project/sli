using System.Globalization;
using System.Numerics;
using System.Text.Json;
using Sli.Server.Access.Administration;

namespace Sli.Server.Access;

// Equivalent dimensions in one group describe one protected object. Generic
// source-neutral dimensions are explicit: a legacy server ID is not a device ID.
public sealed record AccessResource(string Kind, long? Id = null, string? Value = null)
{
    public string? PluginId { get; init; }
    public string? SourceInstanceId { get; init; }
    public string? DeviceId { get; init; }
    public long? EntityId { get; init; }
    public string? CollectionScopeId { get; init; }
    public long? DomainId { get; init; }
}

public static class ResourceAccessDecisions
{
    public static CapabilityResult Capability(CapabilityDecisionSet access, string key,
        IReadOnlyList<IReadOnlyList<AccessResource>>? resourceGroups)
    {
        if (access.IsOwner) return new(true, "platform_owner");
        var policies = access.Policies.Where(p => p.CapabilityKey == key).ToArray();
        if (policies.Any(p => p.Effect == "deny" && !p.Valid)) return new(false, "invalid_scope_policy");
        var denies = policies.Where(p => p.Valid && p.Effect == "deny").ToArray();
        if (denies.Any(p => p.Global)) return new(false, "explicit_deny");
        var groups = resourceGroups ?? [];
        if (groups.Any(g => g.Count == 0)) return new(false, "resource_context_required");
        if (denies.Any(p => groups.Any(g => g.Any(r => Matches(p.Scope, r, trimChannels: true)))))
            return new(false, "explicit_deny");
        if (access.Capabilities.Contains(key)) return new(true, "global_allow");
        if (groups.Count == 0) return new(false, "resource_context_required");
        var allows = policies.Where(p => p.Valid && p.Effect == "allow").ToArray();
        return groups.All(g => allows.Any(p => p.Global || g.Any(r => Matches(p.Scope, r, trimChannels: true))))
            ? new(true, "scoped_allow") : new(false, "insufficient_capability");
    }

    public static CapabilityResult ReportAction(AccessDecision access, string reportKey, string action,
        IReadOnlyList<IReadOnlyList<AccessResource>>? resourceGroups, IReadOnlySet<string>? requiredFields = null)
    {
        var report = access.Reports.FirstOrDefault(r => r.ReportKey == reportKey);
        if (report is null || !report.Allowed) return new(false, "report_not_assigned");
        var fields = requiredFields ?? new HashSet<string>();
        var grants = report.Grants.Where(g => g.AllowedActions.Contains(action) && fields.IsSubsetOf(g.FieldCategories)).ToArray();
        if (grants.Length == 0) return new(false, fields.Count > 0 ? "report_field_categories_not_allowed" : "report_action_not_allowed");
        var groups = resourceGroups ?? [];
        if (groups.Count == 0) return grants.Any(g => Global(g.Scope))
            ? new(true, "global_report_scope") : new(false, "resource_context_required");
        if (groups.Any(g => g.Count == 0)) return new(false, "resource_context_required");
        return groups.All(g => grants.Any(grant => Global(grant.Scope) || g.Any(r => Matches(grant.Scope, r))))
            ? new(true, "report_scope_match") : new(false, "report_scope_denied");
    }

    private static bool Global(JsonElement scope) => scope.ValueKind == JsonValueKind.Object &&
        (scope.Text("kind") == "all" && scope.EnumerateObject().Count() == 1
         || scope.TryGetProperty("mode", out _) && ReportScopeResolver.ParseScope(scope) is { All: true, Invalid: false });

    private static bool Matches(JsonElement scope, AccessResource resource, bool trimChannels = false)
    {
        if (scope.ValueKind != JsonValueKind.Object) return false;
        if (scope.TryGetProperty("mode", out _))
        {
            var generic = ReportScopeResolver.ParseScope(scope);
            if (generic.Invalid) return false;
            if (generic.All) return true;
            var domain = resource.DomainId ?? (resource.Kind == "domain" ? resource.Id : null);
            string? collection = string.IsNullOrEmpty(resource.CollectionScopeId)
                ? domain.HasValue ? "ad-domain:" + domain.Value.ToString(CultureInfo.InvariantCulture) : null
                : resource.CollectionScopeId;
            return generic.Clauses.Any(c => Contains(c, "plugin_ids", resource.PluginId)
                && Contains(c, "source_instance_ids", resource.SourceInstanceId)
                && Contains(c, "device_ids", resource.DeviceId)
                && Contains(c, "collection_scope_ids", collection)
                && (!c.Get("entity_ids").Items().Any() || resource.EntityId.HasValue && c.Get("entity_ids").Items().Any(i => PositiveInteger(i, out var id) && id == resource.EntityId.Value)));
        }
        string kind = scope.Text("kind");
        if (kind == "all") return true;
        if (kind != resource.Kind) return false;
        if (kind is "domain" or "server")
        {
            // Legacy report matching calls Python int() on the entire ID set.
            // Invalid members invalidate the match, even after an earlier hit.
            try
            {
                var ids = scope.Get("ids").Items().Select(AssignmentValidation.Integer).ToArray();
                return resource.Id.HasValue && ids.Contains(new BigInteger(resource.Id.Value));
            }
            catch (Exception error) when (error is AssignmentValidationException or InvalidOperationException or OverflowException or FormatException)
            { return false; }
        }
        return kind == "channel" && scope.Get("values").Items().Any(i =>
            (trimChannels ? AssignmentValidation.Strip(AssignmentValidation.String(i)) : AssignmentValidation.String(i)) == (resource.Value ?? ""));
    }

    private static bool Contains(JsonElement clause, string key, string? value) =>
        !clause.Get(key).Items().Any() || clause.Get(key).Items().Any(i => i.GetString() == value);

    internal static bool PositiveInteger(JsonElement value, out BigInteger id)
    {
        id = default;
        return value.ValueKind == JsonValueKind.Number && BigInteger.TryParse(value.GetRawText(), NumberStyles.AllowLeadingSign,
            CultureInfo.InvariantCulture, out id) && id > 0;
    }
}
