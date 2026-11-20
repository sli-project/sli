using System.Text.Json;
using Sli.Server.Access.Administration;

namespace Sli.Server.Access;

public sealed record CapabilityPolicy(string CapabilityKey, string Effect, bool Valid, bool Global, JsonElement Scope = default);
public sealed record CapabilityResult(bool Allowed, string Reason);
public sealed record CapabilityDecisionSet(bool IsOwner, IReadOnlySet<string> Capabilities,
    IReadOnlySet<string> ResourceCapabilities, IReadOnlyList<CapabilityPolicy> Policies,
    IReadOnlyDictionary<string, JsonElement> AllowedPackages)
{
    public CapabilityResult DecideForResourceGroups(string key, IReadOnlyList<IReadOnlyList<AccessResource>>? groups) =>
        ResourceAccessDecisions.Capability(this, key, groups);

    public CapabilityResult Decide(string key)
    {
        if (IsOwner) return new(true, "platform_owner");
        var policies = Policies.Where(p => p.CapabilityKey == key).ToArray();
        if (policies.Any(p => p.Effect == "deny" && !p.Valid)) return new(false, "invalid_scope_policy");
        if (policies.Any(p => p.Effect == "deny" && p.Valid && p.Global)) return new(false, "explicit_deny");
        if (policies.Any(p => p.Effect == "deny" && p.Valid && !p.Global)) return new(false, "resource_context_required");
        if (Capabilities.Contains(key)) return new(true, "global_allow");
        if (policies.Any(p => p.Effect == "allow" && p.Valid && !p.Global)) return new(false, "resource_context_required");
        return new(false, "insufficient_capability");
    }
}

public interface ICapabilityComposer { CapabilityDecisionSet Compose(AccessFacts facts); }

public sealed class CapabilityComposer : ICapabilityComposer
{
    private static readonly HashSet<string> ViewerSafe = ["workspace.view", "reports.catalog", "objects.view",
        "objects.groups", "events.view", "investigations.view", "field.identity_basic", "field.security", "field.computer_logon_observation"];

    public CapabilityDecisionSet Compose(AccessFacts facts)
    {
        var deniedPackages = facts.Packages.Where(p => p.Text("effect") == "deny").Select(p => p.Text("package_key")).ToHashSet();
        var packages = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var package in facts.Packages)
            if (package.Text("effect") == "allow" && (facts.IsOwner || !deniedPackages.Contains(package.Text("package_key"))))
                packages[package.Text("package_key")] = package;
        var capabilities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var capability in facts.PackageCapabilities)
            if (packages.TryGetValue(capability.Text("package_key"), out var package)
                && (facts.Role != "viewer" || ViewerSafe.Contains(capability.Text("capability_key")) || package.Text("source_kind", "role") != "role"))
                capabilities.Add(capability.Text("capability_key"));
        var policies = facts.DirectCapabilities.Select(row => NormalizePolicy(row)).ToArray();
        var denies = policies.Where(p => p.Effect == "deny" && (!p.Valid || p.Global)).Select(p => p.CapabilityKey).ToHashSet();
        foreach (var policy in policies)
            if (policy.Effect == "allow" && policy.Valid && policy.Global && !denies.Contains(policy.CapabilityKey))
                capabilities.Add(policy.CapabilityKey);
        capabilities.ExceptWith(denies);
        if (facts.IsOwner) capabilities = facts.AllCapabilities.Select(row => row.Text("capability_key")).ToHashSet(StringComparer.Ordinal);
        var resources = policies.Where(p => p.Effect == "allow" && p.Valid && !p.Global && !denies.Contains(p.CapabilityKey))
            .Select(p => p.CapabilityKey).ToHashSet(StringComparer.Ordinal);
        return new(facts.IsOwner, capabilities, resources, policies, packages);
    }

    private static CapabilityPolicy NormalizePolicy(JsonElement row)
    {
        var raw = row.Get("scope_json");
        JsonElement scope;
        try { scope = raw.Object(); }
        catch (JsonException) { return new(row.Text("capability_key"), row.Text("effect"), false, false); }
        var absent = raw.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined || raw.ValueKind == JsonValueKind.String && raw.GetString() == "";
        var global = absent || scope.ValueKind == JsonValueKind.Object && (!scope.EnumerateObject().Any()
            || scope.Text("kind") == "all" && scope.EnumerateObject().Count() == 1);
        var valid = global;
        var kind = scope.Text("kind");
        if (scope.ValueKind == JsonValueKind.Object && scope.EnumerateObject().Count() == 2)
        {
            if (kind is "domain" or "server")
            {
                var ids = scope.Get("ids");
                valid = ids.ValueKind == JsonValueKind.Array && ids.GetArrayLength() > 0
                    && ids.Items().All(i => ResourceAccessDecisions.PositiveInteger(i, out _))
                    && ids.Items().Select(i => i.GetRawText()).Distinct().Count() == ids.GetArrayLength();
            }
            else if (kind == "channel")
            {
                var values = scope.Get("values");
                valid = values.ValueKind == JsonValueKind.Array && values.GetArrayLength() > 0
                    && values.Items().All(i => i.ValueKind == JsonValueKind.String && AssignmentValidation.Strip(i.GetString()!).Length > 0)
                    && values.Items().Select(i => AssignmentValidation.Strip(i.GetString()!)).Distinct().Count() == values.GetArrayLength();
            }
        }
        return new(row.Text("capability_key"), row.Text("effect"), valid, global, scope.ValueKind == JsonValueKind.Undefined ? default : scope.Clone());
    }
}

