using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Sources;

internal sealed class PluginCredentialError(string code) : ArgumentException(code);

internal sealed record CredentialHandleBinding(string HandleId, string PluginId, string ComponentId,
    string SourceInstanceId, int CredentialGeneration, string Scope, IReadOnlyList<string> EnvironmentNames,
    string HandlerSha256)
{
    public string StableSourceIdentity() => Convert.ToHexStringLower(SHA256.HashData(
        Encoding.UTF8.GetBytes(string.Join('\x1f', PluginId, ComponentId, SourceInstanceId))));
}

internal sealed record CredentialLeaseRequest(string HandleId, string PluginId, string ComponentId,
    string SourceInstanceId, int CredentialGeneration, string Scope, IReadOnlyList<string> EnvironmentNames,
    string HandlerSha256, string WorkerInstanceId, string RuntimeInstanceId, int TtlSeconds);

// Contains only binding metadata. Material stays private to the fixture broker.
internal sealed class CredentialLease
{
    private readonly CredentialHandleBinding binding;
    private readonly string workerInstanceId;
    private readonly string runtimeInstanceId;
    public string LeaseId { get; }
    public long IssuedAtEpochSeconds { get; }
    public long ExpiresAtEpochSeconds { get; }
    internal string HandleId => binding.HandleId;

    internal CredentialLease(string leaseId, CredentialHandleBinding binding, CredentialLeaseRequest request, long now)
    {
        LeaseId = leaseId;
        this.binding = binding;
        workerInstanceId = request.WorkerInstanceId;
        runtimeInstanceId = request.RuntimeInstanceId;
        IssuedAtEpochSeconds = now;
        ExpiresAtEpochSeconds = now + request.TtlSeconds;
    }

    public JsonObject AuditMetadata(string outcome) => new() {
        ["lease_id"] = LeaseId, ["handle_id"] = binding.HandleId,
        ["plugin_id"] = binding.PluginId, ["component_id"] = binding.ComponentId,
        ["source_instance_id"] = binding.SourceInstanceId, ["credential_generation"] = binding.CredentialGeneration,
        ["scope"] = binding.Scope, ["worker_instance_id"] = workerInstanceId,
        ["runtime_instance_id"] = runtimeInstanceId,
        ["environment_names"] = new JsonArray(binding.EnvironmentNames.Select(x => (JsonNode)JsonValue.Create(x)!).ToArray()),
        ["issued_at_epoch_seconds"] = IssuedAtEpochSeconds, ["expires_at_epoch_seconds"] = ExpiresAtEpochSeconds,
        ["outcome"] = outcome
    };

    public override string ToString() => AuditMetadata("issued").ToJsonString();
}

// Parity with the Python fixture-only contract. Never register as a live secret backend:
// no filesystem, process, database, environment or network access belongs here.
internal sealed class InMemoryFixtureCredentialBroker
{
    private readonly Dictionary<string, CredentialHandleBinding> bindings = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Dictionary<string, string>> materials = new(StringComparer.Ordinal);
    private readonly Dictionary<(string, string, string), int> activeGenerations = new();
    private readonly HashSet<string> revokedHandles = new(StringComparer.Ordinal);
    private readonly HashSet<string> revokedLeases = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CredentialLease> issuedLeases = new(StringComparer.Ordinal);
    private readonly int maxTtlSeconds;
    private long leaseSequence;

    private static bool Matches(string? value, string pattern) => value is not null
        && Regex.IsMatch(value, "\\A" + pattern + "\\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static bool Identifier(string value) => Matches(value, "[a-z0-9][a-z0-9._-]{0,127}");
    private static (string, string, string) Key(CredentialHandleBinding binding) =>
        (binding.PluginId, binding.ComponentId, binding.SourceInstanceId);

    public InMemoryFixtureCredentialBroker(IEnumerable<CredentialHandleBinding> bindings,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> fixtureMaterials,
        IReadOnlyDictionary<string, string[]> allowedScopes, IReadOnlySet<string> prohibitedEnvironmentNames,
        int maxEnvironmentNames = 8, int maxTtlSeconds = 900)
    {
        if (maxEnvironmentNames < 1 || maxTtlSeconds < 1) throw new PluginCredentialError("invalid_broker_limits");
        this.maxTtlSeconds = maxTtlSeconds;
        foreach (var input in bindings) {
            var binding = input with { EnvironmentNames = Array.AsReadOnly(input.EnvironmentNames.ToArray()) };
            ValidateBinding(binding, allowedScopes, prohibitedEnvironmentNames, maxEnvironmentNames);
            if (this.bindings.ContainsKey(binding.HandleId)) throw new PluginCredentialError("duplicate_handle_id");
            var material = fixtureMaterials.TryGetValue(binding.HandleId, out var values)
                ? new Dictionary<string, string>(values, StringComparer.Ordinal) : new Dictionary<string, string>(StringComparer.Ordinal);
            if (!material.Keys.Order(StringComparer.Ordinal).SequenceEqual(binding.EnvironmentNames.Order(StringComparer.Ordinal)))
                throw new PluginCredentialError("fixture_material_shape_mismatch");
            if (material.Values.Any(string.IsNullOrEmpty)) throw new PluginCredentialError("empty_fixture_material");
            this.bindings.Add(binding.HandleId, binding);
            materials.Add(binding.HandleId, material);
            var key = Key(binding);
            activeGenerations[key] = activeGenerations.TryGetValue(key, out int current)
                ? Math.Min(current, binding.CredentialGeneration) : binding.CredentialGeneration;
        }
    }

    private static void ValidateBinding(CredentialHandleBinding binding, IReadOnlyDictionary<string, string[]> allowedScopes,
        IReadOnlySet<string> prohibited, int maxNames)
    {
        if (!Matches(binding.HandleId, "credh:v1:[0-9a-f]{64}")) throw new PluginCredentialError("invalid_handle_id");
        if (!Identifier(binding.PluginId)) throw new PluginCredentialError("invalid_plugin_id");
        if (!Identifier(binding.ComponentId)) throw new PluginCredentialError("invalid_component_id");
        if (!Identifier(binding.SourceInstanceId)) throw new PluginCredentialError("invalid_source_instance_id");
        if (binding.CredentialGeneration < 1) throw new PluginCredentialError("invalid_credential_generation");
        if (!Matches(binding.HandlerSha256, "[0-9a-f]{64}")) throw new PluginCredentialError("invalid_handler_sha256");
        if (!allowedScopes.TryGetValue(binding.Scope, out var allowed)) throw new PluginCredentialError("scope_not_allowed");
        if (binding.EnvironmentNames.Count == 0 || binding.EnvironmentNames.Count > maxNames)
            throw new PluginCredentialError("environment_name_count_out_of_bounds");
        if (binding.EnvironmentNames.Distinct(StringComparer.Ordinal).Count() != binding.EnvironmentNames.Count)
            throw new PluginCredentialError("duplicate_environment_name");
        foreach (string name in binding.EnvironmentNames) {
            if (!Matches(name, "[A-Z][A-Z0-9_]{0,127}")) throw new PluginCredentialError("invalid_environment_name");
            if (prohibited.Contains(name)) throw new PluginCredentialError("prohibited_environment_name");
            if (!allowed.Contains(name, StringComparer.Ordinal)) throw new PluginCredentialError("environment_name_not_allowed_for_scope");
        }
    }

    public void RotateToGeneration(string pluginId, string componentId, string sourceInstanceId, int credentialGeneration)
    {
        var key = (pluginId, componentId, sourceInstanceId);
        if (!activeGenerations.TryGetValue(key, out int current)) throw new PluginCredentialError("unknown_source_binding");
        if ((long)credentialGeneration != (long)current + 1) throw new PluginCredentialError("generation_must_advance_by_one");
        if (!bindings.Values.Any(b => Key(b) == key && b.CredentialGeneration == credentialGeneration))
            throw new PluginCredentialError("target_generation_not_registered");
        activeGenerations[key] = credentialGeneration;
    }

    public void RevokeHandle(string handleId)
    {
        if (!bindings.ContainsKey(handleId)) throw new PluginCredentialError("unknown_handle");
        revokedHandles.Add(handleId);
    }

    public void RevokeLease(string leaseId) => revokedLeases.Add(leaseId);

    public CredentialLease IssueLease(CredentialLeaseRequest request, long nowEpochSeconds)
    {
        if (!bindings.TryGetValue(request.HandleId, out var binding)) throw new PluginCredentialError("unknown_handle");
        if (revokedHandles.Contains(request.HandleId)) throw new PluginCredentialError("handle_revoked");
        if (request.TtlSeconds < 1 || request.TtlSeconds > maxTtlSeconds) throw new PluginCredentialError("lease_ttl_out_of_bounds");
        if (request.PluginId != binding.PluginId || request.ComponentId != binding.ComponentId
            || request.SourceInstanceId != binding.SourceInstanceId || request.CredentialGeneration != binding.CredentialGeneration
            || request.Scope != binding.Scope || !request.EnvironmentNames.SequenceEqual(binding.EnvironmentNames)
            || request.HandlerSha256 != binding.HandlerSha256) throw new PluginCredentialError("credential_binding_mismatch");
        if (!Identifier(request.WorkerInstanceId)) throw new PluginCredentialError("invalid_worker_instance_id");
        if (!Identifier(request.RuntimeInstanceId)) throw new PluginCredentialError("invalid_runtime_instance_id");
        if (request.CredentialGeneration != activeGenerations[Key(binding)]) throw new PluginCredentialError("credential_generation_not_active");
        var lease = new CredentialLease($"credlease:v1:{++leaseSequence:x16}", binding, request, nowEpochSeconds);
        issuedLeases.Add(lease.LeaseId, lease);
        return lease;
    }

    public Dictionary<string, string> MaterializeChildEnvironment(CredentialLease lease, long nowEpochSeconds)
    {
        if (!issuedLeases.TryGetValue(lease.LeaseId, out var issued) || !ReferenceEquals(lease, issued))
            throw new PluginCredentialError("lease_not_issued_by_broker");
        if (revokedLeases.Contains(lease.LeaseId)) throw new PluginCredentialError("lease_revoked");
        if (nowEpochSeconds >= lease.ExpiresAtEpochSeconds) throw new PluginCredentialError("lease_expired");
        if (!bindings.ContainsKey(lease.HandleId) || revokedHandles.Contains(lease.HandleId)) throw new PluginCredentialError("handle_revoked");
        return new Dictionary<string, string>(materials[lease.HandleId], StringComparer.Ordinal);
    }

    public override string ToString() => $"InMemoryFixtureCredentialBroker(binding_count={bindings.Count}, active_source_count={activeGenerations.Count})";
}
