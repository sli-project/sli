using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.InstallationSetup;

public sealed record PluginLifecycleState(
    string PluginId, long Revision, string PackageVersion, string? RollbackVersion,
    string PackageLifecycle, string DesiredActivation, string ObservedHealth,
    string ComponentRuntime, string QueueState, long ImmutableEvidenceCount,
    bool DetachReaderReady, bool ReadReportParity, IReadOnlyList<string> AcceptedLiveBoundaries);

// The lifecycle contract only plans effects. Execution needs a separate, authoritative operation context.
public static class PluginLifecycle
{
    static string Text(JsonNode? value) => InstallationPackages.Text(value);
    static bool True(JsonNode? value) => value is JsonValue v && v.TryGetValue<bool>(out var flag) && flag;
    static string[] Strings(JsonNode? value) => value is JsonArray array ? array.Select(Text).ToArray() : [];
    static bool Version(string? value) => value is not null && Regex.IsMatch(value, @"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant);
    static readonly JsonSerializerOptions StateJson = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    public static JsonObject LoadContract()
    {
        var contract = InstallationPackages.Contract("stage10_plugin_lifecycle_v1.json");
        var expected = JsonNode.Parse("""
            {"schema_version":1,"contract_id":"sli.plugin-lifecycle.v1",
             "status":"bundled_install_executor_ready_runtime_disabled",
             "architecture_decision_id":"sli.plugin-architecture.v2","trust":"bundled_reviewed_only",
             "supported_plugin_ids":["sli.remote-access"],"required_capability":"plugins.manage",
             "capability_registered":true,"mutation_execution_enabled":true,"executable_actions":["install"],
             "runtime_enabled":false,"autostart_enabled":false,"source_contact_allowed":false,
             "process_control_allowed":false,"database_mutation_allowed":false,
             "production_read_path_cutover":false,"destructive_purge_allowed":false,
             "actions":["install","upgrade","rollback","enable","drain","disable","detach"],
             "install_semantics":"register_bundled_release_manifest_only","confirmation_required":true,
             "audit_category":"plugin_lifecycle","audit_actor_source":"server_authoritative_principal_only"}
            """)!.AsObject();
        foreach (var field in expected)
            if (!JsonNode.DeepEquals(contract[field.Key], field.Value))
                throw new InstallationException("plugin_lifecycle_contract_invalid:" + field.Key);
        string[] axes = ["package_lifecycle", "desired_activation", "observed_health", "component_runtime", "queue_state"];
        if (contract["state_axes"] is not JsonObject states || !axes.ToHashSet().SetEquals(states.Select(p => p.Key)))
            throw new InstallationException("plugin_lifecycle_state_axes_invalid");
        if (Strings(contract["required_live_boundaries"]).Length != 9)
            throw new InstallationException("plugin_lifecycle_boundaries_invalid");
        if (Strings(contract["forbidden_effects"]).Length < 8)
            throw new InstallationException("plugin_lifecycle_forbidden_effects_missing");
        string[] limitations = ["accepted_live_worker_boundaries", "queue_drain_executor", "process_supervisor_executor",
            "versioned_upgrade_or_rollback_executor", "detach_reader_acceptance", "production_mutation_api"];
        if (!limitations.ToHashSet().SetEquals(Strings(contract["explicitly_not_proven"])))
            throw new InstallationException("plugin_lifecycle_limitations_missing");
        return contract;
    }

    public static PluginLifecycleState InitialRemoteAccessState()
    {
        var manifest = InstallationPackages.Contract("plugin_packages/sli.remote-access.json");
        if (Text(manifest["plugin_id"]) != "sli.remote-access" || Text(manifest["status"]) != "accepted_supervised_production_metadata"
            || Text(manifest["delivery"]) != "bundled_reviewed" || Text(manifest["trust"]) != "bundled_reviewed_only"
            || !Version(Text(manifest["plugin_version"])))
            throw new InstallationException("plugin_lifecycle_manifest_invalid");
        return new("sli.remote-access", 1, Text(manifest["plugin_version"]), null, "validated", "disabled", "unknown",
            "stopped", "drained", 1, false, false, []);
    }

    static void Validate(PluginLifecycleState state, JsonObject contract)
    {
        if (!Strings(contract["supported_plugin_ids"]).Contains(state.PluginId, StringComparer.Ordinal)
            || !Regex.IsMatch(state.PluginId, @"\A[a-z0-9][a-z0-9.-]{2,79}\z", RegexOptions.CultureInvariant)
            || state.Revision < 1 || !Version(state.PackageVersion) || state.RollbackVersion is not null && !Version(state.RollbackVersion)
            || state.ImmutableEvidenceCount < 1)
            throw new InstallationException("plugin_lifecycle_state_identity_invalid");
        var serialized = JsonSerializer.SerializeToNode(state, StateJson)!.AsObject();
        foreach (var axis in contract["state_axes"]!.AsObject())
            if (!Strings(axis.Value).Contains(Text(serialized[axis.Key]), StringComparer.Ordinal))
                throw new InstallationException("plugin_lifecycle_state_invalid:" + axis.Key);
        if (state.AcceptedLiveBoundaries.Except(Strings(contract["required_live_boundaries"]), StringComparer.Ordinal).Any())
            throw new InstallationException("plugin_lifecycle_unknown_boundary");
    }

    public static JsonObject Plan(string? action, PluginLifecycleState state, IEnumerable<string> actorCapabilities,
        string? targetVersion = null)
    {
        var contract = LoadContract();
        Validate(state, contract);
        string cleanAction = (action ?? "").Trim().ToLowerInvariant();
        if (!Strings(contract["actions"]).Contains(cleanAction, StringComparer.Ordinal))
            throw new InstallationException("plugin_lifecycle_action_invalid");
        var blockers = new List<string>();
        void Block(bool condition, string code) { if (condition) blockers.Add(code); }
        Block(!actorCapabilities.Contains(Text(contract["required_capability"]), StringComparer.Ordinal), "plugins_manage_required");
        var effects = new JsonObject();
        string? version = targetVersion;
        bool idle = state.PackageLifecycle == "registered" && state.DesiredActivation == "disabled"
            && state.ComponentRuntime == "stopped" && state.QueueState == "drained";
        switch (cleanAction)
        {
            case "install":
                Block(state.PackageLifecycle != "validated", "install_requires_validated_package");
                effects["package_lifecycle"] = "registered";
                version = state.PackageVersion;
                break;
            case "upgrade":
                Block(!Version(version), "upgrade_target_version_invalid");
                Block(!idle, "upgrade_requires_registered_disabled_stopped_drained");
                Block(version == state.PackageVersion, "upgrade_target_must_differ");
                effects["package_version"] = version;
                effects["rollback_version"] = state.PackageVersion;
                break;
            case "rollback":
                Block(state.RollbackVersion is null, "rollback_version_missing");
                Block(!idle, "rollback_requires_registered_disabled_stopped_drained");
                version = state.RollbackVersion;
                effects["package_version"] = version;
                effects["rollback_version"] = null;
                break;
            case "enable":
                Block(state.PackageLifecycle != "registered", "enable_requires_registered_package");
                Block(state.ComponentRuntime != "stopped", "enable_requires_stopped_runtime");
                Block(Strings(contract["required_live_boundaries"]).Except(state.AcceptedLiveBoundaries, StringComparer.Ordinal).Any(),
                    "enable_live_boundaries_not_accepted");
                effects["desired_activation"] = "enabled_manual";
                break;
            case "drain":
                Block(state.PackageLifecycle != "registered", "drain_requires_registered_package");
                Block(state.ComponentRuntime is not ("running" or "failed"), "drain_requires_running_or_failed_runtime");
                effects["component_runtime"] = "draining";
                effects["desired_activation"] = "disabled";
                break;
            case "disable":
                Block(state.PackageLifecycle != "registered", "disable_requires_registered_package");
                Block(state.ComponentRuntime != "stopped" || state.QueueState != "drained", "disable_requires_stopped_drained");
                effects["desired_activation"] = "disabled";
                effects["observed_health"] = "unknown";
                break;
            case "detach":
                Block(!idle, "detach_requires_registered_disabled_stopped_drained");
                Block(!state.DetachReaderReady || !state.ReadReportParity, "detach_reader_and_parity_required");
                effects["package_lifecycle"] = "detached";
                effects["desired_activation"] = "disabled";
                effects["component_runtime"] = "stopped";
                effects["queue_state"] = "drained";
                break;
        }
        var plan = new JsonObject {
            ["contract_id"] = contract["contract_id"]!.DeepClone(), ["plugin_id"] = state.PluginId,
            ["requested_action"] = cleanAction, ["expected_revision"] = state.Revision, ["target_version"] = version,
            ["effects"] = effects, ["preserve_immutable_evidence"] = true,
            ["production_read_path_cutover"] = false, ["destructive_purge"] = false };
        string digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(InstallationSettings.Canonical(plan))));
        plan["plan_sha256"] = digest;
        plan["confirmation"] = $"PLUGIN-{cleanAction.ToUpperInvariant()}-{state.PluginId.ToUpperInvariant().Replace('.', '-')}-R{state.Revision}-{digest[..12].ToUpperInvariant()}";
        plan["required_capability"] = contract["required_capability"]!.DeepClone();
        bool preconditionsMet = blockers.Count == 0;
        bool registered = True(contract["capability_registered"]), enabled = True(contract["mutation_execution_enabled"]);
        bool executable = Strings(contract["executable_actions"]).Contains(cleanAction, StringComparer.Ordinal);
        plan["preconditions_met"] = preconditionsMet;
        plan["execution_allowed"] = preconditionsMet && registered && enabled && executable;
        Block(!registered, "plugins_manage_capability_not_registered");
        Block(!enabled, "plugin_lifecycle_execution_disabled");
        Block(!executable, "plugin_lifecycle_action_not_executable");
        plan["blockers"] = new JsonArray(blockers.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        plan["audit_event"] = new JsonObject {
            ["category"] = contract["audit_category"]!.DeepClone(), ["action_key"] = "plugin." + cleanAction,
            ["target_kind"] = "plugin", ["target_key"] = state.PluginId,
            ["details"] = new JsonObject { ["expected_revision"] = state.Revision, ["plan_sha256"] = digest } };
        plan["forbidden_effects"] = contract["forbidden_effects"]!.DeepClone();
        plan["state_before"] = JsonSerializer.SerializeToNode(state, StateJson);
        return plan;
    }

    public static void Execute(JsonObject plan, string confirmation)
    {
        if (confirmation != Text(plan["confirmation"])) throw new InstallationException("plugin_lifecycle_confirmation_invalid");
        if (!True(plan["execution_allowed"])) throw new InstallationException("plugin_lifecycle_execution_disabled");
        throw new InstallationException("plugin_lifecycle_executor_requires_operation_context");
    }
}
