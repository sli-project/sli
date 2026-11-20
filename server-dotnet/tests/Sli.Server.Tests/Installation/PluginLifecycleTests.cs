using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class PluginLifecycleTests
{
    static readonly string[] Caps = ["plugins.manage"];
    static string Text(JsonNode? n) => n!.GetValue<string>();
    static bool Flag(JsonObject plan, string key) => plan[key]!.GetValue<bool>();
    static string[] Blockers(JsonObject plan) => plan["blockers"]!.AsArray().Select(Text).ToArray();
    static PluginLifecycleState Registered() => PluginLifecycle.InitialRemoteAccessState() with { PackageLifecycle = "registered" };
    static void Effects(JsonObject plan, string json) => Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), plan["effects"]), plan.ToJsonString());

    [Fact]
    public void ContractAllowsOnlyBundledManifestRegistration()
    {
        var contract = PluginLifecycle.LoadContract();
        Assert.Equal("register_bundled_release_manifest_only", Text(contract["install_semantics"]));
        Assert.True(Flag(contract, "capability_registered"));
        Assert.True(Flag(contract, "mutation_execution_enabled"));
        Assert.Equal(["install"], contract["executable_actions"]!.AsArray().Select(Text));
        foreach (string key in new[] { "process_control_allowed", "database_mutation_allowed", "source_contact_allowed",
                     "autostart_enabled", "destructive_purge_allowed", "runtime_enabled", "production_read_path_cutover" })
            Assert.False(Flag(contract, key));
    }

    [Fact]
    public void InstallOnlyRegistersTheBundledManifestAndAuditsThePlan()
    {
        var state = PluginLifecycle.InitialRemoteAccessState();
        var plan = PluginLifecycle.Plan("install", state, Caps);
        Assert.True(Flag(plan, "preconditions_met"));
        Assert.True(Flag(plan, "execution_allowed"));
        Effects(plan, """{"package_lifecycle":"registered"}""");
        Assert.Equal("0.1.0", Text(plan["target_version"]));
        Assert.Contains("dynamic_external_package_execution", plan["forbidden_effects"]!.AsArray().Select(Text));
        Assert.Equal("plugin.install", Text(plan["audit_event"]!["action_key"]));
        Assert.Equal("plugin_lifecycle", Text(plan["audit_event"]!["category"]));
        Assert.Equal("plugin", Text(plan["audit_event"]!["target_kind"]));
        Assert.Equal(state.PluginId, Text(plan["audit_event"]!["target_key"]));
        Assert.Equal(Text(plan["plan_sha256"]), Text(plan["audit_event"]!["details"]!["plan_sha256"]));
        Assert.Equal(1, plan["state_before"]!["immutable_evidence_count"]!.GetValue<int>());
        Assert.Equal("validated", state.PackageLifecycle);
        Assert.Equal("plugin_lifecycle_executor_requires_operation_context",
            Assert.Throws<InstallationException>(() => PluginLifecycle.Execute(plan, Text(plan["confirmation"]))).Message);
    }

    [Fact]
    public void EnableRequiresEveryIndependentBoundaryAndRemainsNonExecutable()
    {
        var state = Registered();
        var blocked = PluginLifecycle.Plan("enable", state, Caps);
        Assert.Contains("enable_live_boundaries_not_accepted", Blockers(blocked));
        Assert.False(Flag(blocked, "preconditions_met"));
        var boundaries = PluginLifecycle.LoadContract()["required_live_boundaries"]!.AsArray().Select(Text).ToArray();
        foreach (string missing in boundaries)
        {
            var partial = state with { AcceptedLiveBoundaries = boundaries.Where(b => b != missing).ToArray() };
            Assert.Contains("enable_live_boundaries_not_accepted", Blockers(PluginLifecycle.Plan("enable", partial, Caps)));
        }
        var plan = PluginLifecycle.Plan("enable", state with { AcceptedLiveBoundaries = boundaries }, Caps);
        Assert.True(Flag(plan, "preconditions_met"));
        Effects(plan, """{"desired_activation":"enabled_manual"}""");
        Assert.False(Flag(plan, "execution_allowed"));
        Assert.Contains("plugin_lifecycle_action_not_executable", Blockers(plan));
    }

    [Fact]
    public void DisablePreservesPackageAndImmutableEvidence()
    {
        var state = Registered() with { DesiredActivation = "enabled_manual" };
        var plan = PluginLifecycle.Plan("disable", state, Caps);
        Assert.True(Flag(plan, "preconditions_met"));
        Effects(plan, """{"desired_activation":"disabled","observed_health":"unknown"}""");
        Assert.True(Flag(plan, "preserve_immutable_evidence"));
        Assert.False(Flag(plan, "destructive_purge"));
        Assert.False(plan["effects"]!.AsObject().ContainsKey("package_lifecycle"));
        Assert.Equal("registered", state.PackageLifecycle);
        Assert.Equal(1, state.ImmutableEvidenceCount);
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, true, true)]
    public void DetachRequiresReaderAndParityAndPreservesResults(bool reader, bool parity, bool ready)
    {
        var state = Registered() with { DetachReaderReady = reader, ReadReportParity = parity };
        var plan = PluginLifecycle.Plan("detach", state, Caps);
        Assert.Equal(ready, Flag(plan, "preconditions_met"));
        Assert.Equal(!ready, Blockers(plan).Contains("detach_reader_and_parity_required"));
        Effects(plan, """{"package_lifecycle":"detached","desired_activation":"disabled","component_runtime":"stopped","queue_state":"drained"}""");
        Assert.False(Flag(plan, "production_read_path_cutover"));
        Assert.True(Flag(plan, "preserve_immutable_evidence"));
        Assert.False(Flag(plan, "destructive_purge"));
        Assert.False(Flag(plan, "execution_allowed"));
    }

    [Fact]
    public void ConfirmationBindsRevisionActionAndEffects()
    {
        var state = PluginLifecycle.InitialRemoteAccessState();
        var install = PluginLifecycle.Plan("install", state, Caps);
        var later = PluginLifecycle.Plan("install", state with { Revision = 2 }, Caps);
        var disable = PluginLifecycle.Plan("disable", Registered(), Caps);
        var upgrade = PluginLifecycle.Plan("upgrade", Registered(), Caps, "0.2.0");
        var changed = PluginLifecycle.Plan("upgrade", Registered(), Caps, "0.3.0");
        foreach (var pair in new[] { (install, later), (install, disable), (upgrade, changed) })
        {
            Assert.NotEqual(Text(pair.Item1["confirmation"]), Text(pair.Item2["confirmation"]));
            Assert.NotEqual(Text(pair.Item1["plan_sha256"]), Text(pair.Item2["plan_sha256"]));
        }
        Assert.True(JsonNode.DeepEquals(install, PluginLifecycle.Plan(" INSTALL ", state, Caps)));
        // Fixed values computed by the Python reference, including its canonical envelope serialization.
        Assert.Equal("9a5b96b88db59fd71632291b79f3507c5637906f8f94704b7c4e5f97bf342f1f", Text(install["plan_sha256"]));
        Assert.Equal("PLUGIN-INSTALL-SLI-REMOTE-ACCESS-R1-9A5B96B88DB5", Text(install["confirmation"]));
        Assert.Equal("7a3ad2b975d021dfcca434da674cc06531ecff9abcfee0b0e2e70b445741ea17", Text(later["plan_sha256"]));
        Assert.Equal("e8fa3ec66120d9d7cc6e0cdc0e8ceb7679a0bbc544f9b4e9669f756e3c54f9fc", Text(upgrade["plan_sha256"]));
    }

    [Fact]
    public void MissingCapabilityIsVisibleAndExecutionFailsClosed()
    {
        var plan = PluginLifecycle.Plan("install", PluginLifecycle.InitialRemoteAccessState(), []);
        Assert.Contains("plugins_manage_required", Blockers(plan));
        Assert.False(Flag(plan, "preconditions_met"));
        Assert.False(Flag(plan, "execution_allowed"));
        Assert.Equal("plugin_lifecycle_confirmation_invalid",
            Assert.Throws<InstallationException>(() => PluginLifecycle.Execute(plan, "wrong")).Message);
        Assert.Equal("plugin_lifecycle_execution_disabled",
            Assert.Throws<InstallationException>(() => PluginLifecycle.Execute(plan, Text(plan["confirmation"]))).Message);
    }

    [Theory]
    [InlineData("upgrade", "0.2.0", """{"package_version":"0.2.0","rollback_version":"0.1.0"}""")]
    [InlineData("rollback", null, """{"package_version":"0.0.9","rollback_version":null}""")]
    [InlineData("drain", null, """{"component_runtime":"draining","desired_activation":"disabled"}""")]
    public void OtherContractActionsPlanEffectsWithoutExecuting(string action, string? target, string effects)
    {
        var state = Registered() with { RollbackVersion = "0.0.9", ComponentRuntime = action == "drain" ? "running" : "stopped" };
        var plan = PluginLifecycle.Plan(action, state, Caps, target);
        Assert.True(Flag(plan, "preconditions_met"));
        Assert.False(Flag(plan, "execution_allowed"));
        Effects(plan, effects);
        Assert.Equal("plugin_lifecycle_execution_disabled",
            Assert.Throws<InstallationException>(() => PluginLifecycle.Execute(plan, Text(plan["confirmation"]))).Message);
    }

    [Fact]
    public void InvalidIdentityAxesBoundariesAndActionsAreRejected()
    {
        var state = PluginLifecycle.InitialRemoteAccessState();
        foreach (var invalid in new[] { state with { Revision = 0 }, state with { PluginId = "sli.other" },
                     state with { PackageVersion = "01.0.0" }, state with { RollbackVersion = "1.0" },
                     state with { ImmutableEvidenceCount = 0 } })
            Assert.Equal("plugin_lifecycle_state_identity_invalid",
                Assert.Throws<InstallationException>(() => PluginLifecycle.Plan("install", invalid, Caps)).Message);
        Assert.Equal("plugin_lifecycle_state_invalid:component_runtime",
            Assert.Throws<InstallationException>(() => PluginLifecycle.Plan("install", state with { ComponentRuntime = "invalid" }, Caps)).Message);
        Assert.Equal("plugin_lifecycle_unknown_boundary",
            Assert.Throws<InstallationException>(() => PluginLifecycle.Plan("install", state with { AcceptedLiveBoundaries = ["unknown"] }, Caps)).Message);
        Assert.Equal("plugin_lifecycle_action_invalid",
            Assert.Throws<InstallationException>(() => PluginLifecycle.Plan("purge", state, Caps)).Message);
    }
}
