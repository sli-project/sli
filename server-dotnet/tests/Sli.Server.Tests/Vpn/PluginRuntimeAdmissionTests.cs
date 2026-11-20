using System.Text.Json.Nodes;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class PluginRuntimeAdmissionTests
{
    static PluginRuntimeState Running() => new("sli.remote-access", "registered", "enabled_manual", "running");
    static PluginRuntimeState Draining() => Running() with { DesiredActivation = "disabled", ComponentRuntime = "draining" };
    static string[] Blockers(JsonObject plan) => plan["blockers"]!.AsArray().Select(x => x!.GetValue<string>()).ToArray();
    static void NoSideEffects(JsonObject plan)
    {
        Assert.False(plan["source_contact_allowed"]!.GetValue<bool>());
        Assert.False(plan["process_control_allowed"]!.GetValue<bool>());
        Assert.False(plan["database_mutation_enabled"]!.GetValue<bool>());
    }

    [Fact]
    public void Drain_closes_producer_but_keeps_consumer_admitted()
    {
        var plan = PluginRuntimeAdmission.PlanBeginDrain(Running(), new("open", "open"));
        Assert.Equal("ready", plan["status"]!.GetValue<string>());
        Assert.Empty(Blockers(plan));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"desired_activation":"disabled","component_runtime":"draining","queue_state":"backlog","acquisition_mode":"closed","consumer_mode":"drain_only"}
            """), plan["effects"]));
        NoSideEffects(plan);

        var cells = new PluginComponentAdmission("closed", "drain_only");
        Assert.False(PluginRuntimeAdmission.AdmissionAllowed("radius-acquisition", Draining(), cells));
        Assert.True(PluginRuntimeAdmission.AdmissionAllowed("radius-session-observation", Draining(), cells));
    }

    [Fact]
    public void Drain_completion_requires_empty_queue_and_no_leases()
    {
        var active = PluginRuntimeAdmission.PlanCompleteDrain(Draining(), new("closed", "drain_only", 1, 1), new(1, 1, 1, 1));
        Assert.Equal("blocked", active["status"]!.GetValue<string>());
        Assert.Equal(new[] { "active_acquisition_leases_present", "queued_deliveries_present", "leased_deliveries_present",
            "failed_deliveries_present", "quarantined_deliveries_present", "active_consumer_leases_present" }, Blockers(active));
        Assert.Equal(4L, active["queue_nonterminal"]!.GetValue<long>());
        NoSideEffects(active);

        var completed = PluginRuntimeAdmission.PlanCompleteDrain(Draining(), new("closed", "drain_only"), new());
        Assert.Equal("ready", completed["status"]!.GetValue<string>());
        Assert.Empty(Blockers(completed));
        Assert.Equal(0L, completed["queue_nonterminal"]!.GetValue<long>());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"component_runtime":"stopped","queue_state":"drained","acquisition_mode":"closed","consumer_mode":"closed"}
            """), completed["effects"]));
        NoSideEffects(completed);
    }

    [Theory]
    [InlineData(1, 0, 0, 0, 0, 0, "active_acquisition_leases_present")]
    [InlineData(0, 1, 0, 0, 0, 0, "active_consumer_leases_present")]
    [InlineData(0, 0, 1, 0, 0, 0, "queued_deliveries_present")]
    [InlineData(0, 0, 0, 1, 0, 0, "leased_deliveries_present")]
    [InlineData(0, 0, 0, 0, 1, 0, "failed_deliveries_present")]
    [InlineData(0, 0, 0, 0, 0, 1, "quarantined_deliveries_present")]
    public void Each_outstanding_work_item_independently_blocks_completion(long acquisition, long consumer, long queued, long leased, long failed, long quarantined, string blocker)
    {
        var plan = PluginRuntimeAdmission.PlanCompleteDrain(Draining(), new("closed", "drain_only", acquisition, consumer), new(queued, leased, failed, quarantined));
        Assert.Equal("blocked", plan["status"]!.GetValue<string>());
        Assert.Equal(blocker, Assert.Single(Blockers(plan)));
    }

    [Theory]
    [InlineData("radius-acquisition", "enabled_manual", "running", "open", true)]
    [InlineData("radius-acquisition", "disabled", "draining", "open", false)]
    [InlineData("radius-acquisition", "enabled_manual", "running", "drain_only", false)]
    [InlineData("radius-session-observation", "enabled_manual", "running", "open", true)]
    [InlineData("radius-session-observation", "disabled", "draining", "drain_only", true)]
    [InlineData("radius-session-observation", "disabled", "draining", "open", false)]
    [InlineData("radius-session-observation", "disabled", "stopped", "drain_only", false)]
    [InlineData("radius-session-observation", "enabled_manual", "running", "closed", false)]
    public void Admission_depends_on_component_activation_runtime_and_mode(string component, string activation, string runtime, string mode, bool expected)
    {
        var state = Running() with { DesiredActivation = activation, ComponentRuntime = runtime };
        Assert.Equal(expected, PluginRuntimeAdmission.AdmissionAllowed(component, state, new(mode, mode)));
        Assert.False(PluginRuntimeAdmission.AdmissionAllowed(component, state with { PluginId = "sli.other" }, new(mode, mode)));
        Assert.False(PluginRuntimeAdmission.AdmissionAllowed(component, state with { PackageLifecycle = "validated" }, new(mode, mode)));
    }

    [Fact]
    public void Begin_drain_checks_preconditions_and_waits_for_existing_acquisition_leases()
    {
        var plan = PluginRuntimeAdmission.PlanBeginDrain(Running() with { ComponentRuntime = "failed" }, new("open", "open", 3));
        Assert.Equal("ready", plan["status"]!.GetValue<string>());
        Assert.Equal(3L, plan["active_acquisition_leases_to_wait"]!.GetValue<long>());
        var blocked = PluginRuntimeAdmission.PlanBeginDrain(Draining(), new("closed", "drain_only"));
        Assert.Equal("blocked", blocked["status"]!.GetValue<string>());
        Assert.Equal(new[] { "drain_requires_registered_enabled_runtime", "drain_requires_open_acquisition_admission", "drain_requires_open_consumer_admission" }, Blockers(blocked));
    }

    [Fact]
    public void Completion_requires_draining_state_and_two_cell_policy_even_with_empty_queue()
    {
        var plan = PluginRuntimeAdmission.PlanCompleteDrain(Running(), new("open", "closed"), new());
        Assert.Equal("blocked", plan["status"]!.GetValue<string>());
        Assert.Equal(new[] { "drain_completion_requires_draining_state", "acquisition_admission_must_be_closed", "consumer_must_remain_drain_only" }, Blockers(plan));
    }

    [Theory]
    [InlineData("invalid", "open", 0, 0)]
    [InlineData("open", "invalid", 0, 0)]
    [InlineData("open", "open", -1, 0)]
    [InlineData("open", "open", 0, -1)]
    public void Invalid_admission_snapshot_is_rejected(string acquisition, string consumer, long acquisitionLeases, long consumerLeases)
    {
        var cells = new PluginComponentAdmission(acquisition, consumer, acquisitionLeases, consumerLeases);
        Assert.Equal("runtime_admission_snapshot_invalid", Assert.Throws<VpnInputException>(() => PluginRuntimeAdmission.PlanBeginDrain(Running(), cells)).Message);
        Assert.Equal("runtime_admission_snapshot_invalid", Assert.Throws<VpnInputException>(() => PluginRuntimeAdmission.PlanCompleteDrain(Draining(), cells, new())).Message);
        Assert.Equal("runtime_admission_snapshot_invalid", Assert.Throws<VpnInputException>(() => PluginRuntimeAdmission.AdmissionAllowed("radius-acquisition", Running(), cells)).Message);
    }

    [Theory]
    [InlineData(-1, 0, 0, 0)] [InlineData(0, -1, 0, 0)] [InlineData(0, 0, -1, 0)] [InlineData(0, 0, 0, -1)]
    public void Invalid_queue_snapshot_is_rejected(long queued, long leased, long failed, long quarantined)
    {
        Assert.Equal("runtime_queue_snapshot_invalid", Assert.Throws<VpnInputException>(() => PluginRuntimeAdmission.PlanCompleteDrain(Draining(), new("closed", "drain_only"), new(queued, leased, failed, quarantined))).Message);
    }

    [Fact]
    public void Unknown_component_is_rejected()
    {
        Assert.Equal("runtime_admission_component_unknown", Assert.Throws<VpnInputException>(() => PluginRuntimeAdmission.AdmissionAllowed("unknown", Running(), new("open", "open"))).Message);
    }
}
