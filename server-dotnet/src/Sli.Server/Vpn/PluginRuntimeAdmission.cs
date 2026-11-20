using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

// Only the lifecycle axes used by the source admission planner. Planning has no
// database, process or source effects; durable lease execution stays separate.
public sealed record PluginRuntimeState(string PluginId, string PackageLifecycle, string DesiredActivation, string ComponentRuntime);
public sealed record PluginComponentAdmission(string AcquisitionMode, string ConsumerMode, long ActiveAcquisitionLeases = 0, long ActiveConsumerLeases = 0);
public sealed record PluginQueueSnapshot(long Queued = 0, long Leased = 0, long Failed = 0, long Quarantined = 0)
{
    public long Nonterminal => checked(Queued + Leased + Failed + Quarantined);
}

public static class PluginRuntimeAdmission
{
    public const string Acquisition = "radius-acquisition";
    public const string Consumer = "radius-session-observation";

    public static bool AdmissionAllowed(string componentId, PluginRuntimeState state, PluginComponentAdmission admission)
    {
        Validate(admission);
        if (state.PluginId != "sli.remote-access" || state.PackageLifecycle != "registered") return false;
        return componentId switch {
            Acquisition => state.DesiredActivation == "enabled_manual" && state.ComponentRuntime == "running" && admission.AcquisitionMode == "open",
            Consumer => (state.DesiredActivation == "enabled_manual" && state.ComponentRuntime == "running" && admission.ConsumerMode == "open")
                || (state.DesiredActivation == "disabled" && state.ComponentRuntime == "draining" && admission.ConsumerMode == "drain_only"),
            _ => throw new VpnInputException("runtime_admission_component_unknown")
        };
    }

    public static JsonObject PlanBeginDrain(PluginRuntimeState state, PluginComponentAdmission admission)
    {
        Validate(admission);
        var blockers = new List<string>();
        if (state.PluginId != "sli.remote-access" || state.PackageLifecycle != "registered"
            || state.DesiredActivation != "enabled_manual" || state.ComponentRuntime is not ("running" or "failed"))
            blockers.Add("drain_requires_registered_enabled_runtime");
        if (admission.AcquisitionMode != "open") blockers.Add("drain_requires_open_acquisition_admission");
        if (admission.ConsumerMode != "open") blockers.Add("drain_requires_open_consumer_admission");
        var plan = Plan(blockers, new JsonObject {
            ["desired_activation"] = "disabled", ["component_runtime"] = "draining", ["queue_state"] = "backlog",
            ["acquisition_mode"] = "closed", ["consumer_mode"] = "drain_only"
        });
        plan["active_acquisition_leases_to_wait"] = admission.ActiveAcquisitionLeases;
        return plan;
    }

    public static JsonObject PlanCompleteDrain(PluginRuntimeState state, PluginComponentAdmission admission, PluginQueueSnapshot queue)
    {
        Validate(admission);
        if (queue.Queued < 0 || queue.Leased < 0 || queue.Failed < 0 || queue.Quarantined < 0)
            throw new VpnInputException("runtime_queue_snapshot_invalid");
        var blockers = new List<string>();
        if (state.PluginId != "sli.remote-access" || state.PackageLifecycle != "registered"
            || state.DesiredActivation != "disabled" || state.ComponentRuntime != "draining")
            blockers.Add("drain_completion_requires_draining_state");
        if (admission.AcquisitionMode != "closed") blockers.Add("acquisition_admission_must_be_closed");
        if (admission.ConsumerMode != "drain_only") blockers.Add("consumer_must_remain_drain_only");
        if (admission.ActiveAcquisitionLeases != 0) blockers.Add("active_acquisition_leases_present");
        if (queue.Queued != 0) blockers.Add("queued_deliveries_present");
        if (queue.Leased != 0) blockers.Add("leased_deliveries_present");
        if (queue.Failed != 0) blockers.Add("failed_deliveries_present");
        if (queue.Quarantined != 0) blockers.Add("quarantined_deliveries_present");
        if (admission.ActiveConsumerLeases != 0) blockers.Add("active_consumer_leases_present");
        var plan = Plan(blockers, new JsonObject {
            ["component_runtime"] = "stopped", ["queue_state"] = "drained",
            ["acquisition_mode"] = "closed", ["consumer_mode"] = "closed"
        });
        plan["queue_nonterminal"] = queue.Nonterminal;
        return plan;
    }

    static void Validate(PluginComponentAdmission admission)
    {
        if (admission.AcquisitionMode is not ("closed" or "open" or "drain_only")
            || admission.ConsumerMode is not ("closed" or "open" or "drain_only")
            || admission.ActiveAcquisitionLeases < 0 || admission.ActiveConsumerLeases < 0)
            throw new VpnInputException("runtime_admission_snapshot_invalid");
    }

    static JsonObject Plan(List<string> blockers, JsonObject effects) => new() {
        ["status"] = blockers.Count == 0 ? "ready" : "blocked",
        ["blockers"] = new JsonArray(blockers.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
        ["effects"] = effects, ["source_contact_allowed"] = false,
        ["process_control_allowed"] = false, ["database_mutation_enabled"] = false
    };
}
