using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

internal sealed class RadiusTimeAlignedPlanError(string code) : Exception(code)
{
    public string Code { get; } = code;
}

// Offline validation of the historical operator artifact, not a runtime policy.
internal static class RadiusTimeAlignedPlan
{
    private const string PlanId = "stage9-radius-time-aligned-preflight-v1";

    public static JsonObject LoadPlan()
    {
        using var stream = typeof(RadiusTimeAlignedPlan).Assembly.GetManifestResourceStream(
            "Sli.Server.Agents.Radius.time-aligned-preflight.json")
            ?? throw new RadiusTimeAlignedPlanError("plan_invalid");
        JsonNode? value;
        try { value = JsonNode.Parse(stream); }
        catch (JsonException) { throw new RadiusTimeAlignedPlanError("plan_invalid"); }
        return value as JsonObject ?? throw new RadiusTimeAlignedPlanError("plan_object_required");
    }

    private static string Text(JsonNode? node) => JsonRead.TryString(node, out string text) ? text : "";
    private static void Require(bool condition, string code)
    {
        if (!condition) throw new RadiusTimeAlignedPlanError(code);
    }

    // Approved target comes from trusted owner configuration, separately from the
    // untrusted plan/inventory. Tests supply a synthetic target; no inventory is opened.
    public static JsonObject ValidatePlan(JsonObject plan, JsonObject inventory, JsonObject approvedTarget)
    {
        Require(JsonNode.DeepEquals(plan["schema_version"], JsonValue.Create(1)), "unsupported_plan_schema");
        Require(Text(plan["plan_id"]) == PlanId, "unexpected_plan_id");
        Require(Text(plan["status"]) == "owner_authorized", "owner_authorization_required");
        var expectedLimits = JsonNode.Parse("""
            {"target_count":1,"event_ids":[6272,6273],"nps_events":500,"accounting_files":1,
             "accounting_candidates":20,"accounting_records":400,"accounting_bytes":262144,
             "alignment_padding_seconds":600,"maximum_alignment_span_seconds":10800,
             "source_timezone_queries":1,"overall_timeout_seconds":75}
            """);
        Require(JsonNode.DeepEquals(plan["limits"], expectedLimits), "bounded_limits_changed");
        string targetSource = Text(plan["targets_source"]);
        try
        {
            Require(Path.GetFullPath(targetSource) == Path.GetFullPath("config/stage9_radius_targets.json"), "unexpected_targets_source");
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException)
        {
            throw new RadiusTimeAlignedPlanError("unexpected_targets_source");
        }
        Require(JsonNode.DeepEquals(inventory["targets"], new JsonArray(approvedTarget.DeepClone())), "approved_target_changed");
        string account = PythonText.Strip(Text(plan["expected_windows_account"]));
        Require(UnicodeCaseFold.Fold(account) == UnicodeCaseFold.Fold(@"EXAMPLE\operator"), "unexpected_windows_account");
        string[] requiredActions =
        [
            "audit_policy_change", "nps_configuration_change", "radius_accounting_enable", "service_change",
            "scheduled_task_change", "firewall_change", "postgresql_write", "clickhouse_write", "event_import",
            "cursor_update", "migration", "source_instance_creation", "descriptor_change", "normalizer_change",
            "worker_activation", "autostart",
        ];
        string[] requiredPersistence =
        [
            "event_xml", "event_payload", "event_timestamp_value", "accounting_raw_line", "accounting_timestamp_value",
            "account_session_identifier", "nas_identity", "subject_sid", "user_name", "distinguished_name",
            "ip_address", "file_name", "file_path", "radius_client", "radius_secret",
        ];
        static bool ContainsRequired(JsonNode? node, string[] required) => node is JsonArray array
            && required.All(value => array.Any(item => Text(item) == value));
        Require(ContainsRequired(plan["prohibited_actions"], requiredActions), "required_action_prohibition_missing");
        Require(ContainsRequired(plan["prohibited_persistence"], requiredPersistence), "required_persistence_prohibition_missing");
        var expectedEvaluation = JsonNode.Parse("""
            {
              "alignment_basis":"accounting_record_date_time_plus_explicit_source_utc_offset",
              "correlation_candidate_key":"account_session_id_plus_nas_identity",
              "principal_bridge":"exact_subject_sid_only_from_one_to_one_matched_nps_event",
              "username_is_not_exact_identity":true,"event_timestamp_preferred":true,
              "fallback_timestamp_basis":"record_date_plus_record_time_plus_explicit_source_timezone",
              "truncated_or_ambiguous_result":"correlation_not_proven",
              "success_result":"ready_for_runtime_adapter_design"
            }
            """);
        Require(JsonNode.DeepEquals(plan["evaluation_contract"], expectedEvaluation), "evaluation_contract_changed");
        Require(Text(plan["next_action"]) == "one_bounded_read_only_time_aligned_source_contact_then_owner_review", "unexpected_next_action");
        return new JsonObject
        {
            ["plan_id"] = PlanId, ["status"] = "owner_authorized", ["source_contact"] = false, ["read_only"] = true,
            ["target_count"] = 1, ["limits"] = plan["limits"]!.DeepClone(), ["target"] = approvedTarget.DeepClone(),
            ["expected_account"] = account,
        };
    }
}
