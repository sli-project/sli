using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Agents.Consumer;

internal enum AdDcProjectionStep
{
    ImportQueueWait, Authorization, PacketValidation, AgentAssignment, ReceiptAttestation, PluginAdmission,
    SourceBinding, SourceConfiguration, PrepareBatch, Catalog, RawReservation,
    Dictionaries, EventReservation, EntityReservation, EntityPreparation, Publication,
    StateProjection, RawFinalization, HotWriteWait, HotEntities, HotEntityResolution, HotEvents, HotLinks, HotVerification, HotCommit
}

// Like WorkerFailure: never serialize an exception, message, Detail, SQL or
// event/packet identity. Even a constraint identifier is untrusted input.
internal static class AdDcProjectionFailure
{
    private static readonly HashSet<string> Constraints = new(StringComparer.Ordinal) {
        "entities_v2_pkey", "entities_v2_natural_key_key", "entity_details_v2_pkey",
        "event_source_representations_v2_pkey", "storage_v2_event_identity_allocations_pkey",
        "storage_v2_event_identity_allocations_server_id_channel_id_event_record_id_time_created_utc_key"
    };
    private static readonly HashSet<string> Reasons = new(StringComparer.Ordinal) {
        "storage_v2_event_profile_pending", "storage_v2_event_id_pending", "storage_v2_catalog_generation_pending",
        "storage_v2_semantic_mode_pending", "storage_v2_timezone_profile_pending",
        "event_representation_pending", "storage_v2_link_replay_pending", "storage_v2_late_link_pending",
        "storage_v2_event_replay_conflict", "storage_v2_fact_replay_conflict",
        "storage_v2_entity_conflict", "agent_ad_dc_source_not_configured",
        "agent_ad_dc_channel_not_configured", "storage_v2_projection_schema_missing",
        "agent_plugin_admission_pending", "agent_ad_dc_source_not_bound",
        "agent_storage_unavailable", "agent_disabled", "agent_module_not_assigned",
        "agent_packet_attestation_invalid", "agent_plugin_disabled",
        "agent_inbox_marker_conflict", "short_event_summary_conflict", "short_event_attestation_failed"
    };
    internal static bool IsPermanent(Exception error) => error is InvalidOperationException &&
        error.Message is "short_event_summary_conflict" or "short_event_attestation_failed";
    internal static string Describe(Exception error, AdDcProjectionStep step)
    {
        PostgresException? postgres = null;
        string reason = error is DirectSourceConflict conflict ? conflict.Reason : "operation_failed";
        for (Exception? current = error; current is not null; current = current.InnerException) {
            postgres ??= current as PostgresException;
            if (Reasons.Contains(current.Message)) reason = current.Message;
        }
        string? sqlState = postgres?.SqlState;
        if (sqlState is not null && (sqlState.Length != 5 || sqlState.Any(c => c is not (>= '0' and <= '9' or >= 'A' and <= 'Z')))) sqlState = "unknown";
        return new JsonObject {
            ["code"] = "agent_ad_dc_projection_failed",
            ["step"] = string.Concat(step.ToString().Select((c,i) => char.IsUpper(c) && i > 0 ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString())),
            ["exception_type"] = error.GetType().Name,
            ["sql_state"] = sqlState,
            ["constraint"] = postgres?.ConstraintName is not { } constraint ? null : Constraints.Contains(constraint) ? constraint : "unrecognized",
            ["reason"] = reason
        }.ToJsonString();
    }
}
