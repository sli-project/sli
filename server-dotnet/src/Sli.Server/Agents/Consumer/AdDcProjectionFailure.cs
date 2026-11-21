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
internal sealed class AdDcProjectionFailure(TimeProvider clock)
{
    internal const string Code = "agent_ad_dc_projection_failed";
    internal const string CatalogUnavailable = "agent_ad_dc_catalog_unavailable";
    internal const string ConnectionUnconfigured = "agent_ad_dc_storage_connection_unconfigured";
    internal const string AuthorizationMissing = "agent_ad_dc_storage_authorization_missing";
    internal const string AuthorizationInvalid = "agent_ad_dc_storage_authorization_invalid";
    internal const string AccessDenied = "agent_ad_dc_storage_access_denied";

    private readonly Dictionary<string, (long LastLogged, long Suppressed)> failures = new(StringComparer.Ordinal);

    internal bool CountAndAllow(JsonObject diagnostic)
    {
        if ((string?)diagnostic["code"] != Code) return true;
        string reason = (string)diagnostic["reason"]!;
        lock (failures)
        {
            long now = clock.GetTimestamp();
            if (failures.TryGetValue(reason, out var previous) &&
                clock.GetElapsedTime(previous.LastLogged, now) < TimeSpan.FromMinutes(1))
            {
                failures[reason] = (previous.LastLogged, previous.Suppressed + 1);
                return false;
            }
            failures[reason] = (now, 0);
            diagnostic["occurrences"] = previous.Suppressed + 1;
            return true;
        }
    }

    internal static bool IsStorageIssue(string? reason) => reason is CatalogUnavailable or ConnectionUnconfigured
        or AuthorizationMissing or AuthorizationInvalid or AccessDenied;

    internal static string? StorageIssue(Exception error, AdDcProjectionStep step)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            if (current is InvalidOperationException && current.Message == "storage_v2_admission_required") return AuthorizationInvalid;
            if (step == AdDcProjectionStep.Authorization && current is InvalidOperationException &&
                current.Message == "agent_storage_unavailable") return AuthorizationMissing;
            if (current is PostgresException { SqlState: "42501" or "28000" or "28P01" } ||
                current is InvalidOperationException && current.Message == "storage_v2_worker_role_required") return AccessDenied;
            if (step == AdDcProjectionStep.Catalog && current is IOException or UnauthorizedAccessException) return CatalogUnavailable;
        }
        return null;
    }
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
    internal static JsonObject Describe(Exception error, AdDcProjectionStep step)
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
            ["code"] = Code,
            ["step"] = string.Concat(step.ToString().Select((c,i) => char.IsUpper(c) && i > 0 ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString())),
            ["exception_type"] = error.GetType().Name,
            ["sql_state"] = sqlState,
            ["constraint"] = postgres?.ConstraintName is not { } constraint ? null : Constraints.Contains(constraint) ? constraint : "unrecognized",
            ["reason"] = StorageIssue(error, step) ?? reason
        };
    }
}
