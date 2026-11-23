using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic;

// Only compile-time operation names and exact, enumerated reason codes can leave
// the worker. Never serialize exception text, SQL, source identity or event data.
internal sealed class DetectionDiagnostics
{
    private static readonly HashSet<string> ProposalCodes = ["future_event","outside_horizon","clock_regression","state_bound","prequalification_native_unavailable","prequalification_proof_budget_exhausted","too_late","coverage_gap","episode_evidence_budget_exhausted","missing_target","unclassified_failure","ambiguous_failure","conflicting_client","missing_client"];
    private static readonly HashSet<string> Reasons = new(StringComparer.Ordinal) {
        "detection_reader_type", "detection_reader_bound", "detection_admission_unconfirmed",
        "detection_xml_budget", "detection_xml_bound", "detection_native_mismatch", "detection_native_fields",
        "detection_ref_invalid", "detection_evidence_unavailable", "detection_signal_conflict",
        "detection_signal_invalid", "detection_queue_identity_conflict", "detection_session_lost",
        "t109_source_window_truncated", "t109_native_proof_invalid", "t109_signal_conflict",
        "t109_source_denied", "t109_window_invalid", "t109_late_episode_bridge", "t109_evidence_window_too_large",
        "identity_attack_native_unavailable", "identity_attack_source_denied", "identity_attack_arguments_invalid",
        "identity_attack_episode_invalid", "identity_attack_native_proof_invalid", "identity_attack_snapshot_truncated",
        "sigma_event_mapping_invalid", "sigma_event_structure_invalid", "sigma_event_schema_unsupported",
        "sigma_event_provider_invalid", "sigma_event_header_invalid", "sigma_event_payload_ambiguous",
        "sigma_event_userdata_unsupported", "sigma_event_positional_unsupported",
        "account_identity_limit", "watch_source_catalog_unavailable", "password_window_truncated",
        "nps_threshold_input_invalid", "nps_watermark_regression", "nps_threshold_event_conflict",
        "nps_threshold_denial_invalid", "nps_group_limit", "account_detection_batch_invalid", "account_detection_policy_unavailable", "qw_signal_invalid",
        "qw_signal_replay_conflict", "file_ransom_source_policy_mismatch", "source_policy_waiting",
        "file_acl_diagnostics_invalid", "file_acl_discovery_invalid", "file_acl_source_diagnostics",
        "default_detection_policy_denied", "default_detection_policy_conflict",
        "file_decoy_batch_invalid", "file_decoy_context_limit", "file_decoy_label_limit", "file_decoy_policy_unavailable",
        "file_ransom_batch_invalid", "file_ransom_episode_conflict", "file_ransom_evidence_invalid",
        "file_ransom_result_invalid", "file_ransom_window_invalid", "file_ransom_rule_invalid", "file_ransom_policy_unavailable",
        "file_acl_portion_conflict", "file_acl_checkpoint_denied", "file_acl_required_jobs_missing",
        "file_acl_medium_required", "file_acl_native_verdict_blocked", "file_acl_native_verdict_conflict",
        "file_acl_resource_invalid", "file_acl_signal_conflict", "file_acl_signal_invalid",
        "nps_context_invalid", "qw_context_rule_mismatch", "qw_processing_mode_invalid", "qw_source_mismatch",
        "password_v2_source_unconfirmed", "password_v2_attempt_invalid", "password_v2_attempt_conflict",
        "password_v2_policy_unconfirmed", "password_v2_window_invalid", "password_v2_window_conflict",
        "password_v2_window_changed393", "password_v2_context_invalid",
        "password_v2_reader_invalid", "password_v2_reader_bound", "password_v2_native_unavailable",
        "password_v2_native_content_conflict", "password_v2_proof_bound", "password_v2_proof_budget_exceeded", "password_v2_chain_invalid",
        "password_v2_barrier_native_conflict", "password_v2_completion_invalid", "password_v2_window_incomplete", "password_v2_worker_privilege_invalid",
        "password_v2_xml_budget_exceeded", "password_v2_window_truncated", "password_v2_outcome_invalid",
        "password_policy_rule_invalid", "password_policy_source_unavailable", "password_policy_unconfirmed",
        "password_policy_denied", "password_policy_conflict", "password_producer_busy",
        "password_v2_call_invalid", "password_v2_chain_unavailable", "password_v2_connection_not_idle",
        "password_v2_continuity_counters", "password_v2_continuity_empty", "password_v2_continuity_gap",
        "password_v2_continuity_identity", "password_v2_continuity_missing", "password_v2_continuity_native_conflict",
        "password_v2_continuity_origin_gap", "password_v2_continuity_origin_missing", "password_v2_continuity_predecessor",
        "password_v2_continuity_root", "password_v2_continuity_seed", "password_v2_continuity_state", "password_v2_continuity_threshold",
        "password_v2_document_invalid", "password_v2_episode_budget_exhausted", "password_v2_frozen_zero_unsupported",
        "password_v2_native_conflict", "password_v2_native_event_mismatch", "password_v2_native_fields_invalid",
        "password_v2_native_invalid", "password_v2_native_scope", "password_v2_native_time_mismatch",
        "password_v2_portion_invalid", "password_v2_proposal_unavailable", "password_v2_queue_identity_conflict",
        "password_v2_queue_source_invalid", "password_v2_reservation_conflict", "password_v2_rule_scope",
        "password_v2_signal_invalid", "password_v2_state_invalid", "password_v2_state_scope",
        "password_v2_storage_unavailable", "password_v2_successor_conflict", "password_v2_time_invalid",
        "password_v2_source_denied", "password_v2_context_bound", "password_v2_ledger_conflict", "password_v2_checkpoint_corrupt",
        "password_v2_arguments_invalid", "password_v2_entity_prelock_required"
    };
    private static readonly string[] Operations = [
        "semantic_import_refresh320", "semantic_default_refresh320", "semantic_import_progress320",
        "default_detection_sources", "t109_detection_sources", "read_default_file_acl_resources",
        "read_account_decoy_events", "read_account_watch_events", "read_default_password_events",
        "read_file_decoy_observations", "read_file_ransom_results", "prepare_file_acl_portion_v265",
        "advance_file_acl_checkpoint_v265", "read_file_acl_portion_v265", "read_file_acl_result_by_id",
        "read_t109_native", "read_t109_policy", "read_t109_agent_health", "read_t109_recent_threats",
        "read_identity_attack_events_v301", "read_identity_attack_snapshot_v301",
        "ensure_default_qw_policy", "resolve_finding_evidence_ref", "identity_attack_episode_v301",
        "password_source_ready_v314", "password_event_clock362", "read_password_event_window362", "password_producer_source382", "begin_password_attempt", "read_password_checkpoint_v2",
        "read_default_password_window_v2", "prepare_password_producer_batch_v2",
        "read_password_episode_portions_v2", "read_password_retained_proof_v2", "track_password_frozen_entity_v2",
        "reserve_password_episode_emission", "complete_password_producer_batch_v2",
        "observe_password_failure_v2", "read_pending_file_acl_portions_v265", "read_file_acl_results"
    ];
    internal string Step { get; set; } = "source";
    private readonly Dictionary<string, JsonObject> failures = new(StringComparer.Ordinal);
    internal void Query(string sql) => Step = Operations.FirstOrDefault(name => sql.Contains(name + "(", StringComparison.Ordinal)) ?? "source_write";
    internal static JsonObject Describe(Exception error, string step)
    {
        string? state = null; string reason = "operation_failed";
        for (Exception? current = error; current is not null; current = current.InnerException) {
            if (current is PostgresException pg) { state ??= pg.SqlState; if (Reasons.Contains(pg.MessageText)) reason = pg.MessageText; }
            else if (Reasons.Contains(current.Message)) reason = current.Message;
            else if (current is TimeoutException && state is null) reason = "client_timeout";
            else if (current is OperationCanceledException && state is null) reason = "operation_cancelled";
            else if (current is IOException or System.Net.Sockets.SocketException && state is null && reason == "operation_failed") reason = "connection_lost";
        }
        if (state is not null && (state.Length != 5 || state.Any(c => c is not (>= '0' and <= '9' or >= 'A' and <= 'Z')))) state = "unknown";
        if (state == PostgresErrorCodes.LockNotAvailable && reason == "operation_failed") reason = "lock_busy";
        var result = new JsonObject { ["step"] = step, ["exception_type"] = error.GetType().Name, ["sql_state"] = state, ["reason"] = reason };
        if(reason=="password_v2_proof_budget_exceeded")
            result["proof_budget"]=new PasswordProofBudget(PasswordProofPhase.NativeVerification).Document;
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is PasswordFailure password) {
                // Text comes only from the fixed reason vocabulary and enum, never
                // from an exception's free text or any native event value.
                result["message"] = Reasons.Contains(password.Message)
                    ? "Password producer: " + password.Message.Replace("password_v2_", "", StringComparison.Ordinal).Replace('_', ' ') + "."
                    : "Password producer operation failed.";
                if(password.ProofBudget is {} budget)result["proof_budget"]=budget.Document;
                if (password.WindowCondition is {} windowCheck && Enum.IsDefined(windowCheck))
                    result["window_check"] = windowCheck.ToString();
                if (password.Check is {} check && Enum.IsDefined(check)) {
                    result["check"] = check.ToString();
                    result["message"] = check switch {
                        PasswordFailure.ContextCheck.Shape => "Password batch context has an invalid status, revision, shape or size.",
                        PasswordFailure.ContextCheck.EntityOrder => "Prelocked password entities are duplicated or out of order.",
                        PasswordFailure.ContextCheck.EntityFormat => "A prelocked password entity has an invalid digest format.",
                        PasswordFailure.ContextCheck.MissingEntity => "A password batch entity is absent from the prelocked context.",
                        PasswordFailure.ContextCheck.MissingBarrierEntity => "A password barrier entity is absent from the prelocked context.",
                        _ => "Password batch context is invalid."
                    };
                }
                if(password.ProposalDiagnostics is {} proposal) {
                    var counts=new JsonObject();foreach(var (code,count) in proposal)if(ProposalCodes.Contains(code)&&count>0)counts[code]=count;
                    result["proposal_diagnostics"]=counts;result["watermark_matches"]=password.WatermarkMatches;
                    if(proposal.GetValueOrDefault("state_bound")>0&&password.StateBytes is >=0)
                        result["state_bytes"]=password.StateBytes.Value;
                }
                break;
            }
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is DetectionFailure { Field: {} field, Difference: {} difference } && Enum.IsDefined(field) && Enum.IsDefined(difference)) {
                result["field"] = field.ToString(); result["difference"] = difference.ToString(); break;
            }
        return result;
    }
    internal void Add(Exception error) => Add(Describe(error, Step));
    internal void Merge(DetectionDiagnostics? other)
    {
        if (other is null) return;
        foreach (var item in other.failures.Values)
            for (int i = 0; i < item.Number("count"); i++) Add(item);
    }
    internal void FileAcl(JsonObject counts)
    {
        var safe = SemanticProduction.AclDiagnostics(counts);
        if (!safe.Any(p => p.Key != "verified_excluded")) return;
        var diagnostic = Describe(new InvalidDataException("file_acl_source_diagnostics"), Step);
        diagnostic["diagnostic_counts"] = safe;
        Add(diagnostic);
    }
    internal void Add(JsonObject diagnostic)
    {
        string key = diagnostic.ToJsonString();
        if (!failures.TryGetValue(key, out var item)) { item = diagnostic.DeepClone().AsObject(); item["count"] = 0; failures.Add(key, item); }
        item["count"] = item["count"]!.GetValue<int>() + 1;
    }
    internal JsonObject Counts {
        get { var counts = new JsonObject(); foreach (var item in failures.Values) { string reason = item["reason"]!.GetValue<string>(); counts[reason] = (counts[reason]?.GetValue<int>() ?? 0) + item["count"]!.GetValue<int>(); } return counts; }
    }
    internal void Write(string cycle, Action<string>? write = null)
    {
        foreach (var item in failures.Values) (write ?? Console.Error.WriteLine)(cycle + "_source_failed:" + item.ToJsonString());
    }
}
