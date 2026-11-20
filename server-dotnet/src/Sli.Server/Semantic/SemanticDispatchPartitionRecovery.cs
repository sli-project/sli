using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic;

// Exact recovery contract from semantic_dispatch_partition_recovery.py. This is
// deliberately separate from the ordinary dispatcher and has no producer entrypoint.
internal static class SemanticDispatchPartitionRecovery
{
    internal const string RuleId = "investigation.account.unlock.after-lock";
    internal const int RuleVersion = 2;
    internal const string RuleSha = "5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e";
    internal const string ErrorConstraint = "semantic_correlation_candidate__candidate_id_evidence_order_key";
    internal const string CompletionConstraint = "semantic_correlation_dispatch_terminal";
    internal const string ConfirmPrefix = "REPAIR-SEMANTIC-DISPATCH-PARTITION:";
    private static readonly IReadOnlyDictionary<string, (long Trigger, string Suffix)> ExpectedJobs =
        new Dictionary<string, (long, string)>(StringComparer.Ordinal)
        {
            ["10eac730-5285-5740-b605-577d3ef9f4c2"] = (6943209, "7291"),
            ["75280b7d-4573-5bc9-9e0e-c1d3f6e897e3"] = (6486534, "6682"),
            ["e24572a7-159d-517c-a284-a0eff96ac007"] = (6487797, "6295")
        };

    private static JsonObject Relation(long trigger, long first, string key) => new()
    {
        ["trigger_source_event_id"] = trigger, ["source_event_ids"] = new JsonArray(first, trigger),
        ["contribution_key"] = "dispatch:" + key
    };
    private static JsonArray ExpectedRelations() => new(
        Relation(6487797, 6442170, "2dfdf2e4219e728fcab50c8a65139153c7bd1b410ed72c0493afdec8ca7df7c4"),
        Relation(6486534, 6436767, "9dd99c4a7bf00789c02b297270df71260e79096577bc4b1e6ccdba437717c037"),
        Relation(6943209, 6923513, "5497fb27862a7026a64b5e77f41d8e0a3fa181d9429bffa34671b899eedebe23"),
        Relation(6943209, 6874055, "b17e18e9d9fd11eb218a0b20b24175a8cf1ec427038c7700114f323a36767cfb"));
    private static InvalidOperationException Changed(string part) => new($"semantic dispatch recovery {part} changed");
    private static string Hex(JsonNode? value)
    {
        string text = value?.ToString().ToLowerInvariant() ?? "";
        if (text.Length != 64 || text.Any(c => !char.IsAsciiHexDigit(c)))
            throw new InvalidOperationException("semantic dispatch recovery source hash is invalid");
        return text;
    }
    private static JsonObject NormalizedContract(JsonNode source)
    {
        var result = new JsonObject
        {
            ["semantic_contract_version"] = source.Number("semantic_contract_version"),
            ["normalizer_id"] = (source.Text("normalizer_id") ?? "").Trim(),
            ["normalizer_version"] = (source.Text("normalizer_version") ?? "").Trim()
        };
        if (result.Number("semantic_contract_version") != 1 || result.Text("normalizer_id") != "windows.named-eventdata"
            || result.Text("normalizer_version") != "1.4+identity-1.0") throw Changed("normalized contract");
        return result;
    }
    private static string Relations(JsonNode source, string field)
    {
        if (source[field] is not JsonArray rows || rows.Any(x => x is not JsonObject)) throw Changed("relation readback");
        return CanonicalJson.Serialize(SemanticJson.Array(rows.OrderBy(x => CanonicalJson.Serialize(x), StringComparer.Ordinal)));
    }
    private static string ValidateJob(JsonNode source, bool permitCompleted)
    {
        string id = source.Text("job_id") ?? "";
        if (!ExpectedJobs.TryGetValue(id, out var expected)) throw Changed("job UUID set");
        string status = source.Text("dispatch_status") ?? "";
        if (status is not ("quarantined" or "queued" or "leased") && !(permitCompleted && status == "completed"))
            throw Changed("job state");
        if (source.Number("source_event_id") != expected.Trigger || source.Text("rule_id") != RuleId
            || source.Number("rule_version") != RuleVersion || Hex(source["definition_sha256"]) != RuleSha
            || !(source.Text("partition_key") ?? "").EndsWith(expected.Suffix, StringComparison.Ordinal)
            || source["trigger_identity"]?.ToString() != expected.Suffix) throw Changed("job contract");
        _ = NormalizedContract(source);
        var expectedRows = new JsonObject { ["relations"] = SemanticJson.Array(ExpectedRelations().Where(x => x.Number("trigger_source_event_id") == expected.Trigger)) };
        string accepted = Relations(source, "accepted_relations"), repairable = Relations(source, "repairable_relations");
        if (Relations(source, "blocking_relations") != "[]") throw Changed("blocking relation");
        string required = Relations(expectedRows, "relations");
        if (status == "completed")
        {
            if (accepted != required || repairable != "[]") throw Changed("completed relation readback");
            return id;
        }
        if (accepted != "[]" || repairable != required) throw Changed("repairable relation readback");
        string? code = source.Text("last_error_code");
        string detail = source.Text("last_error_detail") ?? "";
        if (!(code == "UniqueViolation" && detail.Contains('"' + ErrorConstraint + '"', StringComparison.Ordinal)
            || code == "CheckViolation" && detail.Contains('"' + CompletionConstraint + '"', StringComparison.Ordinal))) throw Changed("job contract");
        bool attempts = source.Number("attempt_count") == 5 && source.Number("max_attempts") == 5;
        bool noLease = source["lease_token"] is null && source["lease_until"] is null;
        bool noHeartbeat = source["heartbeat_at"] is null;
        bool valid = status switch
        {
            "queued" => attempts && noLease && noHeartbeat,
            "leased" => attempts && !string.IsNullOrEmpty(source["lease_token"]?.ToString())
                && source["lease_until"] is not null && !noHeartbeat && source.Flag("lease_expired"),
            _ => attempts && noLease && (code == "UniqueViolation" ? noHeartbeat : !noHeartbeat)
        };
        if (!valid) throw Changed(status == "quarantined" ? "quarantine state" : status + " state");
        return id;
    }
    internal static string[] ValidateRecoveryRows(IReadOnlyList<JsonObject> rows, bool permitCompleted = true)
    {
        if (rows.Count != ExpectedJobs.Count) throw new InvalidOperationException("semantic dispatch recovery requires exactly three planned jobs");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var remaining = new List<string>();
        foreach (var row in rows)
        {
            string id = ValidateJob(row, permitCompleted);
            if (!seen.Add(id)) throw Changed("job UUID set");
            if (row.Text("dispatch_status") != "completed") remaining.Add(id);
        }
        return remaining.Order(StringComparer.Ordinal).ToArray();
    }
    internal static JsonArray ObservedPlanJobs(IReadOnlyList<JsonObject> rows) => SemanticJson.Array(rows.Select(source =>
    {
        string id = ValidateJob(source, true);
        var payload = new JsonObject
        {
            ["job_id"] = id, ["trigger_source_event_id"] = ExpectedJobs[id].Trigger,
            ["partition_key"] = source.Text("partition_key"), ["source_hash_sha256"] = Hex(source["source_hash"])
        };
        var job = (JsonObject)payload.DeepClone();
        job["trigger_identity_suffix"] = ExpectedJobs[id].Suffix;
        job["normalized_contract"] = NormalizedContract(source);
        job["job_payload_sha256"] = Hex(source["job_payload_sha256"] is { } hash && hash.ToString().Length > 0
            ? hash : JsonValue.Create(PasswordJson.Hash(payload)));
        return job;
    }).OrderBy(x => x.Text("job_id"), StringComparer.Ordinal));

    internal static JsonObject BuildSealedPlan(IReadOnlyList<JsonObject> rows, string normalizedBefore)
    {
        if (string.IsNullOrEmpty(normalizedBefore) || !normalizedBefore.Contains('+') && !normalizedBefore.EndsWith('Z'))
            throw new InvalidOperationException("semantic dispatch recovery normalized boundary is invalid");
        _ = ValidateRecoveryRows(rows, permitCompleted: false);
        var plan = new JsonObject
        {
            ["plan_version"] = "semantic_dispatch_partition_recovery_v1",
            ["rule"] = new JsonObject { ["rule_id"] = RuleId, ["rule_version"] = RuleVersion, ["definition_sha256"] = RuleSha },
            ["error"] = new JsonObject { ["code"] = "UniqueViolation", ["constraint"] = ErrorConstraint },
            ["normalized_before"] = normalizedBefore, ["jobs"] = ObservedPlanJobs(rows),
            ["expected_relations"] = ExpectedRelations(), ["scenario_evidence_expected"] = 0
        };
        string digest = PasswordJson.Hash(plan);
        plan["job_count"] = 3; plan["plan_digest"] = digest; plan["confirmation"] = ConfirmPrefix + digest;
        return plan;
    }
}

// Dependencies have the same narrow scope as the Python controller. No defaults
// claim that dispatch or verification succeeded when no implementation was supplied.
internal sealed class SemanticDispatchPartitionRecoveryController(
    Func<IReadOnlyList<JsonObject>> snapshot, Func<bool> workerIsLive, Func<bool> acquireLocks)
{
    internal Action<JsonObject> Requeue { get; init; } = _ => throw new InvalidOperationException("semantic dispatch recovery requeue unavailable");
    internal Func<JsonObject, JsonObject> Dispatch { get; init; } = _ => throw new InvalidOperationException("semantic dispatch recovery dispatch unavailable");
    internal Func<JsonObject, JsonObject> Verify { get; init; } = _ => throw new InvalidOperationException("semantic dispatch recovery verification unavailable");
    internal Action<JsonObject> Audit { get; init; } = _ => { };
    internal Func<JsonObject, bool> Preflight { get; init; } = _ => true;

    internal JsonObject Apply(string planDigest, string confirmation, JsonObject plan)
    {
        var sealedPlan = (JsonObject)plan.DeepClone();
        if (planDigest != sealedPlan.Text("plan_digest") || confirmation != sealedPlan.Text("confirmation")
            || confirmation != SemanticDispatchPartitionRecovery.ConfirmPrefix + planDigest)
            throw new InvalidOperationException("exact semantic dispatch recovery confirmation required");
        if (workerIsLive()) throw new InvalidOperationException("semantic dispatch recovery refuses a live dispatcher");
        if (!acquireLocks()) throw new InvalidOperationException("semantic dispatch recovery advisory lock is busy");
        var rows = snapshot();
        string[] remaining = SemanticDispatchPartitionRecovery.ValidateRecoveryRows(rows);
        if (remaining.Length == 0)
        {
            var complete = new JsonObject { ["status"] = "already_complete", ["plan_digest"] = planDigest, ["production_changed"] = false };
            Audit(complete); return complete;
        }
        if (CanonicalJson.Serialize(SemanticDispatchPartitionRecovery.ObservedPlanJobs(rows)) != CanonicalJson.Serialize(sealedPlan["jobs"]))
            throw new InvalidOperationException("semantic dispatch recovery plan changed before any write");
        if (!Preflight(sealedPlan)) throw new InvalidOperationException("semantic dispatch recovery preflight changed before any write");
        var scope = new JsonObject
        {
            ["allowed_job_ids"] = new JsonArray(remaining.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
            ["normalized_before"] = sealedPlan["normalized_before"].Copy(),
            ["allowed_rule_identity"] = new JsonArray(SemanticDispatchPartitionRecovery.RuleId, SemanticDispatchPartitionRecovery.RuleVersion, SemanticDispatchPartitionRecovery.RuleSha)
        };
        var scopedPlan = (JsonObject)sealedPlan.DeepClone();
        scopedPlan["jobs"] = SemanticJson.Array(sealedPlan["jobs"]!.AsArray().Where(x => remaining.Contains(x.Text("job_id"), StringComparer.Ordinal)));
        Requeue(scopedPlan);
        var dispatch = Dispatch(scope);
        if (dispatch.Number("failed") != 0 || dispatch.Number("completed") != remaining.Length)
            throw new InvalidOperationException("semantic dispatch recovery processing failed or was incomplete");
        var verification = Verify(sealedPlan);
        if (!verification.Flag("completed") || !verification.Flag("relations_exact")
            || !JsonNode.DeepEquals(verification["scenario_evidence_added"], JsonValue.Create(0)) || !verification.Flag("unrelated_status_unchanged"))
            throw new InvalidOperationException("semantic dispatch recovery acceptance verification failed");
        var result = new JsonObject
        {
            ["status"] = "complete", ["plan_digest"] = planDigest, ["production_changed"] = true,
            ["dispatch"] = dispatch.Copy(), ["verification"] = verification.Copy()
        };
        Audit(result); return result;
    }
}
