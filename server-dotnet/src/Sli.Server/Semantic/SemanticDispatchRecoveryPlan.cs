using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal static partial class SemanticDispatchRecovery
{
    private static string Hex(string? value)
    {
        if (value is null || value.Length != 64 || value.Any(c => !char.IsAsciiHexDigit(c))) throw new InvalidOperationException("semantic dispatch recovery source hash is invalid");
        return value.ToLowerInvariant();
    }
    private static bool SameRelations(JsonNode? actual, IEnumerable<JsonObject> expected) => actual is JsonArray array &&
        array.Select(SemanticJson.Hash).Order().SequenceEqual(expected.Select(SemanticJson.Hash).Order());
    internal static Guid[] ValidateRows(JsonArray rows, bool permitCompleted = true)
    {
        if (rows.Count != Jobs.Count) throw new InvalidOperationException("semantic dispatch recovery requires exactly three planned jobs");
        var seen = new HashSet<Guid>(); var remaining = new List<Guid>();
        foreach (var row in rows) {
            if (!Guid.TryParse(row.Text("job_id"), out var id) || !Jobs.TryGetValue(id, out var pin) || !seen.Add(id)) throw new InvalidOperationException("semantic dispatch recovery job UUID set changed");
            string? state = row.Text("dispatch_status");
            if (state is not ("quarantined" or "queued" or "leased") && !(permitCompleted && state == "completed")) throw new InvalidOperationException("semantic dispatch recovery job state changed");
            if (row.Number("source_event_id") != pin.Source || row.Text("rule_id") != RuleId || row.Number("rule_version") != RuleVersion || Hex(row.Text("definition_sha256")) != RuleSha ||
                row.Text("partition_key")?.EndsWith(pin.Suffix, StringComparison.Ordinal) != true || row.Text("trigger_identity") != pin.Suffix || row.Number("semantic_contract_version") != 1 ||
                row.Text("normalizer_id") != "windows.named-eventdata" || row.Text("normalizer_version") != "1.4+identity-1.0") throw new InvalidOperationException("semantic dispatch recovery job contract changed");
            var expected = Relations.Where(x => x.Trigger == pin.Source).Select(x => Relation(x.Trigger, x.Sources, x.Key)).ToArray();
            bool completed = state == "completed";
            if (!SameRelations(row?["blocking_relations"], []) || !SameRelations(row?["accepted_relations"], completed ? expected : []) || !SameRelations(row?["repairable_relations"], completed ? [] : expected))
                throw new InvalidOperationException("semantic dispatch recovery relation readback changed");
            if (completed) continue;
            remaining.Add(id);
            bool unique = row.Text("last_error_code") == ErrorCode && row.Text("last_error_detail")?.Contains('"' + Constraint + '"', StringComparison.Ordinal) == true;
            bool terminal = row.Text("last_error_code") == CompletionError && row.Text("last_error_detail")?.Contains('"' + CompletionConstraint + '"', StringComparison.Ordinal) == true;
            bool token = row?["lease_token"] is not null, until = row?["lease_until"] is not null, heartbeat = row?["heartbeat_at"] is not null;
            if (!(unique || terminal) || row.Number("attempt_count") != 5 || row.Number("max_attempts") != 5 ||
                (state == "queued" && (token || until || heartbeat)) ||
                (state == "quarantined" && (token || until || (unique ? heartbeat : !heartbeat))) ||
                (state == "leased" && (!token || !until || !heartbeat || !row.Flag("lease_expired"))))
                throw new InvalidOperationException("semantic dispatch recovery " + state + " state changed");
        }
        return remaining.Order().ToArray();
    }
    internal static JsonArray PlanJobs(JsonArray rows) => new(rows.OrderBy(x => x.Text("job_id"), StringComparer.Ordinal).Select(row => {
        Guid id = Guid.Parse(row.Text("job_id")!); var pin = Jobs[id]; string hash = Hex(row.Text("source_hash"));
        return (JsonNode)new JsonObject {
            ["job_id"] = id.ToString(), ["trigger_source_event_id"] = pin.Source, ["partition_key"] = row.Text("partition_key"), ["trigger_identity_suffix"] = pin.Suffix,
            ["normalized_contract"] = new JsonObject { ["semantic_contract_version"] = 1, ["normalizer_id"] = "windows.named-eventdata", ["normalizer_version"] = "1.4+identity-1.0" },
            ["source_hash_sha256"] = hash, ["job_payload_sha256"] = Hex(row.Text("job_payload_sha256") ?? SemanticJson.Hash(new JsonObject {
                ["job_id"] = id.ToString(), ["trigger_source_event_id"] = pin.Source, ["partition_key"] = row.Text("partition_key"), ["source_hash_sha256"] = hash }))
        };
    }).ToArray());
    internal static JsonObject BuildPlan(JsonArray rows, JsonObject baseline)
    {
        ValidateRows(rows, permitCompleted: false);
        string boundary = rows.Select(x => x.Text("normalized_at") ?? throw new InvalidOperationException("semantic dispatch recovery normalized boundary is invalid"))
            .OrderBy(x => SemanticQuery.Time(x, "UTC", "invalid_boundary")).Last();
        var plan = new JsonObject { ["plan_version"] = "semantic_dispatch_partition_recovery_v1", ["rule"] = new JsonObject { ["rule_id"] = RuleId, ["rule_version"] = RuleVersion, ["definition_sha256"] = RuleSha },
            ["error"] = new JsonObject { ["code"] = ErrorCode, ["constraint"] = Constraint }, ["normalized_before"] = boundary, ["jobs"] = PlanJobs(rows),
            ["expected_relations"] = new JsonArray(Relations.Select(x => (JsonNode)Relation(x.Trigger, x.Sources, x.Key)).ToArray()), ["scenario_evidence_expected"] = 0,
            ["job_count"] = 3, ["baseline"] = baseline.DeepClone(), ["generated_at_utc"] = SemanticJson.Stamp(DateTimeOffset.UtcNow), ["source_contacted"] = false };
        string digest = Password.PasswordJson.Hash(plan); plan["plan_digest"] = digest; plan["confirmation"] = ConfirmPrefix + digest;
        return plan;
    }
}
