using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Semantic;

// Local progress only; source payloads and source credentials never enter these files.
internal static class SemanticRetainedManifest
{
    internal const string V1 = "retained_security_events_vocabulary_v1", V2 = "retained_security_events_vocabulary_v2";
    internal const string SupersedeReason = "routine_logons_are_exact_context_only";
    internal const string ContextStrategy = "successful_password_reset_same_domain_sid_within_1h";
    internal static readonly int[] Vocabulary = [4740,4767,4723,4724,4720,4722,4725,4726,4738,4781,4728,4729,4732,4733,4756,4757,4727,4730,4737,4731,4734,4735,4754,4755,4758,4764,4624,4625,4771,4776,4719,1102];
    internal static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    internal static string Digest(JsonNode value) => Password.PasswordJson.Hash(value);
    internal static bool IsHash(string? text) => text is not null && Regex.IsMatch(text, "\\A[0-9a-f]{64}\\z");
    internal static JsonObject Normalizer => new() { ["id"] = SemanticEvent.Normalizer, ["version"] = SemanticEvent.Version };
    internal static JsonObject Assembler => new() { ["id"] = "semantic-action-assembler", ["version"] = "1.1" };
    internal static JsonObject ProcessingContract => new() { ["claim_protocol_version"] = 1, ["semantic_contract_version"] = 1,
        ["processor_id"] = "semantic-shadow", ["processor_version"] = SemanticEvent.Version, ["normalizer"] = Normalizer, ["assembler"] = Assembler };
    internal static string Provider(int id) => id == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing";
    internal static JsonObject Predicate(int id) => new() { ["channel"] = "Security", ["provider"] = Provider(id), ["event_id"] = id };
    internal static JsonObject EmptyCohort => new() { ["high_watermark"] = 0, ["count"] = 0, ["cohort_digest"] = Hash(""), ["min_id"] = null, ["max_id"] = null };
    internal static JsonObject EmptyContext => new() { ["count"] = 0, ["cohort_digest"] = Hash(""), ["reset_high_watermark"] = 0 };
    internal static JsonArray Ids(IEnumerable<long> ids) => new(ids.Select(x => (JsonNode)JsonValue.Create(x)!).ToArray());
    internal static string SelectionFingerprint(int batch, bool v2)
    {
        if (batch < 1 || batch > SemanticProducer.MaxBatch) throw new InvalidOperationException("security history manifest batch limit is invalid");
        string v1 = Digest(new JsonObject { ["source"] = "semantic_event_rows", ["runtime_mode"] = "investigation-v1", ["semantic_contract_version"] = 1,
            ["normalizer"] = Normalizer, ["assembler"] = Assembler, ["vocabulary"] = Ids(Vocabulary.Select(x => (long)x)), ["batch_limit"] = batch,
            ["moves_collection_cursors"] = false, ["contacts_sources"] = false });
        return v2 ? Digest(new JsonObject { ["v1_selection_fingerprint"] = v1, ["manifest_type"] = V2, ["logon_semantic_scope"] = ContextStrategy }) : v1;
    }
    internal static JsonObject Cohorts(JsonObject snapshot)
    {
        var result = new JsonObject();
        foreach (int id in Vocabulary) result[id.ToString()] = snapshot["cohorts"]?[id.ToString()]?.DeepClone() ?? EmptyCohort;
        return result;
    }
    internal static string PlanDigest(JsonObject snapshot, string? predecessor = null)
        => Digest(new JsonObject { ["plan_type"] = V2, ["database_identity"] = snapshot["database_identity"].Copy(), ["cohorts"] = Cohorts(snapshot),
            ["semantic_context_cohort"] = snapshot["semantic_context_cohort"].Copy(), ["selection_fingerprint"] = SelectionFingerprint(SemanticProducer.MaxBatch, true),
            ["runtime_mode"] = "investigation-v1", ["supersedes"] = predecessor is null ? null : Predecessor(predecessor) });
    internal static JsonObject Predecessor(string digest) => new() { ["manifest_type"] = V1, ["plan_digest"] = digest, ["reason"] = SupersedeReason };
    internal static JsonObject New(JsonObject snapshot, string digest, string? predecessor = null, bool v2 = true, int batch = SemanticProducer.MaxBatch)
    {
        var events = new JsonObject(); var cohorts = Cohorts(snapshot);
        foreach (int id in Vocabulary) {
            var entry = cohorts[id.ToString()]!.DeepClone().AsObject(); long count = entry.Number("count");
            entry["predicate"] = Predicate(id); entry["cursor"] = 0; entry["normalized_count"] = 0; entry["outbox_count"] = 0; entry["action_count"] = 0;
            entry["samples"] = new JsonObject { ["incomplete_ids"] = new JsonArray(), ["errors"] = new JsonArray() };
            if (v2) {
                entry["raw_retained_count"] = count; entry["raw_cohort_digest"] = entry["cohort_digest"].Copy();
                entry["semantic_scope"] = id == 4624 ? "password_reset_context_only" : "all_retained";
                entry["semantic_expected_count"] = id == 4624 ? snapshot["semantic_context_cohort"].Number("count") : count;
                entry["semantic_context_digest"] = id == 4624 ? snapshot["semantic_context_cohort"]?["cohort_digest"].Copy() : null;
                if (id == 4624) { entry["semantic_context_reset_high_watermark"] = snapshot["semantic_context_cohort"].Number("reset_high_watermark"); count = entry.Number("semantic_expected_count"); entry["count"] = count; }
            }
            entry["state"] = count == 0 ? "no_retained_events" : "planned"; entry["terminal_reason"] = count == 0 ? "no_retained_events" : null;
            events[id.ToString()] = entry;
        }
        var result = new JsonObject { ["manifest_type"] = v2 ? V2 : V1, ["created_at_utc"] = DateTimeOffset.UtcNow, ["updated_at_utc"] = DateTimeOffset.UtcNow,
            ["database_identity"] = snapshot["database_identity"].Copy(), ["runtime_mode"] = "investigation-v1", ["source"] = "semantic_event_rows", ["semantic_contract_version"] = 1,
            ["normalizer"] = Normalizer, ["assembler"] = Assembler, ["vocabulary"] = Ids(Vocabulary.Select(x => (long)x)), ["selection_fingerprint"] = SelectionFingerprint(batch, v2),
            ["batch_limit"] = batch, ["moves_collection_cursors"] = false, ["contacts_sources"] = false, ["plan_digest"] = digest, ["events"] = events };
        if (v2) { result["supersedes"] = predecessor is null ? null : Predecessor(predecessor); result["semantic_context_strategy"] = ContextStrategy; }
        Validate(result, snapshot["database_identity"]!.AsObject()); return result;
    }
    internal static readonly Dictionary<string, string> Reasons = new() {
        ["no_retained_events"] = "no_retained_events", ["complete"] = "current_version_normalized_hash_reconciled", ["incomplete_original"] = "frozen_original_integrity_mismatch",
        ["incomplete_normalization"] = "current_version_non_unknown_normalization_missing", ["blocked"] = "operator_blocked_after_evidence", ["failed"] = "failed_current_version_work", ["quarantined"] = "quarantined_current_version_work" };
    internal static void State(JsonObject entry, string state) { entry["state"] = state; entry["terminal_reason"] = Reasons.GetValueOrDefault(state); }
    internal static void Validate(JsonObject manifest, JsonObject identity)
    {
        bool v2 = manifest.Text("manifest_type") == V2; int batch = checked((int)manifest.Number("batch_limit"));
        if (manifest.Text("manifest_type") is not (V1 or V2)) throw new InvalidOperationException("security history manifest type is invalid");
        var expected = new JsonObject { ["database_identity"] = identity.DeepClone(), ["runtime_mode"] = "investigation-v1", ["source"] = "semantic_event_rows", ["semantic_contract_version"] = 1,
            ["normalizer"] = Normalizer, ["assembler"] = Assembler, ["vocabulary"] = Ids(Vocabulary.Select(x => (long)x)), ["selection_fingerprint"] = SelectionFingerprint(batch, v2), ["moves_collection_cursors"] = false, ["contacts_sources"] = false };
        if (expected.Any(p => !JsonNode.DeepEquals(p.Value, manifest[p.Key])) || !IsHash(manifest.Text("plan_digest"))) throw new InvalidOperationException("security history manifest immutable contract changed");
        if (v2 && (manifest.Text("semantic_context_strategy") != ContextStrategy || manifest["supersedes"] is JsonNode p &&
            (p.Text("manifest_type") != V1 || p.Text("reason") != SupersedeReason || !IsHash(p.Text("plan_digest"))))) throw new InvalidOperationException("security history v2 supersedes contract is invalid");
        if (manifest["events"] is not JsonObject events || events.Count != Vocabulary.Length || Vocabulary.Any(id => events[id.ToString()] is not JsonObject)) throw new InvalidOperationException("security history manifest vocabulary is invalid");
        foreach (int id in Vocabulary) {
            var e = events[id.ToString()]!; string state = e.Text("state") ?? "";
            if (!JsonNode.DeepEquals(e["predicate"], Predicate(id)) || e.Number("cursor") < 0 || e.Number("cursor") > e.Number("high_watermark")) throw new InvalidOperationException("security history manifest cursor or predicate is invalid");
            if (!Reasons.ContainsKey(state) && state is not ("planned" or "publishing" or "queued" or "processing") || e.Text("terminal_reason") != Reasons.GetValueOrDefault(state)) throw new InvalidOperationException("security history state reason is invalid");
            if (e.Number("count") < 0 || (e.Number("count") == 0) != (state == "no_retained_events")) throw new InvalidOperationException("security history empty cohort state is invalid");
            if (v2 && (e.Number("semantic_expected_count") < 0 || e.Number("semantic_expected_count") > e.Number("raw_retained_count") || e.Number("count") != e.Number("semantic_expected_count") ||
                (id == 4624 ? e.Text("semantic_scope") != "password_reset_context_only" || !IsHash(e.Text("semantic_context_digest")) || e.Number("semantic_context_reset_high_watermark") != events["4724"].Number("high_watermark")
                : e.Text("semantic_scope") != "all_retained" || e.Number("count") != e.Number("raw_retained_count") || e["semantic_context_digest"] is not null))) throw new InvalidOperationException("security history v2 semantic coverage is invalid");
        }
    }
    internal static JsonObject Highs(JsonObject manifest) => new(Vocabulary.Select(id => new KeyValuePair<string, JsonNode?>(id.ToString(), manifest["events"]![id.ToString()]!["high_watermark"].Copy())));
    internal static int[] Mismatches(JsonObject manifest, JsonObject snapshot)
    {
        bool v2 = manifest.Text("manifest_type") == V2; var cohorts = Cohorts(snapshot);
        return Vocabulary.Where(id => new[] { "high_watermark", "count", "cohort_digest", "min_id", "max_id" }.Any(field =>
            !JsonNode.DeepEquals(manifest["events"]![id.ToString()]![v2 && field == "count" ? "raw_retained_count" : v2 && field == "cohort_digest" ? "raw_cohort_digest" : field], cohorts[id.ToString()]![field]))).ToArray();
    }
    internal static JsonObject? Read(string path) => !File.Exists(path) ? null : JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? throw new InvalidOperationException("retained checkpoint is invalid");
    internal static void Write(string path, JsonObject value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        string temporary = Path.Combine(Path.GetDirectoryName(path)!, "." + Path.GetFileName(path) + "." + Guid.NewGuid() + ".tmp");
        try { using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write)) { var bytes = Encoding.UTF8.GetBytes(value.ToJsonString()); file.Write(bytes); file.Flush(true); } File.Move(temporary, path, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
