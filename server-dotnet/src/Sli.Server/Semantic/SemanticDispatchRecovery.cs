using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal sealed record SemanticRecoveryScope(Guid[] JobIds, DateTimeOffset NormalizedBefore, Func<string, string?> Configuration)
{
    internal string Mode => SemanticRuntimeSettings.InvestigationMode;
    internal SemanticRuntimeSettings Settings => new(true, true, false, true, false, false);
}

// The historic repair is deliberately pinned; it cannot become a general retry or archive reader.
internal static partial class SemanticDispatchRecovery
{
    internal const string RuleId = "investigation.account.unlock.after-lock";
    internal const int RuleVersion = 2;
    internal const string RuleSha = "5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e";
    internal const string ErrorCode = "UniqueViolation", Constraint = "semantic_correlation_candidate__candidate_id_evidence_order_key";
    internal const string CompletionError = "CheckViolation", CompletionConstraint = "semantic_correlation_dispatch_terminal";
    internal const string ConfirmPrefix = "REPAIR-SEMANTIC-DISPATCH-PARTITION:";
    internal static readonly IReadOnlyDictionary<Guid, (long Source, string Suffix)> Jobs = new Dictionary<Guid, (long, string)> {
        [Guid.Parse("10eac730-5285-5740-b605-577d3ef9f4c2")] = (6943209, "7291"),
        [Guid.Parse("75280b7d-4573-5bc9-9e0e-c1d3f6e897e3")] = (6486534, "6682"),
        [Guid.Parse("e24572a7-159d-517c-a284-a0eff96ac007")] = (6487797, "6295")
    };
    private static readonly (long Trigger, long[] Sources, string Key)[] Relations = [
        (6487797, [6442170, 6487797], "dispatch:2dfdf2e4219e728fcab50c8a65139153c7bd1b410ed72c0493afdec8ca7df7c4"),
        (6486534, [6436767, 6486534], "dispatch:9dd99c4a7bf00789c02b297270df71260e79096577bc4b1e6ccdba437717c037"),
        (6943209, [6923513, 6943209], "dispatch:5497fb27862a7026a64b5e77f41d8e0a3fa181d9429bffa34671b899eedebe23"),
        (6943209, [6874055, 6943209], "dispatch:b17e18e9d9fd11eb218a0b20b24175a8cf1ec427038c7700114f323a36767cfb")
    ];
    internal static void ValidateScope(Guid[] ids)
    {
        if (ids.Length == 0 || ids.Distinct().Count() != ids.Length || ids.Any(id => !Jobs.ContainsKey(id)))
            throw new InvalidOperationException("semantic dispatch recovery claim scope changed");
    }
    private static object?[] Errors => [ErrorCode, '"' + Constraint + '"', CompletionError, '"' + CompletionConstraint + '"'];
    internal static async Task RequeueAsync(ISemanticSession session, Guid[] ids, CancellationToken ct)
    {
        ValidateScope(ids);
        var rows = await session.QueryAsync(SemanticDispatchRecoverySql.Requeue, ct, [ids, ErrorCode, CompletionError, .. Errors]);
        var returned = rows.Select(r => Guid.Parse(r.Text("job_id")!)).ToArray();
        if (returned.Length != ids.Length || !returned.ToHashSet().SetEquals(ids)) throw new InvalidOperationException("semantic dispatch recovery requeue set changed");
    }
    internal static Task<JsonArray> ClaimAsync(ISemanticSession session, Guid[] ids, CancellationToken ct)
    {
        ValidateScope(ids);
        return session.QueryAsync(SemanticDispatchRecoverySql.Claim, ct, [ids, .. Errors, RuleId, RuleVersion, RuleSha, Guid.NewGuid()]);
    }
    internal static async Task CompleteAsync(ISemanticSession session, Guid id, Guid lease, CancellationToken ct)
    {
        var rows = await session.QueryAsync(SemanticDispatchRecoverySql.Complete, ct, id, lease);
        if (rows.Count != 1) throw new InvalidOperationException("semantic dispatch recovery lease was lost");
    }
    private static JsonObject Relation(long trigger, IEnumerable<long> ids, string key) => new() {
        ["trigger_source_event_id"] = trigger, ["source_event_ids"] = new JsonArray(ids.Select(x => JsonValue.Create(x)).ToArray()), ["contribution_key"] = key
    };
    internal static async Task<JsonArray> SnapshotAsync(ISemanticSession session, CancellationToken ct)
    {
        var rows = await session.QueryAsync(SemanticDispatchRecoverySql.Snapshot, ct, Jobs.Keys.Order().ToArray());
        foreach (var row in rows.OfType<JsonObject>()) {
            long trigger = row.Number("source_event_id");
            var relations = await session.QueryAsync(SemanticDispatchRecoverySql.Relations, ct, trigger, (int)row.Number("semantic_contract_version"), row.Text("normalizer_id"), row.Text("normalizer_version"), RuleId, RuleVersion, trigger);
            var accepted = new JsonArray(); var repairable = new JsonArray(); var blocking = new JsonArray();
            foreach (var relation in relations) {
                long[] ids = relation!["source_event_ids"]!.AsArray().Select(x => x!.Deserialize<long>()).ToArray();
                string? key = Relations.Where(x => x.Trigger == trigger && x.Sources.SequenceEqual(ids)).Select(x => x.Key).FirstOrDefault(k =>
                    SemanticJson.Hash(new JsonObject { ["rule_id"] = RuleId, ["rule_version"] = RuleVersion, ["contribution_key"] = k }) == relation.Text("candidate_key_hex"));
                var observed = Relation(trigger, ids, key ?? "unexpected-candidate-key:" + relation.Text("candidate_key_hex"));
                (key is not null && relation.Flag("contract_exact") ? accepted : key is not null && relation.Flag("repairable_contract_exact") ? repairable : blocking).Add(observed);
            }
            row["accepted_relations"] = accepted; row["repairable_relations"] = repairable; row["blocking_relations"] = blocking;
        }
        return rows;
    }
    internal static JsonObject LoadApplyPlan(string path, string digest, string confirmation)
    {
        JsonObject plan;
        try { plan = JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? throw new JsonException(); }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { throw new InvalidOperationException("semantic dispatch recovery plan file is invalid"); }
        var material = plan.DeepClone().AsObject(); material.Remove("plan_digest"); material.Remove("confirmation");
        if (Password.PasswordJson.Hash(material) != plan.Text("plan_digest")) throw new InvalidOperationException("semantic dispatch recovery plan digest is invalid");
        if (digest != plan.Text("plan_digest") || confirmation != plan.Text("confirmation") || confirmation != ConfirmPrefix + digest)
            throw new InvalidOperationException("exact semantic dispatch recovery confirmation required");
        return plan;
    }
    private static JsonNode? Redact(JsonNode? node) => node switch {
        JsonObject obj => new JsonObject(obj.Select(pair => new KeyValuePair<string, JsonNode?>(pair.Key,
            new[] { "password", "secret", "dsn", "credential", "token" }.Any(s => pair.Key.Contains(s, StringComparison.OrdinalIgnoreCase)) ? JsonValue.Create("[redacted]") : Redact(pair.Value)))),
        JsonArray array => new JsonArray(array.Select(Redact).ToArray()), _ => node?.DeepClone()
    };
    internal static JsonObject WriteAtomicAudit(string path, JsonObject payload)
    {
        var safe = Redact(payload)!.AsObject(); path = Path.GetFullPath(path); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = Path.Combine(Path.GetDirectoryName(path)!, "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try { File.WriteAllText(temporary, safe.ToJsonString(new JsonSerializerOptions { WriteIndented = true })); File.Move(temporary, path, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        var loaded = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        if (!JsonNode.DeepEquals(safe, loaded)) throw new InvalidOperationException("semantic dispatch recovery audit readback mismatch");
        return loaded;
    }
    internal static async Task<bool> WorkerIsLiveAsync(Func<Task<int?>> guard)
    {
        try { return await guard() != 0; } catch { return true; }
    }
    internal static async Task<JsonObject> DispatchAsync(Guid[] ids, DateTimeOffset boundary,
        Func<Task<(string Role, string Dsn)>> create, Func<string, Task> drop, Func<string, SemanticRecoveryScope, Task<JsonObject>> run, Func<string, string?> get)
    {
        ValidateScope(ids);
        var login = await create();
        try {
            string? Configuration(string key) => key switch {
                "ADLOG_SEMANTIC_WORKER_DSN" => login.Dsn, "ADLOG_SEMANTIC_RUNTIME_MODE" => SemanticRuntimeSettings.InvestigationMode,
                "ADLOG_SEMANTIC_WORKER_DSN_FILE" or "ADLOG_SEMANTIC_WORKER_PASSWORD" or "ADLOG_SEMANTIC_WORKER_PASSWORD_FILE" => null,
                "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED" or "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED" or "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED" => "0",
                "ADLOG_SEMANTIC_NORMALIZATION_ENABLED" or "ADLOG_SEMANTIC_ASSEMBLY_ENABLED" or "ADLOG_SEMANTIC_CORRELATION_ENABLED" => "1", _ => get(key)
            };
            return await run(login.Dsn, new(ids.ToArray(), boundary, Configuration));
        } finally { await drop(login.Role); }
    }
    internal static async Task<int> ReportAsync(Func<Task<JsonObject>> run, TextWriter output, TextWriter error)
    {
        try { await output.WriteLineAsync(Redact(await run())!.ToJsonString()); return 0; }
        catch (Exception e) { await error.WriteLineAsync(new JsonObject { ["status"] = "failed_closed", ["error_type"] = e.GetType().Name }.ToJsonString()); return 1; }
    }
}
