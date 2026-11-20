using System.Text.Json.Nodes;
using static Sli.Server.Semantic.SemanticRetainedManifest;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticRetainedControl
{
    internal static long[] ExactIds(IEnumerable<long> values)
    {
        var ids = values.ToArray();
        // This is the reference exact-check input contract, not a worker lifetime limit.
        if (ids.Length is < 1 or > 16 || ids.Any(id => id <= 0) || ids.Distinct().Count() != ids.Length) throw new InvalidOperationException("facts check IDs are invalid");
        return ids.Order().ToArray();
    }
    private async Task<JsonObject> ExactIdentity(long[] ids, CancellationToken ct)
    {
        await using var session = await database.OpenAsync(false, ct); var identity = await Identity(session, false, ct, callerRole: true);
        if (!(await session.QueryAsync("select id from semantic_event_rows where id=any($1) order by id", ct, ids)).Select(r => r.Number("id")).SequenceEqual(ids)) throw new InvalidOperationException("facts check exact event IDs are unavailable");
        return identity;
    }
    internal static string ExactDigest(long[] ids, string fingerprint, JsonObject identity) => Digest(new JsonObject { ["check_type"] = "exact_retained_semantic_facts_v1", ["event_ids"] = Ids(ids), ["rules_fingerprint"] = fingerprint,
        ["database_identity"] = identity.DeepClone(), ["include_context"] = true, ["runtime_mode"] = "facts-v1", ["max_consume"] = 16 });
    internal async Task<JsonObject> ExactPlan(IEnumerable<long> values, CancellationToken ct)
    {
        var ids = ExactIds(values); string fingerprint = RulesFingerprint(); var identity = await ExactIdentity(ids, ct); string digest = ExactDigest(ids, fingerprint, identity);
        return new() { ["status"] = "exact_retained_facts_check_plan_ready", ["event_ids"] = Ids(ids), ["rules_fingerprint"] = fingerprint, ["database_identity"] = identity, ["plan_digest"] = digest, ["confirmation"] = ExactPrefix + digest, ["production_changed"] = false };
    }
    internal static JsonObject QueueStatus(long[] ids, JsonArray rows)
    {
        var states = new JsonObject(new[] { "completed", "queued", "failed", "leased", "quarantined", "incomplete", "not_enqueued" }.Select(s => new KeyValuePair<string, JsonNode?>(s, JsonValue.Create(0L)))); var seen = new HashSet<long>();
        foreach (var row in rows) {
            long id = row.Number("source_event_id"); string status = row.Text("status") ?? "";
            if (!ids.Contains(id) || !seen.Add(id) || status is not ("completed" or "queued" or "failed" or "leased" or "quarantined")) throw new InvalidOperationException("exact facts check queue coverage is ambiguous or invalid");
            string key = !row.Flag("identity_matches") || status == "completed" && !row.Flag("normalized") ? "incomplete" : status;
            states[key] = states.Number(key) + 1;
        }
        states["not_enqueued"] = ids.Length - seen.Count; return states;
    }
    private async Task<JsonObject> ExactQueue(long[] ids, CancellationToken ct)
    {
        await using var session = await database.OpenAsync(false, ct);
        return QueueStatus(ids, await session.QueryAsync(SemanticRetainedSql.ExactQueue, ct, 1, SemanticEvent.Normalizer, SemanticEvent.Version, ids, 1, "semantic-shadow", SemanticEvent.Version));
    }
    internal async Task<JsonObject> ExactCheck(IEnumerable<long> values, string digest, string? confirmation, CancellationToken ct,
        Func<long[], CancellationToken, Task<JsonObject>>? consume = null)
    {
        var ids = ExactIds(values);
        if (confirmation != ExactPrefix + digest) throw new InvalidOperationException("exact facts check confirmation required");
        var plan = await ExactPlan(ids, ct);
        if (digest != plan.Text("plan_digest")) throw new InvalidOperationException("exact facts check plan digest mismatch");
        var expected = new JsonObject { ["manifest_type"] = "exact_retained_semantic_facts_check_v1", ["event_ids"] = Ids(ids), ["rules_fingerprint"] = plan["rules_fingerprint"].Copy(), ["database_identity"] = plan["database_identity"].Copy(), ["plan_digest"] = digest, ["include_context"] = true, ["runtime_mode"] = "facts-v1" };
        var manifest = Read(ExactPath);
        if (manifest is null) { manifest = expected.DeepClone().AsObject(); manifest["state"] = "intent"; manifest["result"] = null; manifest["created_at_utc"] = DateTimeOffset.UtcNow; Write(ExactPath, manifest); }
        else if (expected.Any(p => !JsonNode.DeepEquals(p.Value, manifest[p.Key])) || manifest.Text("state") is not ("intent" or "published" or "partial" or "processed" or "no_admitted_events")) throw new InvalidOperationException("exact facts check manifest does not match plan");
        if (manifest.Text("state") is "processed" or "no_admitted_events") { var q = await ExactQueue(ids, ct); if (q.Number("completed") + q.Number("not_enqueued") == ids.Length) { manifest["status"] = "exact_retained_facts_check_already_processed"; return manifest; } }
        ISemanticSession held;
        try { held = await Lock(ProductionLock, ct); }
        catch (InvalidOperationException error) when (error.Message == "retained controller lock is busy") {
            manifest["result"] = new JsonObject { ["status"] = "blocked", ["reason"] = "semantic_production_worker_lock_held" }; Write(ExactPath, manifest); manifest["status"] = "exact_retained_facts_check_blocked"; return manifest;
        }
        JsonObject runtime; JsonNode? producer = manifest["result"]?["producer"].Copy();
        await using (held) {
            if (manifest.Text("state") == "intent") {
                await using var session = await database.OpenAsync(true, ct); producer = await Publish(session, ids, false, ct); await session.CommitAsync(ct);
            }
            runtime = await (consume ?? ConsumeExact)(ids, ct);
        }
        var queue = await ExactQueue(ids, ct); var processing = runtime["processing"];
        string state = processing.Number("failed") + queue.Number("failed") + queue.Number("quarantined") + queue.Number("incomplete") + queue.Number("queued") + queue.Number("leased") > 0 ? "partial"
            : queue.Number("not_enqueued") == ids.Length && processing.Number("completed") == 0 ? "no_admitted_events" : "processed";
        manifest["state"] = state; manifest["result"] = new JsonObject { ["producer"] = producer, ["runtime"] = runtime, ["queue"] = queue }; manifest["updated_at_utc"] = DateTimeOffset.UtcNow; Write(ExactPath, manifest);
        manifest["status"] = "exact_retained_facts_check_complete"; return manifest;
    }
    private static async Task<JsonObject> ConsumeExact(long[] ids, CancellationToken ct)
    {
        await using var runtime = Password.PasswordProducerRuntime.Create(); return await RunExact(runtime, ids, ct);
    }
    internal static async Task<JsonObject> ConsumeExactWithDsn(long[] ids, string dsn, CancellationToken ct)
    {
        await using var runtime = Password.PasswordProducerRuntime.Create(name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? dsn : null, _ => throw new InvalidOperationException("exact_worker_secret_file_unexpected"));
        return await RunExact(runtime, ids, ct);
    }
    private static async Task<JsonObject> RunExact(Password.PasswordProducerRuntime runtime, long[] ids, CancellationToken ct)
    {
        // Fixed facts settings are local to this run; inherited admission is never modified.
        await using var db = await runtime.OpenAsync(ct);
        await using (var tx = await db.BeginTransactionAsync(ct)) { await SemanticProduction.GuardAsync(new SemanticSession(db, tx), SemanticRuntimeSettings.FactsMode, ct); await tx.CommitAsync(ct); }
        var production = new SemanticProduction(runtime, new(true, true, false, false, false, false), SemanticRuntimeSettings.FactsMode, ids.Length, exactSourceIds: ids);
        var processing = await production.ProcessOutbox(db, ct);
        return new() { ["status"] = processing.Number("failed") > 0 ? "partial" : "ok", ["runtime_mode"] = "facts-v1", ["processing"] = processing,
            ["dispatch"] = new JsonObject { ["completed"] = 0, ["failed"] = 0, ["relations"] = 0 }, ["risk_queued"] = 0, ["findings_created"] = 0 };
    }
}
