using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Semantic;

// semantic_production_control.py: retained range checkpoints and exact facts readback.
// Publication uses the existing producer; this controller never creates findings.
internal sealed class RetainedFactsControl(ISemanticDatabase database, string checkpointPath, string fingerprint,
    Action? admission = null)
{
    internal const string ConfirmationPrefix = "CHECK-STAGE8-EXACT-FACTS:";
    internal const string ControllerLock = "semantic_retained_v2_facts_controller";
    private static readonly string[] IdentityFields = ["host", "database", "role", "system_identifier", "port", "database_oid"];
    private static void Fail(string message) => throw new InvalidOperationException(message);

    private void Admit()
    {
        if (admission is not null) { admission(); return; }
        if (SemanticRuntimeSettings.Mode(Environment.GetEnvironmentVariable) != SemanticRuntimeSettings.FactsMode)
            Fail("retained facts requires explicit facts-v1 admission");
        SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable).Validate(SemanticRuntimeSettings.FactsMode, Environment.GetEnvironmentVariable);
    }

    internal static async Task<JsonObject> DatabaseIdentityAsync(ISemanticSession session, CancellationToken ct)
    {
        var basic = (await session.QueryAsync("select coalesce(inet_server_addr()::text,'') as host, current_database() as database, session_user as role", ct)).SingleOrDefault();
        JsonNode? strong;
        try {
            strong = (await session.QueryAsync("select system_identifier::text as system_identifier, inet_server_port()::text as port, (select oid::text from pg_database where datname=current_database()) as database_oid from pg_control_system()", ct)).SingleOrDefault();
        }
        catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.InsufficientPrivilege) {
            // Do not include PostgreSQL detail, query arguments or the original exception.
            throw new InvalidOperationException("retained facts identity requires read-only EXECUTE on pg_control_system(); ask the database administrator to review this prerequisite");
        }
        var identity = new JsonObject();
        foreach (string field in IdentityFields) {
            string value = (field is "host" or "database" or "role" ? basic : strong).Text(field) ?? "";
            if (value.Length == 0) Fail("retained facts database identity is unavailable");
            identity[field] = value;
        }
        return identity;
    }

    internal static JsonObject? Read(string path)
    {
        if (!File.Exists(path)) return null;
        try { return JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? throw new JsonException(); }
        catch (Exception error) when (error is IOException or JsonException) {
            throw new InvalidOperationException("retained facts checkpoint or manifest is invalid");
        }
    }

    internal static void Save(string path, JsonObject payload)
    {
        path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = Path.Combine(Path.GetDirectoryName(path)!, "." + Path.GetFileName(path) + "." + Guid.NewGuid() + ".tmp");
        try {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                JsonSerializer.Serialize(file, payload); file.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private void Validate(JsonObject checkpoint)
    {
        if (checkpoint.Text("checkpoint_type") != "retained_v2_semantic_facts") Fail("retained facts checkpoint type is invalid");
        if (checkpoint.Text("rules_fingerprint") != fingerprint) Fail("retained facts rules fingerprint mismatch");
        if (checkpoint["database_identity"] is not JsonObject identity || identity.Count != IdentityFields.Length
            || !IdentityFields.All(field => identity[field] is JsonValue value && value.TryGetValue<string>(out var text) && text.Length > 0))
            Fail("retained facts checkpoint database identity is missing or invalid; legacy checkpoints require operator-reviewed restart: preserve the old file, review the target, then archive the checkpoint and restart from event 1");
        if (checkpoint.Text("source") != "semantic_event_rows") Fail("retained facts checkpoint source is invalid");
        if (checkpoint.Number("range_start_event_id") != 1 || checkpoint.Number("batch_limit") != SemanticProducer.MaxBatch || !checkpoint.Flag("include_context"))
            Fail("retained facts checkpoint range or context contract is invalid");
        if (!Integer(checkpoint["frozen_high_watermark_event_id"], out long high) || !Integer(checkpoint["last_committed_event_id"], out long committed)
            || high < 0 || committed < 0 || committed > high) Fail("retained facts checkpoint bounds are invalid");
    }
    private static bool Integer(JsonNode? node, out long result)
    {
        return long.TryParse(node?.ToString(), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out result);
    }
    private static async Task RequireIdentity(ISemanticSession session, JsonObject checkpoint, CancellationToken ct)
    {
        if (!JsonNode.DeepEquals(checkpoint["database_identity"], await DatabaseIdentityAsync(session, ct)))
            Fail("retained facts checkpoint database identity mismatch");
    }
    private async Task<JsonObject> NewCheckpoint(CancellationToken ct)
    {
        await using var session = await database.OpenAsync(false, ct);
        var identity = await DatabaseIdentityAsync(session, ct);
        long high = (await session.QueryAsync("select coalesce(max(id),0) as high_watermark from semantic_event_rows", ct)).Single().Number("high_watermark");
        return new() { ["checkpoint_type"] = "retained_v2_semantic_facts", ["source"] = "semantic_event_rows", ["database_identity"] = identity,
            ["status"] = "active", ["created_at_utc"] = DateTimeOffset.UtcNow.ToString("O"), ["range_start_event_id"] = 1,
            ["frozen_high_watermark_event_id"] = high, ["last_committed_event_id"] = 0, ["rules_fingerprint"] = fingerprint,
            ["batch_limit"] = SemanticProducer.MaxBatch, ["include_context"] = true };
    }

    internal async Task<JsonObject> PlanAsync(CancellationToken ct)
    {
        Admit();
        var checkpoint = Read(checkpointPath);
        if (checkpoint is not null) {
            Validate(checkpoint);
            await using var session = await database.OpenAsync(false, ct);
            await RequireIdentity(session, checkpoint, ct);
            return new() { ["status"] = "retained_v2_facts_resume_ready", ["checkpoint_path"] = checkpointPath,
                ["checkpoint"] = checkpoint, ["production_changed"] = false, ["consumer"] = "existing_managed_facts_worker" };
        }
        var preview = await NewCheckpoint(ct);
        return new() { ["status"] = "retained_v2_facts_plan_ready", ["range_start_event_id"] = 1,
            ["observed_high_watermark_event_id"] = preview["frozen_high_watermark_event_id"].Copy(),
            ["database_identity"] = preview["database_identity"].Copy(), ["rules_fingerprint"] = fingerprint,
            ["batch_limit"] = SemanticProducer.MaxBatch, ["include_context"] = true, ["checkpoint_path"] = checkpointPath,
            ["production_changed"] = false, ["consumer"] = "existing_managed_facts_worker" };
    }

    internal async Task<JsonObject> PollAsync(CancellationToken ct)
    {
        Admit();
        // Reject unbound legacy files before even opening a selection transaction.
        if (Read(checkpointPath) is { } previous) Validate(previous);
        await using var controller = await database.OpenAsync(true, ct);
        if (!(await controller.QueryAsync("select pg_try_advisory_xact_lock(hashtext($1)) as acquired", ct, ControllerLock)).Single().Flag("acquired"))
            Fail("retained facts controller lock is busy");
        var checkpoint = Read(checkpointPath);
        if (checkpoint is null) { checkpoint = await NewCheckpoint(ct); Save(checkpointPath, checkpoint); }
        Validate(checkpoint);
        long high = checkpoint.Number("frozen_high_watermark_event_id"), committed = checkpoint.Number("last_committed_event_id");
        long[] ids;
        JsonObject producer;
        await using (var session = await database.OpenAsync(true, ct)) {
            await RequireIdentity(session, checkpoint, ct);
            ids = (await session.QueryAsync("select id from semantic_event_rows where id > $1 and id <= $2 order by id limit $3", ct,
                committed, high, SemanticProducer.MaxBatch)).Select(row => row.Number("id")).ToArray();
            producer = await PublishAsync(session, ids, ct);
            await session.CommitAsync(ct);
        }
        long next = ids.Length == 0 ? high : ids[^1];
        checkpoint["last_committed_event_id"] = next;
        checkpoint["status"] = ids.Length < SemanticProducer.MaxBatch ? "complete" : "active";
        checkpoint["updated_at_utc"] = DateTimeOffset.UtcNow.ToString("O");
        Save(checkpointPath, checkpoint);
        return new() { ["status"] = "retained_v2_facts_poll_complete", ["checkpoint_path"] = checkpointPath,
            ["from_event_id_exclusive"] = committed, ["to_event_id_inclusive"] = next, ["target_events"] = ids.Length,
            ["producer"] = producer, ["consumer"] = "existing_managed_facts_worker", ["production_changed"] = ids.Length > 0 };
    }
    internal static async Task<JsonObject> PublishAsync(ISemanticSession session, long[] ids, CancellationToken ct)
    {
        var selection = await SemanticProducer.ReadSelection(session, ids, SemanticRuntimeSettings.FactsMode, ct);
        await session.QueryAsync("set local role adlog_storage_worker", ct);
        int queued = await SemanticProducer.Enqueue(session, selection.Jobs, ct);
        var result = selection.Counters; result["queued"] = queued; return result;
    }

    internal const string QueueSql = """
        select job.source_event_id,job.status,
          (job.source_identity_json->>'id'=core.id::text
           and job.source_identity_json->>'normalized_hash'=encode(core.normalized_hash,'hex')) as identity_matches,
          exists(select 1 from public.normalized_events normalized where normalized.source_event_id=core.id
            and normalized.semantic_contract_version=$1 and normalized.normalizer_id=$2 and normalized.normalizer_version=$3
            and normalized.processing_status='normalized' and normalized.source_event_sha256=core.normalized_hash) as normalized
        from public.semantic_processing_outbox job left join semantic_event_rows core on core.id=job.source_event_id
        where job.source_event_id=any($4) and job.job_kind='normalize_event' and job.semantic_contract_version=$1
          and job.processor_id=$5 and job.processor_version=$6
        """;
    internal async Task<JsonObject> QueueStatusAsync(long[] ids, CancellationToken ct)
    {
        await using var session = await database.OpenAsync(false, ct);
        var rows = await session.QueryAsync(QueueSql, ct, 1, SemanticEvent.Normalizer, SemanticEvent.Version, ids, "semantic-shadow", SemanticEvent.Version);
        var states = new JsonObject { ["completed"] = 0, ["queued"] = 0, ["failed"] = 0, ["leased"] = 0, ["quarantined"] = 0, ["incomplete"] = 0 };
        var seen = new HashSet<long>();
        foreach (var row in rows) {
            long id = row.Number("source_event_id"); string status = row.Text("status") ?? "";
            if (!ids.Contains(id) || !seen.Add(id) || !states.ContainsKey(status) || status == "incomplete")
                Fail("exact facts check queue coverage is ambiguous or invalid");
            if (!row.Flag("identity_matches") || status == "completed" && !row.Flag("normalized")) status = "incomplete";
            states[status] = states.Number(status) + 1;
        }
        states["not_enqueued"] = ids.Distinct().Count() - seen.Count;
        return states;
    }

    private async Task<JsonObject> CheckIdentity(long[] ids, CancellationToken ct)
    {
        await using var session = await database.OpenAsync(false, ct);
        var identity = (await session.QueryAsync("select coalesce(inet_server_addr()::text,'') as host, current_database() as database, current_user as role", ct)).Single()!.DeepClone().AsObject();
        if (new[] { "host", "database", "role" }.Any(field => string.IsNullOrEmpty(identity.Text(field)))) Fail("facts check database identity is unavailable");
        var found = (await session.QueryAsync("select id from semantic_event_rows where id=any($1) order by id", ct, ids)).Select(row => row.Number("id"));
        if (!found.SequenceEqual(ids)) Fail("facts check exact event IDs are unavailable");
        return identity;
    }
    private static long[] ExactIds(long[] ids)
    {
        if (ids.Length == 0 || ids.Any(id => id <= 0) || ids.Distinct().Count() != ids.Length) Fail("facts check IDs are invalid");
        return ids.Order().ToArray();
    }
    internal async Task<JsonObject> CheckPlanAsync(long[] eventIds, string manifestPath, CancellationToken ct)
    {
        var ids = ExactIds(eventIds); var identity = await CheckIdentity(ids, ct);
        string digest = SemanticJson.Hash(new JsonObject { ["check_type"] = "exact_retained_semantic_facts_v1", ["event_ids"] = JsonSerializer.SerializeToNode(ids),
            ["rules_fingerprint"] = fingerprint, ["database_identity"] = identity.Copy(), ["include_context"] = true, ["runtime_mode"] = SemanticRuntimeSettings.FactsMode });
        return new() { ["status"] = "exact_retained_facts_check_plan_ready", ["event_ids"] = JsonSerializer.SerializeToNode(ids),
            ["rules_fingerprint"] = fingerprint, ["database_identity"] = identity, ["plan_digest"] = digest,
            ["confirmation"] = ConfirmationPrefix + digest, ["manifest_path"] = manifestPath, ["production_changed"] = false };
    }

    internal async Task<JsonObject> CheckAsync(long[] eventIds, string manifestPath, string digest, string confirmation,
        Func<long[], bool, CancellationToken, Task<JsonObject>> execute, CancellationToken ct)
    {
        if (confirmation != ConfirmationPrefix + digest) Fail("exact facts check confirmation required");
        var ids = ExactIds(eventIds); var plan = await CheckPlanAsync(ids, manifestPath, ct);
        if (digest != plan.Text("plan_digest")) Fail("exact facts check plan digest mismatch");
        var expected = new JsonObject { ["manifest_type"] = "exact_retained_semantic_facts_check_v1", ["event_ids"] = plan["event_ids"].Copy(),
            ["rules_fingerprint"] = fingerprint, ["database_identity"] = plan["database_identity"].Copy(), ["plan_digest"] = digest,
            ["include_context"] = true, ["runtime_mode"] = SemanticRuntimeSettings.FactsMode };
        var manifest = Read(manifestPath);
        if (manifest is null) { manifest = expected.DeepClone().AsObject(); manifest["state"] = "intent"; manifest["created_at_utc"] = DateTimeOffset.UtcNow.ToString("O"); Save(manifestPath, manifest); }
        else if (expected.Any(pair => !JsonNode.DeepEquals(pair.Value, manifest[pair.Key]))
            || manifest.Text("state") is not ("intent" or "published" or "partial" or "processed" or "no_admitted_events")) Fail("exact facts check manifest does not match plan");
        if (manifest.Text("state") is "processed" or "no_admitted_events") {
            var before = await QueueStatusAsync(ids, ct);
            if (before.Number("completed") + before.Number("not_enqueued") == ids.Length) {
                var done = manifest.DeepClone().AsObject(); done["status"] = "exact_retained_facts_check_already_processed"; return done;
            }
        }
        var execution = await execute(ids, manifest.Text("state") == "intent", ct);
        string response;
        if (execution.Text("status") == "blocked") { manifest["result"] = execution; response = "exact_retained_facts_check_blocked"; }
        else {
            var queue = await QueueStatusAsync(ids, ct); var processing = execution["runtime"]?["processing"];
            bool partial = processing.Number("failed") > 0 || new[] { "failed", "quarantined", "incomplete", "queued", "leased" }.Any(key => queue.Number(key) > 0);
            manifest["state"] = partial ? "partial" : queue.Number("not_enqueued") == ids.Length && processing.Number("completed") == 0 ? "no_admitted_events" : "processed";
            manifest["result"] = new JsonObject { ["producer"] = (execution["producer"] ?? manifest["result"]?["producer"]).Copy(), ["runtime"] = execution["runtime"].Copy(), ["queue"] = queue };
            response = "exact_retained_facts_check_complete";
        }
        manifest["updated_at_utc"] = DateTimeOffset.UtcNow.ToString("O"); Save(manifestPath, manifest);
        var result = manifest.DeepClone().AsObject(); result["status"] = response; return result;
    }
}
