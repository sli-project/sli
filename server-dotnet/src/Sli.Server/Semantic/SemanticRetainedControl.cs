using System.Text.Json.Nodes;
using static Sli.Server.Semantic.SemanticRetainedManifest;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticRetainedControl(ISemanticDatabase database, string directory, Func<string, string?>? environment = null,
    Action<string, JsonObject>? checkpointWriter = null)
{
    internal const string FactsLock = "semantic_retained_v2_facts_controller", HistoryLock = "semantic_retained_security_history_vocabulary_controller";
    internal const string ProductionLock = "ad_log_reports_runtime_semantic_production_worker";
    internal const string PollPrefix = "POLL-SECURITY-HISTORY:", CheckPrefix = "CHECK-SECURITY-HISTORY:", SupersedePrefix = "SUPERSEDE-SECURITY-HISTORY:", ExactPrefix = "CHECK-STAGE8-EXACT-FACTS:";
    internal string FactsPath => Path.Combine(directory, "semantic-retained-facts-checkpoint.json");
    internal string HistoryPath => Path.Combine(directory, "retained-security-history-vocabulary.json");
    internal string ExactPath => Path.Combine(directory, "semantic-exact-facts-check.json");
    private void Write(string path, JsonObject value) => (checkpointWriter ?? SemanticRetainedManifest.Write)(path, value);
    private void Admit(string mode)
    {
        var get = environment ?? Environment.GetEnvironmentVariable;
        if (SemanticProducer.RuntimeMode(get) != mode) throw new InvalidOperationException(mode == SemanticRuntimeSettings.FactsMode ? "retained facts requires explicit facts-v1 admission" : "security history requires explicit investigation-v1 admission");
    }
    private async Task<ISemanticSession> Lock(string name, CancellationToken ct)
    {
        var session = await database.OpenAsync(true, ct);
        try { if (!(await session.QueryAsync("select pg_try_advisory_xact_lock(hashtextextended($1,0)) as locked", ct, name))[0].Flag("locked")) throw new InvalidOperationException("retained controller lock is busy"); return session; }
        catch { await session.DisposeAsync(); throw; }
    }
    internal static async Task<JsonObject> Identity(ISemanticSession session, bool extended, CancellationToken ct, bool callerRole = false)
    {
        var identity = (await session.QueryAsync(callerRole ? "select coalesce(inet_server_addr()::text,'') as host,current_database() as database,current_user as role" : "select coalesce(inet_server_addr()::text,'') as host,current_database() as database,session_user as role", ct)).Single()!.AsObject();
        if (extended) {
            var cluster = (await session.QueryAsync("select system_identifier::text as system_identifier,inet_server_port()::text as port,(select oid::text from pg_database where datname=current_database()) as database_oid from pg_control_system()", ct)).Single()!;
            foreach (string field in new[] { "system_identifier", "port", "database_oid" }) identity[field] = cluster[field].Copy();
        }
        if (identity.Any(p => string.IsNullOrEmpty(p.Value?.ToString()))) throw new InvalidOperationException("retained database identity is unavailable");
        return identity.DeepClone().AsObject();
    }
    private async Task<JsonObject> CurrentIdentity(CancellationToken ct)
    { await using var session = await database.OpenAsync(false, ct); return await Identity(session, false, ct); }
    internal static void RequireCompatibleWorker(JsonNode? row)
    {
        var details = row?["details_json"];
        if (details is JsonValue text && text.TryGetValue<string>(out var json)) { try { details = JsonNode.Parse(json); } catch (System.Text.Json.JsonException) { details = null; } }
        if (row.Text("status") is not ("running" or "idle") || details is not JsonObject || details.Text("runtime_mode") != "investigation-v1" || details["manual_runtime"] is not JsonValue value || !value.TryGetValue<bool>(out bool manual) || manual || details["processing_contract"] is not JsonObject contract || ProcessingContract.Any(p => !JsonNode.DeepEquals(contract[p.Key], p.Value)))
            throw new InvalidOperationException("security history requires a fresh compatible managed investigation worker");
    }
    private async Task RequireWorker(CancellationToken ct)
    {
        await using var session = await database.OpenAsync(false, ct);
        RequireCompatibleWorker((await session.QueryAsync("select status,phase,details_json from runtime_worker_heartbeats where worker_name='semantic' and status in ('running','idle') and heartbeat_at>=now()-(greatest(180,expected_interval_seconds*3)*interval '1 second')", ct)).SingleOrDefault());
    }
    internal async Task<JsonObject> FactsPoll(CancellationToken ct)
    {
        await using var held = await Lock(FactsLock, ct); Admit(SemanticRuntimeSettings.FactsMode);
        string fingerprint = RulesFingerprint(); var checkpoint = Read(FactsPath);
        if (checkpoint is null) {
            await using var snapshot = await database.OpenAsync(false, ct);
            var identity = await Identity(snapshot, true, ct);
            long high = (await snapshot.QueryAsync("select coalesce(max(id),0) as high_watermark from semantic_event_rows", ct)).Single().Number("high_watermark");
            checkpoint = new JsonObject { ["checkpoint_type"] = "retained_v2_semantic_facts", ["database_identity"] = identity,
                ["status"] = "active", ["created_at_utc"] = DateTimeOffset.UtcNow, ["range_start_event_id"] = 1, ["frozen_high_watermark_event_id"] = high,
                ["last_committed_event_id"] = 0, ["rules_fingerprint"] = fingerprint, ["batch_limit"] = SemanticProducer.MaxBatch, ["include_context"] = true };
            Write(FactsPath, checkpoint);
        }
        if (checkpoint.Text("rules_fingerprint") != fingerprint) throw new InvalidOperationException("retained facts rules fingerprint mismatch");
        long after = checkpoint.Number("last_committed_event_id"), watermark = checkpoint.Number("frozen_high_watermark_event_id");
        if (checkpoint.Text("checkpoint_type") != "retained_v2_semantic_facts" || checkpoint.Number("range_start_event_id") != 1 || checkpoint.Number("batch_limit") != SemanticProducer.MaxBatch || !checkpoint.Flag("include_context") || after < 0 || watermark < after || checkpoint["database_identity"] is not JsonObject stored || stored.Count != 6 || stored.Any(p => string.IsNullOrEmpty(p.Value?.ToString()))) throw new InvalidOperationException("retained facts checkpoint is invalid");
        long[] ids; JsonObject published;
        await using (var session = await database.OpenAsync(true, ct)) {
            if (!JsonNode.DeepEquals(checkpoint["database_identity"], await Identity(session, true, ct))) throw new InvalidOperationException("retained facts checkpoint database identity mismatch");
            ids = (await session.QueryAsync("select id from semantic_event_rows where id>$1 and id<=$2 order by id limit $3", ct, after, watermark, SemanticProducer.MaxBatch)).Select(r => r.Number("id")).ToArray();
            published = await Publish(session, ids, false, ct); await session.CommitAsync(ct);
        }
        checkpoint["last_committed_event_id"] = ids.Length == 0 ? watermark : ids[^1]; checkpoint["status"] = ids.Length < SemanticProducer.MaxBatch ? "complete" : "active"; checkpoint["updated_at_utc"] = DateTimeOffset.UtcNow;
        Write(FactsPath, checkpoint);
        return new() { ["status"] = "retained_v2_facts_poll_complete", ["from_event_id_exclusive"] = after, ["to_event_id_inclusive"] = checkpoint["last_committed_event_id"].Copy(), ["target_events"] = ids.Length, ["producer"] = published, ["consumer"] = "existing_managed_facts_worker", ["production_changed"] = ids.Length > 0 };
    }
    internal async Task<JsonObject> HistoryPlan(CancellationToken ct)
    {
        Admit(SemanticRuntimeSettings.InvestigationMode); var manifest = Read(HistoryPath);
        if (manifest is null) {
            var snapshot = await Snapshot(null, true, ct); string digest = PlanDigest(snapshot);
            snapshot["status"] = "security_history_v2_plan_ready"; snapshot["plan_digest"] = digest; snapshot["confirmation"] = PollPrefix + digest; snapshot["production_changed"] = false; return snapshot;
        }
        Validate(manifest, await CurrentIdentity(ct));
        if (manifest.Text("manifest_type") == V1) return new() { ["status"] = "security_history_explicit_supersede_required", ["production_changed"] = false };
        return new() { ["status"] = "security_history_resume_ready", ["manifest"] = manifest, ["plan_digest"] = manifest["plan_digest"].Copy(), ["confirmation"] = PollPrefix + manifest.Text("plan_digest"), ["production_changed"] = false };
    }
    internal static bool ExactPublication(long[] ids, JsonObject published) => published.Number("scanned") == ids.Length && published.Number("queued") == ids.Length &&
        new[] { "unknown_queued", "unknown_suppressed", "noise_skipped", "context_skipped" }.All(key => published.Number(key) == 0);
    internal async Task<JsonObject> HistoryPoll(string confirmation, CancellationToken ct)
    {
        var plan = await HistoryPlan(ct);
        if (plan.Text("status") == "security_history_explicit_supersede_required") throw new InvalidOperationException("security history v1 requires explicit supersede before poll");
        if (confirmation != plan.Text("confirmation")) throw new InvalidOperationException("security history poll confirmation required");
        await using var held = await Lock(HistoryLock, ct); Admit(SemanticRuntimeSettings.InvestigationMode); await RequireWorker(ct);
        var manifest = Read(HistoryPath);
        if (manifest is null) {
            var snapshot = await Snapshot(null, true, ct); string digest = PlanDigest(snapshot);
            if (confirmation != PollPrefix + digest) throw new InvalidOperationException("security history poll plan changed");
            manifest = New(snapshot, digest); Write(HistoryPath, manifest);
        } else { Validate(manifest, await CurrentIdentity(ct)); if (confirmation != PollPrefix + manifest.Text("plan_digest")) throw new InvalidOperationException("security history poll plan changed"); }
        var events = manifest["events"]!.AsObject();
        JsonObject Waiting() => new() { ["status"] = "security_history_poll_waiting_for_managed_worker", ["consumer"] = "existing_managed_investigation_worker", ["production_changed"] = false };
        if (events.Any(p => p.Value.Text("state") is "queued" or "processing")) return Waiting();
        int id = Vocabulary.FirstOrDefault(id => events[id.ToString()].Text("state") is "planned" or "publishing"); if (id == 0) return Waiting();
        var entry = events[id.ToString()]!.AsObject(); long[] ids; JsonObject published;
        await using (var session = await database.OpenAsync(true, ct)) {
            ids = id == 4624 ? (await ContextPairs(session, entry.Number("cursor"), entry.Number("high_watermark"), entry.Number("semantic_context_reset_high_watermark"), true, ct)).Take((int)manifest.Number("batch_limit")).Select(p => p.Id).ToArray()
                : (await session.QueryAsync(SemanticRetainedSql.Targets, ct, Provider(id), id, entry.Number("cursor"), entry.Number("high_watermark"), 1, SemanticEvent.Normalizer, SemanticEvent.Version, (int)manifest.Number("batch_limit"))).Select(r => r.Number("id")).ToArray();
            published = await Publish(session, ids, true, ct); await session.CommitAsync(ct);
        }
        entry["cursor"] = ids.Length > 0 ? ids[^1] : entry.Number("high_watermark"); State(entry, "queued");
        if (ids.Length > 0 && !ExactPublication(ids, published)) { State(entry, "incomplete_normalization"); entry["terminal_reason"] = "producer_did_not_queue_exact_selected_rows"; entry["samples"]!["incomplete_ids"] = Ids(ids.Take(10)); }
        manifest["updated_at_utc"] = DateTimeOffset.UtcNow; Write(HistoryPath, manifest);
        return new() { ["status"] = "security_history_poll_complete", ["event_id"] = id, ["target_events"] = ids.Length, ["producer"] = published, ["consumer"] = "existing_managed_investigation_worker", ["production_changed"] = ids.Length > 0 };
    }
    private async Task<JsonObject> CheckPlan(JsonObject manifest, CancellationToken ct)
    {
        Validate(manifest, await CurrentIdentity(ct)); string digest = Digest(new JsonObject { ["manifest_digest"] = manifest["plan_digest"].Copy(), ["events"] = manifest["events"].Copy() });
        return new() { ["status"] = "security_history_check_plan_ready", ["plan_digest"] = digest, ["confirmation"] = CheckPrefix + digest, ["production_changed"] = false };
    }
    internal Task<JsonObject> HistoryCheckPlan(CancellationToken ct) => CheckPlan(Read(HistoryPath) ?? throw new InvalidOperationException("security history manifest does not exist"), ct);
    internal async Task<JsonObject> HistoryCheck(string digest, string confirmation, CancellationToken ct)
    {
        var plan = await HistoryCheckPlan(ct);
        if (digest != plan.Text("plan_digest") || confirmation != plan.Text("confirmation")) throw new InvalidOperationException("security history check confirmation required");
        await using var held = await Lock(HistoryLock, ct); var manifest = Read(HistoryPath)!; var locked = await CheckPlan(manifest, ct);
        if (digest != locked.Text("plan_digest") || confirmation != locked.Text("confirmation")) throw new InvalidOperationException("security history check plan changed");
        var events = manifest["events"]!.AsObject(); bool v2 = manifest.Text("manifest_type") == V2;
        await using (var session = await database.OpenAsync(false, ct)) {
            // SemanticDatabase opens a repeatable-read, read-only transaction.
            foreach (int id in Vocabulary) {
                var entry = events[id.ToString()]!.AsObject(); JsonObject current; JsonObject? repairs = null;
                if (id == 4624 && v2) { (current, repairs) = await ReconcileContext(session, entry, manifest.Text("plan_digest")!, ct); entry["v2_repair_states"] = repairs.DeepClone(); }
                else current = (await session.QueryAsync(SemanticRetainedSql.Reconcile, ct, 1, SemanticEvent.Normalizer, SemanticEvent.Version, 1, "semantic-shadow", SemanticEvent.Version, Provider(id), id, entry.Number("high_watermark"))).Single()!.AsObject();
                entry["normalized_count"] = current.Number("normalized_count"); entry["action_count"] = current.Number("action_evidence_count"); entry["outbox_count"] = new[] { "queued", "leased", "completed", "failed", "quarantined" }.Sum(s => current.Number("outbox_" + s));
                if (entry.Text("state") == "no_retained_events") continue;
                string state;
                if (current.Number("retained_count") != entry.Number("count")) state = "incomplete_original";
                else if (repairs is not null) state = repairs.Number("conflict") > 0 ? "incomplete_normalization" : repairs.Number("quarantined") > 0 ? "quarantined" : repairs.Number("failed") > 0 ? "failed" : repairs.Number("leased") > 0 ? "processing" : repairs.Number("queued") > 0 ? "queued" : repairs.Number("absent") > 0 ? "incomplete_normalization" : repairs.Number("completed") == current.Number("retained_count") ? "complete" : "incomplete_normalization";
                else state = current.Number("normalization_quarantined") + current.Number("outbox_quarantined") > 0 ? "quarantined" : current.Number("normalization_failed") + current.Number("outbox_failed") > 0 ? "failed" : current.Number("outbox_leased") > 0 ? "processing" : current.Number("outbox_queued") > 0 ? "queued" : current.Number("normalized_count") == current.Number("retained_count") ? "complete" : entry.Number("cursor") < entry.Number("high_watermark") ? "publishing" : "incomplete_normalization";
                State(entry, state);
            }
        }
        bool terminal = events.All(p => p.Value.Text("state") is "complete" or "no_retained_events"); int[] drift = [];
        if (terminal) {
            var snapshot = await Snapshot(Highs(manifest), v2, ct);
            if (!JsonNode.DeepEquals(snapshot["database_identity"], manifest["database_identity"])) throw new InvalidOperationException("security history database identity changed");
            drift = Mismatches(manifest, snapshot);
            if (v2) { var e = events["4624"]!; var c = snapshot["semantic_context_cohort"]!; if (e.Number("semantic_expected_count") != c.Number("count") || e.Text("semantic_context_digest") != c.Text("cohort_digest") || e.Number("semantic_context_reset_high_watermark") != c.Number("reset_high_watermark")) drift = drift.Append(4624).Distinct().Order().ToArray(); }
            foreach (int id in drift) State(events[id.ToString()]!.AsObject(), "incomplete_original"); terminal = drift.Length == 0;
        }
        manifest["result"] = new JsonObject { ["checked_at_utc"] = DateTimeOffset.UtcNow, ["check_plan_digest"] = digest, ["terminal_success"] = terminal, ["drift_event_ids"] = Ids(drift.Select(x => (long)x)) };
        manifest["updated_at_utc"] = DateTimeOffset.UtcNow; Write(HistoryPath, manifest);
        return new() { ["status"] = terminal ? "security_history_check_complete" : "security_history_check_incomplete", ["terminal_success"] = terminal, ["drift_event_ids"] = Ids(drift.Select(x => (long)x)), ["production_changed"] = false };
    }
    internal async Task<JsonObject> SupersedePlan(CancellationToken ct)
    {
        Admit(SemanticRuntimeSettings.InvestigationMode); var manifest = Read(HistoryPath) ?? throw new InvalidOperationException("security history supersede requires an existing v1 manifest");
        Validate(manifest, await CurrentIdentity(ct)); if (manifest.Text("manifest_type") != V1) throw new InvalidOperationException("security history supersede requires a v1 manifest");
        await using (var session = await database.OpenAsync(false, ct)) if ((await session.QueryAsync(SemanticRetainedSql.PendingRepair, ct, Vocabulary, Vocabulary.Select(id => manifest["events"]![id.ToString()].Number("high_watermark")).ToArray(), 1, "semantic-shadow", SemanticEvent.Version, 1, SemanticEvent.Normalizer, SemanticEvent.Version)).Count != 0) throw new InvalidOperationException("security history exact-100 repair must finish before supersede");
        var snapshot = await Snapshot(Highs(manifest), true, ct);
        if (!JsonNode.DeepEquals(snapshot["database_identity"], manifest["database_identity"]) || Mismatches(manifest, snapshot).Length > 0) throw new InvalidOperationException("security history frozen v1 cohort changed before supersede");
        string digest = PlanDigest(snapshot, manifest.Text("plan_digest"));
        return new() { ["status"] = "security_history_supersede_plan_ready", ["legacy_plan_digest"] = manifest["plan_digest"].Copy(), ["replacement_plan_digest"] = digest, ["raw_cohorts"] = snapshot["cohorts"].Copy(), ["semantic_context_cohort"] = snapshot["semantic_context_cohort"].Copy(), ["batch_limit"] = SemanticProducer.MaxBatch, ["confirmation"] = SupersedePrefix + digest, ["production_changed"] = false };
    }
    internal async Task<JsonObject> Supersede(string digest, string confirmation, CancellationToken ct)
    {
        var plan = await SupersedePlan(ct);
        if (digest != plan.Text("replacement_plan_digest") || confirmation != plan.Text("confirmation")) throw new InvalidOperationException("security history supersede confirmation required");
        await using var held = await Lock(HistoryLock, ct); var locked = await SupersedePlan(ct);
        if (digest != locked.Text("replacement_plan_digest")) throw new InvalidOperationException("security history supersede plan changed");
        var manifest = Read(HistoryPath)!; string archive = Path.Combine(directory, Path.GetFileNameWithoutExtension(HistoryPath) + ".v1-" + manifest.Text("plan_digest") + ".json");
        try { using var file = new FileStream(archive, FileMode.CreateNew, FileAccess.Write); var bytes = System.Text.Encoding.UTF8.GetBytes(manifest.ToJsonString()); file.Write(bytes); file.Flush(true); }
        catch (IOException) when (File.Exists(archive)) { if (!JsonNode.DeepEquals(Read(archive), manifest)) throw new InvalidOperationException("security history v1 archive conflicts with current manifest"); }
        var snapshot = new JsonObject { ["database_identity"] = manifest["database_identity"].Copy(), ["cohorts"] = locked["raw_cohorts"].Copy(), ["semantic_context_cohort"] = locked["semantic_context_cohort"].Copy() };
        Write(HistoryPath, New(snapshot, digest, manifest.Text("plan_digest")));
        return new() { ["status"] = "security_history_superseded_v2", ["v1_archive_path"] = archive, ["production_changed"] = false };
    }
}
