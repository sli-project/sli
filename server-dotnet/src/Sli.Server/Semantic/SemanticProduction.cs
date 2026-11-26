using System.CommandLine;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Hosting;

namespace Sli.Server.Semantic;

public sealed record SemanticProductionOptions(bool Once = false, int PollSeconds = 30, int Limit = 128);
internal sealed partial class SemanticProduction(PasswordProducerRuntime runtime, SemanticRuntimeSettings settings, string mode, int limit, string? repairDigest = null, bool development = false, bool independent = false, int? concurrency = null, Func<bool>? stopping = null, Sli.Server.Storage.Archive.ArchiveReader? authorizedArchive = null, long[]? exactSourceIds = null)
{
    private readonly SemanticWork work = new(independent, concurrency);
    private bool Stopping => stopping?.Invoke() == true;
    private async Task<T?> Source<T>(string key, NpgsqlConnection db, Func<NpgsqlConnection,Task<T>> run, CancellationToken ct) =>
        await work.Run(key, async () => {
            if (Stopping) return default!;
            if (!independent) return await run(db);
            await using var connection = await runtime.OpenAsync(ct);
            return await run(connection);
        }, ct);
    internal async Task<JsonObject> Stage(string key, NpgsqlConnection db, Func<NpgsqlConnection,Task<JsonObject>> run, CancellationToken ct) =>
        await Source(key, db, run, ct) ?? EmptyStage();
    private readonly SemanticQueueRate queueRate = new();
    private SemanticOutboxPump? continuousPump;
    private bool quarantineReplayed;

    private sealed class ReplayConnections(PasswordProducerRuntime runtime) : Sli.Server.Infrastructure.IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => runtime.OpenAsync(ct);
    }

    internal async Task<JsonObject> ReplayFixedQuarantineAsync(CancellationToken ct)
    {
        if (quarantineReplayed || Stopping) return EmptyStage();
        var result = await new SemanticQuarantineReplay(new SemanticDatabase(new ReplayConnections(runtime)), ReplayQuarantined)
            .ReplayFixedAsync(Math.Clamp(limit, 1, 1000), settings.Correlation, ct, SemanticWork.Progress, () => Stopping);
        if (!Stopping) quarantineReplayed = true;
        return result;
    }

    internal async Task<SemanticOutboxPump> ContinuousPumpAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (continuousPump is not null && work.Finished("processing_outbox")) {
            var previous = continuousPump; continuousPump = null;
            try {
                await previous.DisposeAsync();
                Console.Error.WriteLine("semantic_outbox_pump_restarting:processing_outbox:completed");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { Console.Error.WriteLine("semantic_outbox_pump_restarting:" + WorkerFailure.Describe(error, "processing_outbox")); }
            finally { work.Forget("processing_outbox"); }
        }
        return continuousPump ??= new SemanticOutboxPump(runtime, settings, mode, limit, repairDigest, queueRate, ct, work);
    }

    internal static async Task PulseAsync(Func<CancellationToken, Task> heartbeat, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested) {
            try { await heartbeat(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { Console.Error.WriteLine("semantic_pulse_restarting:" + WorkerFailure.Describe(error, "heartbeat")); }
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    internal async Task StopAsync(Task pulse, CancellationTokenSource stop)
    {
        // Cancel executing database commands before joining independent stages.
        stop.Cancel();
        try {
            await work.Drain();
        }
        finally {
            try {
                if (continuousPump is not null) {
                    var pump = continuousPump; continuousPump = null;
                    try { await pump.DisposeAsync(); } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
                    finally { work.Forget("processing_outbox"); }
                }
            }
            finally {
                stop.Cancel();
                try { await pulse; } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            }
        }
    }

    internal const string DevelopmentMode = "development-test-shadow";
    internal async Task<JsonObject> RunDevelopmentOnceAsync(NpgsqlConnection db, CancellationToken ct)
    {
        if (!development || mode != DevelopmentMode || !settings.Normalization || settings.DirectoryState || settings.Findings)
            throw new InvalidOperationException("semantic_development_scope_required");
        await Legacy.DevelopmentSemanticGuard.ValidateDatabaseAsync(db, ct);
        var processing = await Stage("processing_outbox", db, connection => ProcessOutbox(connection,ct), ct);
        var dispatch = settings.Correlation ? await ProcessDispatch(db, ct) : EmptyStage();
        var risk = settings.Risk ? await ProcessRisk(db, ct) : EmptyStage();
        long failed = processing.Number("failed") + dispatch.Number("failed") + risk.Number("failed");
        return new JsonObject { ["status"] = failed == 0 ? "ok" : "partial", ["processing"] = processing,
            ["dispatch"] = dispatch, ["risk"] = risk, ["risk_queued"] = risk.Number("queued"),
            ["completed"] = processing.Number("completed") + dispatch.Number("completed") + risk.Number("completed"),
            ["failed"] = failed, ["modes"] = risk["modes"].Copy() ?? new JsonObject { ["test"] = 0, ["shadow"] = 0 },
            ["findings_created"] = 0 };
    }
    private static JsonObject EmptyStage() => new() { ["claimed"] = 0, ["completed"] = 0, ["failed"] = 0 };
    private const string WorkerLock = "ad_log_reports_runtime_semantic_production_worker";
    internal static async Task<bool> AcquireWorkerLockAsync(NpgsqlConnection db, CancellationToken ct, TimeSpan? wait = null)
    {
        var budget = wait ?? TimeSpan.FromSeconds(30);
        var elapsed = Stopwatch.StartNew();
        bool reported = false;
        while (true) {
            await using var command = new NpgsqlCommand("select pg_try_advisory_lock(hashtextextended($1,0))", db);
            command.Parameters.AddWithValue(WorkerLock);
            if (await command.ExecuteScalarAsync(ct) is true) return true;
            if (!reported) { Console.Error.WriteLine("semantic_production_worker_lock_waiting"); reported = true; }
            var left = budget - elapsed.Elapsed;
            if (left <= TimeSpan.Zero) return false;
            await Task.Delay(left < TimeSpan.FromSeconds(1) ? left : TimeSpan.FromSeconds(1), ct);
        }
    }
    internal static async Task GuardAsync(ISemanticSession session, string mode, CancellationToken ct)
    {
        var guard = (await session.QueryAsync(SemanticProductionSql.Guard1, ct))[0]!;
        void Require(bool condition, string code) { if (!condition) throw new WorkerFailure("production_admission", code); }
        Require(guard.Flag("facts_schema_ready") && guard.Flag("processor_version_gate_schema_ready"), "facts_schema_missing");
        Require(guard.Flag("facts_capability_ready"), "facts_capability_missing");
        if (mode != SemanticRuntimeSettings.FactsMode)
        {
            Require(guard.Flag("investigation_rule_lock_schema_ready") && guard.Flag("investigation_rule_lock_capability_ready"), "rule_lock_capability_missing");
            if (mode == SemanticRuntimeSettings.InvestigationMode)
                Require(guard.Flag("investigation_schema_ready") && guard.Flag("investigation_context_schema_ready") && guard.Flag("investigation_capability_ready") && guard.Flag("investigation_context_capability_ready"), "investigation_capability_missing");
        }
        if (mode == SemanticRuntimeSettings.FindingsMode)
        {
            var policy = (await session.QueryAsync(SemanticProductionSql.Guard0, ct))[0]!;
            Require(policy.Flag("schema_ready") && !policy.Flag("test_policy_exists"), "schema_missing_or_test_policy_present");
            string[] unmanaged = policy["unmanaged_enabled_policies"]!.AsArray().Select(x => x!.GetValue<string>()).ToArray();
            Require(unmanaged.All(x => x == "l1-audit-policy-changed:2") && (policy.Flag("admission_configured") || unmanaged.SequenceEqual(["l1-audit-policy-changed:2"])), "enabled_policy_set_differs");
        }
    }
    internal static void ValidateExactSources(string mode, IReadOnlyList<long>? sourceEventIds, string? repairDigest = null)
    {
        if (sourceEventIds is null) return;
        if (mode != SemanticRuntimeSettings.FactsMode || sourceEventIds.Count is < 1 or > 16
            || sourceEventIds.Any(id => id <= 0) || sourceEventIds.Distinct().Count() != sourceEventIds.Count || repairDigest is not null)
            throw new InvalidOperationException("exact semantic source IDs require facts mode without repair");
    }
    internal async Task<JsonObject> RunOnceAsync(NpgsqlConnection db, CancellationToken ct, bool keepPump = false, IReadOnlyList<long>? sourceEventIds = null)
    {
        ValidateExactSources(mode, sourceEventIds, repairDigest);
        ValidateRepairMode(mode, repairDigest);
        string step = "production_admission";
        try {
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            await using var session = new SemanticSession(db, tx); await GuardAsync(session, mode, ct); await tx.CommitAsync(ct);
        }
        step = "processing_outbox";
        if (sourceEventIds is not null) {
            var exact = await ProcessOutbox(db, ct, sourceEventIds: sourceEventIds);
            return new JsonObject { ["status"] = exact.Number("failed") == 0 ? "ok" : "partial", ["runtime_mode"] = mode,
                ["processing"] = exact, ["dispatch"] = new JsonObject { ["completed"] = 0, ["failed"] = 0, ["relations"] = 0 },
                ["risk_queued"] = 0, ["findings_created"] = 0, ["completed"] = exact.Number("completed"), ["failed"] = exact.Number("failed"),
                ["modes"] = new JsonObject { ["shadow"] = 0, ["enabled"] = 0 } };
        }
        if (repairDigest is not null)
        {
            var repaired = await ProcessOutbox(db, ct);
            return new JsonObject {
                ["status"] = repaired.Number("failed") == 0 ? "ok" : "partial", ["runtime_mode"] = mode,
                ["repair_scope"] = RepairScope(repairDigest), ["processing"] = repaired,
                ["dispatch"] = new JsonObject { ["completed"] = 0, ["failed"] = 0, ["relations"] = 0 },
                ["risk_queued"] = 0, ["findings_created"] = 0,
                ["completed"] = repaired.Number("completed"), ["failed"] = repaired.Number("failed"),
                ["modes"] = new JsonObject { ["shadow"] = 0, ["enabled"] = 0 }
            };
        }
        step = "quarantine_replay";
        var quarantine = await work.Run("quarantine_replay", () => ReplayFixedQuarantineAsync(ct), ct) ?? EmptyStage();
        // Creation remains AFTER production admission. A continuous worker retains
        // this separately connected pump through source waits and polling pauses.
        await using var ownedPump = keepPump ? null : new SemanticOutboxPump(runtime, settings, mode, limit, repairDigest, queueRate, ct, work);
        var pump = ownedPump ?? await ContinuousPumpAsync(ct);
        await pump.Ready;
        step = "producer_backfill";
        var backfill = repairDigest is null && !Stopping ? await SemanticProducerBackfill.RunAsync(db,mode,SemanticProducerBackfill.WindowSize,ct) : new JsonObject { ["status"]=repairDigest is null ? "skipped" : "repair_only",["scanned"]=0,["queued"]=0 };
        step = "import_summary";
        var importSummary = await Stage("import_summary", db, connection => Detections.DetectionProducer.RefreshImportSummary(connection,ct), ct);
        step = "dispatch"; var dispatch = mode == SemanticRuntimeSettings.FactsMode || repairDigest is not null ? new JsonObject { ["completed"] = 0, ["failed"] = 0, ["relations"] = 0, ["claimed"] = 0 } : await Stage("dispatch", db, connection => ProcessDispatch(connection,ct), ct);
        var result = new JsonObject { ["runtime_mode"] = mode, ["quarantine_replay"] = quarantine, ["producer_backfill"] = backfill, ["import_summary"] = importSummary, ["dispatch"] = dispatch, ["risk_queued"] = 0, ["findings_created"] = 0 };

        if (mode == SemanticRuntimeSettings.FindingsMode && !Stopping)
        {
            step = "expire_semantic_suppressions_v160";
            await using (var tx = await db.BeginTransactionAsync(ct))
            { await new SemanticSession(db, tx).QueryAsync("select expire_semantic_suppressions_v160()", ct); await tx.CommitAsync(ct); }
            JsonArray? discovered = null;
            step = "default_detections"; result["detections"] = await Stage("default_detections", db, async connection => {
                var defaults = await ProcessDefaultDetections(connection, ct); discovered = defaults.Sources; return defaults.Result;
            }, ct);
            // Keep the cycle result key for existing worker telemetry. Password
            // thresholds now run alongside the other native threshold rules.
            step = "password_producer"; result["password_producer"] = await work.Run("password_producer", async () => {
                if (Stopping) return EmptyStage();
                await using var detectorDb = await runtime.OpenAsync(ct);
                var batch = await new Detections.DetectionProducer(new(), new()) { Work = work, Runtime = runtime }
                    .RunOnceAsync(detectorDb, ct, independent ? null : discovered, refreshImport: false);
                return new JsonObject { ["sources"] = batch.Sources, ["completed"] = batch.Completed, ["failed"] = batch.Failed,
                    ["jobs"] = batch.Jobs, ["skipped"] = 0, ["failure_reasons"] = batch.FailureReasons, ["import_summary"] = batch.ImportSummary };
            }, ct) ?? EmptyStage();
            step = "password_risk"; var passwordRisk = await work.Run("password_risk", async () => {
                if (Stopping) return EmptyStage();
                var batch = await new PasswordRiskConsumer(runtime, new(MaxJobs: RiskBatchSize(limit))).RunOnceAsync(ct);
                return new JsonObject { ["claimed"] = batch.Claimed, ["completed"] = batch.Completed, ["failed"] = batch.Failed, ["published"] = batch.Published };
            }, ct) ?? EmptyStage(); result["password_risk"] = passwordRisk;
            step = "sigma"; result["sigma"] = await Stage("sigma", db, connection => ProcessSigma(connection,ct), ct);
            step = "risk"; var risk = await Stage("risk", db, connection => ProcessRisk(connection,ct), ct); result["risk"] = risk; result["risk_queued"] = risk["queued"].Copy(); result["findings_created"] = risk.Number("published") + passwordRisk.Number("published");
            step = "enabled_policies";
            await using var policyRead = await db.BeginTransactionAsync(ct);
            var policies = await new SemanticSession(db, policyRead).QueryAsync(SemanticProductionSql.Guard0, ct);
            result["enabled_policies"] = policies[0]?["enabled_policies"].Copy() ?? new JsonArray();
            await policyRead.CommitAsync(ct);
        }
        step = "processing_outbox"; var processing = keepPump ? await pump.ProgressAsync() : await pump.StopAsync(); result["processing"] = processing;
        long failed = quarantine.Number("failed") + (importSummary.Flag("refresh_failed") || importSummary.Flag("tail_refresh_failed") ? 1 : 0) + processing.Number("failed") + dispatch.Number("failed") + result["risk"].Number("failed") + result["sigma"].Number("failed") + result["detections"].Number("failed") + result["password_risk"].Number("failed") + result["password_producer"].Number("failed");

        result["completed"] = quarantine.Number("replayed") + processing.Number("completed") + dispatch.Number("completed") + result["risk"].Number("completed");
        result["modes"] = result["risk"]?["modes"].Copy() ?? new JsonObject { ["shadow"] = 0, ["enabled"] = 0 };
        result["failed"] = failed; result["status"] = CycleStatus(result); return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (WorkerFailure) { throw; }
        catch (Exception error) { throw new WorkerFailure(step, WorkerFailure.Describe(error, "cycle"), error); }
    }
    internal static string CycleStatus(JsonNode? result)
    {
        if (result.Text("status") == "error") return "error";
        long failed = result.Number("failed");
        if (failed == 0) return "ok";
        // Python includes policy waits in failed. They do not mean a broken cycle.
        var waiting = result?["detections"]?["file_ransom_status"];
        if (waiting.Text("code") == "source_policy_waiting" && waiting.Number("sources") == failed) return "partial";
        foreach (string name in new[] { "processing", "dispatch", "risk", "sigma", "detections", "password_risk", "password_producer" })
        {
            var stage = result?[name];
            if (stage.Number("completed") > 0
                || stage is JsonObject obj && !obj.ContainsKey("completed") && Math.Max(stage.Number("sources"), stage.Number("policies")) > stage.Number("failed")) return "partial";
        }
        return "error";
    }

    internal static bool WorkerActive(JsonNode? heartbeat)
    {
        string status = CycleStatus(heartbeat?["details_json"]?["result"]);
        return heartbeat.Text("status") is "running" or "idle" ? status != "error"
            : heartbeat.Text("status") == "partial" && status == "partial";
    }
    internal static JsonObject CycleFailure(Exception error)
    {
        string step = error is WorkerFailure { Step: "production_admission" or "processing_outbox" or "producer_backfill" or "import_summary" or "dispatch" or "expire_semantic_suppressions_v160"
            or "default_detections" or "password_producer" or "password_risk" or "sigma" or "risk" } failure ? failure.Step : "cycle";
        var diagnostic = DetectionDiagnostics.Describe(error, step);
        return new() { ["status"] = "error", ["failed"] = 1, ["error"] = diagnostic };
    }
    internal static Task<JsonArray> Change(ISemanticSession session, string sql, CancellationToken ct, params object?[] args)
    {
        Sli.Server.Infrastructure.SqlArguments.Validate(args);
        return session.QueryAsync("with changed as(" + sql + ") select * from changed", ct, args);
    }
    internal static async Task Complete(ISemanticSession session, string table, string statusColumn, JsonNode job, CancellationToken ct)
    {
        var rows = await Change(session, $"update {table} set {statusColumn}='completed',completed_at=now(),lease_token=null,lease_until=null,heartbeat_at=now(),updated_at=now() where job_id=$1 and {statusColumn}='leased' and lease_token=$2 returning job_id", ct, Guid.Parse(job.Text("job_id")!), Guid.Parse(job.Text("lease_token")!));
        if (rows.Count != 1) throw new InvalidOperationException("semantic lease was lost");
    }
    internal static bool LockWait(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is PostgresException { SqlState: "55P03" }) return true;
        return false;
    }
    private static async Task<ISemanticSession> Transaction(NpgsqlConnection db, CancellationToken ct) =>
        new SemanticSession(db, await db.BeginTransactionAsync(ct));

    internal static Task Fail(NpgsqlConnection db, string table, string statusColumn, JsonNode job, CancellationToken ct, Exception error, SemanticProcessingStep step) =>
        Fail(token => Transaction(db, token), table, statusColumn, job, ct, error, step);

    private static async Task Fail(Func<CancellationToken, Task<ISemanticSession>> open, string table, string statusColumn, JsonNode job, CancellationToken ct, Exception error, SemanticProcessingStep step)
    {
        ct.ThrowIfCancellationRequested(); await using var session = await open(ct);
        await Fail(session, table, statusColumn, job, ct, error, step); await session.CommitAsync(ct);
    }
    internal static async Task Fail(ISemanticSession session, string table, string statusColumn, JsonNode job, CancellationToken ct, Exception error, SemanticProcessingStep step)
    {
        int attempt = (int)job.Number("attempt_count"); bool lockWait = LockWait(error);
        // A lock wait did no work. Yield without consuming the failure budget.
        var rows = await Change(session, $"update {table} set {statusColumn}=$1,available_at=now()+($2*interval '1 second'),attempt_count=case when $6 then greatest(attempt_count-1,0) else attempt_count end,lease_token=null,lease_until=null,last_error_code=case when $6 then 'semantic_lock_wait' else 'semantic_processing_failed' end,last_error_detail=$5,updated_at=now() where job_id=$3 and {statusColumn}='leased' and lease_token=$4 returning job_id", ct,
            lockWait ? "queued" : attempt >= job.Number("max_attempts") ? "quarantined" : "failed", lockWait ? 1 : Math.Min(3600, 30 * (1 << Math.Min(Math.Max(attempt - 1, 0), 7))), Guid.Parse(job.Text("job_id")!), Guid.Parse(job.Text("lease_token")!), SemanticProcessingFailure.Describe(error, step), lockWait);
        if (rows.Count != 1) throw new InvalidOperationException("semantic lease was lost while recording failure");
    }
    internal static JsonObject HeartbeatDetails(string mode, JsonObject? result = null, bool development = false,
        JsonArray? executing = null, string? repairDigest = null)
    {
        repairDigest ??= result?["repair_scope"].Text("repair_plan_digest");
        ValidateRepairMode(mode, repairDigest);
        var details = new JsonObject {
            ["runtime_mode"] = mode, ["manual_runtime"] = development, ["production"] = !development,
            ["allowed_modes"] = development ? new JsonArray("test", "shadow") : mode == SemanticRuntimeSettings.FactsMode
                ? new JsonArray() : mode == SemanticRuntimeSettings.InvestigationMode ? new JsonArray("shadow") : new JsonArray("shadow", "enabled"),
            ["finding_creation"] = !development && mode == SemanticRuntimeSettings.FindingsMode,
            ["result"] = result.Copy(), ["executing"] = executing?.DeepClone() ?? new JsonArray(),
            ["processing_contract"] = new JsonObject {
                ["claim_protocol_version"] = 1, ["semantic_contract_version"] = 1,
                ["processor_id"] = "semantic-shadow", ["processor_version"] = SemanticEvent.Version,
                ["normalizer"] = new JsonObject { ["id"] = SemanticEvent.Normalizer, ["version"] = SemanticEvent.Version },
                ["assembler"] = new JsonObject { ["id"] = "semantic-action-assembler", ["version"] = "1.1" },
                ["release_fingerprint"] = ReleaseFingerprint.Value
            }
        };
        if (repairDigest is not null) details["repair_scope"] = RepairScope(repairDigest);
        if (!development && mode == SemanticRuntimeSettings.FindingsMode && result is not null)
        {
            var policies = result["enabled_policies"] as JsonArray ?? new JsonArray();
            details["enabled_policies"] = policies.DeepClone();
            if (policies.Count == 1) details["enabled_policy"] = policies[0].Copy();
        }
        return details;
    }

    internal static async Task Heartbeat(NpgsqlConnection db, Guid worker, string mode, string status, int poll, CancellationToken ct, JsonObject? result = null, bool development = false, JsonArray? executing = null, string? repairDigest = null)
    {
        var details = HeartbeatDetails(mode, result, development, executing, repairDigest);
        await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
        await session.ExecuteAsync("""
            insert into runtime_worker_heartbeats(worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,started_at,heartbeat_at,details_json)
            values('semantic',$1,$5,$2,$6,$3,now(),now(),$4)
            on conflict(worker_name) do update set worker_id=excluded.worker_id,
              status=case when runtime_worker_heartbeats.worker_id=excluded.worker_id and excluded.status='running'
                  and excluded.details_json->'result'='null'::jsonb and runtime_worker_heartbeats.status in ('partial','error')
                then runtime_worker_heartbeats.status else excluded.status end,phase=excluded.phase,
              expected_interval_seconds=excluded.expected_interval_seconds,started_at=case when runtime_worker_heartbeats.worker_id=excluded.worker_id then runtime_worker_heartbeats.started_at else excluded.started_at end,
              process_pid=excluded.process_pid,heartbeat_at=now(),updated_at=now(),
              details_json=jsonb_build_object('producer_cursors',coalesce(runtime_worker_heartbeats.details_json->'producer_cursors','{}'::jsonb),
                'producer_import_busy_streak',coalesce(runtime_worker_heartbeats.details_json->'producer_import_busy_streak','0'::jsonb)) || case when runtime_worker_heartbeats.worker_id=excluded.worker_id
                  and excluded.details_json->'result'='null'::jsonb
                then jsonb_set(excluded.details_json,'{result}',coalesce(runtime_worker_heartbeats.details_json->'result','null'::jsonb))
                else excluded.details_json end
            """, ct, worker.ToString(), status, poll, details, Environment.ProcessId, HeartbeatPhase(status, result, development)); await tx.CommitAsync(ct);
    }
    internal static string HeartbeatPhase(string status, JsonObject? result, bool development = false) => development
        ? result is null ? "poll" : result["error"] is not null || !CycleHasWork(result) ? "sleep" : "drain"
        : status == "stopped" ? "production_stop_requested" : result is null ? "production_poll"
        : result["error"] is not null || !CycleHasWork(result) ? "production_sleep" : "production_drain";
    internal static bool CycleHasWork(JsonNode? result) => result.Number("completed") > 0 || result.Number("failed") > 0
        || result?["processing"].Number("claimed") > 0 || result?["dispatch"].Number("claimed") > 0 || result?["risk"].Number("claimed") > 0
        || result?["password_producer"].Number("jobs") > 0 || result?["password_risk"].Number("claimed") > 0
        || result.Number("risk_queued") > 0 || result?["producer_backfill"].Number("scanned") > 0;

    internal static async Task<int> RunCyclesAsync(SemanticProductionOptions options, Func<CancellationToken, Task<JsonObject>> cycle,
        Func<string, JsonObject?, Task> heartbeat, Func<bool> stopped, Func<TimeSpan, CancellationToken, Task> delay, CancellationToken ct, bool development = false)
    {
        int failed = 0;
        while (!ct.IsCancellationRequested && !stopped()) {
            await heartbeat("running", null);
            bool busy = false;
            try {
                var result = await cycle(ct); failed = result.Number("failed") > 0 ? 1 : 0;
                Console.WriteLine(result.ToJsonString()); busy = CycleHasWork(result);
                await heartbeat(result.Text("status") == "ok" ? busy ? "running" : "idle" : result.Text("status")!, result);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception error) {
                bool waiting = SemanticWork.ConnectionWait(error); failed = waiting ? 0 : 1;
                var result = waiting ? new JsonObject { ["status"] = "partial", ["failed"] = 0, ["reason"] = "database_connections_exhausted" } : CycleFailure(error);
                Console.Error.WriteLine(waiting ? "semantic_cycle_waiting:database_connections_exhausted:53300:next_poll"
                    : (development ? "semantic_development_cycle_failed:" : "semantic_production_cycle_failed:") + (error is WorkerFailure refusal ? refusal.Diagnostic + " " : "") + result["error"]!.ToJsonString());
                await heartbeat(waiting ? "partial" : "error", result);
            }
            if (options.Once || stopped()) break;
            if (!busy) try { await delay(TimeSpan.FromSeconds(Math.Max(1, options.PollSeconds)), ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
        }
        await heartbeat("stopped", null); return failed;
    }
    internal static Task<int> RunWorker(SemanticProductionOptions options, CancellationToken ct) =>
        RunWorker(options, ct, Environment.GetEnvironmentVariable, PasswordProducerRuntime.Create);

    internal static async Task<int> RunWorker(SemanticProductionOptions options, CancellationToken ct,
        Func<string, string?> get, Func<PasswordProducerRuntime> createRuntime)
    {
        string mode; SemanticRuntimeSettings settings; string? repair = get("ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST")?.Trim(); if (repair == "") repair = null;
        try { mode = SemanticRuntimeSettings.Mode(get); settings = SemanticRuntimeSettings.Read(get); settings.Validate(mode, get); ValidateRepairMode(mode, repair); }
        catch (InvalidOperationException) { Console.Error.WriteLine("semantic_worker_admission_invalid:ADLOG_SEMANTIC_RUNTIME_MODE:feature_chain_or_repair_admission_invalid"); return 1; }
        PasswordProducerRuntime runtime;
        try { runtime = createRuntime(); }
        catch (ServerConfigurationException error) { Console.Error.WriteLine(error.Message); return 1; }
        await using var ownedRuntime = runtime;
        Guid worker = Guid.NewGuid(); var started = DateTimeOffset.UtcNow;
        try
        {
            await using var db = await runtime.OpenControlAsync(ct);
            if (!await AcquireWorkerLockAsync(db, ct)) { Console.Error.WriteLine("semantic_production_worker_already_running"); return 1; }
            using var workStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var capacity = await SemanticCapacity.ReadAsync(db, Environment.ProcessorCount, ct);
            var production = new SemanticProduction(runtime, settings, mode, repair is null ? Math.Clamp(options.Limit, 1, 128) : Math.Max(options.Limit, 1), repair, independent: !options.Once, concurrency: capacity.Sources, stopping: () => ct.IsCancellationRequested || StopRequested(started)); int failed = 0, heartbeatInterval = options.PollSeconds;
            var pulse = PulseAsync(async token => {
                await using var heartbeatDb = await runtime.OpenControlAsync(token);
                await Heartbeat(heartbeatDb, worker, mode, "running", 5, token, executing: production.work.Snapshot(), repairDigest: repair);
            }, workStop.Token);
            try {
                var cycleStarted = System.Diagnostics.Stopwatch.StartNew();
                failed = await RunCyclesAsync(options, async token => {
                    cycleStarted.Restart();
                    if (!options.Once) {
                        capacity = await SemanticCapacity.ReadAsync(db, Environment.ProcessorCount, token);
                        production.work.SetConcurrency(capacity.Sources);
                    }
                    var result = await production.RunOnceAsync(db, token, keepPump: !options.Once && repair is null);
                    result["capacity"] = capacity.Json(); return result;
                }, async (status, result) => {
                    if (status == "stopped") return; // Record stopped only after every executing stage has drained.
                    if (result is not null) heartbeatInterval = Math.Clamp(options.PollSeconds + (int)Math.Ceiling(cycleStarted.Elapsed.TotalSeconds), 1, 86400);
                    if (status == "idle" && production.work.Snapshot().Any(x => x.Text("operation") != "processing_outbox")) status = "running";
                    await Heartbeat(db, worker, mode, status, heartbeatInterval, workStop.Token, result, executing: production.work.Snapshot(), repairDigest: repair);
                }, () => ct.IsCancellationRequested || StopRequested(started), Task.Delay, workStop.Token);
            } finally { await production.StopAsync(pulse, workStop); }
            await Heartbeat(db, worker, mode, "stopped", heartbeatInterval, CancellationToken.None, repairDigest: repair);
            return failed;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 0; }
        catch (Exception error) { Console.Error.WriteLine("semantic_production_worker_failed:" + WorkerFailure.Describe(error, "connect_lock_or_heartbeat")); return 1; }
    }
    internal static bool StopRequested(DateTimeOffset started)
    {
        string root = Directory.GetCurrentDirectory(); string data = Environment.GetEnvironmentVariable("ADLOG_DATA_DIR") ?? Environment.GetEnvironmentVariable("SLI_DATA_DIR") ?? (Directory.Exists(Path.Combine(root, "..", "sli_data")) ? Path.Combine(root, "..", "sli_data") : Path.Combine(root, "data"));
        string path = Path.Combine(root, data, "runtime", "semantic-production-stop.json");
        try { if (!File.Exists(path) || new FileInfo(path).Length > 65536) return false; var payload = JsonNode.Parse(File.ReadAllText(path)); return payload.Text("requested_at_utc") is { } stamp && System.Text.RegularExpressions.Regex.IsMatch(stamp, @"(?:Z|[+-]\d{2}:?\d{2})$") && SemanticQuery.Time(stamp, "UTC", "invalid_stop_request") >= started; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or SemanticInputException) { return false; }
    }
}
public static class SemanticProductionCommand
{
    public static Task<int> RunAsync(string[] args) => RunAsync(args, SemanticProduction.RunWorker);
    internal static async Task<int> RunAsync(string[] args, Func<SemanticProductionOptions, CancellationToken, Task<int>> run)
    {
        var once = new Option<bool>("--once"); var poll = new Option<int>("--poll-seconds") { DefaultValueFactory = _ => 30 }; var limit = new Option<int>("--limit") { DefaultValueFactory = _ => 128 };
        var command = new RootCommand("Run the admitted, bounded semantic production pipeline."); command.Options.Add(once); command.Options.Add(poll); command.Options.Add(limit);
        command.SetAction((parse, ct) => run(new(parse.GetValue(once), parse.GetValue(poll), parse.GetValue(limit)), ct));
        using var stop = new CancellationTokenSource();
        void RequestStop()
        {
            try { stop.Cancel(); }
            catch (ObjectDisposedException) { /* A signal already dispatched can arrive after invocation completes. */ }
        }
        bool linux = OperatingSystem.IsLinux();
        using var term = linux ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; RequestStop(); }) : null;
        using var interrupt = linux ? PosixSignalRegistration.Create(PosixSignal.SIGINT, context => { context.Cancel = true; RequestStop(); }) : null;
        ConsoleCancelEventHandler onCancel = (_, e) => { e.Cancel = true; RequestStop(); };
        if (!linux) Console.CancelKeyPress += onCancel;
        try
        {
            // The worker owns cancellation so it can drain and release its lease before exiting.
            return await command.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null })
                .InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false, ProcessTerminationTimeout = null }, stop.Token);
        }
        finally
        {
            if (!linux) Console.CancelKeyPress -= onCancel;
        }
    }
}
