using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

public sealed record LegacyCollectionBatch(string Status, string[] RecoveryServers, int Events = 0,
    string[]? Errors = null, string[]? Warnings = null, LegacyChannelRun[]? ChannelRuns = null,
    LegacyCollectorRun[]? CollectorRuns = null, IReadOnlyList<LegacyCollectionSummary>? Summaries = null)
{
    internal static LegacyCollectionBatch FromChannels(JsonArray channels, string[] recoveryServers)
    {
        var summary = CollectorCursorContract.Summarize(channels);
        return new(summary["channels_failed"]!.GetValue<int>() > 0 ? "failed"
            : summary["partial_warning"]!.GetValue<bool>() ? "partial" : "completed", recoveryServers,
            checked((int)summary["events_collected"]!.GetValue<long>()),
            summary["errors"]!.AsArray().Select(n => n!.ToString()).ToArray(),
            summary["warnings"]!.AsArray().Select(n => n!.ToString()).ToArray());
    }
}
public interface ILegacyAcquisition
{
    Task<LegacyCollectionBatch> CollectAsync(LegacyJobInput input, CancellationToken ct);
}

public sealed class LegacyAcquisition(LegacySettings settings) : ILegacyAcquisition
{
    public Task<LegacyCollectionBatch> CollectAsync(LegacyJobInput input, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (settings.AcquisitionDisabled) throw new InvalidOperationException("acquisition_disabled");
        // Never invoke the Python collector or silently substitute an agent's
        // source identity. Windows legacy publication needs its own admission.
        throw new InvalidOperationException("legacy_windows_acquisition_not_available");
    }
}

public interface ILegacyJobExecution
{
    Task RunAsync(LegacyWork work, CancellationToken ct, bool collectionOwnerHeld = false);
}

public sealed class LegacyJobExecution(LegacyJobStore store, LegacySettings settings, ILegacyEnvironment environment,
    ILegacyAnalysis analysis, ILegacyAcquisition acquisition, ILegacyPostStore post, IPostgresConnectionFactory connections,
    ILogger<LegacyJobExecution> logger, ILegacyCollectionState? collectionState = null,
    NpsWorkerRuntime? nps = null) : ILegacyJobExecution
{
    public async Task RunAsync(LegacyWork work, CancellationToken ct, bool collectionOwnerHeld = false)
    {
        var clock = Stopwatch.StartNew();
        try {
            if (work.Collect) await CollectAsync(work, ct, collectionOwnerHeld);
            else {
                store.Update(work.Id, j => { j["status"] = "running"; j["message"] = "Выполняется анализ уже собранных событий."; });
                var report = await analysis.RenderAsync(work.Id, work.Input.Servers, ct);
                await LegacyReportPublication.PublishAsync(report, Path.Combine(settings.DataDirectory, "reports"), null, ct);
                store.Update(work.Id, j => { j["status"] = "completed"; j["message"] = "Анализ прошлых событий завершен.";
                    j["analysis_report_url"] = report.Url; j["duration_ms"] = clock.ElapsedMilliseconds; });
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) {
            Fail(work.Id, "job_interrupted", clock.ElapsedMilliseconds); throw;
        }
        catch (Exception error) {
            var decision = work.Collect ? LegacyCollectionFailurePolicy.Classify([error]) : new(false);
            if (decision.Blocked) {
                store.Update(work.Id, j => { j["status"] = "blocked"; j["phase"] = decision.Phase; j["reason"] = decision.Code;
                    j["operator_action"] = decision.OperatorAction; j["duration_ms"] = clock.ElapsedMilliseconds;
                    j["errors"]!.AsArray().Add(decision.Code); j["import_attempted"] = false; j["cursor_advanced"] = false; });
                try {
                    if (collectionState is not null) await collectionState.ActivateAsync(decision.Code!, decision.OperatorAction!,
                        work.Reason, work.Input.Servers.FirstOrDefault(), work.Id, new() { ["failure_code"] = decision.Code, ["failure_scope"] = "worker_identity" }, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { logger.LogWarning("collection_block_persistence_failed"); }
                return;
            }
            string id = "legacy_job_failed_" + Guid.NewGuid().ToString("N");
            Fail(work.Id, id, clock.ElapsedMilliseconds); logger.LogWarning("legacy_job_failed {ErrorId}", id);
        }
    }

    private void Fail(int id, string error, long duration) => store.Update(id, j => {
        j["status"] = "failed"; j["phase"] = "failed"; j["message"] = error; j["duration_ms"] = duration;
        j["errors"]!.AsArray().Add(error);
    });

    private async Task CollectAsync(LegacyWork work, CancellationToken ct, bool collectionOwnerHeld)
    {
        string? reason = await environment.CollectionBlockAsync(ct);
        if (reason is not null) { Skip(work.Id, reason); return; }
        if (!await AdmitAsync(work.Id, ct)) return;
        if (settings.CollectionBlock is {} configuredBlock) { Skip(work.Id, configuredBlock); return; }
        await using var db = collectionOwnerHeld ? null : await connections.OpenAsync(ct);
        if (!collectionOwnerHeld) {
            await using var acquire = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_collection_worker'))", db);
            if (await acquire.ExecuteScalarAsync(ct) is not true) { Skip(work.Id, "external_owner_active"); return; }
        }
        try {
            await CollectBodyAsync(work, ct, (input, token) => CollectAdaptiveBatchAsync(work, input, db, token));
        }
        finally {
            if (!collectionOwnerHeld) {
                await using var unlock = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_collection_worker'))", db);
                await unlock.ExecuteScalarAsync(CancellationToken.None);
            }
        }
    }
    internal async Task<LegacyCollectionBatch> CollectBatchAsync(LegacyJobInput input, int jobId, NpgsqlConnection? db, CancellationToken ct)
    {
        await using var ownedDb = db is null ? await connections.OpenAsync(ct) : null;
        db ??= ownedDb!;
        var requests = new List<LegacyCollectionRequest>();
        foreach (string server in input.Servers) {
            if (input.CollectionPlans?.TryGetValue(server, out var plan) == true) {
                var request = LegacyCollectionRequest.Create(server, plan.Channels, plan.RecoveryMode, settings);
                if (plan.AdaptiveStateMode == "observe") request = request with { CollectionMode = plan.CollectionMode };
                requests.Add(request);
                continue;
            }
            await using var state = new NpgsqlCommand("select recovery_mode from collector_adaptive_state where server=@server and channel='Security'", db) { CommandTimeout = 0 };
            state.Parameters.AddWithValue("server", server);
            bool recovery = await state.ExecuteScalarAsync(ct) is true;
            string[] channels = recovery ? ["Security"] : ["Security", "System", "Directory Service",
                "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "DNS Server"];
            requests.Add(LegacyCollectionRequest.Create(server, channels, recovery, settings));
        }
        var batch = await acquisition.CollectAsync(input with { CollectionRequests = requests.ToArray() }, ct);
        LegacyCollectionFailurePolicy.RequireImportAllowed(batch.Errors ?? []);
        foreach (var run in batch.ChannelRuns ?? []) {
            if (input.CollectionPlans is null || !input.CollectionPlans.TryGetValue(run.Server, out var plan)
                || !plan.Channels.Contains(run.Channel))
                throw new InvalidOperationException("collector_result_outside_plan");
        }
        foreach (var run in batch.CollectorRuns ?? []) {
            var request = requests.FirstOrDefault(r => r.Server == run.Server);
            if (request is null || (run.Summary["channels"] as JsonArray ?? []).OfType<JsonObject>()
                .Any(channel => channel["channel"]?.ToString() is { Length: > 0 } name && !request.Channels.Contains(name)))
                throw new InvalidOperationException("collector_result_outside_plan");
            await run.RecordAsync(jobId, db, ct);
        }
        return batch;
    }

    // Keep admission and process ownership in CollectAsync. Like the reference
    // collector body, this state machine consumes normalized acquisition results.
    internal Task CollectBodyAsync(LegacyWork work, CancellationToken ct) =>
        CollectBodyAsync(work, ct, acquisition.CollectAsync);

    private async Task CollectBodyAsync(LegacyWork work, CancellationToken ct,
        Func<LegacyJobInput, CancellationToken, Task<LegacyCollectionBatch>> collect)
    {
        var clock = Stopwatch.StartNew(); var active = work.Input.Servers;
        bool errors = false, warnings = false;
        for (int cycle = 1; active.Length > 0; cycle++) {
            if (!await AdmitAsync(work.Id, ct)) return;
            store.Update(work.Id, j => { j["status"] = "running"; j["phase"] = "collection"; j["cycle"] = cycle;
                j["trace_id"] = "job-" + j["durable_id"]!.GetValue<string>(); });
            var batch = await collect(work.Input with { Servers = active }, ct);
            LegacyCollectionFailurePolicy.RequireImportAllowed(batch.Errors ?? []);
            string[] batchErrors = batch.Errors ?? [];
            string[] batchWarnings = batch.Warnings ?? [];
            if (batch.Status == "failed" && batchErrors.Length == 0) batchErrors = ["Сбор завершился ошибкой."];
            if (batch.Status == "partial" && batchWarnings.Length == 0) batchWarnings = ["Сбор выполнен частично; успешные каналы сохранены."];
            errors |= batchErrors.Length > 0;
            warnings |= batchWarnings.Length > 0;
            store.Update(work.Id, j => {
                j["events_collected"] = Sli.Server.Operations.OpsJson.N(j["events_collected"]) + batch.Events;
                foreach (string error in batchErrors) j["errors"]!.AsArray().Add(error);
                foreach (string warning in batchWarnings) j["warnings"]!.AsArray().Add(warning);
            });
            if (errors || settings.Get("ADLOG_CONTINUOUS_RECOVERY")?.Trim().ToLowerInvariant() is "0" or "false" or "no" or "off" || batch.RecoveryServers.Length == 0) break;
            // A live recovery follows the source cursor until its boundary;
            // elapsed time and cycle counts are progress, not stopping budgets.
            active = batch.RecoveryServers;
            await Task.Delay(TimeSpan.FromSeconds(ReadInt("ADLOG_CONTINUOUS_RECOVERY_COOLDOWN_SECONDS", 5, 0)), ct);
        }
        string status = errors ? "failed" : warnings ? "partial" : "completed";
        await CompleteCollectionAsync(work, status, clock.ElapsedMilliseconds, ct);
        if (work.Reason == "external_worker" && nps is not null) {
            var result = await nps.CompleteAsync(store.Get(work.Id)!, work, "collection-worker-" + Environment.ProcessId, ct);
            store.Update(work.Id, job => {
                foreach (string key in new[] { "status", "phase", "duration_ms", "nps", "dc_status", "reason", "operator_action" })
                    if (result.ContainsKey(key)) job[key] = result[key]?.DeepClone();
            });
        }
    }

    private async Task<LegacyCollectionBatch> CollectAdaptiveBatchAsync(LegacyWork work, LegacyJobInput input, NpgsqlConnection? db, CancellationToken ct)
    {
        var adaptive = new LegacyAdaptiveCollector(connections, settings);
        var plans = new Dictionary<string, LegacyAdaptivePlan>();
        foreach (string server in input.Servers) plans[server] = await adaptive.PlanAsync(server, ct);
        var batch = await CollectBatchAsync(input with { CollectionPlans = plans }, work.Id, db, ct);
        LegacyCollectionFailurePolicy.RequireImportAllowed(batch.Errors ?? []);
        foreach (var run in batch.ChannelRuns ?? []) {
            if (!plans.TryGetValue(run.Server, out var plan) || !plan.Channels.Contains(run.Channel))
                throw new InvalidOperationException("collector_result_outside_plan");
            await adaptive.RecordAsync(run, work.Id, plan.AdaptiveStateMode, ct);
        }
        if (batch.Summaries is { Count: > 0 }) {
            await using var summaryConnection = db is null ? await connections.OpenAsync(ct) : null;
            var summaryDb = db ?? summaryConnection!;
            await using var tx = await summaryDb.BeginTransactionAsync(ct);
            await using var session = new SemanticSession(summaryDb, tx);
            foreach (var receipt in batch.Summaries)
                await LegacyCollectionState.UpdateAsync(session, receipt, work.Id, "job-" + store.Get(work.Id)!["durable_id"], ct);
            await session.CommitAsync(ct);
        }
        return batch;
    }

    internal async Task CompleteCollectionAsync(LegacyWork work, string status, long duration, CancellationToken ct)
    {
        bool errors = status == "failed";
        bool skip = settings.Get("ADLOG_SCHEDULER_SKIP_REPORT") is null
            ? settings.Enabled("ADLOG_SCHEDULER_CANARY") || settings.Enabled("ADLOG_POSTGRES_SCHEDULER_CANARY")
            : settings.Enabled("ADLOG_SCHEDULER_SKIP_REPORT");
        store.Update(work.Id, j => { j["status"] = status; j["collection_status"] = status; j["duration_ms"] = duration;
            j["analysis_status"] = skip ? "skipped" : errors ? "not_queued" : "queued";
            j["report_status"] = skip ? "skipped" : errors ? "not_queued" : "queued"; j["phase"] = skip || errors ? "done" : "analysis_queued"; });
        if (!skip && !errors) {
            var job = store.Get(work.Id)!;
            try { await post.QueueAsync(job["durable_id"]!.GetValue<string>(), work.Id, work.Input.Servers, ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch {
                // Post-processing is isolated from already committed collection.
                store.Update(work.Id, j => { j["analysis_status"] = "failed"; j["report_status"] = "failed";
                    j["analysis_error_id"] = "post_collection_queue_failed"; j["phase"] = "done"; });
            }
        }
    }
    private async Task<bool> AdmitAsync(int id, CancellationToken ct)
    {
        var guard = await LegacyCollectionAdmission.DiskAsync(environment, ct);
        if (guard["collection_allowed"]?.GetValue<bool>() == true) return true;
        string reason = guard["reason"]?.GetValue<string>() ?? "disk_pressure_guard";
        Skip(id, reason);
        if (reason == "collection_guard_error") store.Update(id, j => {
            j["status"] = "blocked"; j["phase"] = "admission"; j["reason"] = reason;
            j["error_type"] = guard["error_type"]?.DeepClone(); j["errors"]!.AsArray().Add(reason);
        });
        return false;
    }
    private int ReadInt(string key, int fallback, int minimum) => Math.Max(minimum, int.TryParse(settings.Get(key), out var value) ? value : fallback);
    private void Skip(int id, string reason) => store.Update(id, j => { j["status"] = "skipped"; j["phase"] = "skipped";
        j["skipped_reason"] = reason; j["exit_code"] = 0; j["message"] = "Сбор пропущен: " + reason; });
}

public sealed class LegacyJobWorker(IServiceScopeFactory scopes, LegacyWorkQueue queue) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var work in queue.ReadAsync(stoppingToken)) {
            await using var scope = scopes.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<LegacyJobExecution>().RunAsync(work, stoppingToken);
        }
    }
}
