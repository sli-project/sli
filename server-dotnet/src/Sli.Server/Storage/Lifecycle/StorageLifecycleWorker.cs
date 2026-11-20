using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.Lifecycle;

internal interface ILifecycleSession : IAsyncDisposable
{
    Task<JsonObject> ExpirePartitionsAsync(DateTime now, CancellationToken ct);
    Task<bool> TryLockAsync(string name, CancellationToken ct);
    Task EnsureLocksAsync(CancellationToken ct);
    Task ReleaseLockAsync(string name, CancellationToken ct);
    Task HeartbeatAsync(string status, string phase, int interval, JsonObject details, CancellationToken ct);
    Task<JsonObject> RetainInboxAsync(DateTime cutoff, DateTime afterReceivedAt, Guid after, int limit, CancellationToken ct);
    Task<JsonObject> RetainReceiptsAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct);
    Task<JsonObject> RetainOutboxAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct);
}

internal sealed class StorageLifecycleWorker(ILifecycleSession session, LifecycleFiles files,
    Func<DateTime>? utcNow = null, Func<TimeSpan, CancellationToken, Task>? delay = null,
    Func<TimeSpan, CancellationToken, Task>? heartbeatDelay = null)
{
    internal const string LockName = "ad_log_reports_runtime_storage_lifecycle_process";
    JsonObject? progress;
    void ReportProgress(string phase, JsonObject result)
    {
        result["active_phase"] = phase;
        Volatile.Write(ref progress, (JsonObject)result.DeepClone());
    }
    private DateTime Now => (utcNow ?? (() => DateTime.UtcNow))();

    // Imported packets, receipts and outbox jobs no longer depend on any history copy.
    async Task ShortQueuesAsync(JsonObject state, int batch, Action<JsonObject>? output, CancellationToken ct)
    {
        DateTime cutoff = Now.AddDays(-7);
        async Task Drain(string phase, string key, string cursor, Func<Guid, DateTime, Task<JsonObject>> run)
        {
            ReportProgress(phase, state);
            var after = Guid.Empty; long scanned = 0, deleted = 0, held = 0, cleared = 0;
            var afterReceivedAt = DateTime.SpecifyKind(DateTime.MinValue, DateTimeKind.Utc);
            var reasons = new JsonObject();
            for (;;) {
                await session.EnsureLocksAsync(ct);
                var step = await run(after, afterReceivedAt);
                string status = LifecycleJson.Text(step, "status");
                if (status == "blocked" && LifecycleJson.Text(step, "reason") == key + "_schema_not_ready") {
                    state[phase] = LifecycleJson.Result("skipped", key + "_schema_not_ready");
                    state["warning_reason"] = key + "_schema_not_ready"; return;
                }
                if (status is not ("complete" or "partial")) throw new LifecycleBlocked(LifecycleJson.Text(step, "reason"));
                scanned += LifecycleJson.Number(step, "selected_count"); deleted += LifecycleJson.Number(step, "deleted_count"); held += LifecycleJson.Number(step, "held_count");
                if (step["payloads_cleared"] is not null) cleared += LifecycleJson.Number(step, "payloads_cleared");
                if (step["held_reasons"] is JsonObject holds)
                    foreach (var hold in holds) Add(reasons, hold.Key, long.Parse(hold.Value!.ToString(), CultureInfo.InvariantCulture));
                var next = Guid.Parse(LifecycleJson.Text(step, cursor));
                var nextReceivedAt = step["last_scanned_received_at"] is { } stamp
                    ? DateTime.Parse(stamp.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal) : afterReceivedAt;
                state[phase] = step.DeepClone();
                Add(state, key + "_batches", 1);
                string lane = key.Replace("_retention", "");
                state[lane + "_rows_scanned"] = scanned; state[lane + "_rows_deleted"] = deleted;
                state[lane + "_rows_held"] = held; state[lane + "_payloads_cleared"] = cleared;
                ReportProgress(phase, state);
                if (LifecycleJson.Number(state, key + "_batches") % 10 == 0) {
                    var line = (JsonObject)state.DeepClone();
                    line["contract"] = "sli.storage-lifecycle-progress.v1"; line["phase"] = phase;
                    output?.Invoke(line);
                }
                if (status == "complete") { afterReceivedAt = nextReceivedAt; break; }
                if (next == after && nextReceivedAt == afterReceivedAt) throw new LifecycleBlocked(key + "_cursor_did_not_advance");
                after = next; afterReceivedAt = nextReceivedAt;
            }
            state[phase] = new JsonObject { ["status"] = "complete", ["selected_count"] = scanned, ["deleted_count"] = deleted, ["held_count"] = held, ["payloads_cleared"] = cleared, ["held_reasons"] = reasons, [cursor] = state[phase]?[cursor]?.DeepClone() };
            if (key == "inbox_retention") state[phase]!["last_scanned_received_at"] = LifecycleJson.Iso(afterReceivedAt);
        }
        await Drain("agent_inbox_retention", "inbox_retention", "last_scanned_packet_id", (a, received) => session.RetainInboxAsync(cutoff, received, a, batch, ct));
        await Drain("agent_receipt_retention", "receipt_retention", "last_scanned_packet_id", (a, _) => session.RetainReceiptsAsync(cutoff, a, batch, ct));
        await Drain("semantic_outbox_retention", "outbox_retention", "last_scanned_job_id", (a, _) => session.RetainOutboxAsync(cutoff, a, batch, ct));
    }

    internal async Task<JsonObject> CycleAsync(LifecycleOptions options, CancellationToken ct, Action<JsonObject>? output = null)
    {
        var state = new JsonObject { ["status"] = "partial", ["cycle_id"] = LifecycleJson.Iso(Now) };
        ReportProgress("partition_retention", state);
        await session.EnsureLocksAsync(ct);
        state["partitions"] = await session.ExpirePartitionsAsync(Now, ct);
        await ShortQueuesAsync(state, options.BatchSize, output, ct);
        await session.EnsureLocksAsync(ct);
        state["status"] = "ok";
        ReportProgress("completed", state);
        return state;
    }
    internal async Task<int> RunAsync(LifecycleOptions options, Action<JsonObject> output, CancellationToken ct)
    {
        if (!await session.TryLockAsync(LockName, ct)) { output(LifecycleJson.Result("skipped", "storage_lifecycle_lock_held")); return 9; }
        var prior = files.Read("storage-lifecycle-last.json");
        string? watermark = prior?["last_successful_watermark"]?.ToString(), updated = prior?["watermark_updated_at"]?.ToString();
        await session.HeartbeatAsync("starting", "startup", options.IntervalSeconds, prior ?? new JsonObject(), ct);
        while (!ct.IsCancellationRequested) {
            DateTime started = Now;
            await session.HeartbeatAsync("running", "processing", options.IntervalSeconds, prior ?? new JsonObject(), ct);
            // A long retention batch must not make an alive worker appear stale. The runtime uses a
            // separate heartbeat connection; the lock-owning session is never shared.
            using var pulseStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var pulse = PulseAsync(options.IntervalSeconds, prior ?? new JsonObject(), pulseStop.Token);
            JsonObject result;
            try { result = await CycleAsync(options, ct, output); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) {
                result = (JsonObject?)(Volatile.Read(ref progress)?.DeepClone()) ?? new JsonObject();
                result["status"] = "failed"; result["reason"] = LifecycleJson.Failure(error);
                result["error"] = LifecycleJson.Failure(error); result["error_type"] = error.GetType().Name;
            }
            finally { pulseStop.Cancel(); await pulse; }
            DateTime ended = Now;
            string status = LifecycleJson.Text(result, "status"), phase = status is "ok" or "disabled" ? "completed" : status;
            if (phase == "completed" && result["cycle_id"] is { } cycle && cycle.ToString() != watermark) { watermark = cycle.ToString(); updated = LifecycleJson.Iso(ended); }
            result["contract"] = "sli.storage-lifecycle-result.v1"; result["phase"] = phase;
            result["started_at_utc"] = LifecycleJson.Iso(started); result["ended_at_utc"] = LifecycleJson.Iso(ended);
            result["cutoff_utc"] ??= null; result["error"] ??= null; result["error_type"] ??= null;
            result["last_successful_watermark"] = watermark; result["watermark_updated_at"] = updated;
            result["result_digest"] = LifecycleJson.Hash(result).ToLowerInvariant();
            files.Write("storage-lifecycle-last.json", result); output((JsonObject)result.DeepClone());
            int wait = status == "partial" ? 0 : status == "blocked" ? 300 : options.IntervalSeconds;
            await session.HeartbeatAsync(status == "ok" ? result["warning_reason"] is null ? "idle" : "warning" : status,
                status == "failed" ? "error" : "sleep", wait, result, ct);
            if (options.Once) return status is "ok" or "disabled" or "partial" ? 0 : 2;
            prior = result;
            if (wait > 0) await (delay ?? Task.Delay)(TimeSpan.FromSeconds(wait), ct);
            else await Task.Yield();
        }
        return 0;
    }
    async Task PulseAsync(int interval, JsonObject prior, CancellationToken ct)
    {
        try { while (true) { await (heartbeatDelay ?? Task.Delay)(TimeSpan.FromSeconds(30), ct); await session.HeartbeatAsync("running", "processing", interval, Volatile.Read(ref progress) ?? prior, ct); } }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }
    internal static void Add(JsonObject row, string key, long n) => row[key] = (row[key] is null ? 0 : LifecycleJson.Number(row, key)) + n;
}
