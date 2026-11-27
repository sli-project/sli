using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Semantic.Password;
using Sli.Server.Hosting;

namespace Sli.Server.Semantic;

// Successful work calibrates the conservative fixture-derived catch-up budget.
internal sealed class SemanticQueueRate
{
    private const int MeasurementBatch = 8;
    // Conservative lower bound from the fixture benchmark (10 jobs/s),
    // before runtime samples; reserve half for foreground work.
    private double rate = 5;
    private long observed;
    private double seconds;
    // Keep room for a batch even when successful work is very slow.
    internal int HighWatermark => (int)Math.Clamp(Math.Floor(Volatile.Read(ref rate) * 30), MeasurementBatch, SemanticProducer.MaxBatch);
    internal double JobsPerSecond => Volatile.Read(ref rate);
    internal void Observe(long completed, TimeSpan elapsed)
    {
        if (completed < 1 || elapsed.TotalSeconds <= 0) return;
        observed += completed; seconds += elapsed.TotalSeconds;
        if (observed < MeasurementBatch) return; // Average cold starts and individual fsync spikes.
        double sample = observed / seconds / 2; // 50% reserve for live import and detectors.
        // The latest completed segment lets capacity recover after a slow one.
        Volatile.Write(ref rate, sample);
        observed = 0; seconds = 0;
    }
}

// The production worker's session lock still owns this child. A separate login
// connection permits progress during detector timeouts; per-source/action locks
// and lease tokens are unchanged. Stop drains a bounded slice, never abandons it.
internal sealed class SemanticOutboxPump : IAsyncDisposable
{
    private readonly CancellationTokenSource stop = new();
    private readonly Task<JsonObject> work;
    private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemanticWork? operations;
    private readonly object progress = new();
    private readonly JsonObject totals = new() { ["claimed"] = 0, ["completed"] = 0, ["failed"] = 0, ["normalized"] = 0, ["actions"] = 0 };
    private JsonObject reported = new();
    internal Task Ready => ready.Task;
    internal SemanticOutboxPump(PasswordProducerRuntime runtime, SemanticRuntimeSettings settings, string mode,
        int limit, string? repair, SemanticQueueRate rate, CancellationToken ct, SemanticWork? operations = null)
    {
        this.operations = operations;
        work = Run();
        operations?.Track("processing_outbox", work);
        async Task<JsonObject> Run()
        {
            try
            {
                await using var db = await runtime.OpenControlAsync(ct);
                var production = new SemanticProduction(runtime, settings, mode, limit, repair);
                do
                {
                    var watch = Stopwatch.StartNew();
                    var slice = await production.ProcessOutbox(db, ct);
                    rate.Observe(slice.Number("completed"), watch.Elapsed);
                    ready.TrySetResult();
                    lock (progress) {
                        foreach (string key in new[] { "claimed", "completed", "failed", "normalized", "actions" })
                            totals[key] = totals.Number(key) + slice.Number(key);
                        totals["jobs_per_second"] = rate.JobsPerSecond * 2;
                        totals["backfill_high_watermark"] = rate.HighWatermark;
                    }
                    if (slice.Number("claimed") == 0)
                    {
                        using var delay = CancellationTokenSource.CreateLinkedTokenSource(stop.Token, ct);
                        try { await Task.Delay(100, delay.Token); }
                        catch (OperationCanceledException) when (stop.IsCancellationRequested && !ct.IsCancellationRequested) { }
                    }
                    // Repair stays explicitly bounded; ordinary normalization
                    // keeps draining independently of the detection cycle.
                    if (repair is not null && totals.Number("claimed") >= limit) break;
                } while (!stop.IsCancellationRequested && !ct.IsCancellationRequested);
                return totals;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { ready.TrySetCanceled(ct); throw; }
            catch (Exception error) {
                var failure = new WorkerFailure("processing_outbox", WorkerFailure.Describe(error, "cycle"), error);
                ready.TrySetException(failure); throw failure;
            }
        }
    }
    internal async Task<JsonObject> StopAsync() {
        await stop.CancelAsync(); var result = await work;
        operations?.Forget("processing_outbox"); return result;
    }
    internal async Task<JsonObject> ProgressAsync()
    {
        if (work.IsCompleted) await work; // Surface a dead pump even when sources are queued.
        lock (progress) {
            var result = totals.DeepClone().AsObject();
            foreach (string key in new[] { "claimed", "completed", "failed", "normalized", "actions" })
                result[key] = totals.Number(key) - reported.Number(key);
            reported = totals.DeepClone().AsObject(); return result;
        }
    }
    public async ValueTask DisposeAsync() { try { await StopAsync(); } finally { stop.Dispose(); } }
}
