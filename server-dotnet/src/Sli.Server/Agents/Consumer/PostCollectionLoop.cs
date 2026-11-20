using System.Text.Json.Nodes;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.Consumer;

public sealed record PostCollectionBatch(int Scanned, int Imported,
    IReadOnlyDictionary<string, int> PendingReasons, int Quarantined = 0)
{
    public JsonObject? Cursor { get; init; }
    public long Skipped { get; init; }
    public static PostCollectionBatch Empty { get; } = new(0, 0, new Dictionary<string, int>());
    public JsonObject ToJson() => new() {
        ["scanned"] = Scanned, ["imported"] = Imported, ["quarantined"] = Quarantined,
        ["pending_reasons"] = new JsonObject(PendingReasons.Select(p => KeyValuePair.Create<string, JsonNode?>(p.Key, JsonValue.Create(p.Value)))),
        ["cursor"] = Cursor?.DeepClone(), ["skipped"] = Skipped
    };
}

// Work owners execute serially under the host's process lock. Monitoring uses
// its own connection so a long import does not hide the current phase/cursor.
public sealed class PostCollectionLoop(
    Func<CancellationToken, Task<PostCollectionBatch>> events,
    Func<CancellationToken, Task<PostCollectionBatch>> snapshots,
    Func<CancellationToken, Task<PostCollectionBatch>> accounting,
    Func<string, string, JsonObject, CancellationToken, Task> heartbeat,
    Func<TimeSpan> elapsed,
    Func<TimeSpan, CancellationToken, Task> delay,
    Action<JsonObject>? output = null,
    Func<CancellationToken, Task<Sli.Server.Legacy.LegacyPostResult>>? legacy = null,
    Func<CancellationToken, Task>? cleanup = null,
    Func<TimeSpan, CancellationToken, Task>? pulseDelay = null)
{
    public async Task<int> RunAsync(AgentImportOptions options, CancellationToken ct)
    {
        TimeSpan nextSnapshot = TimeSpan.Zero;
        TimeSpan nextCleanup = TimeSpan.Zero;
        var progress = new JsonObject { ["limit"] = options.Limit };
        while (!ct.IsCancellationRequested)
        {
            await heartbeat("running", "poll", new JsonObject { ["limit"] = options.Limit }, ct);
            if (cleanup is not null && elapsed() >= nextCleanup)
            {
                try { await Processing("cleanup", async token => { await cleanup(token); return true; }, progress, options, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception error) { Console.Error.WriteLine(WorkerFailure.Describe(error, "post_collection_cleanup")); }
                finally { nextCleanup = elapsed() + TimeSpan.FromHours(6); }
            }
            ct.ThrowIfCancellationRequested();
            var packets = await Poll(token => Processing("event_inbox", events, progress, options, token), "agent_consumer_unavailable", ct);
            progress["agent_packets"] = packets.ToJson();
            ct.ThrowIfCancellationRequested();
            // Snapshot cycles belong to the core inbox poll in the source and
            // must run before a potentially long legacy report.
            var cycles = PostCollectionBatch.Empty;
            if (elapsed() >= nextSnapshot)
            {
                cycles = await Poll(token => Processing("snapshot_cycles", snapshots, progress, options, token), "agent_snapshot_import_unavailable", ct);
                nextSnapshot = elapsed() + (cycles.Scanned == 4 && cycles.PendingReasons.Count == 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(30));
                progress["snapshots"] = cycles.ToJson();
            }
            ct.ThrowIfCancellationRequested();
            var post = new Sli.Server.Legacy.LegacyPostResult(0, 0, 0);
            bool iterationFailed = false;
            if (legacy is not null)
            {
                try { post = await Processing("legacy_post_collection", legacy, progress, options, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception) { post = new(0, 0, 1); iterationFailed = true; }
            }
            ct.ThrowIfCancellationRequested();
            var radius = iterationFailed ? PostCollectionBatch.Empty :
                await Poll(token => Processing("accounting", accounting, progress, options, token), "agent_radius_import_failed", ct);
            progress["accounting"] = radius.ToJson();
            ct.ThrowIfCancellationRequested();
            bool failed = post.Failed > 0 || Failed(packets, "agent_consumer_unavailable", "agent_projection_failed", "agent_ad_dc_projection_failed")
                || Failed(cycles, "agent_snapshot_import_unavailable") || Failed(radius, "agent_radius_import_failed");
            var snapshotDetails = cycles.ToJson(); snapshotDetails["completed"] = cycles.Imported; snapshotDetails.Remove("imported"); snapshotDetails.Remove("quarantined");
            var packetDetails = packets.ToJson(); packetDetails["snapshots"] = snapshotDetails.DeepClone();
            var lastResult = new JsonObject { ["failed"] = post.Failed + (Failed(radius, "agent_radius_import_failed") ? 1 : 0) };
            if (iterationFailed) lastResult["reason"] = "post_collection_worker_iteration_failed";
            if (legacy is not null) { lastResult["claimed"] = post.Claimed; lastResult["completed"] = post.Completed; }
            if (radius.Imported > 0) lastResult["agent_accounting_packets_imported"] = radius.Imported;
            var details = new JsonObject { ["last_result"] = lastResult, ["agent_packets"] = packetDetails, ["snapshots"] = snapshotDetails, ["accounting"] = radius.ToJson() };
            output?.Invoke((JsonObject)details.DeepClone());
            await heartbeat(failed ? "failed" : packets.Quarantined + radius.Quarantined > 0 ? "warning" : "idle", "sleep", details, ct);
            if (options.Once) return legacy is null ? failed ? 1 : 0 :
                post.Failed > 0 || Failed(cycles, "agent_snapshot_import_unavailable") || Failed(radius, "agent_radius_import_failed") ? 1 : 0;
            if (iterationFailed || packets.Scanned != 16) await delay(TimeSpan.FromSeconds(Math.Clamp(options.PollSeconds, 1, 300)), ct);
        }
        return 0;
    }

    private static bool Failed(PostCollectionBatch batch, params string[] reasons) =>
        reasons.Any(reason => batch.PendingReasons.GetValueOrDefault(reason) > 0);

    private async Task<T> Processing<T>(string phase, Func<CancellationToken, Task<T>> run, JsonObject progress,
        AgentImportOptions options, CancellationToken ct)
    {
        await heartbeat("running", phase, (JsonObject)progress.DeepClone(), ct);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        async Task Pulse()
        {
            try
            {
                while (true)
                {
                    await (pulseDelay ?? Task.Delay)(TimeSpan.FromSeconds(Math.Clamp(options.PollSeconds, 1, 300)), stop.Token);
                    try { await heartbeat("running", phase, (JsonObject)progress.DeepClone(), stop.Token); }
                    catch (OperationCanceledException) when (stop.IsCancellationRequested) { throw; }
                    catch (Exception error) { Console.Error.WriteLine(WorkerFailure.Describe(error, "post_collection_monitor_heartbeat")); }
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        var pulse = Pulse();
        try { return await run(ct); }
        finally { stop.Cancel(); await pulse; }
    }

    private static async Task<PostCollectionBatch> Poll(Func<CancellationToken, Task<PostCollectionBatch>> poll, string failure, CancellationToken ct)
    {
        try { return await poll(ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return new(0, 0, new Dictionary<string, int> { [failure] = 1 }); }
    }
}
