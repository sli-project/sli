using System.Text.Json.Nodes;

namespace Sli.Server.Legacy;

public sealed class LegacyCollectionWorker(ILegacyJobs jobs, ILegacyJobExecution execution, LegacyJobStore store,
    ILegacyCollectionState state, LegacyCollectionPreflight preflight, ILegacyHeartbeat heartbeat)
{
    public async Task<int> RunAsync(string server, string worker, LegacyJobInput input, bool once, int interval, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(server)) {
            await Beat(new() { ["status"] = "blocked", ["phase"] = "security_context_preflight", ["reason"] = "windows_context_preflight_server_required" });
            return 2;
        }
        JsonObject probe;
        try { probe = await preflight.RunAsync(server, worker, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { await Beat(new() { ["status"] = "blocked", ["phase"] = "collection_block_recovery", ["reason"] = "collection_block_clear_failed" }); return 2; }
        if (probe["status"]?.GetValue<string>() != "ok") {
            probe["status"] = "blocked"; probe["phase"] = "security_context_preflight";
            await Beat(probe); return 2;
        }
        do {
            var result = await RunCycleAsync(input, worker, interval, ct);
            await Beat(result);
            string? status = result["status"]?.GetValue<string>();
            if (status == "blocked") return 2;
            if (once) return status is "completed" or "partial" or "skipped" ? 0 : 1;
            await Task.Delay(TimeSpan.FromSeconds(interval), ct);
        } while (!ct.IsCancellationRequested);
        return 0;

        Task Beat(JsonObject result)
        {
            var details = new JsonObject();
            foreach (string key in new[] { "status", "phase", "reason", "operator_action", "job_id", "run_id" }) details[key] = result[key]?.DeepClone();
            Console.WriteLine(details.ToJsonString());
            return heartbeat.WriteAsync("collection", worker, result["status"]!.GetValue<string>(),
                result["phase"]?.GetValue<string>() ?? "sleep", interval, details, ct);
        }
    }

    public async Task<JsonObject> RunCycleAsync(LegacyJobInput input, string worker, int interval, CancellationToken ct)
    {
        var block = await state.BlockAsync(ct);
        if (block is not null) return Blocked(block);
        string run = Guid.NewGuid().ToString("N");
        await state.StartAsync(run, worker, input, ct);
        JsonObject result;
        try {
            var job = await jobs.CreateExternalAsync(input, ct);
            if (job["id"] is not {} idNode) {
                result = job;
                result["phase"] ??= "admission";
            } else {
                int id = idNode.GetValue<int>();
                var servers = job["servers"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();
                var task = execution.RunAsync(new(id, true, input with { Servers = servers }, "external_worker"), ct);
                // No deadline: report the active job while acquisition is still alive.
                using var ticks = new PeriodicTimer(TimeSpan.FromSeconds(30));
                Task<bool>? tick = null;
                try {
                    while (!task.IsCompleted) {
                        var current = store.Get(id)!;
                        await heartbeat.WriteAsync("collection", worker, "running", current["phase"]?.GetValue<string>() ?? "collection", interval,
                            new() { ["job_id"] = id, ["status"] = "running", ["phase"] = current["phase"]?.DeepClone() }, ct);
                        tick ??= ticks.WaitForNextTickAsync(ct).AsTask();
                        if (await Task.WhenAny(task, tick) == task) break;
                        await tick; tick = null;
                    }
                }
                finally { await task; } // Never detach acquisition if heartbeat persistence fails.
                result = store.Get(id)!;
                result["job_id"] = id;
                var decision = LegacyCollectionFailurePolicy.Classify(result["errors"]!.AsArray().Select(n => (object?)n?.GetValue<string>()));
                block = await state.BlockAsync(ct); // A collector can persist a block without recognizable localized text.
                if (decision.Blocked || block is not null) {
                    result["original_status"] = result["status"]?.DeepClone(); result["status"] = "blocked";
                    result["phase"] = decision.Phase ?? "operator_action_required";
                    result["reason"] = decision.Code ?? block?["reason_code"]?.GetValue<string>();
                    result["operator_action"] = decision.OperatorAction ?? block?["operator_action"]?.GetValue<string>();
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) {
            var decision = LegacyCollectionFailurePolicy.Classify([error]);
            result = new() { ["status"] = decision.Blocked ? "blocked" : "failed", ["phase"] = decision.Phase ?? "worker_failed",
                ["reason"] = decision.Code ?? "collection_worker_cycle_failed", ["operator_action"] = decision.OperatorAction,
                ["errors"] = new JsonArray(decision.Code ?? "collection_worker_cycle_failed") };
        }
        result["run_id"] = run;
        await state.FinishAsync(run, result, ct);
        return result;
    }
    private static JsonObject Blocked(JsonObject block) => new() { ["status"] = "blocked", ["phase"] = "operator_action_required",
        ["reason"] = block["reason_code"]?.DeepClone(), ["operator_action"] = block["operator_action"]?.DeepClone() };
}
