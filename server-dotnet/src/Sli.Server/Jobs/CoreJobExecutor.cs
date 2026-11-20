using System.Text.Json.Nodes;

namespace Sli.Server.Jobs;

public delegate Task<JsonObject> CoreJobChild(JsonObject job, string purpose, TimeSpan timeout, Func<Task>? heartbeat, CancellationToken stopping);

public sealed class CoreJobExecutor(CoreJobQueue queue, CoreJobRegistry registry, CoreJobChild child, TimeProvider? timeProvider = null,
    Func<JsonObject, string, bool, Task>? recordFailure = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    public async Task ExecuteAsync(JsonObject job, CancellationToken stopping)
    {
        long started = clock.GetTimestamp();
        var timeout = TimeSpan.FromSeconds(Math.Min(job["budget"]!["wall_seconds"]!.Integer(), job["remaining_seconds"]!.Number()));
        TimeSpan Remaining() => timeout - clock.GetElapsedTime(started);
        async Task Beat() => await queue.HeartbeatAsync(job, CancellationToken.None);
        try
        {
            registry.Resolve(job);
            await Beat();
            var result = await child(job, "handler", Remaining(), Beat, stopping);
            switch (result["status"]?.GetValue<string>())
            {
                case "lease_lost": throw new CoreJobLeaseLost();
                case "retryable_error": throw new CoreJobQueryFailure(SafeFailure(result));
                case "success": case "partial": case "blocked": case "cancelled": break;
                default: throw new CoreJobContractException("job_result_invalid");
            }
            await Beat();
            var publishing = (JsonObject)job.DeepClone(); publishing["staged_result"] = result;
            var remaining = Remaining();
            var outcome = await child(publishing, "publisher", remaining < TimeSpan.FromSeconds(20) ? remaining : TimeSpan.FromSeconds(20),
                Workstations.WorkstationJobPlugin.Drains(job) ? Beat : null, stopping);
            if (outcome["status"]?.GetValue<string>() == "lease_lost") throw new CoreJobLeaseLost();
            if (outcome["status"]?.GetValue<string>() == "retryable_error") throw new CoreJobQueryFailure(SafeFailure(outcome));
            if (outcome["status"]?.GetValue<string>() is not ("committed" or "duplicate" or "conflict")) throw new CoreJobContractException("job_publication_invalid");
        }
        catch (CoreJobLeaseLost) { /* Reaper recovers; never act with a stale fence. */ }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            string code = error is CoreJobQueryFailure failure ? failure.Message : CoreJobCommand.FailureCode(error);
            var diagnostic = CoreJobCommand.Diagnostic(error);
            diagnostic["error_code"] = code;
            diagnostic["job_id"] = job["job_id"]?.DeepClone();
            Console.Error.WriteLine("core_job_failed " + diagnostic.ToJsonString());
            try
            {
                if (recordFailure is not null) await recordFailure(job, code, error is CoreJobContractException);
                else await queue.FailAsync(job, code, error is CoreJobContractException, CancellationToken.None);
            }
            catch (CoreJobLeaseLost) { }
        }
    }
    private static string SafeFailure(JsonObject result) => result["error_code"]?.GetValue<string>() is
        "job_statement_cancelled" or "job_lock_unavailable" or "job_connection_lost" or "job_database_error" or "job_deadline_exceeded" or "job_child_failed" or "job_child_memory_exceeded" or "job_child_exited" or "job_child_start_failed" or "job_child_host_invalid"
        ? result["error_code"]!.GetValue<string>() : "job_execution_failed";
    private sealed class CoreJobQueryFailure(string code) : Exception(code);
}
