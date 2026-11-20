using System.Text.Json.Nodes;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

// Process observation is distinct from the worker's own durable progress and
// result receipts. No credential, source identity or event is included here.
public static class OperationsWorkerObservation
{
    public static Task<int> RunAsync(string name, Func<Task<int>> run, CancellationToken stopping = default) =>
        RunAsync(name, run, new OperationsFiles(new ConfigurationBuilder().Build()), stopping);

    internal static async Task<int> RunAsync(string name, Func<Task<int>> run, OperationsFiles files, CancellationToken stopping = default)
    {
        string directory = Path.Combine(files.DataRoot, "runtime"), instance = Guid.NewGuid().ToString("N");
        DateTimeOffset started = DateTimeOffset.UtcNow;
        void Write(string status, string phase, int? exit = null)
        {
            try
            {
                Directory.CreateDirectory(directory);
                string path = Path.Combine(directory, "native-" + name + ".json"), temporary = path + "." + instance + ".tmp";
                var heartbeat = Payload(name, instance, Environment.ProcessId, started, DateTimeOffset.UtcNow, status, phase, exit);
                File.WriteAllText(temporary, heartbeat.ToJsonString()); File.Move(temporary, path, true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { /* Observation never changes worker admission or outcomes. */ }
        }
        Write("running", "starting");
        using var stop = new CancellationTokenSource();
        async Task Observe()
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
            try { while (await timer.WaitForNextTickAsync(stop.Token)) Write("running", "process_alive"); }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        var observation = Observe(); int code = 1;
        try { code = await run(); return code; }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { code = 0; return code; }
        finally { stop.Cancel(); await observation; Write(code == 0 ? "stopped" : "failed", "exited", code); }
    }
    internal static JsonObject Payload(string name, string instance, int pid, DateTimeOffset started, DateTimeOffset now, string status, string phase, int? exit) => new()
    {
        ["worker_name"] = name, ["worker_instance_id"] = instance, ["process_pid"] = pid, ["started_at"] = Stamp(started),
        ["heartbeat_at_utc"] = Stamp(now), ["expected_interval_seconds"] = 30, ["status"] = status, ["phase"] = phase,
        ["last_result"] = new JsonObject { ["process_exit_code"] = exit, ["service_outcome"] = "unknown", ["basis"] = "process_observation_only" }
    };
}
