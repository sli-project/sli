using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;

namespace Sli.Server.Jobs;

public static class CoreJobProcess
{
    // One sandbox per purpose. Never combine handler and publisher credentials.
    // A changed handler/generation/budget/environment gets a fresh sandbox.
    internal sealed class Persistent(Func<JsonObject, string, ProcessStartInfo>? startInfo = null) : IAsyncDisposable
    {
        private readonly Dictionary<string, (string Key, Child Process)> children = [];
        public async Task<JsonObject> RunAsync(JsonObject job, string purpose, TimeSpan timeout, Func<Task>? heartbeat, CancellationToken stopping)
        {
            var start = (startInfo ?? (static (request, stage) => StartInfo(request, stage, Environment.GetEnvironmentVariable)))(job, purpose);
            if (startInfo is null) start.ArgumentList.Add("--persistent");
            string key = CoreJobJson.Digest(new JsonObject
            {
                ["identity"] = CoreJobJson.Pick(job, "plugin_id", "plugin_version", "manifest_sha256", "handler_id", "handler_version", "resource_profile", "rights_profile", "budget"),
                ["environment"] = new JsonObject(start.Environment.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => KeyValuePair.Create<string, JsonNode?>(p.Key, JsonValue.Create(p.Value))))
            });
            if (children.TryGetValue(purpose, out var previous) && previous.Key != key)
            { children.Remove(purpose); await previous.Process.DisposeAsync(); }
            if (!children.TryGetValue(purpose, out var current))
            {
                var process = new Child(start);
                current = (key, process); children.Add(purpose, current);
            }
            try
            {
                var result = await current.Process.RunAsync(job, heartbeat, stopping);
                if (result["status"]?.GetValue<string>() is "retryable_error" or "permanent_error")
                { children.Remove(purpose); await current.Process.DisposeAsync(); }
                return result;
            }
            catch
            {
                children.Remove(purpose); await current.Process.DisposeAsync(); throw;
            }
        }
        public async ValueTask DisposeAsync()
        {
            foreach (var child in children.Values) await child.Process.DisposeAsync();
            children.Clear();
        }
        private sealed class Child : IAsyncDisposable
        {
            private readonly Process process;
            private readonly CancellationTokenSource io = new();
            private readonly Task<string> errors;
            public Child(ProcessStartInfo start)
            {
                process = new Process { StartInfo = start };
                try { process.Start(); }
                catch { process.Dispose(); io.Dispose(); throw; }
                errors = ReadStderr(process.StandardError, io.Token);
            }
            public async Task<JsonObject> RunAsync(JsonObject job, Func<Task>? heartbeat, CancellationToken stopping)
            {
                var watch = Stopwatch.StartNew();
                var nextHeartbeat = TimeSpan.FromSeconds(10);
                long peak = 0; int retries = 0;
                using var requestCancellation = CancellationTokenSource.CreateLinkedTokenSource(stopping, io.Token);
                var ct = requestCancellation.Token;
                var response = ReadFrame(process.StandardOutput.BaseStream, job["budget"]!["max_result_bytes"]!.GetValue<long>(), ct);
                var request = WriteRequest(process.StandardInput, job, ct);
                try
                {
                    while (true)
                    {
                        stopping.ThrowIfCancellationRequested();
                        if (process.HasExited)
                        {
                            KillGroup(process);
                            throw new ExitFailure(process.ExitCode, await errors.WaitAsync(TimeSpan.FromSeconds(2), ct));
                        }
                        if (request.IsFaulted && request.Exception?.InnerException is not IOException) await request;
                        process.Refresh(); peak = Math.Max(peak, process.PeakWorkingSet64);
                        if (peak > job["budget"]!["memory_bytes"]!.GetValue<long>()) throw new InvalidOperationException("job_child_memory_exceeded");
                        if (response.IsCompleted) break;
                        if (heartbeat is not null && watch.Elapsed >= nextHeartbeat)
                        {
                            try { await heartbeat(); nextHeartbeat = watch.Elapsed + TimeSpan.FromSeconds(10); }
                            catch (PostgresException error) when (error.SqlState == "55P03")
                            { retries++; nextHeartbeat = watch.Elapsed + TimeSpan.FromMilliseconds(100); }
                        }
                        await Task.WhenAny(response, Task.Delay(100, ct));
                    }
                    var bytes = await response; await request;
                    JsonObject result;
                    try { result = JsonNode.Parse(bytes) as JsonObject ?? throw new CoreJobContractException("job_result_invalid"); }
                    catch (System.Text.Json.JsonException) { throw new CoreJobContractException("job_result_invalid"); }
                    result["resource_usage"] = new JsonObject { ["wall_seconds"] = watch.Elapsed.TotalSeconds, ["peak_memory_bytes"] = peak, ["heartbeat_lock_retries"] = retries };
                    return result;
                }
                finally
                {
                    requestCancellation.Cancel();
                    // Observe pipe tasks before another request can use either stream.
                    foreach (Task task in new Task[] { response, request })
                        try { await task; } catch (Exception) { }
                }
            }
            private static async Task WriteRequest(StreamWriter writer, JsonObject job, CancellationToken ct)
            {
                await writer.WriteLineAsync(CanonicalJson.Serialize(job).AsMemory(), ct);
                await writer.FlushAsync(ct);
            }
            public async ValueTask DisposeAsync()
            {
                KillGroup(process); io.Cancel();
                try { await errors.WaitAsync(TimeSpan.FromSeconds(2)); } catch (Exception) { }
                await process.WaitForExitAsync(CancellationToken.None);
                process.Dispose(); io.Dispose();
            }
        }
    }
    internal static async Task<byte[]> ReadFrame(Stream stream, long limit, CancellationToken ct)
    {
        // A short decimal byte count precedes each JSON result. Check the limit
        // before allocation; never use an unbounded ReadLine on child output.
        byte[] one = new byte[1]; long length = 0; int digits = 0, headerBytes = 0;
        while (true)
        {
            await stream.ReadExactlyAsync(one, ct);
            if (++headerBytes > 12) throw new CoreJobContractException("job_result_invalid");
            if (one[0] == '\n' && digits != 0) break;
            if (one[0] == '\r') continue;
            if (one[0] is < (byte)'0' or > (byte)'9' || ++digits > 10) throw new CoreJobContractException("job_result_invalid");
            length = length * 10 + one[0] - '0';
            if (length > limit) throw new CoreJobContractException("job_result_budget_exceeded");
        }
        var result = new byte[checked((int)length)];
        await stream.ReadExactlyAsync(result, ct);
        await stream.ReadExactlyAsync(one, ct);
        if (one[0] == '\r') await stream.ReadExactlyAsync(one, ct);
        if (one[0] != '\n') throw new CoreJobContractException("job_result_invalid");
        return result;
    }
    internal sealed class ExitFailure(int exitCode, string stderr) : InvalidOperationException("job_child_exited")
    {
        internal int ExitCode { get; } = exitCode;
        internal string Stderr { get; } = stderr;
    }

    public static ProcessStartInfo StartInfo(JsonObject job, string purpose, Func<string, string?> environment)
        => StartInfo(job, purpose, environment, Environment.ProcessPath ?? throw new InvalidOperationException("job_child_host_invalid"), Assembly.GetEntryAssembly() == typeof(CoreJobProcess).Assembly);
    internal static ProcessStartInfo StartInfo(JsonObject job, string purpose, Func<string, string?> environment, string executable, bool serverEntry)
    {
        if (purpose is not ("handler" or "publisher")) throw new CoreJobContractException("executor_purpose_invalid");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(typeof(CoreJobProcess).Assembly.Location);
        else if (!serverEntry)
            throw new InvalidOperationException("job_child_host_invalid");
        start.ArgumentList.Add("core-job-executor"); start.ArgumentList.Add("--profile"); start.ArgumentList.Add(job.Text("resource_profile"));
        start.ArgumentList.Add("--child"); start.ArgumentList.Add(purpose);
        start.Environment.Clear();
        foreach (var (key, value) in CoreJobIdentity.ChildEnvironment(new(job.Text("resource_profile"), purpose, job.Text("plugin_id"), job.Text("handler_id")), environment)) start.Environment[key] = value;
        // These children run one serial database stage. Do not let host CPU/cache
        // topology size their GC or thread pool. A single visible processor also
        // selects workstation GC even with the web host's System.GC.Server=true.
        // Reserve half the budget for native/JIT/stack memory, and collect gen0
        // early instead of using a minimum derived from the runner's LLC size.
        start.Environment["DOTNET_GCHeapHardLimit"] = (job["budget"]!["memory_bytes"]!.GetValue<long>() / 2).ToString("X", CultureInfo.InvariantCulture);
        start.Environment["DOTNET_PROCESSOR_COUNT"] = "1";
        start.Environment["DOTNET_GCgen0size"] = "100000"; // 1 MiB, hexadecimal
        start.Environment["DOTNET_GCHeapCount"] = "1";
        start.Environment["DOTNET_EnableDiagnostics"] = "0";
        // glibc's per-thread malloc arenas reserve writable address space too;
        // avoid exhausting RLIMIT_DATA on unused arena capacity.
        start.Environment["MALLOC_ARENA_MAX"] = "1";
        return start;
    }

    public static Task<JsonObject> RunAsync(JsonObject job, string purpose, TimeSpan timeout, Func<Task>? heartbeat, CancellationToken stopping)
        => RunAsync(StartInfo(job, purpose, Environment.GetEnvironmentVariable), job["budget"]!.AsObject(), timeout, heartbeat, stopping, job);

    internal static async Task<JsonObject> RunAsync(ProcessStartInfo start, JsonObject budget, TimeSpan timeout, Func<Task>? heartbeat, CancellationToken stopping, JsonObject? input = null)
    {
        // This overload also tests watchdogs with disposable synthetic processes.
        using var process = new Process { StartInfo = start };
        var watch = Stopwatch.StartNew(); long peak = 0; int heartbeatLockRetries = 0;
        TimeSpan nextHeartbeat = TimeSpan.FromSeconds(10);
        using var io = new CancellationTokenSource();
        process.Start();
        Task<byte[]>? response = null; Task<string>? errors = null; Task? request = null;
        try
        {
            request = WriteInput(process, input ?? throw new CoreJobContractException("job_input_invalid"), io.Token);
            response = ReadResult(process.StandardOutput.BaseStream, budget["max_result_bytes"]!.GetValue<long>(), io.Token);
            errors = ReadStderr(process.StandardError, io.Token);
            while (!process.HasExited)
            {
                var now = watch.Elapsed;
                stopping.ThrowIfCancellationRequested();
                // A broken stdin pipe can be the consequence of a crash. Observe
                // exit first so it does not hide the exit code and stderr.
                if (request.IsFaulted && request.Exception?.InnerException is not IOException) await request;
                if (response.IsFaulted) await response;
                try
                {
                    process.Refresh();
                    peak = Math.Max(peak, process.PeakWorkingSet64);
                }
                catch (InvalidOperationException) when (process.HasExited)
                {
                    // The child can exit between the liveness check and reading its metrics.
                    break;
                }
                if (peak > budget["memory_bytes"]!.GetValue<long>()) throw new InvalidOperationException("job_child_memory_exceeded");
                if (heartbeat is not null && now >= nextHeartbeat)
                {
                    try { await heartbeat(); nextHeartbeat = watch.Elapsed + TimeSpan.FromSeconds(10); }
                    catch (PostgresException error) when (error.SqlState == "55P03")
                    {
                        // A publication batch owns the fenced job row. Yield
                        // until it commits instead of killing its live child.
                        // The database still rejects an expired or changed lease.
                        heartbeatLockRetries++; nextHeartbeat = watch.Elapsed + TimeSpan.FromMilliseconds(100);
                    }
                }
                await Task.Delay(100, CancellationToken.None);
            }
            stopping.ThrowIfCancellationRequested();
            // Kill descendants before awaiting pipe EOF: inherited pipe handles must never hang the host.
            KillGroup(process);
            if (process.ExitCode != 0)
            {
                string stderr;
                try { stderr = await errors.WaitAsync(TimeSpan.FromSeconds(2)); }
                catch (Exception error) when (error is TimeoutException or IOException) { stderr = "[unavailable]"; }
                throw new ExitFailure(process.ExitCode, stderr);
            }
            var bytes = await response.WaitAsync(TimeSpan.FromSeconds(2));
            await request; await errors.WaitAsync(TimeSpan.FromSeconds(2));
            JsonObject result;
            try { result = JsonNode.Parse(bytes) as JsonObject ?? throw new CoreJobContractException("job_result_invalid"); }
            catch (System.Text.Json.JsonException) { throw new CoreJobContractException("job_result_invalid"); }
            result["resource_usage"] = new JsonObject { ["wall_seconds"] = watch.Elapsed.TotalSeconds, ["peak_memory_bytes"] = peak == 0 ? null : JsonValue.Create(peak), ["heartbeat_lock_retries"] = heartbeatLockRetries };
            return result;
        }
        finally
        {
            KillGroup(process); io.Cancel();
            foreach (var task in new Task?[] { response, errors, request })
                if (task is not null) try { await task.WaitAsync(TimeSpan.FromSeconds(2)); } catch (Exception) { /* Never expose child output. */ }
            await process.WaitForExitAsync(CancellationToken.None);
        }
    }
    private static async Task WriteInput(Process process, JsonObject input, CancellationToken ct)
    {
        await process.StandardInput.WriteAsync(CanonicalJson.Serialize(input).AsMemory(), ct);
        process.StandardInput.Close();
    }
    private static async Task<byte[]> ReadResult(Stream stream, long limit, CancellationToken ct)
    {
        using var result = new MemoryStream(); byte[] buffer = new byte[4096]; int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (result.Length + read > limit) throw new CoreJobContractException("job_result_budget_exceeded");
            result.Write(buffer, 0, read);
        }
        return result.ToArray();
    }
    private static async Task<string> ReadStderr(TextReader reader, CancellationToken ct)
    {
        // Always drain the pipe, retaining at most 2 KiB of characters. Raw child
        // output can contain SQL, credentials or host data; emit only fixed CLR
        // messages, never arbitrary lines or stack traces from this tail.
        var tail = new StringBuilder(); char[] buffer = new char[512]; int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), ct)) > 0)
        {
            tail.Append(buffer, 0, read);
            if (tail.Length > 2048) tail.Remove(0, tail.Length - 2048);
        }
        string text = tail.ToString();
        string[] known = ["Out of memory.", "Failed to create CoreCLR, HRESULT: 0x8007000E",
            "GC heap initialization failed with error 0x8007000E", "Failed to reserve memory for GC heap",
            "Failed to create RW mapping for RX memory"];
        string safe = string.Join("\n", known.Where(message => text.Contains(message, StringComparison.Ordinal)));
        return safe.Length != 0 ? safe : text.Length == 0 ? "" : "[redacted]";
    }
    [DllImport("libc", EntryPoint = "kill")] private static extern int Kill(int pid, int signal);
    [DllImport("libc", EntryPoint = "setsid")] private static extern int SetSid();
    [DllImport("libc", EntryPoint = "setrlimit", SetLastError = true)] private static extern int SetLimit(int resource, ref RLimit limit);
    [StructLayout(LayoutKind.Sequential)] private struct RLimit { public ulong Current, Maximum; }
    internal static void KillGroup(Process process)
    {
        if (OperatingSystem.IsLinux()) Kill(-process.Id, 9);
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
    }
    internal static void Isolate()
    {
        if (OperatingSystem.IsLinux() && SetSid() < 0) throw new InvalidOperationException("job_child_failed");
    }
    internal static void Limits(JsonObject budget)
    {
        if (!OperatingSystem.IsLinux()) return;
        // Linux resource 2 is RLIMIT_DATA (RLIMIT_AS is 9). Keep this kernel
        // bound: a managed heap cap and a sampled RSS watchdog alone cannot stop
        // a native allocation between samples.
        // CLR reserves a large PROT_NONE virtual address range. Bound writable data
        // allocations (RLIMIT_DATA), the GC heap and measured RSS, rather than
        // making the CLR's address reservation itself exhaust RLIMIT_AS.
        // Elapsed time and CPU time do not prove death. The parent observes
        // process exit/connection failure and keeps renewing the existing lease.
        // RLIMIT_FSIZE also covers CLR memfd code-backing files (192 KiB
        // templates), not just application files. A 64 KiB result cap can send
        // SIGXFSZ during later JIT compilation. Bound files by the memory budget;
        // ReadResult independently enforces max_result_bytes on the stdout pipe.
        ulong memory = (ulong)budget["memory_bytes"]!.GetValue<long>();
        foreach (var (resource, cap) in new (int, ulong)[] { (1, memory), (2, memory), (4, 0) })
        {
            var limit = new RLimit { Current = cap, Maximum = cap };
            if (SetLimit(resource, ref limit) != 0) throw new InvalidOperationException("job_child_failed");
        }
    }
}
