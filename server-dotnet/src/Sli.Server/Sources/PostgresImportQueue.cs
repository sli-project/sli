using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Sources;

internal sealed class PostgresImportQueueCanceled(string lockPath, long waitMs, CancellationToken ct)
    : OperationCanceledException("postgres_import_queue_canceled", ct)
{
    internal string LockPath { get; } = lockPath;
    internal long WaitMs { get; } = waitMs;
}

// Source: sources/postgres_import_queue.py. The owner replaced elapsed-time
// deadlines with caller cancellation and observable progress for live workers.
internal sealed class PostgresImportQueue
{
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static extern int Flock(int fileDescriptor, int operation);

    internal string LockPath { get; }
    internal TimeSpan PollInterval { get; }
    private readonly Action<string, long> report;

    internal PostgresImportQueue(string? repositoryRoot = null, Func<string, string?>? environment = null,
        Action<string, long>? report = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        string? configured = environment("ADLOG_POSTGRES_IMPORT_QUEUE_LOCK");
        LockPath = Path.GetFullPath(string.IsNullOrEmpty(configured)
            ? Path.Combine(AgentIngressDiagnostics.ResolveDataDirectory(repositoryRoot ?? LifecycleConfiguration.FindRoot(), environment),
                "runtime", "postgres-import.queue.lock") : configured);
        string? raw = environment("ADLOG_POSTGRES_IMPORT_QUEUE_POLL_SECONDS");
        double seconds = double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var value)
            && double.IsFinite(value) ? value : 0.2;
        PollInterval = TimeSpan.FromSeconds(Math.Clamp(seconds, 0.05, 5));
        this.report = report ?? Report;
    }

    internal async Task<Lease> AcquireAsync(string? server, CancellationToken ct, long? jobId = null, string? traceId = null)
    {
        long started = Stopwatch.GetTimestamp();
        long WaitMs() => (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        FileStream? handle = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            try { Directory.CreateDirectory(Path.GetDirectoryName(LockPath)!); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { throw new IOException($"postgres_import_queue_unavailable path={LockPath}: {error.Message}", error); }
            long lastReport = -30_000;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                // On Unix FileStream itself takes a shared flock when opening.
                // Another import's exclusive flock can therefore block the open.
                try { handle ??= new FileStream(LockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite); }
                catch (IOException error) when (OperatingSystem.IsLinux() && (error.HResult & 0xffff) is 11 or 32) { }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                { throw new IOException($"postgres_import_queue_unavailable path={LockPath}: {error.Message}", error); }
                if (handle is not null && TryLock(handle)) break;
                long wait = WaitMs();
                if (wait - lastReport >= 30_000) { Observe("queue_wait", wait); lastReport = wait; }
                await Task.Delay(PollInterval, ct);
            }
            long waitMs = WaitMs();
            handle.SetLength(0);
            byte[] metadata = Encoding.UTF8.GetBytes($"pid={Environment.ProcessId} job_id={jobId?.ToString(CultureInfo.InvariantCulture) ?? "None"} server={Field(server)} trace_id={Field(traceId)}\n");
            await handle.WriteAsync(metadata, ct);
            await handle.FlushAsync(ct);
            Observe("queue_acquired", waitMs);
            var lease = new Lease(handle, LockPath, waitMs, () => Observe("queue_released", waitMs));
            handle = null; // The lease owns the OS handle; closing it also releases the lock after exceptions.
            return lease;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            long waitMs = WaitMs();
            Observe("queue_canceled", waitMs);
            throw new PostgresImportQueueCanceled(LockPath, waitMs, ct);
        }
        finally { handle?.Dispose(); }
    }

    private static bool TryLock(FileStream handle)
    {
        if (OperatingSystem.IsWindows())
        {
            try { handle.Lock(0, 1); return true; }
            catch (IOException error) when ((error.HResult & 0xffff) == 33) { return false; }
        }
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("postgres_import_queue_platform_unsupported");
        // FileStream.Lock uses fcntl on Unix, which does not interoperate with Python's flock.
        if (Flock(handle.SafeFileHandle.DangerousGetHandle().ToInt32(), 2 | 4) == 0) return true;
        int code = Marshal.GetLastPInvokeError();
        if (code is 11 or 4) return false; // EWOULDBLOCK / EINTR: keep waiting, with no deadline.
        throw new Win32Exception(code);
    }

    // Source identity is local lock metadata only, never part of progress logs.
    private static string Field(string? value) => value is null ? "None"
        : new string(value.Take(256).Select(c => char.IsControl(c) ? ' ' : c).ToArray());

    private void Observe(string state, long waitMs)
    {
        try { report(state, waitMs); }
        catch { /* Optional observation must never strand a lock or discard an import. */ }
    }

    private static void Report(string state, long waitMs) => Console.WriteLine(new JsonObject {
        ["component"] = "postgres_import_queue", ["event"] = state, ["pid"] = Environment.ProcessId,
        ["wait_ms"] = waitMs, ["heartbeat_at_utc"] = DateTimeOffset.UtcNow.ToString("O"),
        ["message"] = state == "queue_wait" ? "Ожидаем завершения другого импорта PostgreSQL." : null
    }.ToJsonString());

    internal sealed class Lease(FileStream handle, string lockPath, long waitMs, Action released) : IDisposable
    {
        private FileStream? stream = handle;
        internal string LockPath { get; } = lockPath;
        internal long WaitMs { get; } = waitMs;
        public void Dispose()
        {
            var owned = Interlocked.Exchange(ref stream, null);
            if (owned is null) return;
            try { owned.Dispose(); }
            finally { released(); }
        }
    }
}
