using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Sources;

public sealed class PostgresImportQueueTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "sli-import-queue-" + Guid.NewGuid().ToString("N"));
    private string LockPath => Path.Combine(root, "maintenance", "pg-import.lock");
    private PostgresImportQueue Queue(Action<string, long>? report = null) => new(root, key => key switch {
        "ADLOG_POSTGRES_IMPORT_QUEUE_LOCK" => LockPath,
        "ADLOG_POSTGRES_IMPORT_QUEUE_POLL_SECONDS" => "0.01",
        _ => null
    }, report ?? ((_, _) => { }));

    // Python: test_queue_acquires_and_reports_wait, including the Windows rule
    // that metadata is read only after the locked handle has been closed.
    [Fact]
    public async Task QueueAcquiresReportsWaitAndLeavesMetadataAfterRelease()
    {
        var events = new List<string>();
        var waits = new List<long>();
        var queue = Queue((state, wait) => { waits.Add(wait); events.Add(state); });
        using (var info = await queue.AcquireAsync("DC1", TestContext.Current.CancellationToken, 42, "synthetic-trace"))
        {
            Assert.Equal(LockPath, info.LockPath);
            Assert.True(info.WaitMs >= 0);
            Assert.True(File.Exists(LockPath));
            Assert.Equal(["queue_acquired"], events);
        }
        string metadata = await File.ReadAllTextAsync(LockPath, TestContext.Current.CancellationToken);
        Assert.Contains("server=DC1", metadata);
        Assert.Contains("pid=" + Environment.ProcessId, metadata);
        Assert.Contains("job_id=42", metadata);
        Assert.Contains("trace_id=synthetic-trace", metadata);
        Assert.Equal(["queue_acquired", "queue_released"], events);
        Assert.All(waits, wait => Assert.True(wait >= 0));
        Assert.Equal(waits[0], waits[1]); // Import duration must not inflate the queue wait metric.
        // Also proves clean lock release, rather than just a closed file handle.
        using var next = await queue.AcquireAsync("DC2", TestContext.Current.CancellationToken);
    }

    // The Python timeout_seconds=0 vector is superseded by Q500's no-deadline
    // rule. Exercise real contention, cancellation and the same diagnostic fields.
    [Fact]
    public async Task BusyQueueWaitsUntilCallerCancellationAndReportsPathAndWait()
    {
        var queue = Queue();
        using var owner = await queue.AcquireAsync("DC1", TestContext.Current.CancellationToken);
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var events = new List<string>();
        var waiter = Queue((state, _) => events.Add(state));
        var pending = waiter.AcquireAsync("DC2", cancel.Token);
        Assert.False(pending.IsCompleted);
        Assert.Equal(["queue_wait"], events);
        cancel.Cancel();
        var error = await Assert.ThrowsAsync<PostgresImportQueueCanceled>(() => pending);
        Assert.Equal(LockPath, error.LockPath);
        Assert.True(error.WaitMs >= 0);
        Assert.Equal(cancel.Token, error.CancellationToken);
        Assert.Equal(["queue_wait", "queue_canceled"], events);

        // Closing a canceled waiter's descriptor must not release the owner's lock.
        using var anotherCancel = new CancellationTokenSource();
        var another = queue.AcquireAsync("DC3", anotherCancel.Token);
        Assert.False(another.IsCompleted);
        anotherCancel.Cancel();
        await Assert.ThrowsAsync<PostgresImportQueueCanceled>(() => another);
        owner.Dispose();
        Assert.Contains("server=DC1", await File.ReadAllTextAsync(LockPath, TestContext.Current.CancellationToken));
        using var next = await queue.AcquireAsync("DC2", TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task WaitingImporterAcquiresAfterOwnerReleaseAndReplacesMetadata()
    {
        using var owner = await Queue().AcquireAsync(new string('x', 200), TestContext.Current.CancellationToken);
        var pending = Queue().AcquireAsync("DC2", TestContext.Current.CancellationToken);
        Assert.False(pending.IsCompleted);
        owner.Dispose();
        using (var next = await pending)
        {
            Assert.True(next.WaitMs >= 0);
            Assert.Equal(LockPath, next.LockPath);
        }
        Assert.EndsWith("job_id=None server=DC2 trace_id=None\n",
            await File.ReadAllTextAsync(LockPath, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ImportFailureAndObservationFailureDoNotStrandLock()
    {
        var queue = Queue((_, _) => throw new InvalidOperationException("synthetic-observation-failure"));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => {
            using var lease = await queue.AcquireAsync("DC1", TestContext.Current.CancellationToken);
            throw new InvalidOperationException("synthetic-import-failure");
        });
        using var next = await queue.AcquireAsync("DC2", TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task AlreadyCanceledCallerDoesNotCreateLockOrEnterImport()
    {
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        var error = await Assert.ThrowsAsync<PostgresImportQueueCanceled>(() => Queue().AcquireAsync("DC1", cancel.Token));
        Assert.Equal(LockPath, error.LockPath);
        Assert.True(error.WaitMs >= 0);
        Assert.False(File.Exists(LockPath));
    }

    [Fact]
    public async Task UntrustedMetadataCannotCreateExtraLinesAndIsBounded()
    {
        using (await Queue().AcquireAsync("DC1\nforged\r\0" + new string('x', 500), TestContext.Current.CancellationToken,
            traceId: "synthetic\ntrace")) { }
        string text = await File.ReadAllTextAsync(LockPath, TestContext.Current.CancellationToken);
        Assert.Single(text.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        Assert.DoesNotContain('\r', text);
        Assert.DoesNotContain('\0', text);
        Assert.Contains("trace_id=synthetic trace", text);
        Assert.True(text.Length < 400);
    }

    [Theory]
    [InlineData(null, 0.2)]
    [InlineData("invalid", 0.2)]
    [InlineData("0.01", 0.05)]
    [InlineData("0.3", 0.3)]
    [InlineData("10", 5)]
    public void DefaultPathAndPollingMatchReference(string? raw, double seconds)
    {
        var queue = new PostgresImportQueue(root, key => key switch {
            "ADLOG_DATA_DIR" => root,
            "ADLOG_POSTGRES_IMPORT_QUEUE_POLL_SECONDS" => raw,
            _ => null
        });
        Assert.Equal(Path.Combine(root, "runtime", "postgres-import.queue.lock"), queue.LockPath);
        Assert.Equal(TimeSpan.FromSeconds(seconds), queue.PollInterval);
    }

    [Fact]
    public async Task DefaultLockLivesInRuntimeDirectoryAndIsAcquired()
    {
        var queue = new PostgresImportQueue(root, key => key == "ADLOG_DATA_DIR" ? root : null, (_, _) => { });
        using var lease = await queue.AcquireAsync("DC1", TestContext.Current.CancellationToken);
        Assert.Equal(Path.Combine(root, "runtime", "postgres-import.queue.lock"), lease.LockPath);
        Assert.True(File.Exists(lease.LockPath));
    }

    [Fact]
    public async Task UnwritableLockDirectoryFailsWithErrorNamingThePath()
    {
        Directory.CreateDirectory(root);
        string blocker = Path.Combine(root, "not-a-directory");
        File.WriteAllText(blocker, "x");
        string lockPath = Path.Combine(blocker, "sub", "lock");
        var queue = new PostgresImportQueue(root, key => key == "ADLOG_POSTGRES_IMPORT_QUEUE_LOCK" ? lockPath : null, (_, _) => { });
        var error = await Assert.ThrowsAsync<IOException>(() => queue.AcquireAsync("DC1", TestContext.Current.CancellationToken));
        Assert.Contains(lockPath, error.Message);
    }

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, true);
    }
}
