using System.Diagnostics;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

public sealed record SnapshotFailure(string Code, string Detail);

/// <summary>One bounded background source read; check-in/delivery continues while AD is slow.</summary>
public sealed class SnapshotCapture(string root, IDurableFiles files, IDirectorySnapshotReader reader, TimeProvider clock) : IDisposable
{
    private sealed record Job(string Module, CancellationTokenSource Stop, Task Task)
    {
        public bool Disabled { get; set; }
    }
    private Job? _job;
    private readonly Dictionary<string, DateTimeOffset> _retry = [];
    private readonly Dictionary<string, SnapshotStream> _streams = [];
    private readonly Dictionary<string, SnapshotFailure> _failures = [];
    public IReadOnlyDictionary<string, SnapshotFailure> Failures => _failures;
    public bool Busy => _job is not null;

    public (int Captured, SnapshotFailure? Failure) Tick(IReadOnlyDictionary<string, SnapshotPolicy> policies, IPacketQueue queue,
        IPacketSigner signer, string agentId, DateTimeOffset now, int batchSize, CancellationToken cancellationToken)
    {
        SnapshotFailure? failure = null; var captured = 0;
        foreach (var module in _failures.Keys.Where(module => !policies.ContainsKey(module)).ToArray()) _failures.Remove(module);
        if (_job is { } job)
        {
            if (!policies.ContainsKey(job.Module)) Stop(job);
            if (job.Task.IsCompleted)
            {
                var error = job.Task.Exception?.GetBaseException();
                if (!job.Disabled)
                {
                    var diagnostic = error as SnapshotCaptureException
                        ?? (job.Task.IsCanceled ? SnapshotCaptureException.Describe(job.Module, "timeout", new TimeoutException())
                            : error is null ? null : SnapshotCaptureException.Describe(job.Module, "capture", error));
                    if (diagnostic is null) _failures.Remove(job.Module);
                    else _failures[job.Module] = failure = new(diagnostic.Code, diagnostic.Detail);
                }
                _retry[job.Module] = now.AddSeconds(60); job.Stop.Dispose(); _job = null;
            }
        }
        var wall = Stopwatch.StartNew();
        foreach (var (moduleId, policy) in policies)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_streams.TryGetValue(moduleId, out var stream)) _streams[moduleId] = stream = new SnapshotStream(root, moduleId, files);
            var state = stream.Read();
            if (state?["ready"]?.GetValue<bool>() == true)
            {
                var budget = Math.Min(16, batchSize) - queue.Pending().Count(p => p.Envelope.ModuleId == moduleId);
                for (var step = 0; step < budget && wall.Elapsed < CaptureRunner.WallBudget; step++)
                {
                    var sample = stream.NextSample(queue.Captured(moduleId));
                    if (sample is null) break;
                    queue.Capture(signer, agentId, sample, now); captured++;
                }
                continue;
            }
            if (_job is not null || _retry.TryGetValue(moduleId, out var retry) && now < retry) continue;
            state = stream.Begin(policy, now);
            if (state is null) continue;
            var frozenPolicy = SnapshotPolicy.Parse(moduleId, state["policy"]!.AsObject());
            var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            stop.CancelAfter(TimeSpan.FromSeconds(frozenPolicy.Number("capture_seconds")));
            var frozenState = state;
            var task = Task.Run(async () =>
            {
                var families = moduleId == SnapshotPolicy.Ad
                    ? await new AdSnapshotModule(reader, clock).CaptureAsync(frozenPolicy, stop.Token).ConfigureAwait(false)
                    : await new GpoSnapshotModule(reader).CaptureAsync(frozenPolicy, stop.Token).ConfigureAwait(false);
                stop.Token.ThrowIfCancellationRequested();
                try { stream.Freeze(frozenState, families); }
                catch (Exception e) when (e is AgentException or IOException or UnauthorizedAccessException)
                { throw SnapshotCaptureException.Describe(moduleId, e is AgentException { Code: "agent_snapshot_size_limit" or "agent_snapshot_buffer_limit" } ? "size" : "freeze", e); }
            }, stop.Token);
            _job = new(moduleId, stop, task);
        }
        return (captured, failure);
    }

    public void Cancel(bool clearFailures = false)
    {
        if (clearFailures) _failures.Clear();
        if (_job is { } job) Stop(job);
    }

    private static void Stop(Job job)
    {
        job.Disabled = true;
        job.Stop.Cancel();
    }
    public void Dispose()
    {
        Cancel();
        if (_job is { } job)
        {
            // Observe failure and release the CTS after the reader has terminated, without blocking service shutdown.
            _ = job.Task.ContinueWith(t => { _ = t.Exception; job.Stop.Dispose(); }, TaskScheduler.Default);
            _job = null;
        }
    }
}
