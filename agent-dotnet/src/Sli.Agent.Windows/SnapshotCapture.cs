using System.Diagnostics;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

/// <summary>One bounded background source read; check-in/delivery continues while AD is slow.</summary>
public sealed class SnapshotCapture(string root, IDurableFiles files, IDirectorySnapshotReader reader, TimeProvider clock) : IDisposable
{
    private sealed record Job(string Module, CancellationTokenSource Stop, Task Task);
    private Job? _job;
    private readonly Dictionary<string, DateTimeOffset> _retry = [];
    private readonly Dictionary<string, SnapshotStream> _streams = [];
    public bool Busy => _job is not null;

    public (int Captured, string? Error) Tick(IReadOnlyDictionary<string, SnapshotPolicy> policies, IPacketQueue queue,
        IPacketSigner signer, string agentId, DateTimeOffset now, int batchSize, CancellationToken cancellationToken)
    {
        string? error = null; var captured = 0;
        if (_job is { } job)
        {
            if (!policies.ContainsKey(job.Module)) job.Stop.Cancel();
            if (job.Task.IsCompleted)
            {
                if (job.Task.IsFaulted)
                {
                    var exception = job.Task.Exception!.GetBaseException();
                    error = exception is AgentException agent ? agent.Code : "agent_snapshot_capture_failed";
                }
                else if (job.Task.IsCanceled && policies.ContainsKey(job.Module)) error = "agent_snapshot_capture_timeout";
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
                stream.Freeze(frozenState, families);
            }, stop.Token);
            _job = new(moduleId, stop, task);
        }
        return (captured, error);
    }

    public void Cancel() => _job?.Stop.Cancel();
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
