using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Windows;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class SnapshotCaptureTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();
    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private sealed class SignaledFiles : IDurableFiles
    {
        private readonly PhysicalDurableFiles _inner = new();
        public TaskCompletionSource Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void WriteAtomic(string path, ReadOnlySpan<byte> bytes)
        {
            _inner.WriteAtomic(path, bytes);
            if (path.EndsWith("cycle.json", StringComparison.Ordinal) && JsonNode.Parse(bytes)!["ready"]!.GetValue<bool>()) Ready.TrySetResult();
        }
        public byte[]? ReadAll(string path) => _inner.ReadAll(path);
        public long Length(string path) => _inner.Length(path);
        public void Delete(string path) => _inner.Delete(path);
        public IReadOnlyList<string> List(string path, string pattern) => _inner.List(path, pattern);
        public void EnsureDirectory(string path) => _inner.EnsureDirectory(path);
    }

    internal sealed class BlockingReader : IDirectorySnapshotReader
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<JsonObject> ReadAsync(SnapshotPolicy policy, CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
            catch (OperationCanceledException) { Cancelled.TrySetResult(); throw; }
            throw new InvalidOperationException();
        }
    }

    [Fact]
    public async Task SnapshotBackgroundCaptureResumesFrozenPolicyAndObeysQueueBackpressure()
    {
        var v = Vectors.Load("snapshot-scenarios.json").AsArray()[0]!;
        var policy = SnapshotModuleTests.Policy(); var files = new SignaledFiles(); var reader = new FakeSnapshotReader(v["raw"]!.AsObject());
        var root = Path.Combine(_directory, "snapshots"); using var queue = Helpers.Queue(Path.Combine(_directory, "queue")); using var key = Helpers.NewKey();
        var policies = new Dictionary<string, SnapshotPolicy> { [policy.ModuleId] = policy };
        using (var capture = new SnapshotCapture(root, files, reader, new TestClock()))
        {
            Assert.Equal(0, capture.Tick(policies, queue, Helpers.Signer(key), Helpers.AgentId, Helpers.Now, 1, CancellationToken.None).Captured);
            await files.Ready.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, capture.Tick(policies, queue, Helpers.Signer(key), Helpers.AgentId, Helpers.Now, 1, CancellationToken.None).Captured);
            Assert.Equal(0, capture.Tick(policies, queue, Helpers.Signer(key), Helpers.AgentId, Helpers.Now, 1, CancellationToken.None).Captured);
            Assert.Single(queue.Pending()); Assert.Equal(1, reader.Reads);
        }
        // Revision changes and a service restart cannot replace an unfinished frozen source pass.
        var changed = (JsonObject)policy.Config.DeepClone(); changed["policy_revision"] = "2";
        policies[policy.ModuleId] = SnapshotPolicy.Parse(policy.ModuleId, changed);
        using (var capture = new SnapshotCapture(root, files, reader, new TestClock()))
        {
            var packet = Assert.Single(queue.Pending()); Assert.True(queue.Acknowledge(packet, Helpers.Receipt(packet)));
            Assert.Equal(1, capture.Tick(policies, queue, Helpers.Signer(key), Helpers.AgentId, Helpers.Now, 1, CancellationToken.None).Captured);
            Assert.Equal("1", Assert.Single(queue.Pending()).Envelope.PolicyRevision); Assert.Equal(1, reader.Reads);
        }
    }

    [Fact]
    public async Task SnapshotDisableAndDeadlineCancelTheOnlyReaderWithoutBlockingTicks()
    {
        var reader = new BlockingReader(); var policy = SnapshotModuleTests.Policy(); var cfg = policy.Config; cfg["capture_seconds"] = 1;
        policy = SnapshotPolicy.Parse(policy.ModuleId, cfg);
        using var queue = Helpers.Queue(Path.Combine(_directory, "queue")); using var key = Helpers.NewKey();
        using var capture = new SnapshotCapture(_directory, new PhysicalDurableFiles(), reader, new TestClock());
        var policies = new Dictionary<string, SnapshotPolicy> { [policy.ModuleId] = policy };
        capture.Tick(policies, queue, Helpers.Signer(key), Helpers.AgentId, Helpers.Now, 1, CancellationToken.None);
        await reader.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(capture.Busy);
        // A second tick returns while the read is blocked; deadline must cancel it, without a second reader.
        Assert.Equal(0, capture.Tick(policies, queue, Helpers.Signer(key), Helpers.AgentId, Helpers.Now, 1, CancellationToken.None).Captured);
        await reader.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Empty(queue.Pending());
        Assert.False(new SnapshotStream(_directory, policy.ModuleId, new PhysicalDurableFiles()).Read()!["ready"]!.GetValue<bool>());
    }
}
