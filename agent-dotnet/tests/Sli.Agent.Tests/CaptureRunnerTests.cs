using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>An Event Log with a fixed content: returns events after the cursor, in order, up to the limit.</summary>
public sealed class FakeLog(Dictionary<string, List<long>> events) : IEventLogSource
{
    public List<string> Reads { get; } = [];

    public SourceBatch Read(string channel, ChannelProgress progress, int limit)
    {
        Reads.Add(channel);
        var rows = events.GetValueOrDefault(channel, []).Where(id => id > (progress.RecordId ?? 0)).Take(limit)
            .Select(id => new EventRow(AdDcModuleTests.Xml(id, channel), "bm-" + id)).ToList();
        return new SourceBatch(rows);
    }
}

public sealed class CaptureRunnerTests : IDisposable
{
    private static readonly EventCatalog Catalog = EventCatalog.Load();
    private readonly string _directory = Helpers.TempDirectory();
    private readonly System.Security.Cryptography.ECDsa _key = Helpers.NewKey();
    private readonly FilePacketQueue _queue;

    public CaptureRunnerTests() => _queue = Helpers.Queue(_directory);

    public void Dispose()
    {
        _queue.Dispose();
        _key.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private static AdDcModule Module(IEventLogSource log, int batch = 2)
    {
        var config = new JsonObject { ["source_name"] = "fixture-dc", ["connect_address"] = "fixture-endpoint", ["batch_size"] = batch };
        return new AdDcModule(Helpers.HostId, AdDcConfig.Parse(config, Catalog), log, Catalog);
    }

    [Fact]
    public async Task ADeepBacklogIsDrainedInDurableBoundedPacketsAndTheBurstIsCappedByWhatIsStillUnsent()
    {
        var log = new FakeLog(new() { ["Security"] = [.. Enumerable.Range(1, 10).Select(i => (long)i)] });
        var module = Module(log);
        var captured = CaptureRunner.Capture(module, _queue, Helpers.Signer(_key), Helpers.AgentId, Helpers.Now, batchSize: 3);
        Assert.Equal(3, captured);
        var packets = _queue.Pending();
        // Each packet continues exactly where the previous one ended.
        Assert.Equal(new long?[] { null, 2, 4 }, packets.Select(p => p.Payload["header"]!["cursor"]!["after_record_id"]?.GetValue<long>()).ToArray());
        Assert.Equal(6, packets.SelectMany(p => p.Payload["records"]!.AsArray()).Count());
        // Unsent packets use up the burst: another pass must not read at all.
        var reads = log.Reads.Count;
        Assert.Equal(0, CaptureRunner.Capture(module, _queue, Helpers.Signer(_key), Helpers.AgentId, Helpers.Now, batchSize: 3));
        Assert.Equal(reads, log.Reads.Count);

        // Once the server has acknowledged them, the rotation moves on to the next channel.
        var delivered = await new PacketDelivery(_queue, new FakeServer()).DeliverOnceAsync();
        Assert.True(delivered.Success);
        Assert.Equal(1, CaptureRunner.Capture(module, _queue, Helpers.Signer(_key), Helpers.AgentId, Helpers.Now, batchSize: 3));
        Assert.Equal("System", log.Reads[^1]);
        Assert.Single(_queue.Pending());
    }

    [Fact]
    public void TheWallClockBudgetEndsTheBurstBetweenReads()
    {
        var log = new FakeLog(new() { ["Security"] = [.. Enumerable.Range(1, 10).Select(i => (long)i)] });
        var ticks = 0;
        // Each look at the clock is two seconds later: the 5 s budget allows the first read and then stops.
        TimeSpan Clock() => TimeSpan.FromSeconds(2 * ticks++);
        var captured = CaptureRunner.Capture(Module(log), _queue, Helpers.Signer(_key), Helpers.AgentId, Helpers.Now, batchSize: 16, Clock);
        Assert.InRange(captured, 1, 3);
        Assert.True(captured < 5);
    }

    [Fact]
    public void ANativeReadFailureStillProducesAGapPacketAndTheCursorStaysPut()
    {
        var module = Module(new FailingLog());
        Assert.Equal(1, CaptureRunner.Capture(module, _queue, Helpers.Signer(_key), Helpers.AgentId, Helpers.Now, batchSize: 16));
        var packet = _queue.Pending().Single();
        Assert.Equal("gap", packet.Envelope.ContinuityState);
        Assert.Null(packet.Envelope.LostCount);
        Assert.Equal(0, packet.Envelope.RecordCount);
    }

    [Fact]
    public void AFullQueuePausesCaptureWithoutLosingTheCursor()
    {
        var log = new FakeLog(new() { ["Security"] = [1, 2, 3, 4] });
        var module = Module(log);
        using var small = Helpers.Queue(Helpers.TempDirectory(), maxBytes: 3500);
        Assert.Throws<QueueFullException>(() => CaptureRunner.Capture(module, small, Helpers.Signer(_key), Helpers.AgentId, Helpers.Now, batchSize: 16));
        // What was stored is intact and the position is that of the last stored packet: nothing is skipped.
        var stored = small.Pending();
        Assert.NotEmpty(stored);
        var position = DcCursor.Parse(small.Captured(AdDcModule.ModuleId)!.CursorAfter);
        Assert.Equal(stored.SelectMany(p => p.Payload["records"]!.AsArray()).Count(), position.Progress["Security"].RecordId);
    }

    private sealed class FailingLog : IEventLogSource
    {
        public SourceBatch Read(string channel, ChannelProgress progress, int limit) => throw new EventLogReadException();
    }
}
