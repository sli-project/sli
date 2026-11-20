using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>The queue holds evidence until the server proves receipt. These mirror the Python spool's crash and ordering tests.</summary>
public sealed class PacketQueueTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();
    private readonly System.Security.Cryptography.ECDsa _key = Helpers.NewKey();
    private readonly List<FilePacketQueue> _queues = [];

    public void Dispose()
    {
        foreach (var queue in _queues) queue.Dispose();
        _key.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private FilePacketQueue Open(IDurableFiles? files = null, long maxBytes = 10_000_000, long maxAge = 7 * 86400)
    {
        var queue = Helpers.Queue(_directory, files, maxBytes, maxAge);
        _queues.Add(queue);
        return queue;
    }

    private void Close(FilePacketQueue queue)
    {
        queue.Dispose();
        _queues.Remove(queue);
    }

    private SignedPacket Capture(FilePacketQueue queue, string before, string after, DateTimeOffset? now = null, string module = "sli.test", string generation = "gen-1") =>
        queue.Capture(Helpers.Signer(_key), Helpers.AgentId, Helpers.Sample(before, after, module, generation), now ?? Helpers.Now);

    [Fact]
    public void ARestartKeepsPendingPacketsAndALostAckIsRecovered()
    {
        var queue = Open();
        var packet = Capture(queue, "", "1");
        Close(queue);
        var restarted = Open();
        Assert.Equal([packet.ToCanonical()], restarted.Pending().Select(item => item.ToCanonical()));
        Assert.False(restarted.Acknowledge(packet, Helpers.Receipt(packet, "rejected")));
        Assert.False(restarted.Acknowledge(packet, Helpers.Receipt(packet, "retry_later")));
        var wrong = Helpers.Receipt(packet);
        wrong["payload_sha256"] = new string('0', 64);
        Assert.False(restarted.Acknowledge(packet, wrong));
        Assert.True(restarted.Acknowledge(packet, Helpers.Receipt(packet, "duplicate")));
        Assert.Empty(restarted.Pending());
        var next = Capture(restarted, "1", "2");
        Assert.Equal(2, next.Envelope.Sequence);
    }

    [Fact]
    public void AnOutOfOrderReceiptCannotAdvanceTheCursor()
    {
        var queue = Open();
        var first = Capture(queue, "", "1");
        var second = Capture(queue, "1", "2");
        Assert.False(queue.Acknowledge(second, Helpers.Receipt(second)));
        Assert.Equal(2, queue.Pending().Count);
        Assert.True(queue.Acknowledge(first, Helpers.Receipt(first)));
        Assert.True(queue.Acknowledge(second, Helpers.Receipt(second)));
        Assert.Empty(queue.Pending());
    }

    [Fact]
    public void ACrashAfterTheCheckpointButBeforeTheDeleteLosesNothingAndSendsNothingTwice()
    {
        var faulty = new FaultyFiles(new PhysicalDurableFiles());
        var queue = Open(faulty);
        var first = Capture(queue, "", "1");
        faulty.FailDelete = path => path.EndsWith(".packet", StringComparison.Ordinal);
        Assert.Throws<IOException>(() => queue.Acknowledge(first, Helpers.Receipt(first)));
        Close(queue);
        var restarted = Open();
        // The receipt checkpoint was durable, so the leftover file is removed and the stream continues at sequence 2.
        Assert.Empty(restarted.Pending());
        Assert.Equal(1, restarted.Captured("sli.test") is { } ? 1 : 0);
        Assert.Equal(2, Capture(restarted, "1", "2").Envelope.Sequence);
    }

    [Fact]
    public void ACrashBetweenThePacketAndItsCheckpointKeepsThePacketAndTheStreamPosition()
    {
        var faulty = new FaultyFiles(new PhysicalDurableFiles());
        var queue = Open(faulty);
        Capture(queue, "", "1");
        faulty.FailWrite = path => path.EndsWith("checkpoints.json", StringComparison.Ordinal);
        Assert.Throws<IOException>(() => Capture(queue, "1", "2"));
        Close(queue);
        var restarted = Open();
        // Both packets are on disk and the position was rebuilt from them: the next read starts after cursor "2".
        Assert.Equal(2, restarted.Pending().Count);
        Assert.Equal("2", restarted.Captured("sli.test")!.CursorAfter.Token);
        Assert.Equal(3, Capture(restarted, "2", "3").Envelope.Sequence);
    }

    [Fact]
    public void AFailedPacketWriteDoesNotMoveTheStreamPosition()
    {
        var faulty = new FaultyFiles(new PhysicalDurableFiles());
        var queue = Open(faulty);
        Capture(queue, "", "1");
        faulty.FailWrite = path => path.EndsWith(".packet", StringComparison.Ordinal);
        Assert.Throws<IOException>(() => Capture(queue, "1", "2"));
        Assert.Equal("1", queue.Captured("sli.test")!.CursorAfter.Token);
        faulty.FailWrite = null;
        Assert.Equal(2, Capture(queue, "1", "2").Envelope.Sequence);
    }

    [Fact]
    public void AMalformedReceiptIsNotAuthorityToDelete()
    {
        var queue = Open();
        var packet = Capture(queue, "", "1");
        var bad = Helpers.Receipt(packet);
        bad["committed_at_utc"] = "invalid";
        Assert.False(queue.Acknowledge(packet, bad));
        Assert.False(queue.Acknowledge(packet, null));
        Assert.False(queue.Acknowledge(packet, JsonValue.Create("oops")));
        Assert.Single(queue.Pending());
    }

    [Fact]
    public void AReceiptForAForeignPacketDeletesNothing()
    {
        var queue = Open();
        var first = Capture(queue, "", "1");
        var forged = first with { Payload = new JsonObject { ["contract"] = "sli.test.v1", ["records"] = new JsonArray(), ["tampered"] = true } };
        Assert.False(queue.Acknowledge(forged, Helpers.Receipt(first)));
        Assert.Single(queue.Pending());
    }

    [Fact]
    public void OnlyDiskSizePausesCaptureWithoutDestroyingEvidence()
    {
        var queue = Open(maxAge: 60);
        var first = Capture(queue, "", "1");
        var late = Helpers.Now.AddSeconds(61);
        Capture(queue, "1", "2", late);
        Assert.Equal(first.ToCanonical(), queue.Pending()[0].ToCanonical());
        Assert.Equal(2, queue.Pending().Count);

        var small = Helpers.Queue(Helpers.TempDirectory(), maxBytes: 1500);
        using (small)
        {
            small.Capture(Helpers.Signer(_key), Helpers.AgentId, Helpers.Sample("", "1"), Helpers.Now);
            Assert.Equal("agent_spool_size_limit", Assert.Throws<QueueFullException>(() => small.Capture(Helpers.Signer(_key), Helpers.AgentId, Helpers.Sample("1", "2"), Helpers.Now)).Code);
            Assert.Single(small.Pending());
        }
    }

    [Fact]
    public void ExpiryCheckpointSurvivesACrashBeforeDeleteAndMarksTheNextCapture()
    {
        var faulty = new FaultyFiles(new PhysicalDurableFiles());
        var queue = Open(faulty);
        var first = Capture(queue, "", "1");
        faulty.FailDelete = path => path.EndsWith(".packet", StringComparison.Ordinal);
        Assert.Throws<IOException>(() => queue.Acknowledge(first, Helpers.ExpiredReceipt(first)));
        Close(queue);
        var restarted = Open();
        Assert.Empty(restarted.Pending());
        var next = Capture(restarted, "1", "2");
        Assert.Equal(2, next.Envelope.Sequence);
        Assert.Equal("gap", next.Envelope.ContinuityState);
        Assert.True(restarted.Acknowledge(next, Helpers.Receipt(next)));
        Assert.Equal("not_proven", Capture(restarted, "2", "3").Envelope.ContinuityState);
    }

    [Fact]
    public void ExpiryDoesNotDeleteUntilTheGapCheckpointIsDurable()
    {
        var faulty = new FaultyFiles(new PhysicalDurableFiles());
        var queue = Open(faulty);
        var first = Capture(queue, "", "1");
        var second = Capture(queue, "1", "2");
        Assert.False(queue.Acknowledge(second, Helpers.ExpiredReceipt(second)));
        faulty.FailWrite = path => path.EndsWith("checkpoints.json", StringComparison.Ordinal);
        Assert.Throws<IOException>(() => queue.Acknowledge(first, Helpers.ExpiredReceipt(first)));
        Close(queue);
        var restarted = Open();
        Assert.Equal(2, restarted.Pending().Count);
        Assert.True(restarted.Acknowledge(first, Helpers.ExpiredReceipt(first)));
        var prepared = restarted.PrepareDelivery(second, Helpers.Signer(_key));
        Assert.Equal("gap", prepared.Envelope.ContinuityState);
        Assert.Equal(second.Envelope.PacketId, prepared.Envelope.PacketId);
        Assert.Equal(prepared.Envelope, PacketVerifier.Verify(prepared.ToJson(), _key));
        Assert.False(restarted.Acknowledge(second, Helpers.Receipt(second)));
    }

    [Fact]
    public void TheHistoryModuleIsExemptFromTheAgeLimit()
    {
        var queue = Open(maxAge: 60);
        Capture(queue, "", "1", module: FilePacketQueue.HistoryModuleId);
        Capture(queue, "", "1", Helpers.Now.AddSeconds(3600));
        Assert.Equal(2, queue.Pending().Count);
    }

    [Fact]
    public void AStreamMustContinueFromItsOwnCursor()
    {
        var queue = Open();
        Capture(queue, "", "1");
        Assert.Equal("agent_capture_cursor_mismatch", Assert.Throws<AgentException>(() => Capture(queue, "9", "10")).Code);
        // A new generation (a log reset) restarts the cursor and the sequence keeps counting.
        Assert.Equal(2, Capture(queue, "", "1", generation: "gen-2").Envelope.Sequence);
    }

    [Fact]
    public void AStreamCannotChangeItsIdentity()
    {
        var queue = Open();
        Capture(queue, "", "1");
        var other = Helpers.Sample("1", "2", channel: "other");
        Assert.Equal("agent_capture_stream_changed", Assert.Throws<AgentException>(() => queue.Capture(Helpers.Signer(_key), Helpers.AgentId, other, Helpers.Now)).Code);
        Assert.Equal("agent_spool_identity_mismatch", Assert.Throws<AgentException>(() => queue.Capture(Helpers.Signer(_key), "00000000-0000-4000-8000-000000000009", Helpers.Sample("1", "2"), Helpers.Now)).Code);
    }

    [Fact]
    public void ModulesKeepIndependentSequencesAndOrder()
    {
        var queue = Open();
        var a1 = Capture(queue, "", "1", module: "sli.a");
        var b1 = Capture(queue, "", "1", module: "sli.b");
        var a2 = Capture(queue, "1", "2", module: "sli.a");
        Assert.Equal([1, 2], new[] { a1.Envelope.Sequence, a2.Envelope.Sequence });
        Assert.Equal(1, b1.Envelope.Sequence);
        Assert.Equal(["sli.a", "sli.a", "sli.b"], queue.Pending().Select(item => item.Envelope.ModuleId));
        Assert.True(queue.Acknowledge(b1, Helpers.Receipt(b1)));
        Assert.False(queue.Acknowledge(a2, Helpers.Receipt(a2)));
    }

    [Fact]
    public void LeftoverTemporaryFilesAreNotPackets()
    {
        var queue = Open();
        var first = Capture(queue, "", "1");
        File.WriteAllText(Path.Combine(_directory, ".leftover.tmp"), "half a packet");
        Capture(queue, "1", "2");
        Assert.False(File.Exists(Path.Combine(_directory, ".leftover.tmp")));
        Assert.Equal(2, queue.Pending().Count);
        Assert.Equal(first.Envelope.PacketId, queue.Pending()[0].Envelope.PacketId);
    }

    [Fact]
    public void ACorruptOrRenamedPacketFileStopsTheQueueLoudly()
    {
        var queue = Open();
        var packet = Capture(queue, "", "1");
        Close(queue);
        File.Move(Path.Combine(_directory, packet.Envelope.PacketId + ".packet"), Path.Combine(_directory, "00000000-0000-4000-8000-000000000001.packet"));
        Assert.Equal("agent_spool_corrupt", Assert.Throws<AgentException>(() => Open()).Code);
        File.WriteAllText(Path.Combine(_directory, "00000000-0000-4000-8000-000000000001.packet"), "{not json");
        Assert.Equal("agent_spool_corrupt", Assert.Throws<AgentException>(() => Open()).Code);
    }

    [Fact]
    public void ACorruptCheckpointFileStopsTheQueueLoudly()
    {
        var queue = Open();
        Capture(queue, "", "1");
        Close(queue);
        File.WriteAllText(Path.Combine(_directory, "checkpoints.json"), "[1,2");
        Assert.Equal("agent_spool_corrupt", Assert.Throws<AgentException>(() => Open()).Code);
    }

    [Fact]
    public void ASecondWriterOnTheSameDirectoryIsRefused()
    {
        Open();
        Assert.Equal("agent_state_locked", Assert.Throws<AgentException>(() => Helpers.Queue(_directory)).Code);
    }

    [Fact]
    public void LimitsMustBePositive()
    {
        Assert.Equal("agent_spool_limits_invalid", Assert.Throws<AgentException>(() => Helpers.Queue(Helpers.TempDirectory(), maxBytes: 0)).Code);
        Assert.Equal("agent_spool_limits_invalid", Assert.Throws<AgentException>(() => Helpers.Queue(Helpers.TempDirectory(), maxAgeSeconds: 0)).Code);
    }

    [Fact]
    public void PacketFilesAreCanonicalAsciiSoTheyAreReadBackExactly()
    {
        var queue = Open();
        var sample = Helpers.Sample("", "1") with { Payload = new JsonObject { ["contract"] = "sli.test.v1", ["records"] = new JsonArray(), ["note"] = "Пользователь \U0001F600" } };
        var packet = queue.Capture(Helpers.Signer(_key), Helpers.AgentId, sample, Helpers.Now);
        var raw = File.ReadAllBytes(Path.Combine(_directory, packet.Envelope.PacketId + ".packet"));
        Assert.All(raw, b => Assert.True(b < 0x80));
        Assert.Equal(packet.ToCanonical(), queue.Pending().Single().ToCanonical());
    }
}
