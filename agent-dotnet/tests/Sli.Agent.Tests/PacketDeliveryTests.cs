using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>A stand-in for the server's ledger: commits in order, answers a repeat with <c>duplicate</c>.</summary>
public sealed class FakeServer : IPacketTransport
{
    private readonly Dictionary<(string Module, long Sequence), string> _committed = [];

    public List<(string Module, long Sequence)> Posted { get; } = [];

    public Func<SignedPacket, int, JsonNode?>? Override { get; set; }

    public bool DropAnswerOnce { get; set; }

    public Task<JsonNode?> PostPacketAsync(SignedPacket packet, CancellationToken cancellationToken)
    {
        var envelope = packet.Envelope;
        Posted.Add((envelope.ModuleId, envelope.Sequence));
        if (Override?.Invoke(packet, Posted.Count) is { } forced) return Task.FromResult<JsonNode?>(forced);
        var key = (envelope.ModuleId, envelope.Sequence);
        var repeat = _committed.ContainsKey(key);
        _committed[key] = envelope.PacketId;
        if (DropAnswerOnce)
        {
            // The server committed but the answer never arrived: a timeout on the agent's side.
            DropAnswerOnce = false;
            throw new TransportException();
        }
        return Task.FromResult<JsonNode?>(Helpers.Receipt(packet, repeat ? "duplicate" : "committed"));
    }
}

public sealed class PacketDeliveryTests : IDisposable
{
    [Fact]
    public async Task DisabledModuleStopsDeliveryAcrossRestartAndPreservesOtherModules()
    {
        var first=Capture("","1"); Capture("1","2");
        Capture("","1","sli.other");
        var server=new FakeServer { Override=(packet,_)=> {
            if(packet.Envelope.ModuleId!="sli.test") return null;
            var refusal=Helpers.ExpiredReceipt(packet); refusal["error_code"]="module_disabled"; return refusal;
        } };
        var result=await new PacketDelivery(_queue,server,Helpers.Signer(_key)).DeliverOnceAsync();
        Assert.True(result.Success); Assert.Contains("sli.test",result.DisabledModules);
        Assert.Equal(1,result.Acknowledged); Assert.Equal(2,result.Attempted);
        Assert.Empty(_queue.Pending());
        _queue.Dispose();
        using var restarted=Helpers.Queue(_directory);
        Assert.Empty(restarted.Pending());
        Assert.Equal("2",restarted.Captured("sli.test")!.CursorAfter.Token);
        Assert.Equal(0,(await new PacketDelivery(restarted,server).DeliverOnceAsync()).Attempted);
        var resumed=restarted.Capture(Helpers.Signer(_key),Helpers.AgentId,Helpers.Sample("2","3"),Helpers.Now);
        Assert.Equal("gap",resumed.Envelope.ContinuityState);
        Assert.False(Receipt.IsDeliveryProof(first.Envelope,Helpers.ExpiredReceipt(first)));
    }

    [Theory]
    [InlineData("packet_id")]
    [InlineData("payload_sha256")]
    [InlineData("contract_id")]
    [InlineData("status")]
    [InlineData("committed_cursor")]
    [InlineData("evidence_ref")]
    [InlineData("committed_at_utc")]
    public async Task MalformedDisabledRefusalNeverDiscardsPackets(string field)
    {
        Capture("","1"); Capture("1","2");
        var server=new FakeServer { Override=(packet,_)=> {
            var refusal=Helpers.ExpiredReceipt(packet); refusal["error_code"]="module_disabled"; refusal[field]="wrong"; return refusal;
        } };
        var result=await new PacketDelivery(_queue,server).DeliverOnceAsync();
        Assert.False(result.Success); Assert.Empty(result.DisabledModules); Assert.Equal(2,_queue.Pending().Count);
    }

    [Fact]
    public void DisabledModuleCheckpointSurvivesFailedBodyDeletion()
    {
        var directory=Path.Combine(_directory,"crash");
        var files=new FaultyFiles(new PhysicalDurableFiles());
        using(var queue=Helpers.Queue(directory,files)) {
            var first=queue.Capture(Helpers.Signer(_key),Helpers.AgentId,Helpers.Sample("","1"),Helpers.Now);
            queue.Capture(Helpers.Signer(_key),Helpers.AgentId,Helpers.Sample("1","2"),Helpers.Now);
            queue.Capture(Helpers.Signer(_key),Helpers.AgentId,Helpers.Sample("","1","sli.other"),Helpers.Now);
            var refusal=Helpers.ExpiredReceipt(first); refusal["error_code"]="module_disabled";
            files.FailDelete=_=>true;
            Assert.Throws<IOException>(()=>queue.Acknowledge(first,refusal));
        }
        using var recovered=Helpers.Queue(directory);
        Assert.Equal("sli.other",Assert.Single(recovered.Pending()).Envelope.ModuleId);
        var next=recovered.Capture(Helpers.Signer(_key),Helpers.AgentId,Helpers.Sample("2","3"),Helpers.Now);
        Assert.Equal("gap",next.Envelope.ContinuityState);
    }

    [Fact]
    public async Task ExpiredHeadDoesNotBlockAlreadyQueuedOrNewPackets()
    {
        var signer = Helpers.Signer(_key);
        var old = _queue.Capture(signer, Helpers.AgentId, Helpers.Sample("", "1"), Helpers.Now.AddDays(-8));
        var second = Capture("1", "2");
        Capture("2", "3");
        var seen = new List<SignedPacket>();
        var server = new FakeServer { Override = (packet, _) => {
            PacketVerifier.Verify(packet.ToJson(), _key);
            seen.Add(packet);
            return packet.Envelope.PacketId == old.Envelope.PacketId ? Helpers.ExpiredReceipt(packet) : null;
        } };
        var result = await new PacketDelivery(_queue, server, signer).DeliverOnceAsync();
        Assert.True(result.Success);
        Assert.Equal(3, result.Acknowledged);
        Assert.Empty(_queue.Pending());
        Assert.Equal(second.Envelope.PacketId, seen[1].Envelope.PacketId);
        Assert.Equal("gap", seen[1].Envelope.ContinuityState);
        Assert.Equal("not_proven", seen[2].Envelope.ContinuityState);
        Assert.Equal("not_proven", Capture("3", "4").Envelope.ContinuityState);
        Assert.True((await new PacketDelivery(_queue, server, signer).DeliverOnceAsync()).Success);
    }

    private readonly string _directory = Helpers.TempDirectory();
    private readonly System.Security.Cryptography.ECDsa _key = Helpers.NewKey();
    private readonly FilePacketQueue _queue;

    public PacketDeliveryTests() => _queue = Helpers.Queue(_directory);

    public void Dispose()
    {
        _queue.Dispose();
        _key.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private SignedPacket Capture(string before, string after, string module = "sli.test") =>
        _queue.Capture(Helpers.Signer(_key), Helpers.AgentId, Helpers.Sample(before, after, module), Helpers.Now);

    [Fact]
    public async Task DeliversInOrderAndEmptiesTheQueue()
    {
        Capture("", "1");
        Capture("1", "2");
        Capture("2", "3");
        var server = new FakeServer();
        var result = await new PacketDelivery(_queue, server).DeliverOnceAsync();
        Assert.True(result.Success);
        Assert.Equal(3, result.Acknowledged);
        Assert.Equal([1L, 2L, 3L], server.Posted.Select(item => item.Sequence));
        Assert.Empty(_queue.Pending());
    }

    [Fact]
    public async Task ALostAnswerKeepsThePacketAndTheRetryIsAcceptedAsADuplicate()
    {
        var packet = Capture("", "1");
        var server = new FakeServer { DropAnswerOnce = true };
        var delivery = new PacketDelivery(_queue, server);
        var first = await delivery.DeliverOnceAsync();
        Assert.False(first.Success);
        Assert.Single(_queue.Pending());
        var second = await delivery.DeliverOnceAsync();
        Assert.True(second.Success);
        Assert.Empty(_queue.Pending());
        Assert.Equal([1L, 1L], server.Posted.Select(item => item.Sequence));
        Assert.Equal(packet.Envelope.PacketId, packet.Envelope.PacketId);
    }

    [Fact]
    public async Task AFailureBlocksTheRestOfThatModuleButNotOtherModules()
    {
        Capture("", "1", "sli.a");
        Capture("1", "2", "sli.a");
        Capture("", "1", "sli.b");
        var server = new FakeServer { Override = (packet, _) => packet.Envelope.ModuleId == "sli.a" ? Helpers.Receipt(packet, "retry_later") : null };
        var result = await new PacketDelivery(_queue, server).DeliverOnceAsync();
        Assert.False(result.Success);
        // sli.a's second packet is not even tried; sli.b is delivered.
        Assert.Equal([("sli.a", 1L), ("sli.b", 1L)], server.Posted);
        Assert.Equal(2, _queue.Pending().Count);
    }

    [Theory]
    [InlineData("rejected")]
    [InlineData("retry_later")]
    public async Task ARefusalIsNotAnAcknowledgement(string status)
    {
        Capture("", "1");
        var server = new FakeServer { Override = (packet, _) => Helpers.Receipt(packet, status) };
        Assert.False((await new PacketDelivery(_queue, server).DeliverOnceAsync()).Success);
        Assert.Single(_queue.Pending());
    }

    [Fact]
    public async Task ATransportFailureKeepsEverything()
    {
        Capture("", "1");
        var server = new ThrowingTransport(new HttpRequestException());
        Assert.False((await new PacketDelivery(_queue, server).DeliverOnceAsync()).Success);
        Assert.Single(_queue.Pending());
    }

    [Fact]
    public async Task AFailedPacketPostReportsTheHttpStatusAndKeepsThePacket()
    {
        Capture("", "1");
        var server = new ThrowingTransport(new TransportException("agent_service_unavailable", 503));
        var result = await new PacketDelivery(_queue, server).DeliverOnceAsync();
        Assert.False(result.Success);
        Assert.Equal("Server returned HTTP 503.", result.TransportFailure?.Detail);
        Assert.Single(_queue.Pending());
    }

    [Theory]
    [InlineData("agent_http_timeout")]
    [InlineData("agent_tls_client_key_unusable")]
    [InlineData("agent_tls_server_untrusted")]
    [InlineData("agent_tls_name_mismatch")]
    public async Task ATransportDiagnosticKeepsThePacketAndPreservesItsCode(string code)
    {
        Capture("", "1");
        var server = new ThrowingTransport(new TransportException(code));
        var error = await Assert.ThrowsAsync<TransportException>(() => new PacketDelivery(_queue, server).DeliverOnceAsync());
        Assert.Equal(code, error.Code);
        Assert.Single(_queue.Pending());
    }

    [Fact]
    public async Task TheRateLimitCapsPostsPerCycle()
    {
        for (var i = 0; i < 5; i++) Capture(i.ToString(), (i + 1).ToString());
        var server = new FakeServer();
        var result = await new PacketDelivery(_queue, server).DeliverOnceAsync(limit: 2);
        Assert.Equal(2, result.Attempted);
        Assert.Equal(3, _queue.Pending().Count);
    }

    [Fact]
    public async Task HistoryGoesLastAndOnlyAfterLiveDeliverySucceeded()
    {
        Capture("", "1", FilePacketQueue.HistoryModuleId);
        Capture("", "1", "sli.live");
        var server = new FakeServer();
        await new PacketDelivery(_queue, server).DeliverOnceAsync();
        Assert.Equal(["sli.live", FilePacketQueue.HistoryModuleId], server.Posted.Select(item => item.Module));

        Capture("1", "2", "sli.live");
        Capture("1", "2", FilePacketQueue.HistoryModuleId);
        var failing = new FakeServer { Override = (packet, _) => packet.Envelope.ModuleId == "sli.live" ? Helpers.Receipt(packet, "rejected") : null };
        var result = await new PacketDelivery(_queue, failing).DeliverOnceAsync();
        Assert.False(result.Success);
        Assert.DoesNotContain(failing.Posted, item => item.Module == FilePacketQueue.HistoryModuleId);
    }

    [Fact]
    public async Task AFailedHistoryPacketDoesNotCountAgainstTheLiveLoop()
    {
        Capture("", "1", FilePacketQueue.HistoryModuleId);
        var server = new FakeServer { Override = (packet, _) => Helpers.Receipt(packet, "retry_later") };
        Assert.True((await new PacketDelivery(_queue, server).DeliverOnceAsync()).Success);
    }

    [Fact]
    public async Task CancellationIsNotSwallowed()
    {
        Capture("", "1");
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var server = new ThrowingTransport(new OperationCanceledException());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PacketDelivery(_queue, server).DeliverOnceAsync(cancellationToken: cancelled.Token));
        Assert.Single(_queue.Pending());
    }

    private sealed class ThrowingTransport(Exception exception) : IPacketTransport
    {
        public Task<JsonNode?> PostPacketAsync(SignedPacket packet, CancellationToken cancellationToken) => Task.FromException<JsonNode?>(exception);
    }
}
