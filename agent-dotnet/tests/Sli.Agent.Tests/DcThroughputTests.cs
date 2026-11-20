using System.Net;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Service;
using Sli.Agent.Tests.Support;
using Xunit;
using Xunit.Abstractions;

namespace Sli.Agent.Tests;

public sealed class DcThroughputTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();
    private readonly TestAuthority _ca = new();
    private readonly TestClock _clock = new();
    private readonly AgentOptions _options;
    private readonly List<SignedPacket> _sent = [];
    private readonly ITestOutputHelper _output;
    private readonly JsonObject _assignment = new()
    {
        ["agent_id"] = Helpers.AgentId, ["policy_revision"] = 1,
        ["assigned_modules"] = new JsonArray(new JsonObject
        {
            ["module_id"] = AdDcModule.ModuleId, ["enabled"] = true,
            ["config"] = new JsonObject
            {
                ["source_name"] = "dc.example.test", ["connect_address"] = "dc.example.test",
                ["channels"] = new JsonObject(DcCursor.Channels.Select(channel =>
                    KeyValuePair.Create<string, JsonNode?>(channel, JsonValue.Create(channel == "Security")))),
            },
        }),
        ["collection_policy"] = new JsonObject
        {
            ["state"] = "active", ["interval_seconds"] = 120, ["batch_size"] = 32,
            ["rate_limit_per_minute"] = 10000,
        },
    };
    private bool _loseReceipt;
    private AgentRuntime? _runtime;

    public DcThroughputTests(ITestOutputHelper output)
    {
        _output = output;
        _options = new AgentOptions { ServerUrl = "https://core.example.test/", StateDir = Path.Combine(_directory, "state"), TokenFile = Path.Combine(_directory, "token") };
        File.WriteAllText(_options.TokenFile, new string('t', 43));
        File.SetLastWriteTimeUtc(_options.TokenFile, Helpers.Now.UtcDateTime);
    }

    public void Dispose()
    {
        _runtime?.Dispose();
        _ca.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private sealed class Backlog(int count, int filler) : IEventLogSource
    {
        public int Reads { get; private set; }
        public SourceBatch Read(string channel, ChannelProgress progress, int limit)
        {
            Reads++;
            var start = (int)(progress.RecordId ?? 0);
            return new SourceBatch(Enumerable.Range(start + 1, Math.Min(limit, count - start))
                .Select(id => new EventRow(AdDcModuleTests.Xml(id, channel, new string('x', filler)), "bm-" + id)).ToList());
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
    }

    private sealed class Audit : IWindowsAudit
    {
        public JsonObject Reconcile(AgentPolicy policy, DateTimeOffset now) => new() { ["windows_audit"] = new JsonObject() };
    }

    private AgentRuntime Runtime(IEventLogSource source) => _runtime ??= new(Options.Create(_options), _clock, identity =>
        new AgentHttpClient(new HttpClient(new Handler(async request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            JsonObject result;
            if (path.EndsWith("/enroll", StringComparison.Ordinal)) result = _ca.Issue(AgentRuntime.CreateIdentityStore(_options));
            else if (path.EndsWith("/identity", StringComparison.Ordinal)) result = _assignment;
            else if (path.EndsWith("/packets", StringComparison.Ordinal))
            {
                var packet = SignedPacket.FromJson(JsonNode.Parse(await request.Content!.ReadAsStringAsync()));
                Assert.NotNull(identity);
                using var publicKey = identity.Certificate.GetECDsaPublicKey()!;
                PacketVerifier.Verify(packet.ToJson(), publicKey);
                _sent.Add(packet);
                if (_loseReceipt) throw new HttpRequestException("synthetic lost receipt");
                result = Helpers.Receipt(packet);
            }
            else result = new JsonObject();
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(result.ToJsonString(), Encoding.UTF8, "application/json") };
        })) { BaseAddress = new Uri(_options.ServerUrl) }), source, new Audit());

    [Theory]
    [InlineData(0)]
    [InlineData(1000)]
    public async Task TenThousandEventsContinueWithoutPollingPausesAndKeepSignedOrder(int filler)
    {
        var source = new Backlog(10000, filler);
        var runtime = Runtime(source);
        var elapsed = Stopwatch.StartNew();
        for (var cycle = 0; cycle < 1000; cycle++)
        {
            var status = await runtime.RunCycleAsync(CancellationToken.None);
            Assert.Null(status.ErrorCode);
            Assert.False(status.DeliveryFailed);
            if (!runtime.ContinueImmediately) break;
        }
        Assert.False(runtime.ContinueImmediately);
        _output.WriteLine("10000 events, filler {0}: {1} packets in {2:F2} s ({3:F0} events/s); synthetic HTTP, durable disk queue",
            filler, _sent.Count, elapsed.Elapsed.TotalSeconds, 10000 / elapsed.Elapsed.TotalSeconds);
        // Fixed policy time: no interval can elapse between these cycles. The first permitted
        // idle pause must occur only after every event is acknowledged and the queue is empty.
        Assert.Equal(Helpers.Now, _clock.Now);
        Assert.Equal(Enumerable.Range(1, 10000).Select(id => (long)id),
            _sent.SelectMany(packet => packet.Payload["records"]!.AsArray()).Select(row => row!["record_id"]!.GetValue<long>()));
        Assert.Equal(Enumerable.Range(1, _sent.Count).Select(sequence => (long)sequence), _sent.Select(packet => packet.Envelope.Sequence));
        Assert.InRange(_sent.Count, 313, 1250);
        Assert.All(_sent.SkipLast(1), packet => Assert.InRange(packet.Envelope.RecordCount, 8, 32));
        Assert.All(_sent, packet => Assert.True(CanonicalJson.Length(packet.Payload) <= AdDcConfig.MaxPayloadBytes));
        for (var i = 1; i < _sent.Count; i++)
        {
            Assert.Equal(_sent[i - 1].Envelope.CursorAfter, _sent[i].Envelope.CursorBefore);
            var previous = _sent[i - 1].Payload["records"]!.AsArray();
            if (previous.Count < 32 && _sent[i].Payload["records"]!.AsArray().FirstOrDefault() is { } next)
                Assert.True(CanonicalJson.Length(previous) + 1 + CanonicalJson.Length(next) > AdDcConfig.MaxPayloadBytes - 4096);
        }
        var reads = source.Reads;
        var idle = await runtime.RunCycleAsync(CancellationToken.None);
        Assert.Equal(0, idle.Pending);
        Assert.False(runtime.ContinueImmediately);
        Assert.Equal(reads, source.Reads);
    }

    [Fact]
    public async Task WorkerStartsTheNextBacklogCycleWithoutTheHealthyPollDelay()
    {
        var runtime = Runtime(new Backlog(10000, 0));
        var logger = new RecordingLogger();
        using var worker = new AgentWorker(runtime, logger);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var first = await logger.Entry.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var second = await logger.SecondEntry.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Null(first.Exception);
            Assert.Null(second.Exception);
            Assert.NotEmpty(_sent);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [Fact]
    public async Task LostReceiptStopsFastRetryAndRestartResendsTheSamePacketBeforeContinuing()
    {
        var source = new Backlog(10000, 0);
        var runtime = Runtime(source);
        Assert.Null((await runtime.RunCycleAsync(CancellationToken.None)).ErrorCode);
        Assert.True(runtime.ContinueImmediately);
        _loseReceipt = true;
        var failed = await runtime.RunCycleAsync(CancellationToken.None);
        Assert.True(failed.DeliveryFailed);
        Assert.False(runtime.ContinueImmediately);
        var unacknowledged = Assert.Single(_sent).ToCanonical();
        runtime.Dispose(); _runtime = null; _loseReceipt = false;
        runtime = Runtime(source);
        Assert.Null((await runtime.RunCycleAsync(CancellationToken.None)).ErrorCode);
        Assert.Equal(unacknowledged, _sent[1].ToCanonical());
        Assert.True(runtime.ContinueImmediately);
    }

    [Theory]
    [InlineData("paused")]
    [InlineData("drain")]
    [InlineData("disabled")]
    public async Task ChangedPolicyStopsCatchUpBeforeReadingAgain(string state)
    {
        var source = new Backlog(10000, 0);
        var runtime = Runtime(source);
        await runtime.RunCycleAsync(CancellationToken.None);
        Assert.True(runtime.ContinueImmediately);
        var reads = source.Reads;
        if (state == "disabled")
            foreach (var channel in DcCursor.Channels)
                _assignment["assigned_modules"]![0]!["config"]!["channels"]![channel] = false;
        else _assignment["collection_policy"]!["state"] = state;
        var status = await runtime.RunCycleAsync(CancellationToken.None);
        Assert.Null(status.ErrorCode);
        Assert.Equal(0, status.Captured);
        Assert.False(runtime.ContinueImmediately);
        Assert.Equal(reads, source.Reads);
    }

    [Theory]
    [InlineData(24, 720, 684)]
    [InlineData(8, 1200, 1124)]
    public async Task DcDefaultQuotaAllowsMeasuredServerCapacityWithoutPausingCatchUp(int batchSize, int packets, int serverPacketsPerMinute)
    {
        // Both the usual packet and a smaller packet must exceed measured server capacity.
        int events = batchSize * packets;
        _assignment["assigned_modules"]![0]!["config"]!["batch_size"] = batchSize;
        _assignment["collection_policy"]!["rate_limit_per_minute"] = AdDcConfig.DefaultRateLimitPerMinute;
        var runtime = Runtime(new Backlog(events, 0));
        for (int cycle = 0; cycle < 100 && _sent.Sum(p => p.Envelope.RecordCount) < events; cycle++) {
            var status = await runtime.RunCycleAsync(CancellationToken.None);
            Assert.Null(status.ErrorCode); Assert.False(status.DeliveryFailed);
            if (_sent.Sum(p => p.Envelope.RecordCount) < events) Assert.True(runtime.ContinueImmediately);
        }
        Assert.Equal(Helpers.Now, _clock.Now);
        Assert.True(_sent.Count > serverPacketsPerMinute);
        Assert.Equal(Enumerable.Range(1, events).Select(id => (long)id),
            _sent.SelectMany(p => p.Payload["records"]!.AsArray()).Select(r => r!["record_id"]!.GetValue<long>()));
        Assert.Equal(Enumerable.Range(1, _sent.Count).Select(n => (long)n), _sent.Select(p => p.Envelope.Sequence));
    }

    [Fact]
    public async Task ExplicitDeliveryRateLimitStillAppliesDuringCatchUp()
    {
        var source = new Backlog(10000, 0);
        _assignment["collection_policy"]!["rate_limit_per_minute"] = 2;
        var runtime = Runtime(source);
        await runtime.RunCycleAsync(CancellationToken.None);
        await runtime.RunCycleAsync(CancellationToken.None);
        Assert.Equal(2, _sent.Count);
        Assert.False(runtime.ContinueImmediately);
        await runtime.RunCycleAsync(CancellationToken.None);
        Assert.Equal(2, _sent.Count);
        _clock.Now = _clock.Now.AddMinutes(1);
        await runtime.RunCycleAsync(CancellationToken.None);
        Assert.Equal(4, _sent.Count);
    }
}
