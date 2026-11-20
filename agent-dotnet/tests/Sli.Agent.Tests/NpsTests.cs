using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class NpsTests
{
    internal static JsonNode Scenario(string name) => Vectors.Load("nps-scenarios.json").AsArray().Single(s => s!["name"]!.GetValue<string>() == name)!;
    internal static JsonObject Config(string module) => Scenario(module == NpsPolicy.Nps ? "nps-continuity-restart" : "radius-blank-progress")["steps"]![0]!["config"]!.DeepClone().AsObject();
    public static TheoryData<string> Names()
    {
        var names = new TheoryData<string>();
        foreach (var scenario in Vectors.Load("nps-scenarios.json").AsArray()) names.Add(scenario!["name"]!.GetValue<string>());
        return names;
    }
    internal sealed class Events(JsonObject script) : INpsEventSource
    {
        public int Reads { get; private set; }
        public Action? OnRead { get; init; }
        public SourceBatch Read(JsonObject progress, int limit)
        {
            Reads++;
            OnRead?.Invoke();
            if (script["read_error"] is not null) throw new EventLogReadException(code: script["read_error"]!.GetValue<string>());
            var after = progress["record_id"]?.GetValue<long>();
            return new(script["rows"]!.AsArray().Where(r => after is null || r!["record_id"]!.GetValue<long>() > after)
                .Take(limit).Select(r => new EventRow(r!["xml"]!.GetValue<string>(), r["bookmark"]!.GetValue<string>())).ToList());
        }
    }
    internal static Sample Collect(string module, NpsPolicy config, JsonObject step, CapturedPosition? previous, DateTimeOffset now)
    {
        return module == NpsPolicy.Nps ? new NpsModule(Helpers.HostId, config, new Events(step)).Collect(previous, now)
            : new RadiusAccountingModule(Helpers.HostId, config, new RadiusTailSource(new RadiusMemoryFiles(step["files"]!.AsArray()))).Collect(previous, now);
    }

    [Theory, MemberData(nameof(Names))]
    public void MatchesPythonPacketsCursorsPrivacyAndRecoveryAcrossRestart(string name)
    {
        var scenario = Scenario(name);
        var module = scenario["module_id"]!.GetValue<string>();
        CapturedPosition? previous = null;
        using var key = Helpers.NewKey();
        var packets = new JsonArray();
        foreach (var node in scenario["steps"]!.AsArray())
        {
            var step = node!.AsObject();
            var config = NpsPolicy.Parse(module, step["config"]!.AsObject());
            Assert.Equal(CanonicalJson.Serialize(step["config"]), CanonicalJson.Serialize(config.Value));
            var now = Iso8601.ParseUtc(step["now"]!.GetValue<string>());
            if (step["error"] is { } expectedError)
            {
                Assert.Equal(expectedError.GetValue<string>(), Assert.ThrowsAny<AgentException>(() => Collect(module, config, step, previous, now)).Code);
                continue;
            }
            // Every step creates a fresh module and adapter: the only progress is its durable signed cursor.
            var sample = Collect(module, config, step, previous, now);
            Assert.Equal(step["payload_canonical"]!.GetValue<string>(), CanonicalJson.Serialize(sample.Payload));
            Assert.Equal(CanonicalJson.Serialize(step["cursor_before"]), CanonicalJson.Serialize(sample.CursorBefore.ToJson()));
            Assert.Equal(CanonicalJson.Serialize(step["cursor_after"]), CanonicalJson.Serialize(sample.CursorAfter.ToJson()));
            Assert.Equal(step["continuity_state"]!.GetValue<string>(), sample.ContinuityState);
            Assert.Equal(step["filtered_count"]!.GetValue<long>(), sample.FilteredCount);
            Assert.Equal(step["lost_count"]?.GetValue<long>(), sample.LostCount);
            Assert.DoesNotContain("never-persist-this", CanonicalJson.Serialize(sample.Payload));
            Assert.DoesNotContain("SharedSecret", CanonicalJson.Serialize(sample.Payload));
            packets.Add(new JsonObject { ["config"] = config.Value.DeepClone(), ["packet"] = Packets.Make(Helpers.Signer(key), Helpers.AgentId, packets.Count + 1, sample, now).ToJson() });
            previous = new(sample.Generation, sample.CursorAfter);
        }
        if (Environment.GetEnvironmentVariable("SLI_DOTNET_INTEROP_DIR") is { Length: > 0 } target)
        {
            Directory.CreateDirectory(target);
            File.WriteAllText(Path.Combine(target, name + ".json"), new JsonObject
            { ["host_id"] = Helpers.HostId, ["module_id"] = module, ["public_key_spki_b64"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), ["samples"] = packets }.ToJsonString());
        }
    }

    [Theory]
    [InlineData(NpsPolicy.Nps)]
    [InlineData(NpsPolicy.Accounting)]
    public void QueueBackpressureRestartLostAckAndExactReceiptPreserveBothCursorTypes(string module)
    {
        var step = Scenario(module == NpsPolicy.Nps ? "nps-continuity-restart" : "radius-blank-progress")["steps"]![0]!.AsObject();
        var config = NpsPolicy.Parse(module, step["config"]!.AsObject());
        var directory = Helpers.TempDirectory();
        using var key = Helpers.NewKey();
        try
        {
            SignedPacket packet;
            using (var queue = Helpers.Queue(directory, maxBytes: 1))
            {
                var sample = Collect(module, config, step, queue.Captured(module), Helpers.Now);
                Assert.Throws<QueueFullException>(() => queue.Capture(Helpers.Signer(key), Helpers.AgentId, sample, Helpers.Now));
                Assert.Null(queue.Captured(module));
                queue.MaxBytes = 1000000;
                var retried = Collect(module, config, step, queue.Captured(module), Helpers.Now);
                Assert.Equal(sample.CursorAfter, retried.CursorAfter);
                Assert.Equal(CanonicalJson.Serialize(sample.Payload), CanonicalJson.Serialize(retried.Payload));
                packet = queue.Capture(Helpers.Signer(key), Helpers.AgentId, retried, Helpers.Now);
            }
            using (var queue = Helpers.Queue(directory))
            {
                Assert.Equal(packet.ToCanonical(), Assert.Single(queue.Pending()).ToCanonical());
                var wrong = Helpers.Receipt(packet); wrong["committed_cursor"] = Cursor.Start(packet.Envelope.CursorAfter.Strategy).ToJson();
                Assert.False(queue.Acknowledge(packet, wrong)); Assert.Single(queue.Pending());
                Assert.Equal(packet.Envelope.CursorAfter, queue.Captured(module)!.CursorAfter);
                Assert.True(queue.Acknowledge(packet, Helpers.Receipt(packet, "duplicate"))); Assert.Empty(queue.Pending());
            }
            using (var queue = Helpers.Queue(directory)) Assert.Equal(packet.Envelope.CursorAfter, queue.Captured(module)!.CursorAfter);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData(NpsPolicy.Nps)]
    [InlineData(NpsPolicy.Accounting)]
    public void PolicyDefaultsOptInFamilyPauseAndStrictSecrets(string module)
    {
        var body = PolicyCycleTests.Assignment(); body["assigned_modules"] = new JsonArray();
        Assert.Empty(AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load()).NpsModules);
        var assignment = new JsonObject { ["module_id"] = module, ["enabled"] = false, ["config"] = new JsonObject { ["shared_secret"] = "never-persist-this" } };
        body["assigned_modules"]!.AsArray().Add(assignment);
        Assert.Empty(AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load()).NpsModules);
        assignment["enabled"] = true;
        Assert.Equal("agent_nps_config_invalid", Assert.Throws<AgentException>(() => AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load())).Code);
        assignment["config"] = Config(module);
        Assert.Single(AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load()).NpsModules);
        body["collection_policy"]!["batch_size"] = 1;
        Assert.Equal(1, AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load()).NpsModules[module].BatchSize);
        Assert.True(assignment["config"]!["batch_size"]!.GetValue<int>() > 1);
        assignment["config"]!["paused"] = true;
        Assert.Empty(AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load()).NpsModules);
        assignment["config"]!["paused"] = false;
        var family = module == NpsPolicy.Nps ? "nps" : "radius_accounting";
        assignment["config"]!["families"]![family] = false;
        Assert.Empty(AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load()).NpsModules);
    }

    [Theory]
    [InlineData("batch_size", "true")]
    [InlineData("batch_size", "129")]
    [InlineData("paused", "1")]
    [InlineData("families", "null")]
    [InlineData("families", "{\"nps\":1}")]
    [InlineData("source_instance_id", "null")]
    [InlineData("event_generation", "\"\"")]
    public void InvalidPolicyCannotReadASource(string field, string json)
    {
        var config = Config(NpsPolicy.Nps); config[field] = JsonNode.Parse(json);
        Assert.Equal("agent_nps_config_invalid", Assert.Throws<AgentException>(() => NpsPolicy.Parse(NpsPolicy.Nps, config)).Code);
    }

    [Fact]
    public void CursorIdentityAndUnknownRecoveryProvenanceFailClosed()
    {
        var config = NpsPolicy.Parse(NpsPolicy.Accounting, Config(NpsPolicy.Accounting));
        var source = new RadiusTailSource(new RadiusMemoryFiles(new JsonArray()));
        var module = new RadiusAccountingModule(Helpers.HostId, config, source);
        var value = config.Value["initial_cursor"]!.DeepClone().AsObject();
        value["exact_boundary_recovery"] = "false";
        Assert.Equal("agent_radius_cursor_invalid", Assert.Throws<AgentException>(() => module.Collect(new(Helpers.HostId, new("file_offset", CanonicalJson.Serialize(value))), Helpers.Now)).Code);
        value.Remove("exact_boundary_recovery"); value["transport_binding"] = "different";
        Assert.Equal("agent_radius_cursor_invalid", Assert.Throws<AgentException>(() => module.Collect(new(Helpers.HostId, new("file_offset", CanonicalJson.Serialize(value))), Helpers.Now)).Code);
        Assert.Equal("agent_radius_cursor_invalid", Assert.Throws<AgentException>(() => module.Collect(new("other-host", Cursor.Start("file_offset")), Helpers.Now)).Code);
        Assert.Equal("agent_nps_cursor_invalid", Assert.Throws<AgentException>(() => NpsModule.BookmarkState(new("bookmark", "{\"record_id\":true}"), "1")).Code);
    }

    private sealed class NativeReaders(IReadOnlyList<EventRow> rows, string? fault = null) : INpsEventLogReaders
    {
        public int Opens { get; private set; }
        public string? Selector { get; private set; }
        public bool Disposed { get; private set; }
        public INpsEventLogReader Open(string selector, int batchSize)
        {
            Opens++; Selector = selector;
            if (fault == "open") throw new IOException("secret-native-details");
            return new Reader(this, new Queue<EventRow>(rows), fault);
        }
        private sealed class Reader(NativeReaders owner, Queue<EventRow> rows, string? fault) : INpsEventLogReader
        {
            public void Seek(string bookmark) { if (fault == "seek") throw new IOException("secret-native-details"); }
            public EventRow? Read() => fault == "read" ? throw new IOException("secret-native-details") : rows.TryDequeue(out var row) ? row : null;
            public void Dispose() => owner.Disposed = true;
        }
    }

    private static EventRow NativeRow(int index)
    {
        var row = Scenario("nps-continuity-restart")["steps"]![1]!["rows"]![index]!;
        return new(row["xml"]!.GetValue<string>(), row["bookmark"]!.GetValue<string>());
    }
    private static JsonObject AnchoredState()
        => JsonNode.Parse(Scenario("nps-continuity-restart")["steps"]![0]!["cursor_after"]!["token"]!.GetValue<string>())!.AsObject();

    [Theory]
    [InlineData("open")]
    [InlineData("seek")]
    [InlineData("read")]
    [InlineData("anchor-missing")]
    [InlineData("anchor-record-id")]
    [InlineData("anchor-hash")]
    public void NativeBoundaryRefusesLostOrReplacedAnchorsWithoutFallbackAndRedactsErrors(string fault)
    {
        var row = NativeRow(fault == "anchor-record-id" ? 1 : 0);
        if (fault == "anchor-hash") row = row with { Xml = row.Xml.Replace("synthetic-user", "changed-user", StringComparison.Ordinal) };
        var readers = new NativeReaders(fault == "anchor-missing" ? [] : [row], fault);
        var exception = Assert.Throws<EventLogReadException>(() => new NpsBookmarkSource(readers).Read(AnchoredState(), 2));
        Assert.Equal("agent_nps_read_failed", exception.Code); Assert.DoesNotContain("secret-native-details", exception.ToString());
        Assert.Equal(1, readers.Opens); Assert.Equal("*", readers.Selector);
        Assert.Equal(fault != "open", readers.Disposed);
    }

    [Fact]
    public void NativeBoundarySkipsTheVerifiedAnchorAndUsesRecordIdOnlyForLegacyUnbookmarkedReads()
    {
        var readers = new NativeReaders([NativeRow(0), NativeRow(1)]);
        var batch = new NpsBookmarkSource(readers).Read(AnchoredState(), 1);
        Assert.Equal(NativeRow(1), Assert.Single(batch.Rows)); Assert.False(batch.BookmarkRecovered); Assert.True(readers.Disposed);
        var legacy = AnchoredState(); legacy["bookmark"] = "";
        var legacyReaders = new NativeReaders([]);
        Assert.Empty(new NpsBookmarkSource(legacyReaders).Read(legacy, 1).Rows);
        Assert.Equal("*[System[EventRecordID > 1]]", legacyReaders.Selector);
    }
}

internal sealed class RadiusMemoryFiles : IRadiusFileSystem
{
    public List<RadiusFile> Files { get; } = [];
    public Dictionary<string, byte[]> Bytes { get; } = [];
    public Func<RadiusFile, RadiusFile>? OnOpen { get; set; }
    public int ReadBytes { get; private set; }
    public int OpenCount { get; private set; }
    public bool InventoryFails { get; set; }
    public RadiusMemoryFiles(JsonArray specs)
    {
        foreach (var spec in specs)
        {
            var name = spec!["name"]!.GetValue<string>(); var bytes = Convert.FromBase64String(spec["data_b64"]!.GetValue<string>());
            Files.Add(new(name, name, spec["creation_time_ns"]!.GetValue<long>(), spec["modified_time_ns"]!.GetValue<long>(), bytes.Length, "device", name));
            Bytes[name] = bytes;
        }
    }
    public RadiusMemoryFiles(byte[] bytes) { Files.Add(new("IN0.log", "IN0.log", 1700000000000000000, 1700000000000000000, bytes.Length, "device", "1")); Bytes["IN0.log"] = bytes; }
    public IEnumerable<RadiusFile> Inventory(string directory) => InventoryFails ? throw new IOException("private-source") : Files;
    public IRadiusReadFile Open(RadiusFile file) { OpenCount++; return new Opened(this, OnOpen?.Invoke(file) ?? file); }
    private sealed class Opened(RadiusMemoryFiles owner, RadiusFile file) : IRadiusReadFile
    {
        public RadiusFile Metadata => file;
        public byte[] Read(long offset, int count)
        {
            var result = owner.Bytes[file.Key].Skip((int)offset).Take(count).ToArray(); owner.ReadBytes += result.Length; return result;
        }
        public void Dispose() { }
    }
}
