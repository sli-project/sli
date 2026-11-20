using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Windows;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class SnapshotModuleTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();
    private static readonly Guid FamilyId = Guid.Parse("00000000-0000-0000-0000-00000000002a");
    private static readonly Guid CycleId = Guid.Parse("00000000-0000-0000-0000-00000000002b");
    public void Dispose() => Directory.Delete(_directory, recursive: true);
    public static IEnumerable<object[]> Scenarios() => Vectors.Load("snapshot-scenarios.json").AsArray().Select(n => new object[] { n!["name"]!.GetValue<string>() });
    private static JsonObject Scenario(string name) => Vectors.Load("snapshot-scenarios.json").AsArray().First(n => n!["name"]!.GetValue<string>() == name)!.AsObject();
    internal static SnapshotPolicy Policy(string name = "ad-full")
    {
        var v = Scenario(name); return SnapshotPolicy.Parse(v["module_id"]!.GetValue<string>(), v["config"]!.AsObject());
    }
    private static IReadOnlyDictionary<string, SnapshotFamily> Normalize(JsonObject v, SnapshotPolicy p) => p.ModuleId == SnapshotPolicy.Ad
        ? AdSnapshotModule.Normalize(v["raw"]!.AsObject(), p, Iso8601.ParseUtc(v["now"]!.GetValue<string>()), () => FamilyId)
        : GpoSnapshotModule.Normalize(v["raw"]!.AsObject(), p, () => FamilyId);

    [Theory]
    [MemberData(nameof(Scenarios))]
    public void SnapshotFamiliesAndEveryFragmentMatchPython(string name)
    {
        var v = Scenario(name); var policy = Policy(name); var families = Normalize(v, policy);
        foreach (var (family, expected) in v["families"]!.AsObject())
        {
            Assert.Equal(expected!["count"]!.GetValue<int>(), families[family].Count);
            Assert.Equal(expected["data_canonical"]!.GetValue<string>(), CanonicalJson.Serialize(families[family].Data));
        }
        var files = new PhysicalDurableFiles(); var stream = new SnapshotStream(_directory, policy.ModuleId, files);
        stream.Freeze(stream.Begin(policy, Helpers.Now, () => CycleId)!, families);
        Assert.DoesNotContain("never-persist-this", File.ReadAllText(Path.Combine(_directory, policy.ModuleId, "cycle.json")));
        CapturedPosition? position = null;
        using var key = Helpers.NewKey(); var packets = new JsonArray(); var sequence = 0;
        foreach (var step in v["samples"]!.AsArray())
        {
            // Reopen at every fragment to prove restart/resumption, including family boundaries.
            stream = new SnapshotStream(_directory, policy.ModuleId, files);
            var sample = stream.NextSample(position)!;
            Assert.Equal(step!["payload_canonical"]!.GetValue<string>(), CanonicalJson.Serialize(sample.Payload));
            Assert.Equal(Cursor.FromJson(step["cursor_before"]), sample.CursorBefore);
            Assert.Equal(Cursor.FromJson(step["cursor_after"]), sample.CursorAfter);
            Assert.Equal("complete", sample.ContinuityState); Assert.Equal(0, sample.LostCount);
            var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, ++sequence, sample, Helpers.Now);
            PacketVerifier.Verify(packet.ToJson(), key); packets.Add(packet.ToJson());
            position = new(sample.Generation, sample.CursorAfter);
        }
        Assert.Null(stream.NextSample(position)); Assert.Null(stream.Begin(policy, Helpers.Now));
        Assert.NotNull(stream.Begin(policy, Helpers.Now.AddHours(12)));
        if (Environment.GetEnvironmentVariable("SLI_DOTNET_INTEROP_DIR") is { Length: > 0 } target)
        {
            Directory.CreateDirectory(target);
            File.WriteAllText(Path.Combine(target, "snapshot-" + name + ".json"), new JsonObject
            { ["public_key_spki_b64"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), ["config"] = policy.Config.DeepClone(), ["packets"] = packets }.ToJsonString());
        }
    }

    [Fact]
    public void SnapshotQueueSurvivesLostReceiptAndUsesTheSameSignedDeliveryContract()
    {
        var v = Scenario("ad-full"); var policy = Policy(); var files = new PhysicalDurableFiles();
        var stream = new SnapshotStream(_directory, policy.ModuleId, files);
        stream.Freeze(stream.Begin(policy, Helpers.Now, () => CycleId)!, Normalize(v, policy));
        using var key = Helpers.NewKey(); var signer = Helpers.Signer(key); var queuePath = Path.Combine(_directory, "queue");
        SignedPacket first;
        using (var queue = Helpers.Queue(queuePath))
        {
            first = queue.Capture(signer, Helpers.AgentId, stream.NextSample(null)!, Helpers.Now);
            Assert.False(queue.Acknowledge(first, new JsonObject { ["status"] = "committed" }));
            Assert.Single(queue.Pending());
        }
        using (var queue = Helpers.Queue(queuePath))
        {
            Assert.Equal(first.Envelope.PacketId, Assert.Single(queue.Pending()).Envelope.PacketId);
            PacketVerifier.Verify(first.ToJson(), key);
            Assert.Equal(first.Envelope.CursorAfter, stream.NextSample(queue.Captured(policy.ModuleId))!.CursorBefore);
            Assert.True(queue.Acknowledge(first, Helpers.Receipt(first, "duplicate")));
            Assert.Empty(queue.Pending());
        }
    }

    [Fact]
    public void SnapshotFreezeAndQueueFailureNeverAdvanceSourcePosition()
    {
        var policy = Policy(); var files = new FaultyFiles(new PhysicalDurableFiles()); var stream = new SnapshotStream(_directory, policy.ModuleId, files);
        var state = stream.Begin(policy, Helpers.Now)!;
        files.FailWrite = path => path.EndsWith("cycle.json", StringComparison.Ordinal);
        Assert.Throws<IOException>(() => stream.Freeze(state, Normalize(Scenario("ad-full"), policy)));
        Assert.Null(stream.NextSample(null)); files.FailWrite = null; stream.Freeze(state, Normalize(Scenario("ad-full"), policy));
        var first = stream.NextSample(null)!;
        using var queue = Helpers.Queue(Path.Combine(_directory, "small-queue"), maxBytes: 1); using var key = Helpers.NewKey();
        Assert.Throws<QueueFullException>(() => queue.Capture(Helpers.Signer(key), Helpers.AgentId, first, Helpers.Now));
        Assert.Null(queue.Captured(policy.ModuleId)); Assert.Equal(first.CursorAfter, stream.NextSample(null)!.CursorAfter);
    }

    [Fact]
    public async Task SnapshotModulesReadThroughThePortableInterfaceAndHonorCancellation()
    {
        var reader = new FakeSnapshotReader(Scenario("ad-full")["raw"]!.AsObject());
        var result = await new AdSnapshotModule(reader, new TestClock()).CaptureAsync(Policy(), CancellationToken.None);
        Assert.Equal(6, result.Count); Assert.Equal(1, reader.Reads);
        reader.Raw = Scenario("gpo-full")["raw"]!.AsObject();
        Assert.Equal(2, (await new GpoSnapshotModule(reader).CaptureAsync(Policy("gpo-full"), CancellationToken.None)).Count);
        using var stop = new CancellationTokenSource(); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new GpoSnapshotModule(reader).CaptureAsync(Policy("gpo-full"), stop.Token));
        Assert.Equal(2, reader.Reads);
    }

    [Fact]
    public void SnapshotReaderShipsPagedServiceIdentityCollectorsWithoutSecretAttributesOrCheckoutPaths()
    {
        var ad = DirectorySnapshotReader.Request(Policy()); var gpo = DirectorySnapshotReader.Request(Policy("gpo-full"));
        var script = ad["collector"]!.GetValue<string>();
        Assert.Contains("$searcher.PageSize = 500", script); Assert.Contains("AuthenticationTypes]::Signing", script);
        var attrs = ad["policy"]!["ldap_attributes"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();
        Assert.DoesNotContain("unicodepwd", attrs); Assert.DoesNotContain("mslaps-password", attrs); Assert.DoesNotContain("msds-managedpassword", attrs); Assert.DoesNotContain("*", attrs);
        Assert.Contains("$searcher.PageSize = 500", gpo["collector"]!.GetValue<string>());
        Assert.DoesNotContain("$PSScriptRoot", gpo["collector"]!.GetValue<string>());
        Assert.Contains("Export-ModuleMember", gpo["contract"]!.GetValue<string>());
        foreach (var function in new[] { "ConvertFrom-SLIGpoReportXml", "ConvertFrom-SLIGpoPermissionObjects", "Merge-SLIGpoGovernanceAttributes" })
            Assert.Contains(function, gpo["contract"]!.GetValue<string>().Split('\n').Last());
        if (Environment.GetEnvironmentVariable("SLI_DOTNET_INTEROP_DIR") is { Length: > 0 } target)
        {
            Directory.CreateDirectory(target); File.WriteAllText(Path.Combine(target, "gpo-reader-request.json"), gpo.ToJsonString());
        }
    }

    [Theory]
    [InlineData("domain_sid", "S-1-5-21-100000009-200000008-300000007")]
    [InlineData("domain_dns", "different.invalid")]
    public void SnapshotDomainBindingFailsClosed(string field, string value)
    {
        var v = Scenario("ad-full"); var cfg = Policy().Config; cfg[field] = value;
        Assert.Throws<AgentException>(() => Normalize(v, SnapshotPolicy.Parse(SnapshotPolicy.Ad, cfg)));
        var gpo = Scenario("gpo-full"); cfg = Policy("gpo-full").Config; cfg[field] = value;
        Assert.Throws<AgentException>(() => Normalize(gpo, SnapshotPolicy.Parse(SnapshotPolicy.Gpo, cfg)));
    }

    [Fact]
    public void SnapshotPolicyValidatesLimitsSchedulesAndModuleEnablement()
    {
        var cfg = Policy().Config; cfg["capture_seconds"] = 0; Assert.Throws<AgentException>(() => SnapshotPolicy.Parse(SnapshotPolicy.Ad, cfg));
        cfg = Policy().Config; cfg["schedule"]!["hours"] = new JsonArray(18, 6); Assert.Throws<AgentException>(() => SnapshotPolicy.Parse(SnapshotPolicy.Ad, cfg));
        var assignment = PolicyCycleTests.Assignment(); assignment["assigned_modules"] = new JsonArray(new JsonObject
        { ["module_id"] = SnapshotPolicy.Ad, ["enabled"] = false, ["config"] = cfg });
        Assert.Empty(AgentPolicy.Parse(assignment, Helpers.AgentId, EventCatalog.Load()).Snapshots);
        assignment["assigned_modules"]![0]!["config"] = Policy().Config;
        assignment["assigned_modules"]![0]!["enabled"] = true;
        Assert.Single(AgentPolicy.Parse(assignment, Helpers.AgentId, EventCatalog.Load()).Snapshots);
    }

    [Fact]
    public void SnapshotDefaultScheduleUsesTheServersIanaTimezoneOnEveryPlatform()
    {
        var cfg = Policy().Config; cfg.Remove("schedule");
        var policy = SnapshotPolicy.Parse(SnapshotPolicy.Ad, cfg);
        Assert.Equal("2026-10-07T11:00:00+00:00", policy.DueSlot(Helpers.Now));
    }

    [Fact]
    public void SnapshotCursorRejectsMalformedOrNonCanonicalPositions()
    {
        Assert.Throws<AgentException>(() => SnapshotStream.ParseCursor(new("bookmark", "")));
        Assert.Throws<AgentException>(() => SnapshotStream.ParseCursor(new("snapshot", "{}")));
        var sample = JsonNode.Parse(Scenario("ad-full")["samples"]![0]!["payload_canonical"]!.GetValue<string>())!.AsObject();
        var cursor = SnapshotStream.MakeCursor(sample);
        Assert.NotNull(SnapshotStream.ParseCursor(cursor));
        Assert.Throws<AgentException>(() => SnapshotStream.ParseCursor(cursor with { Token = " " + cursor.Token }));
    }
}

internal sealed class FakeSnapshotReader(JsonObject raw) : IDirectorySnapshotReader
{
    public JsonObject Raw { get; set; } = raw;
    public int Reads { get; private set; }
    public Task<JsonObject> ReadAsync(SnapshotPolicy policy, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); Reads++; return Task.FromResult((JsonObject)Raw.DeepClone()); }
}
