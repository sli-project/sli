using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public class RuntimeHandoffTests
{
    [Fact]
    public void WorkstationContinuesPythonCursorAndPersistsItsFirstPacketAcrossRestart()
    {
        var scenario = Vectors.Load("workstations-scenarios.json").AsArray().First(x => x!["steps"]!.AsArray().Count >= 2)!;
        var steps = scenario["steps"]!.AsArray();
        var host = scenario["host_id"]!.GetValue<string>();
        var handoff = RuntimeHandoff.Parse(new JsonObject { ["source_host_id"] = host,
            ["cursors"] = new JsonObject { [WorkstationsModule.ModuleId] = new JsonObject {
                ["generation"] = host, ["cursor_after"] = steps[0]!["cursor_after"]!.DeepClone() } } })!;
        var source = new ScriptedSource { Script = steps[1]!["reader"]!.AsObject() };
        var module = new WorkstationsModule(handoff.SourceHostId, WorkstationPolicy.Parse(scenario["config"]!.AsObject()), source);
        var sample = module.Collect(handoff.Position(WorkstationsModule.ModuleId), Iso8601.ParseUtc(steps[1]!["now"]!.GetValue<string>())).Sample!;
        Assert.Equal(steps[1]!["payload_canonical"]!.GetValue<string>(), CanonicalJson.Serialize(sample.Payload));
        var directory = Helpers.TempDirectory();
        using var key = Helpers.NewKey();
        try
        {
            using (var queue = new FilePacketQueue(directory, new PhysicalDurableFiles(), 10_000_000, 86400))
            {
                var packet = queue.Capture(Helpers.Signer(key), Helpers.AgentId, sample, Helpers.Now);
                Assert.Equal(1, packet.Envelope.Sequence);
                Assert.Equal(handoff.Position(WorkstationsModule.ModuleId)!.CursorAfter, packet.Envelope.CursorBefore);
            }
            using var reopened = new FilePacketQueue(directory, new PhysicalDurableFiles(), 10_000_000, 86400);
            Assert.Single(reopened.Pending());
            Assert.Equal(new CapturedPosition(host, sample.CursorAfter), reopened.Captured(WorkstationsModule.ModuleId));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void UsesTheRetainedGenerationAndCursorWithoutChangingTransportIdentity()
    {
        var host = Guid.NewGuid().ToString("D");
        var body = new JsonObject { ["source_host_id"] = host, ["cursors"] = new JsonObject
        {
            ["sli.workstations"] = new JsonObject { ["generation"] = host,
                ["cursor_after"] = new Cursor("bookmark", "retained").ToJson() }
        }};
        var handoff = RuntimeHandoff.Parse(body)!;
        Assert.Equal(host, handoff.SourceHostId);
        Assert.Equal(new CapturedPosition(host, new Cursor("bookmark", "retained")), handoff.Position("sli.workstations"));
        Assert.Null(handoff.Position("sli.vpn-nps"));
        Assert.Null(RuntimeHandoff.Parse(null));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"source_host_id\":\"private name\",\"cursors\":{}}")]
    [InlineData("{\"source_host_id\":\"00000000-0000-4000-8000-000000000001\",\"cursors\":[]}")]
    public void RefusesMalformedAuthority(string json) =>
        Assert.Throws<AgentException>(() => RuntimeHandoff.Parse(JsonNode.Parse(json)));
}
