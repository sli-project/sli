using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>A scripted Event Log: returns what the scenario says and records how it was asked.</summary>
public sealed class ScriptedSource : IEventLogSource
{
    public JsonObject? Script { get; set; }

    public List<(string Channel, string Cursor, int Limit)> Calls { get; } = [];

    public SourceBatch Read(string channel, ChannelProgress progress, int limit)
    {
        Calls.Add((channel, CanonicalJson.Serialize(progress.ToJson()), limit));
        var mode = Script!["mode"]!.GetValue<string>();
        if (mode == "error") throw new EventLogReadException();
        var rows = Script["rows"]!.AsArray().Select(item => new EventRow(item!["xml"]!.GetValue<string>(), item["bookmark"]!.GetValue<string>())).ToList();
        return new SourceBatch(rows, mode == "recovered");
    }
}

public class AdDcModuleTests
{
    private static readonly EventCatalog Catalog = EventCatalog.Load();

    public static TheoryData<string> Names()
    {
        var data = new TheoryData<string>();
        foreach (var item in Vectors.Load("ad-dc-scenarios.json").AsArray()) data.Add(item!["name"]!.GetValue<string>());
        return data;
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void CaptureMaintainsCursorAndDeliveryContinuity(string name)
    {
        var scenario = Vectors.Load("ad-dc-scenarios.json").AsArray().Single(node => node!["name"]!.GetValue<string>() == name)!.AsObject();
        var settings = scenario["config"]!.DeepClone().AsObject();
        // These vectors exercise the original three streams. Keep their source
        // and backlog scenarios isolated from the newly collected channels.
        settings["channels"] ??= new JsonObject();
        foreach (string extra in DcCursor.Channels.Skip(3)) settings["channels"]![extra] = false;
        var config = AdDcConfig.Parse(settings, Catalog);
        var source = new ScriptedSource();
        var module = new AdDcModule(scenario["host_id"]!.GetValue<string>(), config, source, Catalog);

        var index = 0;
        foreach (var node in scenario["steps"]!.AsArray())
        {
            var step = node!.AsObject();
            index++;
            source.Script = step["reader"]!.AsObject();
            source.Calls.Clear();
            var captured = step["captured"] is JsonObject position
                ? new CapturedPosition(position["generation"]!.GetValue<string>(), Cursor.FromJson(position["cursor_after"]))
                : null;
            var result = module.Collect(captured, Iso8601.ParseUtc(step["now"]!.GetValue<string>()), step["channel_override"]?.GetValue<string>());

            var reads = step["expected_reads"]!.AsArray();
            Assert.True(reads.Count == source.Calls.Count, $"{name} step {index}: reads");
            for (var i = 0; i < reads.Count; i++)
            {
                Assert.Equal(reads[i]!["channel"]!.GetValue<string>(), source.Calls[i].Channel);
                Assert.Equal(CanonicalJson.Serialize(reads[i]!["cursor"]), source.Calls[i].Cursor);
                Assert.Equal(reads[i]!["limit"]!.GetValue<int>(), source.Calls[i].Limit);
            }
            var expected = step["expected"]?.AsObject();
            if (expected is null)
            {
                Assert.Null(result.Sample);
                continue;
            }
            var sample = result.Sample!;
            Assert.Equal(expected["module_id"]!.GetValue<string>(), sample.ModuleId);
            Assert.Equal(expected["source_instance_id"]!.GetValue<string>(), sample.SourceInstanceId);
            Assert.Equal(expected["channel"]!.GetValue<string>(), sample.Channel);
            Assert.Equal(expected["generation"]!.GetValue<string>(), sample.Generation);
            Assert.Equal(CanonicalJson.Serialize(expected["cursor_before"]), CanonicalJson.Serialize(sample.CursorBefore.ToJson()));
            var expectedAfter = expected["cursor_after"]!.DeepClone();
            var channel = sample.Payload["header"]!["channel"]!.GetValue<string>();
            var expectedState = JsonNode.Parse(expectedAfter["token"]!.GetValue<string>())!;
            expectedState["next"] = (DcCursor.Channels.ToList().IndexOf(channel) + 1) % DcCursor.Channels.Count;
            expectedAfter["token"] = CanonicalJson.Serialize(expectedState);
            Assert.Equal(CanonicalJson.Serialize(expectedAfter), CanonicalJson.Serialize(sample.CursorAfter.ToJson()));
            // Keep the existing backlog/error/reset inputs; assert the new collection behaviour.
            var priorRecords = JsonNode.Parse(expected["payload_canonical"]!.GetValue<string>())!["records"]!.AsArray();
            var removed = priorRecords.Count(record => record!["payload"]!["event_id"]!.GetValue<int>() is 4634 or 6013 or 1162);
            Assert.Equal(priorRecords.Count - removed, sample.Payload["records"]!.AsArray().Count);
            Assert.DoesNotContain(sample.Payload["records"]!.AsArray(), record => record!["payload"]!["event_id"]!.GetValue<int>() is 4634 or 6013 or 1162);
            Assert.Equal(expected["module_version"]!.GetValue<string>(), sample.ModuleVersion);
            Assert.Equal(expected["policy_revision"]!.GetValue<string>(), sample.PolicyRevision);
            Assert.Equal(removed > 0 ? "filtered" : expected["continuity_state"]!.GetValue<string>(), sample.ContinuityState);
            Assert.Equal(expected["filtered_count"]!.GetValue<long>() + removed, sample.FilteredCount);
            Assert.Equal(expected["lost_count"]?.GetValue<long>(), sample.LostCount);
            Assert.Equal(expected["catch_up_channel"]?.GetValue<string>(), result.CatchUpChannel);
        }
    }

    private static AdDcModule Module(IEventLogSource source, JsonObject? extra = null)
    {
        var config = new JsonObject { ["source_name"] = "fixture-dc", ["connect_address"] = "fixture-endpoint", ["channels"] = new JsonObject { ["Security"] = true, ["System"] = false, ["Directory Service"] = false } };
        foreach (var (key, value) in extra ?? []) config[key] = value?.DeepClone();
        return new AdDcModule(Helpers.HostId, AdDcConfig.Parse(config, Catalog), source, Catalog);
    }

    [Fact]
    public void NoEnabledChannelMeansNoPacket()
    {
        var module = Module(new ScriptedSource(), new JsonObject { ["channels"] = new JsonObject(
            DcCursor.Channels.Select(c => KeyValuePair.Create<string,JsonNode?>(c,JsonValue.Create(false)))) });
        Assert.Null(module.Collect(null, Helpers.Now).Sample);
    }

    [Fact]
    public void ACursorOfAnotherHostIsRefused()
    {
        var module = Module(new ScriptedSource { Script = new JsonObject { ["mode"] = "rows", ["rows"] = new JsonArray() } });
        var other = new CapturedPosition("someone-else", Cursor.Start("bookmark"));
        Assert.Equal("agent_ad_dc_cursor_invalid", Assert.Throws<AgentException>(() => module.Collect(other, Helpers.Now)).Code);
    }

    [Fact]
    public void ACatchUpOnADisabledChannelIsRefused()
    {
        var module = Module(new ScriptedSource { Script = new JsonObject { ["mode"] = "rows", ["rows"] = new JsonArray() } });
        Assert.Equal("agent_ad_dc_channel_invalid", Assert.Throws<AgentException>(() => module.Collect(null, Helpers.Now, "System")).Code);
    }

    [Fact]
    public void RecordIdsMustGrowAndBookmarksMustExist()
    {
        static JsonObject Rows(params (long Id, string Bookmark)[] rows) => new()
        {
            ["mode"] = "rows",
            ["rows"] = new JsonArray(rows.Select(row => (JsonNode?)new JsonObject { ["xml"] = Xml(row.Id), ["bookmark"] = row.Bookmark }).ToArray()),
        };
        var source = new ScriptedSource { Script = Rows((5, "b5"), (5, "b5")) };
        Assert.Equal("agent_ad_dc_range_invalid", Assert.Throws<AgentException>(() => Module(source).Collect(null, Helpers.Now)).Code);
        source.Script = Rows((5, string.Empty));
        Assert.Equal("agent_ad_dc_range_invalid", Assert.Throws<AgentException>(() => Module(source).Collect(null, Helpers.Now)).Code);
    }

    [Fact]
    public void TheChannelInsideTheEventMustBeTheOneRead()
    {
        var source = new ScriptedSource
        {
            Script = new JsonObject
            {
                ["mode"] = "rows",
                ["rows"] = new JsonArray(new JsonObject { ["xml"] = Xml(5, channel: "System"), ["bookmark"] = "b5" }),
            },
        };
        Assert.Equal("agent_ad_dc_channel_invalid", Assert.Throws<AgentException>(() => Module(source).Collect(null, Helpers.Now)).Code);
    }

    [Fact]
    public void AMalformedEventStopsTheCycleInsteadOfBeingSkipped()
    {
        var source = new ScriptedSource
        {
            Script = new JsonObject { ["mode"] = "rows", ["rows"] = new JsonArray(new JsonObject { ["xml"] = "<broken", ["bookmark"] = "b" }) },
        };
        Assert.IsAssignableFrom<AgentException>(Record.Exception(() => Module(source).Collect(null, Helpers.Now)));
    }

    [Fact]
    public void AReadBeyondTheBatchSizeIsRefused()
    {
        var rows = new JsonArray(Enumerable.Range(1, 3).Select(i => (JsonNode?)new JsonObject { ["xml"] = Xml(i), ["bookmark"] = "b" + i }).ToArray());
        var source = new ScriptedSource { Script = new JsonObject { ["mode"] = "rows", ["rows"] = rows } };
        var module = Module(source, new JsonObject { ["batch_size"] = 2 });
        Assert.Equal("agent_ad_dc_range_invalid", Assert.Throws<AgentException>(() => module.Collect(null, Helpers.Now)).Code);
    }

    [Fact]
    public void ASingleEventOverTheWireBudgetIsRefused()
    {
        var huge = Xml(1, filler: new string('x', 45 * 1024));
        var source = new ScriptedSource { Script = new JsonObject { ["mode"] = "rows", ["rows"] = new JsonArray(new JsonObject { ["xml"] = huge, ["bookmark"] = "b" }) } };
        Assert.Equal("agent_ad_dc_event_size_limit", Assert.Throws<AgentException>(() => Module(source).Collect(null, Helpers.Now)).Code);
    }

    [Fact]
    public void TheCursorSurvivesAJsonRoundTripThroughTheQueue()
    {
        var source = new ScriptedSource { Script = new JsonObject { ["mode"] = "rows", ["rows"] = new JsonArray(new JsonObject { ["xml"] = Xml(7), ["bookmark"] = "<BookmarkList/>" }) } };
        var first = Module(source).Collect(null, Helpers.Now).Sample!;
        var restored = DcCursor.Parse(Cursor.FromJson(JsonNode.Parse(first.CursorAfter.ToJson().ToJsonString())));
        Assert.Equal(7, restored.Progress["Security"].RecordId);
        Assert.Equal(1, restored.Next);
    }

    internal static string Xml(long recordId, string channel = "Security", string filler = "") =>
        $"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>{recordId}</EventRecordID>"
        + $"<Channel>{channel}</Channel><Computer>dc1.example.test</Computer><TimeCreated SystemTime='2026-10-07T00:00:00Z'/></System><EventData><Data Name='A'>{filler}</Data></EventData></Event>";
}
