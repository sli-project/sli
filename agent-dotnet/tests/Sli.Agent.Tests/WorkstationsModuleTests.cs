using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class WorkstationsModuleTests
{
    private sealed class RowsSource(List<EventRow> rows) : IEventLogSource
    {
        public SourceBatch Read(string channel, ChannelProgress progress, int limit) => new(rows.Take(limit).ToList());
    }

    private sealed class RecordingSource : IEventLogSource
    {
        public List<string> Channels { get; } = [];

        public SourceBatch Read(string channel, ChannelProgress progress, int limit)
        {
            Channels.Add(channel);
            return new SourceBatch([]);
        }
    }

    [Fact]
    public void CollectionSkipsChannelsExcludedByTheWorkstationPolicy()
    {
        var policy = WorkstationPolicy.Parse(new JsonObject
        {
            ["allow_event_ids"] = new JsonArray(1102, 4624, 4625, 4698, 4732, 4733, 5001, 5010, 5012, 7036, 7040, 7045),
            ["families"] = new JsonObject { ["processes"] = false, ["usb"] = false },
        });
        var source = new RecordingSource();
        var module = new WorkstationsModule(Helpers.HostId, policy, source);
        CapturedPosition? position = null;
        for (var i = 0; i < 4; i++)
        {
            var sample = module.Collect(position, Helpers.Now).Sample!;
            position = new CapturedPosition(sample.Generation, sample.CursorAfter);
        }

        Assert.Equal(["Security", "System", "Microsoft-Windows-Windows Defender/Operational", "Security"], source.Channels);
    }

    [Fact]
    public void ProtectionSnapshotSurvivesWhenItsEventsAreFilteredOut()
    {
        var policy = WorkstationPolicy.Parse(new JsonObject
        {
            ["allow_event_ids"] = new JsonArray(4624),
            ["families"] = new JsonObject { ["processes"] = false, ["usb"] = false },
        });
        var source = new RecordingSource();
        var module = new WorkstationsModule(Helpers.HostId, policy, source);
        var security = module.Collect(null, Helpers.Now).Sample!;
        var protection = module.Collect(new CapturedPosition(security.Generation, security.CursorAfter), Helpers.Now).Sample!;

        Assert.Equal(["Security", "Microsoft-Windows-Windows Defender/Operational"], source.Channels);
        Assert.NotNull(protection.Payload["context"]?["workstations"]?["protection_state"]);
    }

    private static EventRow Native(int id, long recordId, string channel, string provider, params (string, string)[] fields)
    {
        System.Xml.Linq.XNamespace ns = EventXml.Namespace;
        var root = new System.Xml.Linq.XElement(ns + "Event",
            new System.Xml.Linq.XElement(ns + "System", new System.Xml.Linq.XElement(ns + "Provider", new System.Xml.Linq.XAttribute("Name", provider)),
                new System.Xml.Linq.XElement(ns + "EventID", id), new System.Xml.Linq.XElement(ns + "EventRecordID", recordId),
                new System.Xml.Linq.XElement(ns + "Channel", channel)),
            new System.Xml.Linq.XElement(ns + "EventData", fields.Select(f => new System.Xml.Linq.XElement(ns + "Data", new System.Xml.Linq.XAttribute("Name", f.Item1), f.Item2))));
        return new(root.ToString(), "bookmark-" + recordId);
    }

    [Theory]
    [InlineData(7036)]
    [InlineData(7040)]
    public void OnlyProtectionServicesAndExactPolicyNamesAreCollected(int id)
    {
        var source = new RowsSource([
            Native(id, 1, "System", "Service Control Manager", ("param1", "Spooler")),
            Native(id, 2, "System", "Service Control Manager", ("param1", "SLI Agent .NET")),
            Native(id, 3, "System", "Service Control Manager", ("param1", "Fixture Backup")),
            Native(id, 4, "System", "Service Control Manager", ("param1", "WinDefend-extra"))]);
        var policy = WorkstationPolicy.Parse(new JsonObject { ["protected_services"] = new JsonArray("Fixture Backup") });
        var sample = new WorkstationsModule(Helpers.HostId, policy, source).Collect(null, Helpers.Now, "System").Sample!;
        Assert.Equal(2, sample.Payload["records"]!.AsArray().Count);
        Assert.Equal(2, sample.FilteredCount);
        Assert.Equal("1.1.0", sample.ModuleVersion);
    }

    [Fact]
    public void SecurityLogClearUsesItsNativeEventlogProvider()
    {
        var source = new RowsSource([Native(1102, 1, "Security", "Microsoft-Windows-Eventlog"),
            Native(1102, 2, "Security", "Microsoft-Windows-Security-Auditing")]);
        var sample = new WorkstationsModule(Helpers.HostId, WorkstationPolicy.Parse(new()), source).Collect(null, Helpers.Now).Sample!;
        Assert.Single(sample.Payload["records"]!.AsArray());
        Assert.Equal(1, sample.FilteredCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NativeProcessCommandLineIsCollectedOnlyWhenEnabledAndBoundedBeforeSigning(bool includeCommand)
    {
        const string provider = "Microsoft-Windows-Security-Auditing";
        string original = "<&" + new string('界', 700);
        string expected = includeCommand ? original[..342] : "";
        var policy = WorkstationPolicy.Parse(new JsonObject { ["allow_event_ids"] = new JsonArray(4688, 6416) });
        var source = new RowsSource([
            Native(4688, 1, "Security", provider, ("CommandLine", original)),
            Native(6416, 2, "Security", provider, ("DeviceId", @"USBSTOR\Fixture")),
        ]);
        var collector = new WorkstationsModule(Helpers.HostId, policy, source, includeProcessCommandLine: includeCommand);
        var sample = collector.Collect(null, Helpers.Now).Sample!;
        var rows = sample.Payload["records"]!.AsArray();
        Assert.Equal(2, rows.Count);
        var process = rows[0]!["payload"]!;
        string xml = process["xml"]!.GetValue<string>();
        System.Xml.Linq.XNamespace ns = EventXml.Namespace;
        Assert.Equal(expected, Assert.Single(EventXml.ParseBounded(xml).Descendants(ns + "Data")).Value);
        Assert.Equal(includeCommand ? expected : null, process["properties"]![0]?.GetValue<string>());
        Assert.Equal(includeCommand, xml.Contains("&lt;&amp;", StringComparison.Ordinal));
        Assert.Equal(6416, rows[1]!["payload"]!["event_id"]!.GetValue<int>());
    }

    [Fact]
    public void WorkstationNativeFilterIncludesAssignedEventsAndKeepsTheSavedAnchor()
    {
        var policy = WorkstationPolicy.Parse(new JsonObject { ["allow_event_ids"] = new JsonArray(4624, 4688, 6416) });
        var query = EventQueries.BuildWorkstation("Security", new ChannelProgress(31, "saved", Helpers.HostId), policy);
        Assert.Contains("EventID=4624", query);
        Assert.Contains("EventID=4688", query);
        Assert.Contains("EventID=6416", query);
        Assert.Contains("EventRecordID=31", query);
        Assert.DoesNotContain("EventID=4625", query);
    }

    [Fact]
    public void ScriptQuotaCannotBeRaisedAndSurvivesRestart()
    {
        var channel = WorkstationPolicy.Channels[6];
        var policy = WorkstationPolicy.Parse(new JsonObject { ["rate_limits"] = new JsonObject { ["4104"] = 1000 } });
        var first = new WorkstationsModule(Helpers.HostId, policy, new RowsSource(Enumerable.Range(1, 12)
            .Select(i => Native(4104, i, channel, "Microsoft-Windows-PowerShell", ("ScriptBlockText", "fixture"))).ToList()))
            .Collect(null, Helpers.Now, channel).Sample!;
        Assert.Equal(10, first.Payload["records"]!.AsArray().Count);
        Assert.Equal(2, first.LostCount);
        var second = new WorkstationsModule(Helpers.HostId, policy, new RowsSource([Native(4104, 13, channel, "Microsoft-Windows-PowerShell", ("ScriptBlockText", "fixture"))]))
            .Collect(new(first.Generation, first.CursorAfter), Helpers.Now, channel).Sample!;
        Assert.Empty(second.Payload["records"]!.AsArray());
        Assert.Equal(1, second.LostCount);
        Assert.Equal("gap", second.ContinuityState);
    }

    [Theory]
    [InlineData("x")]
    [InlineData("Я")]
    [InlineData("😀")]
    [InlineData("<&\"")]
    public void LongScriptIsTruncatedInXmlAndProperties(string token)
    {
        var channel = WorkstationPolicy.Channels[6];
        var text = string.Concat(Enumerable.Repeat(token, 30000));
        var source = new RowsSource([Native(4104, 1, channel, "Microsoft-Windows-PowerShell", ("ScriptBlockText", text))]);
        var sample = new WorkstationsModule(Helpers.HostId, WorkstationPolicy.Parse(new()), source).Collect(null, Helpers.Now, channel).Sample!;
        var row = sample.Payload["records"]![0]!["payload"]!;
        System.Xml.Linq.XNamespace ns = EventXml.Namespace;
        var data = EventXml.ParseBounded(row["xml"]!.GetValue<string>()).Descendants(ns + "Data").ToDictionary(e => e.Attribute("Name")!.Value, e => e.Value);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(data["ScriptBlockText"]) <= 8192);
        Assert.StartsWith(data["ScriptBlockText"], text, StringComparison.Ordinal);
        Assert.Equal("true", data["ScriptBlockTextTruncated"]);
        Assert.Equal(data["ScriptBlockText"], row["properties"]![0]!.GetValue<string>());
        Assert.True(CanonicalJson.ToBytes(sample.Payload).Length < 44 * 1024);
    }

    public static TheoryData<string> Names()
    {
        var data = new TheoryData<string>();
        foreach (var item in Vectors.Load("workstations-scenarios.json").AsArray()) data.Add(item!["name"]!.GetValue<string>());
        return data;
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void ReproducesThePythonWorkstationCollector(string name)
    {
        var scenario = Vectors.Load("workstations-scenarios.json").AsArray().Single(item => item!["name"]!.GetValue<string>() == name)!;
        var source = new ScriptedSource();
        var module = new WorkstationsModule(scenario["host_id"]!.GetValue<string>(), WorkstationPolicy.Parse(scenario["config"]!.AsObject()), source);
        CapturedPosition? position = null;
        foreach (var step in scenario["steps"]!.AsArray())
        {
            source.Script = step!["reader"]!.AsObject();
            var result = module.Collect(position, Iso8601.ParseUtc(step["now"]!.GetValue<string>()));
            var sample = result.Sample!;
            Assert.Equal(step["payload_canonical"]!.GetValue<string>(), CanonicalJson.Serialize(sample.Payload));
            Assert.Equal(CanonicalJson.Serialize(step["cursor_before"]), CanonicalJson.Serialize(sample.CursorBefore.ToJson()));
            Assert.Equal(CanonicalJson.Serialize(step["cursor_after"]), CanonicalJson.Serialize(sample.CursorAfter.ToJson()));
            Assert.Equal(step["continuity_state"]!.GetValue<string>(), sample.ContinuityState);
            Assert.Equal(step["filtered_count"]!.GetValue<long>(), sample.FilteredCount);
            Assert.Equal(step["lost_count"]?.GetValue<long>(), sample.LostCount);
            Assert.Equal(step["catch_up_channel"]?.GetValue<string>(), result.CatchUpChannel);
            position = new(sample.Generation, sample.CursorAfter);
        }
    }
}
