using System.Security;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class EventValueCollectionTests
{
    private const string DefenderChannel = "Microsoft-Windows-Windows Defender/Operational";
    private static readonly EventCatalog Catalog = EventCatalog.Load();
    private static JsonArray Table => JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "event_storage_meanings.json")))!["events"]!.AsArray();

    public static TheoryData<string, string, int, bool, string> Events()
    {
        var cases = new TheoryData<string, string, int, bool, string>();
        foreach (var row in Table)
        {
            string channel = row!["channel"]!.GetValue<string>();
            if (channel == DefenderChannel) continue;
            cases.Add(channel, row["provider"]!.GetValue<string>(), row["event_id"]!.GetValue<int>(),
                row["layer"]!.GetValue<string>() != "not_collected", row["replication_rights"]?[0]?.GetValue<string>() ?? "");
        }
        return cases;
    }

    public static TheoryData<string, int, bool> DefenderEvents()
    {
        var cases = new TheoryData<string, int, bool>();
        foreach (var row in Table)
        {
            if (row!["channel"]!.GetValue<string>() != DefenderChannel) continue;
            cases.Add(row["provider"]!.GetValue<string>(), row["event_id"]!.GetValue<int>(),
                row["layer"]!.GetValue<string>() != "not_collected");
        }
        return cases;
    }

    [Theory]
    [MemberData(nameof(Events))]
    public void CollectsOnlyTableEventsAndAdvancesCursor(string channel, string provider, int id, bool collect, string rights)
    {
        var sample = Collect(channel, provider, id, rights);
        Assert.Equal(collect ? 1 : 0, sample.Payload["records"]!.AsArray().Count);
        Assert.Equal(collect ? 0 : 1, sample.FilteredCount);
        Assert.Equal(1, DcCursor.Parse(sample.CursorAfter).Progress[channel].RecordId);
    }

    [Theory]
    [MemberData(nameof(DefenderEvents))]
    public void DefenderEventsUseWorkstationsAndAreUnavailableToAdDc(string provider, int id, bool collect)
    {
        var source = CreateSource(DefenderChannel, provider, id, "", "Properties");
        var module = new WorkstationsModule(Helpers.HostId, WorkstationPolicy.Parse(new()), source);
        var sample = module.Collect(null, Helpers.Now, DefenderChannel).Sample!;
        Assert.Equal(collect ? 1 : 0, sample.Payload["records"]!.AsArray().Count);
        Assert.Equal(collect ? 0 : 1, sample.FilteredCount);
        var progress = JsonNode.Parse(sample.CursorAfter.Token)!["channels"]![DefenderChannel]!;
        Assert.Equal(1L, progress["record_id"]!.GetValue<long>());
        Assert.Equal("fixture-bookmark", progress["bookmark"]!.GetValue<string>());

        var denied = Assert.Throws<AgentException>(() => Collect(DefenderChannel, provider, id));
        Assert.Equal("agent_ad_dc_channel_invalid", denied.Code);
    }

    [Theory]
    [InlineData("Security", "Microsoft-Windows-Security-Auditing", 65535)]
    [InlineData("Security", "OtherProvider", 4624)]
    [InlineData("System", "Microsoft-Windows-Security-Auditing", 4624)]
    public void RejectsUnknownIdentities(string channel, string provider, int id)
        => Assert.Empty(Collect(channel, provider, id).Payload["records"]!.AsArray());

    [Theory]
    [InlineData("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")]
    [InlineData("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")]
    [InlineData("89e95b76-444d-4c62-991a-0facbeda640c")]
    public void Sends4662WithAnyReplicationRight(string guid)
    {
        var sample = Collect("Security", "Microsoft-Windows-Security-Auditing", 4662, $"%%7688\n{{{guid.ToUpperInvariant()}}}");
        Assert.Single(sample.Payload["records"]!.AsArray());
        Assert.Equal(0, sample.FilteredCount);
    }

    [Theory]
    [InlineData("", "Properties")]
    [InlineData("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Properties")]
    [InlineData("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "ObjectName")]
    [InlineData("01131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "Properties")]
    public void Drops4662WithoutAnExactReplicationRightInProperties(string value, string field)
    {
        var sample = Collect("Security", "Microsoft-Windows-Security-Auditing", 4662, value, field);
        Assert.Empty(sample.Payload["records"]!.AsArray());
        Assert.Equal(1, sample.FilteredCount);
        Assert.Equal(1, DcCursor.Parse(sample.CursorAfter).Progress["Security"].RecordId);
    }

    [Fact]
    public void AnOldPolicyCannotEnableNotCollectedEvents()
        => Assert.Empty(Collect("Security", "Microsoft-Windows-Security-Auditing", 4634, allow: new JsonArray(4634)).Payload["records"]!.AsArray());

    [Theory]
    [InlineData(4103)]
    [InlineData(4104)]
    public void CollectsPowerShellTextFromTheSharedTable(int id)
    {
        var sample = Collect("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", id,
            "<synthetic> ' ; --", id == 4104 ? "ScriptBlockText" : "Payload");
        Assert.Single(sample.Payload["records"]!.AsArray());
        Assert.Equal(0, sample.FilteredCount);
    }

    [Fact]
    public void PolicyMayNarrowTheTable()
        => Assert.Empty(Collect("Security", "Microsoft-Windows-Security-Auditing", 4624, allow: new JsonArray(4625)).Payload["records"]!.AsArray());

    internal static Sample Collect(string channel, string provider, int id, string value = "", string field = "Properties", JsonArray? allow = null)
    {
        var config = AdDcConfig.Parse(new JsonObject { ["source_name"] = "dc.example.test", ["connect_address"] = "dc.example.test", ["allow_event_ids"] = allow }, Catalog);
        var source = CreateSource(channel, provider, id, value, field);
        return new AdDcModule(Helpers.HostId, config, source, Catalog).Collect(null, Helpers.Now, channel).Sample!;
    }

    private static ScriptedSource CreateSource(string channel, string provider, int id, string value, string field)
        => new() { Script = new JsonObject { ["mode"] = "rows", ["rows"] = new JsonArray(new JsonObject {
            ["xml"] = $"""
                <Event xmlns="{EventXml.Namespace}"><System><Provider Name="{provider}"/><EventID>{id}</EventID>
                <EventRecordID>1</EventRecordID><Channel>{channel}</Channel><Computer>dc.example.test</Computer>
                <TimeCreated SystemTime="2026-10-07T11:00:00Z"/></System>
                <EventData><Data Name="{field}">{SecurityElement.Escape(value)}</Data></EventData></Event>
                """, ["bookmark"] = "fixture-bookmark" }) } };
}
