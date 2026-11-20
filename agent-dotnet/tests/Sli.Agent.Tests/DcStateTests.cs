using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Xunit;

namespace Sli.Agent.Tests;

public class DcStateTests
{
    private static readonly EventCatalog Catalog = EventCatalog.Load();

    private static void Invalid(string token) =>
        Assert.Equal("agent_ad_dc_cursor_invalid", Assert.Throws<AgentException>(() => DcCursor.Parse(new Cursor("bookmark", token))).Code);

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{\"next\":0}")]
    [InlineData("{\"next\":6,\"channels\":{}}")]
    [InlineData("{\"next\":-1,\"channels\":{}}")]
    [InlineData("{\"next\":0,\"channels\":{},\"extra\":1}")]
    [InlineData("{\"next\":0,\"channels\":{\"Application\":{\"record_id\":1,\"bookmark\":\"b\",\"generation\":\"g\"}}}")]
    [InlineData("{\"next\":0,\"channels\":{\"Security\":{\"record_id\":0,\"bookmark\":\"b\",\"generation\":\"g\"}}}")]
    [InlineData("{\"next\":0,\"channels\":{\"Security\":{\"record_id\":1,\"bookmark\":\"\",\"generation\":\"g\"}}}")]
    [InlineData("{\"next\":0,\"channels\":{\"Security\":{\"record_id\":null,\"bookmark\":\"b\",\"generation\":\"g\"}}}")]
    [InlineData("{\"next\":0,\"channels\":{\"Security\":{\"record_id\":1,\"bookmark\":\"b\",\"generation\":\"\"}}}")]
    [InlineData("{\"next\":0,\"channels\":{\"Security\":{\"record_id\":1,\"bookmark\":\"b\",\"generation\":\"g\",\"junk\":1}}}")]
    [InlineData("{\"next\":0,\"channels\":{\"Security\":{\"record_id\":1,\"bookmark\":\"b\",\"generation\":\"g\",\"since_utc\":\"yesterday\"}}}")]
    [InlineData("{\"next\":0,\"channels\":{\"Security\":{\"record_id\":1,\"bookmark\":\"b\",\"generation\":\"g\",\"complete\":true}}}")]
    public void RefusesMalformedCursors(string token) => Invalid(token);

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    public void EveryRotationIndexOfTheCurrentChannelsStaysValid(int next) =>
        Assert.Equal(next, DcCursor.Parse(new Cursor("bookmark", "{\"channels\":{},\"next\":" + next + "}")).Next);

    [Fact]
    public void RefusesAnotherStrategy() =>
        Assert.Equal("agent_ad_dc_cursor_invalid", Assert.Throws<AgentException>(() => DcCursor.Parse(new Cursor("record_id", string.Empty))).Code);

    [Fact]
    public void AnEmptyTokenIsTheStartOfTheStream()
    {
        var start = DcCursor.Parse(Cursor.Start("bookmark"));
        Assert.Equal(0, start.Next);
        Assert.Empty(start.Progress);
    }

    [Fact]
    public void ATokenOverTheLimitIsRefusedBeforeItIsSigned()
    {
        var state = new DcCursor { Next = 1 };
        state.Progress["Security"] = new ChannelProgress(1, new string('b', 2048), new string('g', 128));
        state.Progress["System"] = new ChannelProgress(1, new string('b', 2048), new string('g', 128));
        Assert.Equal("agent_ad_dc_cursor_size_limit", Assert.Throws<AgentException>(state.ToCursor).Code);
    }

    [Fact]
    public void RoundTripsEveryOptionalField()
    {
        var state = new DcCursor { Next = 2 };
        state.Progress["System"] = new ChannelProgress(9, "b", "g", "2026-10-07T00:00:00+00:00", "2026-10-08T00:00:00+00:00", true);
        var again = DcCursor.Parse(state.ToCursor());
        Assert.Equal(state.Progress["System"], again.Progress["System"]);
        Assert.Equal(2, again.Next);
    }

    private static AgentException Config(JsonObject config) => Assert.Throws<AgentException>(() => AdDcConfig.Parse(config, Catalog));

    private static JsonObject Valid() => new() { ["source_name"] = "fixture-dc", ["connect_address"] = "fixture-endpoint" };

    [Fact]
    public void APolicySignedWithTheOriginalThreeChannelsKeepsRotatingOverThemOnly()
    {
        var config = Valid();
        config["channels"] = new JsonObject { ["Security"] = true, ["System"] = true, ["Directory Service"] = true };
        var parsed = AdDcConfig.Parse(config, Catalog);
        Assert.Equal(["Security", "System", "Directory Service"], parsed.RotationChannels);
        Assert.Equal(3, parsed.ToJson()["channels"]!.AsObject().Count);
    }

    [Fact]
    public void APolicyWithoutChannelsRotatesOverEverySupportedChannel()
    {
        var parsed = AdDcConfig.Parse(Valid(), Catalog);
        Assert.Equal(DcCursor.Channels, parsed.RotationChannels);
    }

    [Fact]
    public void ADefaultConfigHasTheDocumentedDefaults()
    {
        var config = AdDcConfig.Parse(Valid(), Catalog);
        Assert.Equal(32, config.BatchSize);
        Assert.Equal("1", config.PolicyRevision);
        Assert.Equal(24, config.InitialReadHours);
        Assert.Null(config.AllowEventIds);
        Assert.All(DcCursor.Channels, channel => Assert.True(config.Channels[channel]));
        var forty = Valid();
        forty["initial_read_hours"] = 48;
        Assert.Equal(48, AdDcConfig.Parse(forty, Catalog).InitialReadHours);
        var all = Valid();
        all["initial_read_hours"] = "all";
        Assert.Null(AdDcConfig.Parse(all, Catalog).InitialReadHours);
    }

    [Theory]
    [InlineData("missing-source")]
    [InlineData("blank-source")]
    [InlineData("unknown-key")]
    [InlineData("batch-zero")]
    [InlineData("batch-129")]
    [InlineData("batch-text")]
    [InlineData("hours-negative")]
    [InlineData("hours-text")]
    [InlineData("generation-unknown-channel")]
    [InlineData("generation-blank")]
    [InlineData("channels-not-bool")]
    [InlineData("channels-unknown")]
    [InlineData("allow-unknown-id")]
    [InlineData("allow-not-list")]
    [InlineData("allow-too-long")]
    public void RefusesInvalidConfiguration(string kind)
    {
        var config = Valid();
        switch (kind)
        {
            case "missing-source": config.Remove("source_name"); break;
            case "blank-source": config["source_name"] = "  "; break;
            case "unknown-key": config["extra"] = 1; break;
            case "batch-zero": config["batch_size"] = 0; break;
            case "batch-129": config["batch_size"] = 129; break;
            case "batch-text": config["batch_size"] = "32"; break;
            case "hours-negative": config["initial_read_hours"] = -1; break;
            case "hours-text": config["initial_read_hours"] = "none"; break;
            case "generation-unknown-channel": config["channel_generations"] = new JsonObject { ["Application"] = "g" }; break;
            case "generation-blank": config["channel_generations"] = new JsonObject { ["Security"] = "" }; break;
            case "channels-not-bool": config["channels"] = new JsonObject { ["Security"] = "yes" }; break;
            case "channels-unknown": config["channels"] = new JsonObject { ["Application"] = true }; break;
            case "allow-unknown-id": config["allow_event_ids"] = new JsonArray(99999); break;
            case "allow-not-list": config["allow_event_ids"] = 4624; break;
            case "allow-too-long": config["allow_event_ids"] = new JsonArray(Enumerable.Range(0, 513).Select(_ => (JsonNode?)4624).ToArray()); break;
        }
        Assert.Equal("agent_ad_dc_config_invalid", Config(config).Code);
    }
}
