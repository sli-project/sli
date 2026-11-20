using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Domains;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class HomeTrendsTests
{
    private static JsonObject Measurement(double value = 4, bool previous = false) => new()
    {
        ["value"] = value, ["scope"] = new JsonObject { ["domain_ids"] = new JsonArray(7) },
        ["time_zone"] = "UTC", ["unit"] = "events", ["definition_version"] = 1,
        ["coverage"] = new JsonObject { ["sources"] = new JsonArray(7), ["complete"] = true },
        ["window"] = JsonNode.Parse(previous
            ? """{"from_utc":"2026-09-30T00:00:00Z","to_utc":"2026-10-01T00:00:00Z"}"""
            : """{"from_utc":"2026-10-01T00:00:00Z","to_utc":"2026-10-02T00:00:00Z"}""")
    };

    private static void Comparison(JsonObject actual, string expected) =>
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected), actual), actual.ToJsonString());

    [Fact]
    public void MissingBaselineHasNoInventedChange() => Comparison(HomeTrends.Compare(Measurement(), null),
        """{"state":"missing","message_code":"home.comparison.missing","absolute_change":null,"percent_change":null,"tone":"neutral"}""");

    [Fact]
    public void ZeroBaselineUsesAbsoluteChange() => Comparison(HomeTrends.Compare(Measurement(), Measurement(0, previous: true)),
        """{"state":"comparable","message_code":"home.comparison.absolute","absolute_change":4,"percent_change":null,"tone":"neutral"}""");

    [Theory]
    [InlineData(4, "lower_is_better", "danger", 2, 100)]
    [InlineData(4, "higher_is_better", "success", 2, 100)]
    [InlineData(1, "lower_is_better", "success", -1, -50)]
    [InlineData(1, "higher_is_better", "danger", -1, -50)]
    [InlineData(4, "neutral", "neutral", 2, 100)]
    [InlineData(2, "lower_is_better", "neutral", 0, 0)]
    [InlineData(2.5, "neutral", "neutral", 0.5, 25)]
    public void ComparableChangeRespectsMeaning(double value, string meaning, string tone, double change, double percent)
    {
        var result = HomeTrends.Compare(Measurement(value), Measurement(2, previous: true), meaning);
        Assert.Equal("comparable", (string?)result["state"]);
        Assert.Equal("home.comparison.percent", (string?)result["message_code"]);
        Assert.Equal(tone, (string?)result["tone"]);
        Assert.Equal(change, (double)result["absolute_change"]!);
        Assert.Equal(percent, (double)result["percent_change"]!);
    }

    [Theory]
    [InlineData("scope", """{"domain_ids":[8]}""")]
    [InlineData("time_zone", "\"Asia/Bangkok\"")]
    [InlineData("unit", "\"accounts\"")]
    [InlineData("definition_version", "2")]
    [InlineData("coverage", """{"sources":[8],"complete":true}""")]
    [InlineData("coverage", "{}")]
    [InlineData("window", """{"from_utc":"2026-09-29T00:00:00Z","to_utc":"2026-10-01T00:00:00Z"}""")]
    public void ChangedMeasurementContractIsIncomparable(string key, string json)
    {
        var previous = Measurement(2, previous: true); previous[key] = JsonNode.Parse(json);
        Comparison(HomeTrends.Compare(Measurement(), previous),
            """{"state":"incomparable","message_code":"home.comparison.incomparable","absolute_change":null,"percent_change":null,"tone":"neutral"}""");
    }

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("\"4\"")]
    [InlineData("-1")]
    public void NonMeasurementsNeverBecomeZeroBaselines(string json)
    {
        var current = Measurement(); var previous = Measurement(2, previous: true);
        previous["value"] = JsonNode.Parse(json);
        Assert.Equal("missing", (string?)HomeTrends.Compare(current, previous)["state"]);
        current["value"] = JsonNode.Parse(json);
        Assert.Equal("missing", (string?)HomeTrends.Compare(current, Measurement(2, previous: true))["state"]);
    }

    [Fact]
    public void MatchingButIncompleteCoverageIsIncomparable()
    {
        var current = Measurement(); var previous = Measurement(2, previous: true);
        current["coverage"]!["complete"] = false;
        previous["coverage"]!["complete"] = false;
        Assert.Equal("incomparable", (string?)HomeTrends.Compare(current, previous)["state"]);
    }

    [Theory]
    [InlineData("""{"from_utc":"2026-09-29T00:00:00Z","to_utc":"2026-09-30T00:00:00Z"}""")]
    [InlineData("""{"from_utc":"2026-10-01T00:00:00Z","to_utc":"2026-09-30T00:00:00Z"}""")]
    [InlineData("""{"from_utc":"2026-09-30T00:00:00","to_utc":"2026-10-01T00:00:00"}""")]
    [InlineData("{}")]
    public void NonAdjacentReversedOrMalformedWindowsAreIncomparable(string window)
    {
        var previous = Measurement(2, previous: true); previous["window"] = JsonNode.Parse(window);
        Assert.Equal("incomparable", (string?)HomeTrends.Compare(Measurement(), previous)["state"]);
    }

    private static HomeSummaryQuery Query(string query, string now)
    {
        var context = new DefaultHttpContext(); context.Request.QueryString = new QueryString(query);
        return HomeSummaryQuery.Parse(context.Request.Query, DateTimeOffset.Parse(now));
    }

    private static void Window(HomeWindow window, string from, string to)
    {
        Assert.Equal(DateTimeOffset.Parse(from), window.From);
        Assert.Equal(DateTimeOffset.Parse(to), window.To);
    }

    [Fact]
    public void CurrentUsesLastCompletedBangkokDay()
    {
        var query = Query("?contract=v2&period=current&tz=Asia/Bangkok", "2026-10-07T08:30:00Z");
        Window(query.Current, "2026-10-05T17:00:00Z", "2026-10-06T17:00:00Z");
        Window(query.Previous, "2026-10-04T17:00:00Z", "2026-10-05T17:00:00Z");
        Assert.True(query.WindowComplete);
    }

    [Fact]
    public void CustomTimestampBoundsRemainExactAndExclusive()
    {
        var query = Query("?contract=v2&period=custom&from=2026-10-05T02:00:00Z&to=2026-10-07T08:30:00Z&tz=Asia/Bangkok", "2026-10-07T08:30:00Z");
        Window(query.Current, "2026-10-05T02:00:00Z", "2026-10-07T08:30:00Z");
        Window(query.Previous, "2026-10-02T19:30:00Z", "2026-10-05T02:00:00Z");
        Assert.True(query.WindowComplete);
    }

    private sealed class NoReads : IHomeSummaryRepository
    {
        public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct) =>
            throw new InvalidOperationException("Incomplete windows must not read observations");
    }

    [Fact]
    public async Task FutureCustomEndReportsIncompleteInsteadOfComparing()
    {
        var query = Query("?contract=v2&period=custom&from=2026-10-07T00:00:00Z&to=2026-10-08T00:00:00Z&tz=UTC", "2026-10-07T08:30:00Z");
        Assert.False(query.WindowComplete);
        var reads = new HomeSummaryReaders(new NoReads());
        foreach (var result in new[] { await reads.Changes([7], query, TestContext.Current.CancellationToken),
            await reads.Vpn(7, query, TestContext.Current.CancellationToken) })
        {
            Assert.Equal("partial", (string?)result["state"]);
            Assert.Equal("home_window_incomplete", (string?)result["reason"]);
        }
    }

    [Fact]
    public void CompletedLocalDaysStayComparableAcrossSpringDst()
    {
        var query = Query("?contract=v2&period=24h&tz=America/New_York", "2026-03-09T12:00:00Z");
        Window(query.Current, "2026-03-08T05:00:00Z", "2026-03-09T04:00:00Z");
        Window(query.Previous, "2026-03-07T05:00:00Z", "2026-03-08T05:00:00Z");
        var current = Measurement(); var previous = Measurement(2, previous: true);
        current["time_zone"] = "America/New_York";
        previous["time_zone"] = "America/New_York";
        current["window"] = System.Text.Json.JsonSerializer.SerializeToNode(query.Current.Json());
        previous["window"] = System.Text.Json.JsonSerializer.SerializeToNode(query.Previous.Json());
        Assert.Equal("comparable", (string?)HomeTrends.Compare(current, previous)["state"]);
    }
}
