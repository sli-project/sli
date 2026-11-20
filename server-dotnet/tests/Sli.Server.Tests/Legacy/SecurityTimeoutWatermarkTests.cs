using System.Text.Json.Nodes;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Legacy;

public sealed class SecurityTimeoutWatermarkTests
{
    private const string Archive = "2026-07-01T00:00:00+00:00";
    private const string Start = "2026-07-07T04:00:00+00:00";
    private static JsonObject Channel() => new() {
        ["channel"] = "Security", ["status"] = "partial_timeout", ["count"] = 1,
        ["batch_max_record_id"] = 200, ["start_time_utc"] = Start,
        ["error"] = "Channel timed out after 120 seconds; 1 partial events were saved."
    };

    [Fact]
    public void PartialTimeoutCountsAsCollectedWarningNotFailed()
    {
        // tests/core/test_security_timeout_watermark.py: exact mixed-channel vector.
        var status = LegacyCollectionSummary.SummarizeChannelStatus(JsonNode.Parse("""
            {"channels":[
                {"channel":"Security","status":"partial_timeout","count":10,"error":"timeout with partial data"},
                {"channel":"System","status":"completed","count":2,"error":null}
            ]}
            """)!.AsObject());
        Assert.Equal(1, status.Number("channels_completed"));
        Assert.Equal(1, status.Number("channels_partial"));
        Assert.Equal(0, status.Number("channels_failed"));
        Assert.Equal(1, status.Number("channels_timeout"));
        Assert.Equal(12, status.Number("events_collected"));
        Assert.False(status.Flag("all_failed"));
        Assert.False(status.Flag("partial_failed"));
        Assert.True(status.Flag("partial_warning"));
        Assert.Empty(status["errors"]!.AsArray());
        Assert.Equal("Security: timeout with partial data", Assert.Single(status["warnings"]!.AsArray())!.GetValue<string>());
    }

    [Theory]
    [InlineData(0, null, null, 0, 1, 0, true)]
    [InlineData(1, "failure", null, 0, 1, 0, true)]
    [InlineData(1, null, false, 0, 1, 0, true)]
    [InlineData(1, null, true, 1, 0, 1, false)]
    public void EmptyOrBrokenPartialIsNotCollected(long count, string? kind, bool? allowed,
        long partial, long failed, long events, bool allFailed)
    {
        var channel = Channel(); channel["count"] = count; channel["partial_kind"] = kind; channel["cursor_commit_allowed"] = allowed;
        var status = LegacyCollectionSummary.SummarizeChannelStatus(new() { ["channels"] = new JsonArray(channel) });
        Assert.Equal(partial, status.Number("channels_partial")); Assert.Equal(failed, status.Number("channels_failed"));
        Assert.Equal(events, status.Number("events_collected")); Assert.Equal(allFailed, status.Flag("all_failed"));
        Assert.Equal(partial > 0, status.Flag("partial_warning"));
    }

    [Fact]
    public async Task RetiredPartialTimeoutWriterRejectsEvenConfirmedImport()
    {
        var watermark = new LegacyPartialTimeoutWatermark(new UnusedDatabase());
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            watermark.CommitAsync("fixture", Archive, Start, Channel(), 1, 0, TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled", error.Message);
    }

    private sealed class UnusedDatabase : ISemanticDatabase
    {
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) =>
            throw new InvalidOperationException("Retired partial timeout writer accessed the database.");
    }
}
