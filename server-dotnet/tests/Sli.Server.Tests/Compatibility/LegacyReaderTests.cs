using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Sli.Server.Access;
using Sli.Server.Compatibility;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Compatibility;

public sealed class LegacyReaderTests
{
    sealed class Events : IEventReadService
    {
        internal int Reads;
        internal bool Missing;
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<AccessResource>>([new("server", 1)]);
        public async Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids, bool exact,
            Func<long,CancellationToken,Task<bool>> admitted, CancellationToken ct)
        {
            Reads++;
            Assert.True(exact);
            Assert.True(await admitted(7, ct));
            return Missing ? [] : new() { [7] = new JsonObject { ["id"] = 7, ["event_id"] = 4624 } };
        }
        public Task<JsonObject> RelationsAsync(long id, Func<long,CancellationToken,Task<bool>> admitted, CancellationToken ct)
            => throw new InvalidOperationException("unexpected_relation_read");
    }

    [Theory]
    [InlineData("/api/events/search")]
    [InlineData("/api/events/search/deep")]
    [InlineData("/api/events/timeline")]
    [InlineData("/api/events/summary")]
    [InlineData("/api/entities/details")]
    [InlineData("/api/entities/summary")]
    [InlineData("/api/security/events-monitor")]
    [InlineData("/reports/security-events-monitor.csv")]
    [InlineData("/api/ai/prompt-preview")]
    [InlineData("/api/ai/redaction-preview")]
    [InlineData("/api/ai/runs")]
    [InlineData("/reports/ai-analysis.html")]
    public async Task Retired_modules_do_not_read_events_or_release_payload(string path)
    {
        var events = new Events();
        var reader = new LegacyHttpReader(events, NullLogger<LegacyHttpReader>.Instance);
        var error = await Assert.ThrowsAsync<LegacyInputException>(() => reader.ReadAsync(path,
            new(new JsonObject { ["q"] = "untrusted'; drop table event_hot; --", ["redaction_level"] = "off" }), TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled", error.Message);
        Assert.Equal(503, error.Status);
        Assert.Equal(0, events.Reads);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Exact_detail_keeps_one_owner_and_never_falls_back(bool missing)
    {
        var events = new Events { Missing = missing };
        var reader = new LegacyHttpReader(events, NullLogger<LegacyHttpReader>.Instance);
        var query = new LegacyQuery(new JsonObject { ["event_db_id"] = 7 });
        if (missing) {
            var error = await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReadAsync("/api/events/details", query, TestContext.Current.CancellationToken));
            Assert.Equal("event_not_found", error.Message);
        }
        else {
            var result = await reader.ReadAsync("/api/events/details", query, TestContext.Current.CancellationToken);
            Assert.Equal(7, Assert.Single(result["items"]!.AsArray())!["id"]!.GetValue<int>());
        }
        Assert.Equal(1, events.Reads);
    }

    [Fact]
    public async Task Type_filter_cannot_replace_exact_event_identity()
    {
        var events = new Events();
        var reader = new LegacyHttpReader(events, NullLogger<LegacyHttpReader>.Instance);
        await Assert.ThrowsAsync<InvalidOperationException>(() => reader.ReadAsync("/api/events/details",
            new(new JsonObject { ["event_id"] = 4624 }), TestContext.Current.CancellationToken));
        Assert.Equal(0, events.Reads);
    }

    [Fact]
    public async Task Compatibility_rows_cannot_reopen_retired_history()
    {
        using var rows = new PostgresLegacyRows(null!);
        var error = await Assert.ThrowsAsync<LegacyInputException>(() => rows.HistoryAsync("untrusted", new Dictionary<string,string>(), TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled", error.Message);
        error = await Assert.ThrowsAsync<LegacyInputException>(() => rows.HistoryEventsAsync([7], TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled", error.Message);
    }

    [Fact]
    public void Retained_redaction_masks_accounts_hosts_and_addresses_and_blocks_leaks()
    {
        var redaction = new AiPreviewRedaction("strict");
        var source = new JsonObject { ["server"] = "dc01.example.test", ["target_user_name"] = "fixture-account",
            ["ip_address"] = "192.0.2.13", ["workstation_name"] = "WS01", ["time_created_utc"] = "2026-11-01T00:00:00Z" };
        var row = redaction.Event(source, null);
        foreach (string value in new[] { "dc01.example.test", "fixture-account", "192.0.2.13", "WS01" })
            Assert.DoesNotContain(value, row.ToJsonString());
        Assert.True(AiPreviewRedaction.Leaks(new JsonObject { ["text"] = "fixture.example.test 192.0.2.13" }, "strict")["blocked"]!.GetValue<bool>());
        Assert.False(AiPreviewRedaction.Leaks(row, "strict")["blocked"]!.GetValue<bool>());
    }
}

