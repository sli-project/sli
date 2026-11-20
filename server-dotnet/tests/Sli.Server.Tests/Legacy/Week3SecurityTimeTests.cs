using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Legacy;

public sealed class Week3SecurityTimeTests
{
    private sealed class Acquisition : ILegacyAcquisition
    {
        public LegacyJobInput? Input;
        public Task<LegacyCollectionBatch> CollectAsync(LegacyJobInput input, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Input = input;
            var summary = new JsonObject {
                ["collection_mode"] = "per_channel_record_id", ["requested_collection_mode"] = input.CollectionRequests[0].CollectionMode,
                ["channels"] = new JsonArray(new JsonObject { ["channel"] = "Security", ["status"] = "completed", ["count"] = 0,
                    ["cursor_strategy"] = "time_window_fallback", ["cursor_fallback_reason"] = "latest_record_id_before_saved_cursor" })
            };
            return Task.FromResult(new LegacyCollectionBatch("completed", [], CollectorRuns: [new(input.Servers[0], summary, new())]));
        }
    }

    [Fact]
    public async Task Runner_passes_recovery_request_and_commits_empty_channel_history_to_Postgres()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await using (var seed = new NpgsqlCommand("""
            insert into collector_adaptive_state(server,channel,current_limit,consecutive_completed,recovery_mode)
            values('DC1','Security',500,0,true)
            """, db)) await seed.ExecuteNonQueryAsync(ct);
        var acquisition = new Acquisition();
        var runner = new LegacyJobExecution(new(), Settings(), null!, null!, acquisition, null!, null!, NullLogger<LegacyJobExecution>.Instance);
        var result = await runner.CollectBatchAsync(new(["DC1"], 1, 500), 11, db, ct);
        Assert.Equal("completed", result.Status);
        var request = Assert.Single(acquisition.Input!.CollectionRequests);
        Assert.Equal(1, acquisition.Input.Hours); Assert.Equal(500, acquisition.Input.MaxEvents);
        Assert.Equal("recovery", request.CollectionMode); Assert.Equal("false", request.CollectMessage); Assert.Equal(["Security"], request.Channels);
        await using var command = new NpgsqlCommand("""
            select job_id,server,channel,count,inserted,skipped,collection_mode,requested_collection_mode,cursor_strategy,cursor_fallback_reason
            from collector_channel_runs where job_id=11
            """, db);
        await using (var rows = await command.ExecuteReaderAsync(ct)) {
            Assert.True(await rows.ReadAsync(ct)); Assert.Equal(11, rows.GetInt64(0)); Assert.Equal("DC1", rows.GetString(1)); Assert.Equal("Security", rows.GetString(2));
            Assert.Equal(0, rows.GetInt64(3)); Assert.Equal(0, rows.GetInt64(4)); Assert.Equal(0, rows.GetInt64(5));
            Assert.Equal("per_channel_record_id", rows.GetString(6)); Assert.Equal("recovery", rows.GetString(7));
            Assert.Equal("time_window_fallback", rows.GetString(8)); Assert.Equal("latest_record_id_before_saved_cursor", rows.GetString(9));
            Assert.False(await rows.ReadAsync(ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static LegacySettings Settings(string mode = "auto", string? message = null) => new(
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:Legacy:ADLOG_COLLECTION_MODE"] = mode,
            ["Sli:Legacy:ADLOG_COLLECT_MESSAGE"] = message
        }).Build());

    [Fact]
    public void Empty_security_run_keeps_effective_requested_mode_and_cursor_fallback()
    {
        var run = new LegacyCollectorRun("DC1", JsonNode.Parse("""
            {"finished_at":"2026-07-07T03:00:00Z","collection_mode":"per_channel_record_id","requested_collection_mode":"recovery",
             "channels":[{"channel":"Security","status":"completed","count":0,"max_events":500,"timeout_seconds":900,
               "started_at":"2026-07-07T02:00:00Z","cursor_strategy":"time_window_fallback",
               "cursor_fallback_reason":"latest_record_id_before_saved_cursor"}]}
            """)!.AsObject(), new() { ["Security"] = new JsonObject { ["inserted"] = 0, ["skipped"] = 0 } });
        using var command = Assert.Single(run.Commands(11));
        Assert.StartsWith("insert into collector_channel_runs(", command.CommandText);
        object? P(string name) => command.Parameters[name].Value;
        Assert.Equal(11L, P("job_id")); Assert.Equal("DC1", P("server")); Assert.Equal("Security", P("channel"));
        Assert.Equal(0L, P("count")); Assert.Equal(0L, P("inserted")); Assert.Equal(0L, P("skipped"));
        Assert.Equal("completed", P("status"));
        Assert.Equal("per_channel_record_id", P("collection_mode")); Assert.Equal("recovery", P("requested_collection_mode"));
        Assert.Equal("time_window_fallback", P("cursor_strategy"));
        Assert.Equal("latest_record_id_before_saved_cursor", P("cursor_fallback_reason"));
        Assert.Equal("2026-07-07T03:00:00Z", P("finished_utc"));
        Assert.Equal(900, P("timeout_seconds")); Assert.Equal(500, P("limit_used"));
        Assert.Equal(0, command.CommandTimeout);
    }

    [Fact]
    public void Channel_history_skips_unnamed_channels_and_does_not_reuse_another_channels_metadata()
    {
        var run = new LegacyCollectorRun("dc.example.test", JsonNode.Parse("""
            {"collection_mode":"current","channels":[{},
             {"channel":"Security","status":"partial_timeout","count":3,"cursor_strategy":"record_id"},
             {"channel":"System","status":"completed","count":0}]}
            """)!.AsObject(), new());
        var commands = run.Commands(12).ToArray();
        try {
            Assert.Equal(2, commands.Length);
            Assert.Equal(3L, commands[0].Parameters["partial_count"].Value);
            Assert.Equal("System", commands[1].Parameters["channel"].Value);
            Assert.Equal(DBNull.Value, commands[1].Parameters["cursor_strategy"].Value);
            Assert.Equal(DBNull.Value, commands[1].Parameters["requested_collection_mode"].Value);
        }
        finally { foreach (var command in commands) command.Dispose(); }
    }

    [Fact]
    public void Recovery_request_preserves_security_channel_and_skips_message_by_default()
    {
        var request = LegacyCollectionRequest.Create("DC1", ["Security"], true, Settings());
        Assert.Equal("recovery", request.CollectionMode); Assert.Equal("false", request.CollectMessage);
        Assert.Equal(["Security"], request.Channels); Assert.Equal("DC1", request.Server);
    }

    [Theory]
    [InlineData(false, "auto", "current")]
    [InlineData(true, "invalid", "recovery")]
    [InlineData(true, " current ", "current")]
    [InlineData(false, "BACKFILL", "backfill")]
    [InlineData(false, "recovery", "recovery")]
    public void Explicit_collection_mode_overrides_adaptive_mode(bool recovery, string configured, string expected)
    {
        var request = LegacyCollectionRequest.Create("dc.example.test", ["Security"], recovery, Settings(configured, "true"));
        Assert.Equal(expected, request.CollectionMode); Assert.Equal("true", request.CollectMessage);
    }

    [Fact]
    public void Time_format_supports_local_context_and_offsets()
    {
        const string offset = "2026-07-07T02:34:28.9127653+03:00";
        Assert.Equal("06.07.2026 23:34:28 UTC", ReportTime.Event(offset));
        Assert.Equal("06.07.2026 23:34:28 UTC", LegacySemantics.Display(JsonValue.Create(offset)));
        Assert.Equal("07.07.2026 05:34:28 Europe/Moscow", ReportTime.Report("2026-07-07T02:34:28.9127653Z", "Europe/Moscow"));
        var context = ReportTime.WithContext("2026-07-07T02:34:28Z", "Europe/Moscow", "local");
        Assert.Equal("07.07.2026 05:34:28 Europe/Moscow", context["display"]!.ToString());
        Assert.Equal("2026-07-07T02:34:28Z", context["tooltip"]!.ToString());
        Assert.Equal("Europe/Moscow", context["timezone"]!.ToString());
    }

    [Theory]
    [InlineData(null, "—", "", "unknown")]
    [InlineData("", "—", "", "unknown")]
    [InlineData("invalid", "invalid", "invalid", "unknown")]
    [InlineData("2026-07-07T02:34:28", "07.07.2026 02:34:28 UTC", "2026-07-07T02:34:28Z", "UTC")]
    [InlineData("2026-07-07T02:34:28.9999999-03:00", "07.07.2026 05:34:28 UTC", "2026-07-07T05:34:28Z", "UTC")]
    public void Missing_invalid_naive_and_fractional_times_keep_Python_semantics(string? value, string display, string tooltip, string zone)
    {
        var context = ReportTime.WithContext(value, "invalid/timezone", "local");
        Assert.Equal(display, context["display"]!.ToString()); Assert.Equal(tooltip, context["tooltip"]!.ToString());
        Assert.Equal(zone, context["timezone"]!.ToString());
    }

    [Fact]
    public void Report_renders_human_time_and_keeps_raw_UTC_in_tooltip()
    {
        var context = LegacyReportContext.Build(11, ["dc.example.test"], [],
            "2026-07-07T02:34:28.9127653+03:00", "2026-07-07T02:34:28Z", [], true, "Europe/Moscow");
        string html = LegacyReportTemplate.Render(context);
        Assert.Contains("title=\"2026-07-06T23:34:28Z -&gt; 2026-07-07T02:34:28Z\"", html);
        Assert.Contains("07.07.2026 02:34:28 Europe/Moscow", html);
        Assert.Contains("07.07.2026 05:34:28 Europe/Moscow", html);
        Assert.DoesNotContain("2026-07-07T02:34:28.9127653+03:00", html);
        string visible = System.Text.RegularExpressions.Regex.Replace(html, @"<(script|style)\b[^>]*>[\s\S]*?</\1>", "",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        visible = System.Net.WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Replace(visible, @"<[^>]+>", ""));
        Assert.DoesNotMatch(@"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", visible);
    }
}
