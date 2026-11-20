using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Parity vectors from tests/sources/test_week5_collector_health_hotfix.py.
public sealed class CollectorHealthHotfixTests
{
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-07T09:31:07.803468+00:00");
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    static JsonObject Channel(string name, int eventLag, int pollLag, string status = "completed", bool recovery = false) =>
        OperationsCollector.Channel(new JsonObject {
            ["server_hostname"] = "DC1", ["channel"] = name, ["recovery_mode"] = recovery,
            ["last_successful_collection_utc"] = Now.AddMinutes(-pollLag).ToString("O"),
            ["last_event_time_utc"] = Now.AddMinutes(-eventLag).ToString("O")
        }, new JsonObject { ["last_status"] = status }, null, Now);
    static JsonObject Data() => new() { ["summary"] = new JsonObject(), ["items"] = new JsonArray(), ["post_collection"] = new JsonObject() };
    static string Html(JsonObject data) => WebUtility.HtmlDecode(LegacyCollectorHealth.Render(data));

    [Theory]
    [InlineData("Microsoft-Windows-PowerShell/Operational", 662, 7, "новых событий не обнаружено", "good")]
    [InlineData("Security", 90, 3, "события отстают", "high")]
    public void EventObservationSeparatesQuietChannelsFromSecurityLag(string channel, int eventLag, int pollLag, string label, string severity)
    {
        var item = Channel(channel, eventLag, pollLag);
        Assert.Equal(label, (string?)item["event_observation_label"]);
        Assert.Equal(severity, (string?)item["event_observation_severity"]);
    }

    [Theory]
    [InlineData("Security", "completed", 475, true, "сбор завершён, данные ещё догоняются")]
    [InlineData("System", "stale", 240, false, "данные устарели")]
    public void ChannelStatusExplainsRecovery(string channel, string status, int lag, bool recovery, string expected) =>
        Assert.Equal(expected, (string?)Channel(channel, lag, 0, status, recovery)["display_status"]);

    [Theory]
    [InlineData("keep:completed_streak; 5000->5000; recovery=on", "лимит сохранен: серия успешных сборов; 5000 → 5000; восстановление включено")]
    [InlineData("decrease_limit:skipped_gt_inserted_x2; 1000->500; recovery=on", "лимит уменьшен: много повторно прочитанных событий; 1000 → 500; восстановление включено")]
    public void ReportTranslatesAdaptiveActionAndHeaderTime(string action, string translated)
    {
        var data = Data(); data["generated_at_utc"] = "2026-07-07T09:31:07.803468+00:00";
        var item = Channel("Security", 475, 0, recovery: true);
        // Match the reference's fallback when newer freshness fields are absent.
        item.Remove("freshness_label"); item["adaptive_action"] = action; item["adaptive_limit"] = 5000;
        data["items"] = new JsonArray(item);
        string html = Html(data);
        Assert.Contains("07.07.2026 09:31:07 UTC", html);
        Assert.DoesNotContain("2026-07-07T09:31:07.803468+00:00", html);
        Assert.Contains("сбор завершён, данные ещё догоняются", html);
        Assert.Contains(translated, html);
    }

    sealed class Queries : IOperationsQueries
    {
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            JsonArray rows = [];
            if (sql == OperationsSql.CollectorState)
                rows = new JsonArray(
                    new JsonObject { ["server_hostname"] = "DC1", ["channel"] = "Security", ["last_event_time_utc"] = Now.AddMinutes(-170).ToString("O"), ["last_successful_collection_utc"] = Now.ToString("O") },
                    new JsonObject { ["server_hostname"] = "DC2", ["channel"] = "Security", ["last_event_time_utc"] = Now.AddMinutes(-11).ToString("O"), ["last_successful_collection_utc"] = "2020-01-01T00:00:00Z" });
            return Task.FromResult(rows);
        }
    }
    [Fact]
    public async Task SloMeasuresSuccessfulPollInsteadOfSecurityEventAge()
    {
        var service = new OperationsService(new Queries(), new OperationsFiles(new ConfigurationBuilder().Build()), new OperationsCatalog(), new OperationsJobs(), new Clock());
        var result = await service.ReadAsync("/api/collector/health", new(), TestContext.Current.CancellationToken);
        var slo = result["operations_slo"]!;
        Assert.Equal("breached", (string?)slo["status"]);
        Assert.Equal(1, (int?)slo["freshness_current"]);
        Assert.Equal(1, (int?)slo["freshness_breached"]);
        Assert.Equal(5, (int?)slo["warning_minutes"]);
        Assert.Equal(20, (int?)slo["breach_minutes"]);
    }

    [Fact]
    public void ReportExplainsSloBaselineInPlainLanguage()
    {
        var data = Data(); data["operations_slo"] = new JsonObject { ["status"] = "attention", ["label"] = "Требует внимания", ["security_channels"] = 2,
            ["freshness_current"] = 1, ["freshness_warning"] = 1, ["warning_minutes"] = 30, ["breach_minutes"] = 120 };
        string html = Html(data);
        Assert.Contains("Работа сбора и свежесть данных", html);
        Assert.Contains("Проверка каналов Security задерживается", html);
        Assert.Contains("Security: актуальная проверка (до 30 мин.)", html);
    }

    [Fact]
    public void ReportShowsDurableWorkerHistory()
    {
        var data = Data(); data["runtime_history"] = new JsonObject { ["status"] = "ok", ["items"] = new JsonArray(new JsonObject {
            ["status"] = "running", ["phase"] = "collection", ["worker_id"] = "collection-dc1", ["started_at"] = "2026-07-16T00:00:00Z",
            ["max_events_per_channel"] = 50000, ["servers_json"] = new JsonArray("DC1", "DC2"), ["duration_ms"] = null }) };
        string html = Html(data);
        Assert.Contains("Независимый worker сбора", html); Assert.Contains("50000", html);
        Assert.Contains("История хранится в PostgreSQL", html);
    }

    [Fact]
    public void ReportShowsV2OutboxWithoutBlamingTheDc()
    {
        var data = Data(); data["storage_v2_outbox"] = new JsonObject { ["status"] = "ok", ["events"] = 43000, ["batches"] = 86,
            ["states"] = new JsonObject { ["leased"] = new JsonObject { ["events"] = 500 } } };
        string html = Html(data);
        Assert.Contains("Очередь архивирования V2", html); Assert.Contains("не блокирует успешный сбор", html); Assert.Contains("43,000", html);
    }

    [Fact]
    public void PostgresTimestampPeriodRendersOneHourFiveMinutes()
    {
        // The .NET PG query returns timestamps as text, not Python datetime objects.
        var context = LegacyReportContext.Build(23, ["dc.example.test"], [], "2026-07-17 10:00:00+00", "2026-07-17 11:05:00+00", [], true);
        Assert.Equal("1ч 5м", (string?)context["kpis"]![2]!["value"]);
    }

    [Fact]
    public void ReportEscapesChannelWorkerAndAdaptiveActionData()
    {
        const string hostile = "<script>alert(1)</script> & \"";
        var data = Data();
        var item = Channel("Security", 0, 0);
        item["server"] = hostile; item["adaptive_action"] = hostile;
        data["items"] = new JsonArray(item);
        data["runtime_history"] = new JsonObject { ["items"] = new JsonArray(new JsonObject {
            ["phase"] = hostile, ["worker_id"] = hostile, ["servers_json"] = new JsonArray(hostile), ["errors_json"] = new JsonArray(hostile) }) };
        data["post_collection"] = new JsonObject { ["items"] = new JsonArray(new JsonObject { ["status"] = hostile }) };
        string html = LegacyCollectorHealth.Render(data);
        Assert.DoesNotContain(hostile, html); Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;", html);
    }

    sealed class Connections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("unexpected database access");
    }
    [Fact]
    public void StandaloneLegacyWorkerCanResolveTheCollectorReportDependency()
    {
        using var provider = new ServiceCollection()
            .AddSingleton<IConfiguration>(new ConfigurationBuilder().Build())
            .AddSingleton<IPostgresConnectionFactory, Connections>()
            .AddLegacyJobs(hosted: false).BuildServiceProvider();
        using var scope = provider.CreateScope();
        Assert.IsType<LegacyAnalysis>(scope.ServiceProvider.GetRequiredService<ILegacyAnalysis>());
    }
}
