using System.Text.Json.Nodes;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class UiLabelsTests
{
    [Fact]
    public void CoreLabelsAreRussianByDefault()
    {
        // tests/reporting/test_ui_labels.py::test_core_labels_are_russian_by_default
        Assert.Equal("завершено", UiLabels.Status("completed"));
        Assert.Equal("частичный сбор по таймауту", UiLabels.Status("partial_timeout"));
        Assert.Equal("высокий", UiLabels.Severity("high"));
        Assert.Equal("кто выполнил действие", UiLabels.EntityRole("actor"));
        Assert.Equal("учетная запись", UiLabels.EntityType("user"));
        Assert.Equal("Безопасность (Security)", UiLabels.Channel("Security", withOriginal: true));
        Assert.Equal("Инициатор", UiLabels.Field("subject"));
        Assert.Equal("Event ID 4740: Учетная запись заблокирована", UiLabels.EventId("4740"));
        Assert.Equal("Account locked out", UiLabels.EventId("4740", "en", prefix: false));
        Assert.Equal("возможно повторное чтение backlog", UiLabels.TranslateWarning("possible repeated backlog read"));
    }

    static JsonObject Health() => JsonNode.Parse("""
        {
          "generated_at_utc": "2026-07-07T10:00:00+00:00",
          "summary": {"channels_total":1,"security_high":1,"security_warn":0,"timeouts_24h":1,"partial_timeouts_24h":1},
          "items": [{
            "server":"DC1", "channel":"Security", "last_status":"partial_timeout", "severity":"high",
            "last_successful_collection_utc":"2026-07-07T09:00:00+00:00", "last_event_time_utc":"2026-07-07T08:00:00+00:00",
            "last_event_record_id":123, "lag_minutes":120, "timeouts_24h":1, "partial_timeouts_24h":1,
            "last_partial_count":50, "inserted_skipped_ratio":"50/10", "warnings":["channel timeout","Security lag > 30m"],
            "adaptive_limit":300, "adaptive_action":"partial_timeout", "recovery_mode":true
          }]
        }
        """)!.AsObject();

    [Fact]
    public void CollectorHealthReportUsesHumanReadableLabels()
    {
        // tests/reporting/test_ui_labels.py::test_collector_health_report_uses_human_readable_labels
        string html = LegacyCollectorHealth.Render(Health());
        foreach (string text in new[] { "Безопасность (Security)", "частичный сбор по таймауту", "высокий", "таймаут канала", "Отставание" })
            Assert.Contains(text, html);
        Assert.Contains("отставание Security больше 30 минут", html);
        Assert.Contains("включен", html);
    }

    [Fact]
    public void CollectorProjectionFeedsTranslatedReport()
    {
        var now = DateTimeOffset.Parse("2026-07-07T10:00:00+00:00");
        var row = new JsonObject { ["server_hostname"] = "dc.example.test", ["channel"] = "Security",
            ["last_successful_collection_utc"] = "2026-07-07T09:00:00+00:00", ["last_event_time_utc"] = "2026-07-07T07:00:00+00:00" };
        var stats = new JsonObject { ["last_status"] = "partial_timeout", ["inserted"] = 50, ["skipped"] = 10 };
        var item = OperationsCollector.Channel(row, stats, null, now);
        Assert.Equal("частичный сбор по таймауту", (string?)item["display_status"]);
        string html = LegacyCollectorHealth.Render(new JsonObject { ["items"] = new JsonArray(item) });
        foreach (string text in new[] { "Безопасность (Security)", "частичный сбор по таймауту", "высокий", "таймаут канала", "Отставание" })
            Assert.Contains(text, html);
    }

    [Fact]
    public void ReportEscapesHostValuesAndUnrecognizedLabels()
    {
        var health = Health();
        var item = health["items"]![0]!;
        foreach (string field in new[] { "server", "channel", "last_status", "severity" }) item[field] = "<script>fixture</script>";
        item["warnings"] = new JsonArray("<script>fixture</script>");
        string html = LegacyCollectorHealth.Render(health);
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;fixture&lt;/script&gt;", html);
        Assert.Contains("Нет данных.", LegacyCollectorHealth.Render(new JsonObject()));
    }

    [Theory]
    [InlineData(null, "неизвестно")]
    [InlineData("", "неизвестно")]
    [InlineData("custom_status", "custom_status")]
    public void MissingAndUnknownStatusesFollowReference(string? value, string expected) => Assert.Equal(expected, UiLabels.Status(value));

    [Fact]
    public void LanguageNormalizationAndFallbacksFollowReference()
    {
        Assert.Equal("completed", UiLabels.Status("completed", " EN "));
        Assert.Equal("завершено", UiLabels.Status("completed", "unsupported"));
        Assert.Equal("Security", UiLabels.Channel("Security", "en", withOriginal: true));
        Assert.Equal("custom_channel", UiLabels.Channel("custom_channel", withOriginal: true));
        Assert.Equal("channel timeout", UiLabels.TranslateWarning("channel timeout", "en"));
        Assert.Equal("—", UiLabels.TranslateWarning(null));
        Assert.Equal("Event ID —", UiLabels.EventId("invalid"));
        Assert.Equal("—", UiLabels.EventId(null, prefix: false));
        Assert.Equal("Event ID 999999", UiLabels.EventId("999999"));
        Assert.Equal("неизвестный тип события", UiLabels.EventId("999999", prefix: false));
    }
}
