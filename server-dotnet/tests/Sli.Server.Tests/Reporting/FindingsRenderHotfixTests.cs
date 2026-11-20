using System.Text.Json.Nodes;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class FindingsRenderHotfixTests
{
    private static JsonObject Entity(string name, string role = "actor", string type = "account") => new()
    {
        ["entity_type"] = type, ["display_name"] = name, ["entity_role"] = role
    };

    [Fact]
    public void Findings_report_deduplicates_entities_and_localizes_status()
    {
        var entities = new JsonArray();
        for (int i = 0; i < 100; i++) entities.Add(Entity(@"DEMO\admin"));
        for (int i = 0; i < 100; i++) entities.Add(Entity(@"DEMO\ivanov", "target"));
        var data = JsonNode.Parse("""
            {"generated_at_utc":"2026-07-07T08:03:00Z",
             "summary":[{"severity":"high","status":"repeated","count":1}],
             "items":[{"id":1,"title":"Сброс пароля","severity":"high","status":"repeated","confidence":0.7,
               "actor":"DEMO\\admin","target":"DEMO\\ivanov","source":"192.0.2.7",
               "evidence_count":3,"repeat_count":2,"recommended_action":"Проверить основание.",
               "evidence":[{"event_db_id":1,"event_id":4724,"hostname":"DC1"}]}]}
            """)!.AsObject();
        data["items"]![0]!["entities"] = entities;

        string report = FindingsReportRenderer.Render(data);

        Assert.Contains("Findings: объекты проверки", report);
        Assert.Contains("Что сделать", report);
        Assert.Contains("повторяется", report);
        Assert.DoesNotContain(">repeated<", report);
        Assert.DoesNotContain("UTC: 2026-", report);
        Assert.Equal(2, report.Split(@"DEMO\admin").Length - 1);
        Assert.Equal(2, report.Split(@"DEMO\ivanov").Length - 1);
        Assert.True(report.Length < 80000);
        Assert.Contains("Сформирован: 07.07.2026 08:03:00 UTC", report);
        Assert.Contains("evidence: 3", report);
        Assert.Contains("повторов: 2", report);
        Assert.Contains("Проверить основание.", report);
        Assert.Contains("/reports/event-details.html?event_db_id=1&amp;limit=1", report);
        Assert.Contains("Event ID 4724: Попытка сброса пароля · DC1", report);
        Assert.Contains("инициатор: DEMO", report);
        Assert.Contains("цель: DEMO", report);
    }

    [Theory]
    [InlineData("repeated", "повторяется")]
    [InlineData("false_positive", "ложное срабатывание")]
    public void Findings_status_labels_are_localized(string status, string expected)
    {
        Assert.Equal(expected, FindingsReportRenderer.StatusLabel(status));
        var data = new JsonObject { ["summary"] = new JsonArray(new JsonObject { ["severity"] = "high", ["status"] = status, ["count"] = 1 }),
            ["items"] = new JsonArray(new JsonObject { ["status"] = status }) };
        string report = FindingsReportRenderer.Render(data);
        Assert.Contains($"<td>{expected}</td>", report);
        Assert.Contains($"<span class=\"pill\">{expected}</span>", report);
        Assert.DoesNotContain($">{status}<", report);
    }

    [Fact]
    public void Related_entities_ignore_blank_names_and_deduplicate_by_role_type_and_trimmed_case_insensitive_name()
    {
        var entities = new JsonArray(Entity(" "), Entity(" Example "), Entity("example"), Entity("EXAMPLE", "target"), Entity("example", "actor", "host"));
        var data = new JsonObject { ["items"] = new JsonArray(new JsonObject { ["entities"] = entities }) };
        string report = FindingsReportRenderer.Render(data);
        Assert.Contains("Связанные сущности: инициатор: Example; цель: EXAMPLE; инициатор: example</p>", report);
    }

    [Fact]
    public void Related_entities_show_eight_distinct_names_and_count_only_hidden_distinct_names()
    {
        var entities = new JsonArray();
        for (int i = 0; i < 10; i++)
            for (int copy = 0; copy < 20; copy++) entities.Add(Entity($"object-{i}"));
        string report = FindingsReportRenderer.Render(new() { ["items"] = new JsonArray(new JsonObject { ["entities"] = entities }) });
        Assert.Contains("инициатор: object-7; еще 2</p>", report);
        Assert.DoesNotContain("object-8", report);
        Assert.DoesNotContain("object-9", report);
    }

    [Fact]
    public void Empty_report_and_untrusted_fields_keep_reference_fallbacks_and_html_escaping()
    {
        string empty = FindingsReportRenderer.Render(new());
        Assert.Contains("Findings пока не обнаружены.", empty);
        Assert.Contains("Нет данных", empty);
        Assert.Contains("Сформирован: —", empty);
        const string untrusted = "<script>\"&'";
        var finding = new JsonObject();
        foreach (string field in new[] { "title", "summary", "actor", "target", "source", "why_it_matters", "recommended_action", "assigned_to", "status_reason", "severity", "status" }) finding[field] = untrusted;
        finding["entities"] = new JsonArray(Entity(untrusted));
        finding["evidence"] = new JsonArray(new JsonObject { ["event_db_id"] = untrusted, ["hostname"] = untrusted });
        string report = FindingsReportRenderer.Render(new() { ["items"] = new JsonArray(finding) });
        Assert.DoesNotContain(untrusted, report);
        Assert.Contains("&lt;script&gt;&quot;&amp;&#x27;", report);
        Assert.Contains("%3Cscript%3E%22%26%27", report);
    }

    [Fact]
    public void Status_history_localizes_transitions_and_repeat_time_is_formatted_in_utc()
    {
        var finding = JsonNode.Parse("""
            {"repeat_count":2,"last_repeat_detected_at":"2026-07-07T11:03:00+03:00",
             "status_history":[{"old_status":"repeated","new_status":"false_positive","changed_by":"<analyst>",
             "changed_at":"2026-07-07T08:03:00Z","note":"<reason>"}]}
            """)!.AsObject();
        string report = FindingsReportRenderer.Render(new() { ["items"] = new JsonArray(finding) });
        Assert.Contains("последний повтор: 07.07.2026 08:03:00 UTC", report);
        Assert.Contains("повторяется → ложное срабатывание · &lt;analyst&gt; · 07.07.2026 08:03:00 UTC: &lt;reason&gt;", report);
    }
}
