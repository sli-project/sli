using System.Net;
using System.Text.Json.Nodes;
using Sli.Server.Tests.Operations;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

public sealed class RoleViewsReleaseTests
{
    // tests/access/test_week8_role_views_release.py: shared preloaded snapshot.
    [Fact]
    public void RoleViewsGroupSharedDataWithoutRemovingLayers()
    {
        var input = JsonNode.Parse("""
            {
              "events": {"total_events": 3, "by_channel": [{"channel": "Security", "count": 3}]},
              "entities": {"total_entities": 2, "total_event_entity_links": 3},
              "collector": {"items": [], "summary": {"security_high": 0}},
              "system": {"status": "ok", "retention": {"candidates": 0}},
              "findings": {"items": [{"status": "open"}]},
              "ai_runs": {"items": []},
              "sources": [{"hostname": "DC1"}]
            }
            """)!;
        var original = input.DeepClone();

        var data = DashboardSnapshotReader.RoleViews(input["events"]!, input["entities"]!,
            input["collector"]!, input["system"]!, input["findings"]!, input["ai_runs"]!, input["sources"]!);

        var views = data["views"]!.AsArray();
        Assert.Equal(["security", "it", "technical"], views.Select(view => (string?)view!["id"]));
        Assert.Equal(3, (long)data["summary"]!["total_events"]!);
        Assert.Equal(3, (long)data["summary"]!["security_events"]!);
        Assert.Equal(1, (long)data["summary"]!["active_findings"]!);
        Assert.Equal(2, (long)data["summary"]!["entities"]!);
        Assert.Equal(1, (int)data["summary"]!["sources"]!);

        JsonNode View(string id) => Assert.Single(views, view => (string?)view!["id"] == id)!;
        static void HasAction(JsonNode view, string url) =>
            Assert.Contains(view["actions"]!.AsArray(), action => (string?)action!["url"] == url);

        HasAction(View("security"), "/reports/findings.html");
        HasAction(View("security"), "/reports/ai-reports.html");
        HasAction(View("it"), "/reports/collector-health.html");
        Assert.Contains(View("technical")["actions"]!.AsArray(),
            action => action!["url"]!.ToString().Contains("event-details", StringComparison.Ordinal));
        Assert.Equal("Ролевые представления не удаляют данные: они только меняют порядок и акценты.",
            (string?)data["principle"]);
        Assert.All(views, view => Assert.False(string.IsNullOrWhiteSpace((string?)view!["kept_for_other_roles"])));
        Assert.True(JsonNode.DeepEquals(original, input));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReleaseCheckReturnsShippedRoleViewsEvenWhenDatabaseIsUnavailable(bool databaseUnavailable)
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.Fail = databaseUnavailable;
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/diagnostics/overview?run_checks=yes");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var data = (await OperationsEndpointTests.Body(response))["parsed_checks"]!["release_check"]!;
        Assert.Contains((string?)data["status"], new[] { "ok", "warn" });
        var roles = Assert.IsType<JsonArray>(data["role_views"]);
        Assert.Equal(["security", "it", "technical"], roles.Select(id => (string?)id));
        // Release discovery reads shipped role definitions, never dashboard summaries.
        Assert.DoesNotContain(app.Queries.Calls, call => call.Sql.Contains("findings_active", StringComparison.Ordinal)
            || call.Sql.Contains("events_v2_core", StringComparison.Ordinal));
    }
}
