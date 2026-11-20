using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

public sealed class WorkspaceEndpointTests
{
    [Theory]
    [InlineData("viewer")]
    [InlineData("operator")]
    [InlineData("admin")]
    public void BootstrapPreservesAuthenticatedRoleAndNavigationWithoutUiMode(string role)
    {
        static JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
        string[] keys = ["workspace.view", "events.view", "operations.view"];
        var facts = new AccessFacts(false, role, [], [], keys.Select(key => J(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray(), [], [], [], []);
        var caps = new CapabilityComposer().Compose(facts);
        var access = new AccessReadEvaluation(facts, caps, new ReportEligibility().Compose(facts, caps));
        var body = J(WorkspaceEndpoints.Bootstrap(new Principal("session", 1, role, Username: "user"), access));
        Assert.Equal(role, body.GetProperty("effective_role").GetString());
        Assert.Equal(role, body.GetProperty("principal").GetProperty("role").GetString());
        Assert.False(body.TryGetProperty("ui_mode", out _));
        var navigation = body.GetProperty("navigation").EnumerateArray().ToArray();
        foreach (string id in new[] { "workspace", "events", "operations" }) Assert.Contains(navigation, item => item.GetProperty("id").GetString() == id);
        Assert.Equal("/events", navigation.Single(item => item.GetProperty("id").GetString() == "events").GetProperty("path").GetString());
    }

    [Fact]
    public void BootstrapUsesEffectiveAccessAndReferenceFields()
    {
        var facts = new AccessFacts(false, "viewer", [], [], [], [], [], [], []);
        var caps = new CapabilityComposer().Compose(facts);
        var access = new AccessReadEvaluation(facts, caps, new ReportEligibility().Compose(facts, caps));
        var body = JsonSerializer.SerializeToElement(WorkspaceEndpoints.Bootstrap(new Principal("session", 1, "viewer", Username: "test"), access));
        Assert.Equal("viewer", body.GetProperty("effective_role").GetString());
        Assert.Equal("composite_v4", body.GetProperty("access_model").GetString());
        Assert.Equal(0, body.GetProperty("allowed_report_count").GetInt32());
        Assert.Empty(body.GetProperty("navigation").EnumerateArray());
        Assert.Equal("insufficient_capability", caps.Decide("workspace.view").Reason);
        Assert.Equal("insufficient_capability", caps.Decide("reports.catalog").Reason);
    }

    [Fact]
    public void EmptyAgentsMatchesReferenceShape()
    {
        var body = JsonSerializer.SerializeToElement(WorkspaceEndpoints.EmptyAgents(new DateTimeOffset(2026, 1, 2, 0, 0, 0, TimeSpan.Zero)));
        Assert.Equal("v1", body.GetProperty("api_version").GetString());
        var health = body.GetProperty("agent_collection");
        Assert.Equal("unknown", health.GetProperty("state").GetString());
        Assert.Equal("not_assessed", health.GetProperty("completeness").GetProperty("state").GetString());
        Assert.Empty(health.GetProperty("items").EnumerateArray());
        Assert.Equal(0, health.GetProperty("active_agents").GetInt32());
        Assert.Equal(0, health.GetProperty("current_agents").GetInt32());
    }
}
