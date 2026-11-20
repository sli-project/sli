using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Agents.Control;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Owned agent lifecycle")]
public sealed class AgentLifecycleTests
{
    private const string Remove = "/api/v1/admin/agents/remove", Probe = "/api/v1/admin/agents/rights-probe", Agents = "/api/v1/admin/agents";
    private static void Error((HttpStatusCode Status, JsonElement Body) actual, HttpStatusCode status, string error)
    { Assert.Equal(status, actual.Status); Assert.Equal(error, actual.Body.GetProperty("error").GetString()); }
    private static JsonElement Row(JsonElement state, Guid id) => Assert.Single(state.GetProperty("agents").EnumerateArray(), a => a.GetProperty("id").GetGuid() == id);

    [Fact]
    public async Task RemovalRequiresRealPlatformOwnerAndSerializesCompleteBatchBeforeRevocation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var l = await AgentLifecycleFixture.OpenAsync(ct); var f = l.Control; using var host = f.Host(); using var client = f.Client(host);
        Guid operation = Guid.NewGuid(); var payload = new { operation_id = operation, agent_ids = new[] { f.OtherAgent, f.Agent } };
        Error(await f.Send(client, "POST", Remove, payload, f.AdminCookie), HttpStatusCode.Forbidden, "platform_owner_required");
        Error(await f.Send(client, "POST", Remove, payload, f.ManagerCookie), HttpStatusCode.Forbidden, "platform_owner_required");
        Error(await f.Send(client, "POST", Remove, payload, l.OwnerCookie, origin: "https://invalid.example"), HttpStatusCode.Forbidden, "cross_origin_request_rejected");
        Error(await f.Send(client, "POST", Remove, payload, l.OwnerCookie, key: f.ReportKey), HttpStatusCode.Forbidden, "report_key_route_denied");
        var before = await l.StateAsync(ct);
        Error(await f.Send(client, "POST", Remove, new { operation_id = operation, agent_ids = new[] { f.Agent, f.Agent } }, l.OwnerCookie), HttpStatusCode.BadRequest, "agent_removal_invalid");
        Error(await f.Send(client, "POST", Remove, new { operation_id = operation, agent_ids = new[] { f.Agent, Guid.NewGuid() } }, l.OwnerCookie), HttpStatusCode.NotFound, "agent_not_found");
        Assert.True(JsonElement.DeepEquals(before, await l.StateAsync(ct)));
        var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => f.Send(client, "POST", Remove, payload, l.OwnerCookie)));
        var success = Assert.Single(results, r => r.Status == HttpStatusCode.OK);
        Error(Assert.Single(results, r => r.Status == HttpStatusCode.Conflict), HttpStatusCode.Conflict, "agent_removal_replay");
        Assert.Equal(operation, success.Body.GetProperty("operation_id").GetGuid());
        Assert.Equal(new[] { f.Agent, f.OtherAgent }.OrderBy(id => id.ToString(), StringComparer.Ordinal), success.Body.GetProperty("items").EnumerateArray().Select(a => a.GetProperty("agent_id").GetGuid()));
        Error(await f.Send(client, "POST", Remove, new { operation_id = Guid.NewGuid(), agent_ids = new[] { f.Agent } }, l.OwnerCookie), HttpStatusCode.Conflict, "agent_removal_replay");
        var after = await l.StateAsync(ct); Assert.Equal("adlog_user", after.GetProperty("current_user").GetString());
        foreach (Guid id in new[] { f.Agent, f.OtherAgent })
        {
            var row = Row(after, id); Assert.Equal("disabled", row.GetProperty("status").GetString()); Assert.Equal(0, row.GetProperty("active_certificates").GetInt64());
            Assert.Equal(1, row.GetProperty("policy_revision").GetInt64()); Assert.Equal("pending", row.GetProperty("removal").GetProperty("state").GetString());
            Assert.Equal(operation, row.GetProperty("removal").GetProperty("operation_id").GetGuid()); Assert.True(row.GetProperty("removal").GetProperty("command_id").GetGuid() != Guid.Empty);
            Assert.Single(row.GetProperty("audits").EnumerateArray(), a => a.GetProperty("action").GetString() == "removal_request");
            Assert.Single(row.GetProperty("audits").EnumerateArray(), a => a.GetProperty("action").GetString() == "disable");
        }
        Assert.True(JsonElement.DeepEquals(Row(before, f.ExpiredAgent), Row(after, f.ExpiredAgent)));
        var list = await f.Send(client, "GET", Agents, cookie: l.OwnerCookie); Assert.Equal(HttpStatusCode.OK, list.Status);
        Assert.DoesNotContain(list.Body.GetProperty("items").EnumerateArray(), r => r.GetProperty("id").GetGuid() == f.Agent || r.GetProperty("id").GetGuid() == f.OtherAgent);
        var detail = await f.Send(client, "GET", Agents + "?agent_id=" + f.Agent, cookie: l.OwnerCookie);
        var item = Assert.Single(detail.Body.GetProperty("items").EnumerateArray()); Assert.Equal("administrator_removed", item.GetProperty("inventory_hidden_reason").GetString()); Assert.Equal("pending", item.GetProperty("removal").GetProperty("state").GetString());
        await AgentControlFixture.RecordAsync(f.Marker + "-removal", new { before, after, response = success.Body, exact_detail = item });
    }

    [Fact]
    public async Task RightsProbeHasOnePendingRequestUnderConcurrencyAndAuditFailureRollsBack()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var l = await AgentLifecycleFixture.OpenAsync(ct); var f = l.Control; using var host = f.Host(); using var client = f.Client(host);
        var before = await l.StateAsync(ct); var payload = new { agent_id = f.Agent };
        Error(await f.Send(client, "POST", Probe, payload, f.ViewerCookie), HttpStatusCode.Forbidden, "insufficient_capability");
        var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => f.Send(client, "POST", Probe, payload, f.ManagerCookie)));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.Status)); Assert.True(JsonElement.DeepEquals(results[0].Body, results[1].Body));
        var pending = results[0].Body.GetProperty("rights_probe").GetProperty("pending"); Assert.True(Guid.TryParse(pending.GetProperty("request_id").GetString(), out _)); Assert.Contains('T', pending.GetProperty("requested_at").GetString()!);
        var after = await l.StateAsync(ct); var row = Row(after, f.Agent); Assert.Equal(1, row.GetProperty("policy_revision").GetInt64());
        Assert.Single(row.GetProperty("audits").EnumerateArray(), a => a.GetProperty("action").GetString() == "probe_request");
        Assert.True(row.GetProperty("rights_probe").TryGetProperty("eventlog_diagnostics", out _));
        Error(await f.Send(client, "POST", Probe, new { agent_id = f.RetiredAgent }, f.ManagerCookie), HttpStatusCode.Conflict, "agent_disabled");
        Error(await f.Send(client, "POST", Probe, new { agent_id = f.OtherAgent, extra = true }, f.ManagerCookie), HttpStatusCode.BadRequest, "invalid_agent_probe_request");
        using var failedHost = f.Host(services => { services.RemoveAll<IAgentControlAudit>(); services.AddSingleton<IAgentControlAudit>(new FailedAudit("probe_request")); }); using var failedClient = f.Client(failedHost);
        Error(await f.Send(failedClient, "POST", Probe, new { agent_id = f.OtherAgent }, f.ManagerCookie), HttpStatusCode.ServiceUnavailable, "agent_service_unavailable");
        Assert.True(JsonElement.DeepEquals(after, await l.StateAsync(ct)));
        await AgentControlFixture.RecordAsync(f.Marker + "-probe", new { before, after, injection = "real probe update/audit then throw; transaction rollback", duplicate_response_equal = true });
    }

    [Fact]
    public async Task RemovalFailureAfterLaterAgentAuditRollsBackEarlierAgentStatusCertAndCommand()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var l = await AgentLifecycleFixture.OpenAsync(ct); var f = l.Control;
        Guid later = new[] { f.Agent, f.OtherAgent }.OrderBy(id => id.ToString(), StringComparer.Ordinal).Last();
        using var host = f.Host(services => { services.RemoveAll<IAgentControlAudit>(); services.AddSingleton<IAgentControlAudit>(new FailedAudit("removal_request", later.ToString())); }); using var client = f.Client(host);
        var before = await l.StateAsync(ct);
        var result = await f.Send(client, "POST", Remove, new { operation_id = Guid.NewGuid(), agent_ids = new[] { f.Agent, f.OtherAgent } }, l.OwnerCookie);
        Error(result, HttpStatusCode.ServiceUnavailable, "agent_service_unavailable"); Assert.Single(result.Body.EnumerateObject());
        Assert.True(JsonElement.DeepEquals(before, await l.StateAsync(ct)));
        await AgentControlFixture.RecordAsync(f.Marker + "-removal-rollback", new { before, after = await l.StateAsync(ct), injected_after_later_agent_audit = later, http = 503 });
    }
    private sealed class FailedAudit(string action, string? selected = null) : IAgentControlAudit
    {
        public async Task AppendAsync(NpgsqlConnection db, NpgsqlTransaction tx, string actual, string actor, string target, object details, CancellationToken ct)
        { await new AgentControlAudit().AppendAsync(db, tx, actual, actor, target, details, ct); if (actual == action && (selected is null || selected == target)) throw new InvalidOperationException("injected_lifecycle_audit_failure"); }
    }
}
