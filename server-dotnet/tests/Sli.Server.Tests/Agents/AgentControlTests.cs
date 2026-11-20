using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Agents.Control;
using Sli.Server.Auth;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Owned agent control")]
public sealed class AgentControlTests
{
    private const string Agents = "/api/v1/admin/agents", Tokens = "/api/v1/admin/agent-tokens";
    private static void Error((HttpStatusCode Status, JsonElement Body) actual, HttpStatusCode status, string error)
    { Assert.Equal(status, actual.Status); Assert.Equal(error, actual.Body.GetProperty("error").GetString()); }

    [Fact]
    public async Task ActualManagementRoutesRequireRealAuthorityAndPreserveSafeInventoryAndTokenLifecycle()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AgentControlFixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        foreach (string lang in new[] { "ru", "en" })
        {
            Error(await f.Send(client, "GET", Agents, language: lang), HttpStatusCode.Unauthorized, "authentication_required");
            Error(await f.Send(client, "POST", Tokens, f.TokenPayload(), f.AdminCookie, origin: "https://invalid.example", language: lang), HttpStatusCode.Forbidden, "cross_origin_request_rejected");
        }
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Send(client, "GET", Agents, cookie: f.ViewerCookie)).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Send(client, "GET", Agents, cookie: f.DeniedCookie)).Status);
        Error(await f.Send(client, "GET", Agents, cookie: f.AdminCookie, key: f.ReportKey), HttpStatusCode.Forbidden, "report_key_route_denied");
        // Source _owner uses owner OR access.manage, with only coarse viewer:
        // a viewer granted access.manage is authorized without an invented admin gate.
        var list = await f.Send(client, "GET", Agents + "?ignored=value", cookie: f.ManagerCookie); Assert.Equal(HttpStatusCode.OK, list.Status);
        Assert.Contains(list.Body.GetProperty("items").EnumerateArray(), a => a.GetProperty("id").GetGuid() == f.Agent);
        Assert.DoesNotContain(list.Body.GetProperty("items").EnumerateArray(), a => a.GetProperty("id").GetGuid() == f.ExpiredAgent || a.GetProperty("id").GetGuid() == f.RetiredAgent);
        var detail = await f.Send(client, "GET", Agents + "?agent_id=&agent_id=" + f.Agent + "&agent_id=invalid", cookie: f.AdminCookie);
        Assert.Equal(HttpStatusCode.OK, detail.Status); var agent = Assert.Single(detail.Body.GetProperty("items").EnumerateArray());
        Assert.Equal("owned-control.example", agent.GetProperty("host_name").GetString()); Assert.Equal("agent_reported", agent.GetProperty("host_name_source").GetString());
        Assert.True(agent.TryGetProperty("eventlog_diagnostics", out _)); Assert.False(agent.GetProperty("rights_probe").TryGetProperty("eventlog_diagnostics", out _));
        Assert.Equal(2, agent.GetProperty("certificates").GetArrayLength()); Assert.Equal("unconfigured", agent.GetProperty("password_detection_domain").GetProperty("status").GetString());
        var expired = await f.Send(client, "GET", Agents + "?agent_id=" + f.ExpiredAgent, cookie: f.AdminCookie);
        Assert.Equal("never_seen_expired", Assert.Single(expired.Body.GetProperty("items").EnumerateArray()).GetProperty("inventory_hidden_reason").GetString());
        Error(await f.Send(client, "GET", Agents + "?agent_id=invalid", cookie: f.AdminCookie), HttpStatusCode.BadRequest, "invalid_agent_identity");
        Error(await f.Send(client, "POST", Tokens, f.TokenPayload(true), f.AdminCookie), HttpStatusCode.BadRequest, "invalid_enrollment_ttl");
        // uuid_text uses UUID(str(value)); a 32-digit integer host identity is
        // accepted by source as well as the usual UUID string.
        var payload = JsonSerializer.SerializeToNode(f.TokenPayload())!.AsObject(); payload["host_id"] = System.Text.Json.Nodes.JsonNode.Parse(f.TokenHost.ToString("N"));
        var created = await f.Send(client, "POST", Tokens, payload, key: f.AdminKey); Assert.Equal(HttpStatusCode.OK, created.Status);
        Guid tokenId = created.Body.GetProperty("id").GetGuid(); string token = created.Body.GetProperty("token").GetString()!;
        Assert.Equal(43, token.Length); Assert.Matches("^[A-Za-z0-9_-]{43}$", token); Assert.True(created.Body.GetProperty("expires_at").GetString()!.Contains('T'));
        var inventory = await f.Send(client, "GET", Tokens, cookie: f.AdminCookie); Assert.Equal(HttpStatusCode.OK, inventory.Status);
        var item = Assert.Single(inventory.Body.GetProperty("items").EnumerateArray(), t => t.GetProperty("id").GetGuid() == tokenId);
        Assert.False(item.TryGetProperty("token", out _)); Assert.False(item.TryGetProperty("token_hash", out _)); Assert.Contains(' ', item.GetProperty("expires_at").GetString()!);
        var revoked = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => f.Send(client, "POST", Tokens + "/revoke", new { id = tokenId }, f.AdminCookie)));
        Assert.All(revoked, r => { Assert.Equal(HttpStatusCode.OK, r.Status); Assert.Equal("revoked", r.Body.GetProperty("status").GetString()); });
        var tokenState = await f.TokenStateAsync(tokenId, token, ct); Assert.True(tokenState.GetProperty("digest_matches").GetBoolean()); Assert.True(tokenState.GetProperty("revoked").GetBoolean());
        Assert.Equal(2, tokenState.GetProperty("revoke_audits").GetInt64()); Assert.StartsWith("api_key:", tokenState.GetProperty("actor").GetString());
        Assert.Equal("owned-control.example", tokenState.GetProperty("create_details").GetProperty("registration_host_name").GetString());
        Error(await f.Send(client, "POST", Tokens + "/revoke", new { id = Guid.NewGuid() }, f.AdminCookie), HttpStatusCode.NotFound, "enrollment_token_not_found");
        using var offHost = f.Host(auth: false); using var off = f.Client(offHost);
        Error(await f.Send(off, "POST", Tokens, f.TokenPayload(), f.AdminCookie), HttpStatusCode.Unauthorized, "operator_token_required");
        Error(await f.Send(off, "POST", Tokens, f.TokenPayload(), operatorToken: "owned-agent-control-operator"), HttpStatusCode.Unauthorized, "authentication_required");
        Assert.Equal(HttpStatusCode.OK, (await f.Send(off, "POST", Tokens, f.TokenPayload(), f.ManagerCookie, operatorToken: "owned-agent-control-operator")).Status);
        var state = await f.StateAsync(ct); Assert.Equal("adlog_user", state.GetProperty("current_user").GetString()); Assert.Equal(2, state.GetProperty("tokens").GetInt64());
        await AgentControlFixture.RecordAsync(f.Marker + "-management", new { active_id = f.Agent, expired_id = f.ExpiredAgent, exact_detail = agent, runtime = state, token_length = token.Length, token_inventory_secret_free = true, token_state = tokenState, concurrent_token_revoke = "both200 as source; each audited" });
    }

    [Fact]
    public async Task PolicyRevisionRacesAndCertificateDisableAreRealAtomicSourceMutations()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AgentControlFixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        var initial = await f.StateAsync(ct); Assert.Equal(1, initial.GetProperty("revision").GetInt64());
        var changed = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => f.Send(client, "POST", Agents + "/policy", f.Policy(1, new { state = "paused", interval_seconds = 15 }), f.AdminCookie)));
        Assert.Single(changed, r => r.Status == HttpStatusCode.OK); Error(Assert.Single(changed, r => r.Status == HttpStatusCode.Conflict), HttpStatusCode.Conflict, "agent_policy_revision_conflict");
        var state = await f.StateAsync(ct); Assert.Equal(2, state.GetProperty("revision").GetInt64()); Assert.Equal(initial.GetProperty("applied_revision").GetInt64(), state.GetProperty("applied_revision").GetInt64());
        Assert.Equal(new long[] { 1, 2 }, state.GetProperty("history").EnumerateArray().Select(h => h.GetProperty("revision").GetInt64()));
        Assert.Equal("active", state.GetProperty("history")[0].GetProperty("control").GetProperty("state").GetString()); Assert.Equal("paused", state.GetProperty("control").GetProperty("state").GetString());
        Assert.Single(state.GetProperty("audits").EnumerateArray(), a => a.GetProperty("action").GetString() == "policy_update");
        Error(await f.Send(client, "POST", Agents + "/policy", f.Policy(2, new { batch_size = true }), f.AdminCookie), HttpStatusCode.BadRequest, "invalid_agent_collection_policy");
        Error(await f.Send(client, "POST", Agents + "/policy", f.Policy(2, new { unknown = true }), f.AdminCookie), HttpStatusCode.BadRequest, "invalid_agent_collection_policy");
        Error(await f.Send(client, "POST", Agents + "/policy", f.Policy(2, new { batch_size = 1.5 }), f.AdminCookie), HttpStatusCode.BadRequest, "invalid_agent_collection_policy");
        var read = await f.Send(client, "GET", Agents + "?agent_id=" + f.Agent, cookie: f.AdminCookie); var item = Assert.Single(read.Body.GetProperty("items").EnumerateArray());
        Assert.Equal(2, item.GetProperty("policy_revision").GetInt64()); Assert.Equal("paused", item.GetProperty("collection_policy").GetProperty("state").GetString());
        Assert.Single(item.GetProperty("policy_audit").EnumerateArray());
        Error(await f.Send(client, "POST", Agents + "/revoke", new { agent_id = f.Agent, serial = "UPPER" }, f.AdminCookie), HttpStatusCode.BadRequest, "invalid_agent_serial");
        Assert.Equal(HttpStatusCode.OK, (await f.Send(client, "POST", Agents + "/revoke", new { agent_id = f.Agent, serial = f.Serial }, f.AdminCookie)).Status);
        var afterRevoke = await f.StateAsync(ct); Assert.Equal(0, afterRevoke.GetProperty("active_certificates").GetInt64()); Assert.Equal(1, afterRevoke.GetProperty("other_active_certificates").GetInt64());
        Assert.Equal(HttpStatusCode.OK, (await f.Send(client, "POST", Agents + "/disable", new { agent_id = f.Agent }, f.AdminCookie)).Status);
        Error(await f.Send(client, "POST", Agents + "/policy", f.Policy(2, new { state = "active" }), f.AdminCookie), HttpStatusCode.Conflict, "agent_disabled");
        var final = await f.StateAsync(ct); Assert.Equal("disabled", final.GetProperty("status").GetString()); Assert.Equal(1, final.GetProperty("other_active_certificates").GetInt64());
        await AgentControlFixture.RecordAsync(f.Marker + "-policy-revoke", new { initial, after_policy = state, final });
    }

    [Fact]
    public async Task AuditFailureRollsBackTokenPolicyHistoryAndCertificateRevocation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AgentControlFixture.OpenAsync(ct);
        using var host = f.Host(services => { services.RemoveAll<IAgentControlAudit>(); services.AddSingleton<IAgentControlAudit, FailedAudit>(); }); using var client = f.Client(host);
        var before = await f.StateAsync(ct);
        foreach ((string path, object body) in new[] { (Tokens, f.TokenPayload()), (Agents + "/policy", f.Policy(1, new { state = "drain" })), (Agents + "/disable", (object)new { agent_id = f.Agent }) })
        {
            var response = await f.Send(client, "POST", path, body, f.AdminCookie); Error(response, HttpStatusCode.ServiceUnavailable, "agent_service_unavailable");
            Assert.Single(response.Body.EnumerateObject()); var after = await f.StateAsync(ct); Assert.True(JsonElement.DeepEquals(before, after));
        }
        await AgentControlFixture.RecordAsync(f.Marker + "-audit-rollback", new { injection = "real audit insert then dependency throw inside caller transaction", before, after = await f.StateAsync(ct), status = 503 });
    }
    private sealed class FailedAudit : IAgentControlAudit
    {
        public async Task AppendAsync(NpgsqlConnection db, NpgsqlTransaction tx, string action, string actor, string target, object details, CancellationToken ct)
        { await new AgentControlAudit().AppendAsync(db, tx, action, actor, target, details, ct); throw new InvalidOperationException("injected_control_audit_failure"); }
    }
    [Fact]
    public async Task AdmissionDependencyFailureUsesOuterSource500BeforeTransactionalExecute()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AgentControlFixture.OpenAsync(ct);
        using var host = f.Host(services => { services.RemoveAll<IPrincipalAuthenticator>(); services.AddScoped<IPrincipalAuthenticator, FailedAuthentication>(); }); using var client = f.Client(host);
        var before = await f.StateAsync(ct);
        var result = await f.Send(client, "GET", Agents, cookie: f.AdminCookie);
        Error(result, HttpStatusCode.InternalServerError, "internal_server_error"); Assert.Equal(2, result.Body.EnumerateObject().Count());
        Assert.True(Guid.TryParse(result.Body.GetProperty("internal_error_id").GetString(), out _));
        Assert.True(JsonElement.DeepEquals(before, await f.StateAsync(ct)));
        await AgentControlFixture.RecordAsync(f.Marker + "-admission-failure", new { injection = "principal authenticator dependency throws before _execute phase", status = 500, body_shape = new[] { "error", "internal_error_id" }, state_unchanged = true });
    }
    private sealed class FailedAuthentication : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(Microsoft.AspNetCore.Http.HttpContext context, CancellationToken ct) => throw new InvalidOperationException("injected_authentication_dependency_failure");
    }
}
