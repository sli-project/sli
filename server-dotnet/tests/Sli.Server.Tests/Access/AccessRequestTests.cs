using System.Net;
using System.Text.Json;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access.Administration;
using Sli.Server.Access.Requests;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Access;

[Collection("Owned access requests")]
public sealed class AccessRequestTests
{
    [Fact]
    public async Task IntegratedProgramComposesKeyLifecycleAndRequestApproval()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AccessRequestFixture.OpenAsync(ct);
        const string password = "Integration-Request-Synthetic-Password";
        await f.SetReviewerPasswordAsync(password, ct);
        using var host = f.Host();
        using var client = f.Client(host);
        using var loginBody = new StringContent(JsonSerializer.Serialize(new { username = f.Marker + "reviewer", password }), Encoding.UTF8, "application/json");
        using var login = await client.PostAsync("/api/auth/login", loginBody, ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        string reviewer = Assert.Single(login.Headers.GetValues("Set-Cookie")).Split(';')[0].Split('=', 2)[1];
        Assert.Equal(HttpStatusCode.OK, (await f.Send(client, "GET", "/api/auth/me", null, reviewer)).Status);
        Assert.Equal(HttpStatusCode.OK, (await f.Send(client, "GET", "/api/auth/users", null, reviewer)).Status);
        var key = await f.Send(client, "POST", "/api/auth/api-keys", new { label = f.Marker, role = "viewer" }, reviewer);
        Assert.Equal(HttpStatusCode.Created, key.Status);
        long keyId = key.Body.GetProperty("item").GetProperty("id").GetInt64();
        Assert.StartsWith("adl_", key.Body.GetProperty("token").GetString());
        Assert.Equal(HttpStatusCode.OK, (await f.Send(client, "POST", $"/api/auth/api-keys/{keyId}/revoke", new { }, reviewer)).Status);
        Assert.Empty(await f.DomainsAsync(client));
        var request = await f.Send(client, "POST", Requests, f.Request("domain"), f.RequesterCookie);
        Assert.Equal(HttpStatusCode.Created, request.Status);
        long requestId = Id(request.Body);
        Assert.Equal(HttpStatusCode.OK, (await f.Send(client, "POST", Decision(requestId), f.Decision(), reviewer)).Status);
        Assert.Equal(new long[] { 101 }, await f.DomainsAsync(client));
        Assert.Equal(HttpStatusCode.OK, (await f.Send(client, "POST", Preference, new { pinned = true }, f.RequesterCookie)).Status);
    }

    private const string Requests = "/api/v1/access/report-requests";
    private static string Decision(long id) => Requests + "/" + id + "/decision";
    private const string Preference = "/api/v1/reports/ad.state/preference";
    private static long Id(JsonElement body) => body.GetProperty("item").GetProperty("id").GetInt64();
    private static void Plain((HttpStatusCode Status, JsonElement Body) response, HttpStatusCode status, string error)
    { Assert.Equal(status, response.Status); Assert.Equal(error, response.Body.GetProperty("error").GetString()); Assert.False(response.Body.TryGetProperty("message", out _)); }

    [Theory]
    [InlineData("all")]
    [InlineData("domain")]
    [InlineData("server")]
    public async Task ConcurrentRequestsAndDecisionsProduceOneGrantAndRealScopeWithoutWidening(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AccessRequestFixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        Assert.False((await f.EffectiveAsync(client)).GetProperty("allowed").GetBoolean()); Assert.Empty(await f.DomainsAsync(client));
        // Warm the actual authority reader before mutation; caller field overrides
        // must not replace the published request profile.
        await f.EffectiveAsync(client);
        var payload = f.Request(kind); payload["field_categories"] = new[] { "privilege" };
        var created = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => f.Send(client, "POST", Requests, payload, f.RequesterCookie)));
        Assert.Single(created, r => r.Status == HttpStatusCode.Created);
        Plain(Assert.Single(created, r => r.Status == HttpStatusCode.Conflict), HttpStatusCode.Conflict, "active_request_already_exists");
        var item = created.Single(r => r.Status == HttpStatusCode.Created).Body.GetProperty("item"); long id = item.GetProperty("id").GetInt64();
        Assert.Equal(AccessRequestFixture.Fields, item.GetProperty("requested_field_categories").EnumerateArray().Select(v => v.GetString()));
        Plain(await f.Send(client, "POST", Requests, payload, f.RequesterCookie), HttpStatusCode.Conflict, "active_request_already_exists");
        var other = await f.Send(client, "GET", Requests, null, f.OtherCookie); Assert.Empty(other.Body.GetProperty("items").EnumerateArray());
        var mine = await f.Send(client, "GET", Requests, null, f.RequesterCookie); Assert.Equal(id, Assert.Single(mine.Body.GetProperty("items").EnumerateArray()).GetProperty("id").GetInt64());
        Assert.False(mine.Body.GetProperty("review_allowed").GetBoolean());
        Plain(await f.Send(client, "GET", Requests + "?scope=all", null, f.RequesterCookie), HttpStatusCode.Forbidden, "access_manage_required");
        var all = await f.Send(client, "GET", Requests + "?scope=all&limit=250", null, f.ReviewerCookie);
        Assert.True(all.Body.GetProperty("review_allowed").GetBoolean()); Assert.Contains(all.Body.GetProperty("items").EnumerateArray(), v => v.GetProperty("id").GetInt64() == id);
        Assert.Equal(f.Marker + "published", Assert.Single(mine.Body.GetProperty("items").EnumerateArray()).GetProperty("report_name").GetString());
        Plain(await f.Send(client, "POST", Decision(id), f.Decision(), f.MissingAssignCookie), HttpStatusCode.Forbidden, "access_request_review_required");
        var viewerDecision = await f.Send(client, "POST", Decision(id), f.Decision(), f.RequesterCookie);
        Assert.Equal(HttpStatusCode.Forbidden, viewerDecision.Status);
        var operatorDecision = await f.Send(client, "POST", Decision(id), f.Decision(), f.OperatorCookie); Assert.Equal(HttpStatusCode.Forbidden, operatorDecision.Status);
        var decided = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => f.Send(client, "POST", Decision(id), f.Decision(), f.ReviewerCookie)));
        var success = Assert.Single(decided, r => r.Status == HttpStatusCode.OK).Body.GetProperty("item");
        Plain(Assert.Single(decided, r => r.Status == HttpStatusCode.BadRequest), HttpStatusCode.BadRequest, "access_request_not_pending");
        Assert.Equal("approved", success.GetProperty("status").GetString());
        Plain(await f.Send(client, "POST", Decision(id), f.Decision(), f.ReviewerCookie), HttpStatusCode.BadRequest, "access_request_not_pending");
        var state = await f.StateAsync(id, ct); Assert.Equal(1, state.Grants); Assert.Equal(1, state.DecisionAudits); Assert.Equal(1, state.AssignmentAudits);
        Assert.Equal(f.Reviewer.Id, state.DecidedBy); Assert.NotNull(state.AssignmentId);
        var scope = await f.AssignmentScopeAsync(state.AssignmentId.Value, ct);
        Assert.Equal(kind, scope.GetProperty("kind").GetString());
        if (kind != "all")
        {
            Assert.Equal("101", success.GetProperty("requested_scope_json").GetProperty("ids")[0].GetString());
            Assert.Equal("101", success.GetProperty("granted_scope_json").GetProperty("ids")[0].GetString());
            Assert.Equal(JsonValueKind.Number, scope.GetProperty("ids")[0].ValueKind); Assert.Equal(101, scope.GetProperty("ids")[0].GetInt64());
        }
        var effective = await f.EffectiveAsync(client); Assert.True(effective.GetProperty("allowed").GetBoolean());
        Assert.Equal(AccessRequestFixture.Fields, effective.GetProperty("field_categories").EnumerateArray().Select(v => v.GetString()));
        var domains = await f.DomainsAsync(client);
        Assert.Equal(kind switch { "all" => f.AllDomainIds, "domain" => [101], _ => [] }, domains);
        if (kind == "server")
        {
            var grant = Assert.Single(effective.GetProperty("grants").EnumerateArray());
            Assert.Equal("server", grant.GetProperty("scope").GetProperty("kind").GetString());
            Assert.Equal(101, grant.GetProperty("scope").GetProperty("ids")[0].GetInt64());
        }
        Plain(await f.Send(client, "POST", Requests, f.Request(kind), f.RequesterCookie), HttpStatusCode.BadRequest, "report_already_accessible");
        var preference = await f.Send(client, "POST", Preference, new { pinned = true, focus_metric_keys = new[] { "owned.metric" }, user_id = f.Other.Id }, f.RequesterCookie);
        Assert.Equal(HttpStatusCode.OK, preference.Status); Assert.Equal(f.Requester.Id, preference.Body.GetProperty("item").GetProperty("user_id").GetInt64());
        Plain(await f.Send(client, "POST", Preference, new { pinned = true }, f.OtherCookie), HttpStatusCode.Forbidden, "report_access_denied");
        Plain(await f.Send(client, "POST", Preference, new { pinned = 1 }, f.RequesterCookie), HttpStatusCode.BadRequest, "invalid_report_preference");
        Plain(await f.Send(client, "POST", Preference, new { focus_metric_keys = new[] { "missing.metric" } }, f.RequesterCookie), HttpStatusCode.BadRequest, "invalid_report_preference");
        var clear = await f.Send(client, "POST", Preference + "?ignored=yes", new { focus_metric_keys = Array.Empty<string>() }, f.RequesterCookie);
        Assert.Equal(HttpStatusCode.OK, clear.Status); Assert.True(clear.Body.GetProperty("item").GetProperty("pinned").GetBoolean());
        Assert.Empty(clear.Body.GetProperty("item").GetProperty("view_json").GetProperty("focus_metric_keys").EnumerateArray());
        Assert.True((await f.EffectiveAsync(client)).GetProperty("pinned").GetBoolean());
        await AccessRequestFixture.RecordAsync("approval-" + kind, new { request_id = id, scope_wire = success.GetProperty("granted_scope_json"), assignment_scope = scope, state, domains, preference_owner = f.Requester.Id });
    }

    [Fact]
    public async Task SourceGatesValidationLocalesAndEmptyFieldsFailClosedThenRejectAndLimitedApproval()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AccessRequestFixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        foreach (string lang in new[] { "ru", "en" })
        {
            var missing = await f.Send(client, "POST", Requests, f.Request(), language: lang); Assert.Equal(HttpStatusCode.Unauthorized, missing.Status); Assert.True(missing.Body.TryGetProperty("message", out _));
            var origin = await f.Send(client, "POST", Requests, f.Request(), f.RequesterCookie, origin: "https://invalid.example", language: lang);
            Assert.Equal(HttpStatusCode.Forbidden, origin.Status); Assert.True(origin.Body.TryGetProperty("message", out _));
            Plain(await f.Send(client, "POST", Requests, "{", f.RequesterCookie, language: lang, raw: true), HttpStatusCode.BadRequest, "invalid_json");
        }
        Plain(await f.Send(client, "POST", Requests, f.Request(), key: f.OrdinaryKey), HttpStatusCode.Forbidden, "authenticated_user_required");
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Send(client, "POST", Requests, f.Request(), key: f.RestrictedKey)).Status);
        foreach ((string key, object? value, string error) in new (string, object?, string)[] {
            ("business_reason", "short", "invalid_access_request"), ("scope", null, "request_scope_not_supported"),
            ("scope", new { kind = "domain", ids = new[] { 101 } }, "invalid_request_scope"),
            ("scope", new { kind = "planet" }, "request_scope_not_supported"),
            ("valid_until", DateTimeOffset.UtcNow.AddDays(-1).ToString("o"), "invalid_request_valid_until"),
            ("valid_until", DateTimeOffset.UtcNow.AddDays(31).ToString("o"), "invalid_request_valid_until") })
        { var payload = f.Request(); payload[key] = value; Plain(await f.Send(client, "POST", Requests, payload, f.RequesterCookie), HttpStatusCode.BadRequest, error); }
        var query = await f.Send(client, "GET", Requests + "?limit=&limit=0&limit=99&scope=&Scope=all", null, f.RequesterCookie);
        Assert.Equal(HttpStatusCode.OK, query.Status); Assert.Equal(1, query.Body.GetProperty("limit").GetInt32());
        var clamped = await f.Send(client, "GET", Requests + "?limit=99999999999999999999999999", null, f.RequesterCookie); Assert.Equal(250, clamped.Body.GetProperty("limit").GetInt32());
        using (var offHost = f.Host(auth: false)) using (var off = f.Client(offHost))
        {
            Plain(await f.Send(off, "POST", Requests, f.Request(), f.RequesterCookie), HttpStatusCode.Unauthorized, "operator_token_required");
            Plain(await f.Send(off, "POST", Requests, f.Request(), f.RequesterCookie, operatorToken: "owned-request-operator-token"), HttpStatusCode.Forbidden, "authenticated_user_required");
        }
        await f.ProfileFieldsAsync([], ct);
        var created = await f.Send(client, "POST", Requests, f.Request(), f.RequesterCookie); Assert.Equal(HttpStatusCode.Created, created.Status); long id = Id(created.Body);
        Plain(await f.Send(client, "POST", Decision(id), f.Decision(), f.ReviewerCookie), HttpStatusCode.BadRequest, "decision_may_not_expand_request");
        var emptyState = await f.StateAsync(id, ct); Assert.Equal("submitted", emptyState.Status); Assert.Null(emptyState.DecidedBy); Assert.Equal(0, emptyState.Grants); Assert.Equal(0, emptyState.DecisionAudits);
        var emptyEffective = await f.EffectiveAsync(client); Assert.False(emptyEffective.GetProperty("allowed").GetBoolean()); Assert.Empty(await f.DomainsAsync(client));
        await AccessRequestFixture.RecordAsync("empty-fields", new { state = emptyState, effective_allowed = false, domains = Array.Empty<long>() });
        var rejected = await f.Send(client, "POST", Decision(id), f.Decision("reject"), f.ReviewerCookie); Assert.Equal(HttpStatusCode.OK, rejected.Status); Assert.Equal("rejected", rejected.Body.GetProperty("item").GetProperty("status").GetString());
        Plain(await f.Send(client, "POST", Decision(id), f.Decision("reject"), f.ReviewerCookie), HttpStatusCode.BadRequest, "access_request_not_pending");
        await f.ProfileFieldsAsync(AccessRequestFixture.Fields, ct);
        created = await f.Send(client, "POST", Requests, f.Request(), f.RequesterCookie); Assert.Equal(HttpStatusCode.Created, created.Status); id = Id(created.Body);
        var emptySelection = f.Decision(); emptySelection["field_categories"] = Array.Empty<string>();
        Plain(await f.Send(client, "POST", Decision(id), emptySelection, f.ReviewerCookie), HttpStatusCode.BadRequest, "decision_may_not_expand_request");
        Assert.Equal("submitted", (await f.StateAsync(id, ct)).Status);
        var expanded = f.Decision(); expanded["field_categories"] = new[] { "privilege" };
        Plain(await f.Send(client, "POST", Decision(id), expanded, f.ReviewerCookie), HttpStatusCode.BadRequest, "decision_may_not_expand_request");
        var narrow = f.Decision(); narrow["scope"] = new { kind = "domain", ids = new[] { "101" } };
        var limited = await f.Send(client, "POST", Decision(id), narrow, f.ReviewerCookie); Assert.Equal(HttpStatusCode.OK, limited.Status); Assert.Equal("approved_limited", limited.Body.GetProperty("item").GetProperty("status").GetString());
        Assert.Equal(new long[] { 101 }, await f.DomainsAsync(client));
    }

    [Fact]
    public async Task RealSqlPreservesSourceCommittedStagesAndAssignmentFailureCompensation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AccessRequestFixture.OpenAsync(ct);
        // Inject only named dependency failures; production SQL and T9 writer
        // remain real. A delegate audit writes then fails inside the caller TX.
        foreach (string failure in new[] { "approved-audit", "preview", "rejected-audit", "writer-target", "requested-audit", "preference-audit" })
        {
            await f.ResetOwnRequestsAsync(ct);
            using var host = f.Host(services => {
                if (failure == "preview") { services.RemoveAll<IAccessRequestEvaluator>(); services.AddScoped<IAccessRequestEvaluator>(sp => new FailedPreview(new AccessRequestEvaluator(sp.GetRequiredService<AccessReadService>()))); }
                else if (failure.EndsWith("audit", StringComparison.Ordinal)) { services.RemoveAll<IAccessRequestAudit>(); services.AddSingleton<IAccessRequestAudit>(new FailedAudit(failure)); }
            });
            using var client = f.Client(host);
            var request = f.Request(failure == "writer-target" ? "domain" : "all", "99999999");
            var created = await f.Send(client, "POST", Requests, request, f.RequesterCookie);
            if (failure == "requested-audit")
            {
                Assert.Equal(HttpStatusCode.InternalServerError, created.Status); Assert.False(created.Body.TryGetProperty("message", out _));
                Assert.Equal((0L, 0L, 0L, 0L), await f.CountsAsync(ct));
                await AccessRequestFixture.RecordAsync("failure-" + failure, new { injected_dependency = failure, requests = 0, grants = 0, audits = 0 }); continue;
            }
            Assert.Equal(HttpStatusCode.Created, created.Status); long id = Id(created.Body);
            if (failure == "preference-audit")
            {
                Assert.Equal(HttpStatusCode.OK, (await f.Send(client, "POST", Decision(id), f.Decision(), f.ReviewerCookie)).Status);
                Assert.Equal(HttpStatusCode.InternalServerError, (await f.Send(client, "POST", Preference, new { pinned = true }, f.RequesterCookie)).Status);
                Assert.False((await f.EffectiveAsync(client)).GetProperty("pinned").GetBoolean());
                var counts = await f.CountsAsync(ct); Assert.Equal(0, counts.Preferences); Assert.Equal(3, counts.Audits);
                await AccessRequestFixture.RecordAsync("failure-" + failure, new { injected_dependency = failure, preferences = counts.Preferences, existing_workflow_audits = counts.Audits }); continue;
            }
            var result = await f.Send(client, "POST", Decision(id), f.Decision(failure == "rejected-audit" ? "reject" : "approve"), f.ReviewerCookie);
            var state = await f.StateAsync(id, ct);
            if (failure == "writer-target")
            { Plain(result, HttpStatusCode.BadRequest, "report_scope_target_not_found"); Assert.Equal("submitted", state.Status); Assert.Null(state.DecidedBy); Assert.Equal(0, state.Grants); }
            else
            { Assert.Equal(HttpStatusCode.InternalServerError, result.Status); Assert.False(result.Body.TryGetProperty("message", out _)); Assert.Equal("reviewing", state.Status); Assert.Equal(f.Reviewer.Id, state.DecidedBy); Assert.Equal(failure == "rejected-audit" ? 0 : 1, state.Grants); Assert.Equal(0, state.DecisionAudits); Assert.Null(state.AssignmentId); }
            var domains = await f.DomainsAsync(client); Assert.Equal(state.Grants > 0 ? f.AllDomainIds : [], domains);
            await AccessRequestFixture.RecordAsync("failure-" + failure, new { injected_dependency = failure, http_status = (int)result.Status, state, domains });
        }
    }

    [Fact]
    public async Task CancellationAfterCommittedClaimDoesNotInterruptAcceptedDurableMutation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AccessRequestFixture.OpenAsync(ct); using var cancel = new CancellationTokenSource();
        using var host = f.Host(services => { services.RemoveAll<IReportAssignmentWriter>(); services.AddScoped<IReportAssignmentWriter>(sp => new CancelAfterClaim(new ReportAssignmentWriter(sp.GetRequiredService<IPostgresConnectionFactory>()), cancel)); });
        using var client = f.Client(host);
        var created = await f.Send(client, "POST", Requests, f.Request("domain"), f.RequesterCookie); Assert.Equal(HttpStatusCode.Created, created.Status); long id = Id(created.Body);
        using var scope = host.Services.CreateScope(); var service = scope.ServiceProvider.GetRequiredService<IAccessRequestService>();
        var result = await service.DecideAsync(id, JsonSerializer.SerializeToElement(f.Decision()), f.Reviewer, null, cancel.Token);
        Assert.True(cancel.IsCancellationRequested); Assert.Equal("approved", result.GetProperty("status").GetString());
        var state = await f.StateAsync(id, ct); Assert.Equal(1, state.Grants); Assert.Equal(1, state.DecisionAudits); Assert.Equal(new long[] { 101 }, await f.DomainsAsync(client));
        await AccessRequestFixture.RecordAsync("cancellation", new { injection = "cancel supplied caller token after committed claim before real writer", state, domains = new long[] { 101 } });
    }

    private sealed class FailedAudit(string failure) : IAccessRequestAudit
    {
        public async Task AppendAsync(NpgsqlTransaction transaction, AccessRequestAuditEvent entry, CancellationToken ct)
        {
            await new AccessRequestAudit().AppendAsync(transaction, entry, ct);
            if ((failure, entry.Action) is ("approved-audit", "report_access_request_approved") or ("rejected-audit", "report_access_request_rejected")
                or ("requested-audit", "report_access_requested") or ("preference-audit", "report_preference_updated")) throw new InvalidOperationException("injected_request_audit_failure");
        }
    }
    private sealed class FailedPreview(IAccessRequestEvaluator inner) : IAccessRequestEvaluator
    {
        public Task<RequestAccessView> EvaluateAsync(Principal principal, CancellationToken ct) => inner.EvaluateAsync(principal, ct);
        public Task<JsonElement> PreviewReportAsync(long userId, string reportKey, CancellationToken ct) => throw new InvalidOperationException("injected_post_assignment_preview_failure");
    }
    private sealed class CancelAfterClaim(IReportAssignmentWriter inner, CancellationTokenSource cancel) : IReportAssignmentWriter
    {
        public Task<ReportAssignmentResult> CreateAsync(ReportAssignmentCommand command, AssignmentActor? actor, string? remoteAddress, CancellationToken ct)
        { cancel.Cancel(); Assert.False(ct.CanBeCanceled); return inner.CreateAsync(command, actor, remoteAddress, ct); }
    }
}
