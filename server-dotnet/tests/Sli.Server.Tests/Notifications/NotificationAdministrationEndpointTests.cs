using System.Net;
using System.Text.Json.Nodes;
using Sli.Server.Auth;
using Sli.Server.Notifications;
using Xunit;

namespace Sli.Server.Tests.Notifications;

public sealed class NotificationAdministrationEndpointTests
{
    private const string C = NotificationAdministrationEndpoints.Channels;
    private const string S = NotificationAdministrationEndpoints.Subscriptions;
    public const string SmtpSave = """
        {"host":"mail.invalid","port":587,"username":"synthetic","sender":"sender@example.invalid","password":"synthetic-password",
         "recipients":[{"user_id":7,"mailbox":"recipient@example.invalid"}],"revision":1,"tls_mode":"starttls","enabled":true}
        """;
    public static TheoryData<string, string, string?> Routes => new()
    {
        { "GET", C, null }, { "GET", C + "/workspace", null }, { "POST", C + "/smtp", "{\"enabled\":true,\"tls_mode\":\"tls\",\"secret_ref\":\"SLI_NOTIFY_SMTP_PASSWORD\",\"revision\":1}" },
        { "POST", C + "/smtp/setup/status", "{}" }, { "POST", C + "/smtp/setup/save", SmtpSave },
        { "POST", C + "/telegram/setup/status", "{}" }, { "POST", C + "/telegram/setup/token", "{\"token\":\"1:synthetic\"}" },
        { "POST", C + "/telegram/setup/chats", "{}" }, { "POST", C + "/telegram/setup/bind", "{\"choice\":\"replace\"}" }, { "POST", C + "/telegram/setup/test", "{}" },
        { "GET", S, null }, { "POST", S, "{\"recipient_user_id\":7,\"channel\":\"telegram\",\"enabled\":true}" },
        { "POST", S + "/" + NotificationRepositoryStub.SubscriptionId, "{\"recipient_user_id\":7,\"channel\":\"telegram\",\"enabled\":false,\"revision\":1}" },
        { "POST", S + "/" + NotificationRepositoryStub.SubscriptionId + "/test", "{\"problem_id\":\"00000000-0000-0000-0000-000000000009\"}" }
    };
    private static async Task<JsonObject> Json(HttpResponseMessage response) => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRouteSucceedsWithReferenceShape(string method, string path, string? body)
    {
        await using var h = new NotificationHarness();
        if (path.EndsWith("/bind", StringComparison.Ordinal))
        {
            var choices = await h.Service.HandleAsync(JsonNode.Parse("{\"action\":\"chats\",\"user_id\":7}")!.AsObject(), TestContext.Current.CancellationToken);
            body = new JsonObject { ["choice"] = choices["chats"]![0]!["choice"]!.DeepClone() }.ToJsonString();
        }
        using var response = await h.Request(method, path, body);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store, max-age=0", response.Headers.CacheControl?.ToString());
        var result = await Json(response);
        if (method == "GET" && path != C + "/workspace") Assert.IsType<JsonArray>(result["items"]);
        else if (path == C + "/workspace")
        {
            Assert.Equal(new[] { "can_configure", "channels", "counts", "has_more", "items", "next_cursor", "previous_login_at", "subscriptions" }, result.Select(p => p.Key).Order().ToArray());
            Assert.True(result["can_configure"]!.GetValue<bool>());
        }
        else if (path == C + "/smtp/setup/status")
        {
            Assert.Equal(7, result["self_user_id"]!.GetValue<int>());
            Assert.Null(result["password"]); Assert.Single(result["recipients"]!.AsArray()); Assert.False(result["secret_set"]!.GetValue<bool>());
        }
        else if (path.EndsWith("/telegram/setup/status", StringComparison.Ordinal)) Assert.True(result.ContainsKey("test_state"));
        else if (path.EndsWith("/telegram/setup/test", StringComparison.Ordinal)) Assert.Equal("pending", result["state"]!.GetValue<string>());
        else if (!path.Contains("/setup/", StringComparison.Ordinal)) Assert.IsType<JsonObject>(result["item"]);
        Assert.DoesNotContain("synthetic-password", result.ToJsonString());
    }

    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRouteRejectsMissingReportBeforeSideEffects(string method, string path, string? body)
    {
        await using var h = new NotificationHarness { Reports = false };
        using var response = await h.Request(method, path, body);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(path.StartsWith(C, StringComparison.Ordinal) ? "notification_channels_access_denied" : "notifications_access_denied", (await Json(response))["error"]!.GetValue<string>());
        Assert.Empty(h.Repository.Operations); Assert.Empty(h.Client.Calls); Assert.Empty(h.Files.Writes);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRouteRequiresAuthentication(string method, string path, string? body)
    {
        await using var h = new NotificationHarness { Authenticated = false };
        using var response = await h.Request(method, path, body); Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); Assert.Empty(h.Repository.Operations);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRouteHandlesInvalidInputAccordingToItsContract(string method, string path, string? body)
    {
        await using var h = new NotificationHarness();
        Assert.Equal(method == "POST", body is not null);
        if (method == "GET")
        {
            // Registry reads take no input and the reference ignores unknown query keys.
            using var get = await h.Request(method, path + (path.EndsWith("/workspace", StringComparison.Ordinal) ? "?days=2" : "?invalid=anything"));
            Assert.Equal(path.EndsWith("/workspace", StringComparison.Ordinal) ? HttpStatusCode.BadRequest : HttpStatusCode.OK, get.StatusCode); return;
        }
        using var response = await h.Request(method, path, "{\"unexpected\":\"synthetic secret\"}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        string expected = path.Contains("/smtp/setup/", StringComparison.Ordinal) ? "smtp_setup_invalid" : path.StartsWith(C, StringComparison.Ordinal) ? "invalid_notification_channel_metadata" : "invalid_notification_request";
        Assert.Equal(expected, (await Json(response))["error"]!.GetValue<string>()); Assert.Empty(h.Client.Calls); Assert.Empty(h.Files.Writes);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRouteFailsClosedWhenDatabaseIsUnavailable(string method, string path, string? body)
    {
        await using var h = new NotificationHarness(); h.Repository.Throw = true;
        using var response = await h.Request(method, path, body);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        string json = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("private diagnostic", json); Assert.DoesNotContain("synthetic-password", json);
    }
    [Theory] [InlineData("viewer")] [InlineData("operator")]
    public async Task CoarseRoleCannotBeUpgradedByReportGrants(string role)
    {
        await using var h = new NotificationHarness { Principal = new("session", 7, role) };
        using var get = await h.Request("GET", C); Assert.Equal(HttpStatusCode.Forbidden, get.StatusCode);
        using var post = await h.Request("POST", C + "/smtp/setup/status", "{}"); Assert.Equal(HttpStatusCode.Forbidden, post.StatusCode); Assert.Empty(h.Repository.Operations);
    }
    [Theory] [InlineData(false, "{\"kind\":\"all\"}")] [InlineData(true, "{\"kind\":\"domain\",\"ids\":[1]}")]
    public async Task GlobalCapabilityAndAtomicGlobalScopeAreBothRequired(bool cap, string scope)
    {
        await using var h = new NotificationHarness { GlobalCapability = cap, Scope = scope };
        using var response = await h.Request("GET", C); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(h.Repository.Operations);
    }
    [Fact] public async Task WorkspaceNeedsIndependentDeliveriesGrant()
    {
        await using var h = new NotificationHarness { Deliveries = false };
        using var response = await h.Request("GET", C + "/workspace"); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(h.Repository.Operations);
    }
    [Fact] public async Task ReadOnlyChannelGrantCannotConfigure()
    {
        await using var h = new NotificationHarness { Configure = false };
        using var read = await h.Request("GET", C + "/workspace"); Assert.Equal(HttpStatusCode.OK, read.StatusCode); Assert.False((await Json(read))["can_configure"]!.GetValue<bool>());
        using var write = await h.Request("POST", C + "/smtp/setup/status", "{}"); Assert.Equal(HttpStatusCode.Forbidden, write.StatusCode); Assert.Empty(h.Client.Calls);
    }
    [Fact] public async Task FindingFilterRequiresGlobalSecurityQueueAccess()
    {
        await using var h = new NotificationHarness { Queue = false };
        using var response = await h.Request("GET", C + "/workspace?finding_id=7"); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(h.Repository.Operations);
    }
    [Theory] [InlineData("smtp/setup/status")] [InlineData("telegram/setup/token")]
    public async Task SetupRequiresSessionPrincipal(string suffix)
    {
        await using var h = new NotificationHarness { Principal = new("api_key", 7, "admin") };
        using var response = await h.Request("POST", C + "/" + suffix, suffix.EndsWith("token", StringComparison.Ordinal) ? "{\"token\":\"1:synthetic\"}" : "{}");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(h.Client.Calls);
    }
    [Theory] [InlineData(C + "/smtp/setup/status")] [InlineData(C + "/telegram/setup/status")] [InlineData(S)] [InlineData(S + "/" + NotificationRepositoryStub.SubscriptionId)]
    public async Task NonSessionIsRejectedBeforeMalformedBodyIsRead(string path)
    {
        await using var h = new NotificationHarness { Principal = new("api_key", 7, "admin") };
        using var response = await h.Request("POST", path, "malformed"); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(h.Client.Calls); Assert.Empty(h.Repository.Operations);
    }
    [Fact] public async Task RegistryGetPreservesOuterCapabilityErrorContract()
    {
        await using var h = new NotificationHarness { GlobalCapability = false };
        using var response = await h.Request("GET", C); var result = await Json(response);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal("resource_context_required", result["error"]!.GetValue<string>()); Assert.Equal("access.manage", result["required_capability"]!.GetValue<string>());
    }
    [Theory] [InlineData("enabled", "\"true\"")] [InlineData("revision", "true")] [InlineData("revision", "1.0")]
    [InlineData("revision", "9223372036854775807")] [InlineData("secret_ref", "\"/arbitrary/path\"")] [InlineData("tls_mode", "\"plain\"")]
    public async Task ChannelRejectsInvalidMetadataWithoutDatabaseWrite(string key, string json)
    {
        await using var h = new NotificationHarness(); var body = JsonNode.Parse("{\"enabled\":true,\"tls_mode\":\"tls\",\"secret_ref\":\"SLI_NOTIFY_SMTP_PASSWORD\",\"revision\":1}")!.AsObject(); body[key] = JsonNode.Parse(json);
        using var response = await h.Request("POST", C + "/smtp", body.ToJsonString()); Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Empty(h.Repository.Operations);
    }
    [Fact] public async Task CrossOriginMutationIsDeniedBeforeAnyGrantOrInputRead()
    {
        await using var h = new NotificationHarness();
        using var response = await h.Request("POST", C + "/smtp/setup/save", "malformed", "https://attacker.invalid");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal("cross_origin_request_rejected", (await Json(response))["error"]!.GetValue<string>()); Assert.Empty(h.Repository.Operations);
    }
    [Fact] public async Task ChannelRevisionConflictIs409()
    {
        await using var h = new NotificationHarness(); h.Repository.Revision = 2;
        using var response = await h.Request("POST", C + "/smtp", "{\"enabled\":true,\"tls_mode\":\"tls\",\"secret_ref\":\"SLI_NOTIFY_SMTP_PASSWORD\",\"revision\":1}");
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode); Assert.Equal("notification_channel_revision_conflict", (await Json(response))["error"]!.GetValue<string>());
    }
    [Fact] public async Task MalformedSubscriptionIdIs400InsteadOfFallback501()
    { await using var h = new NotificationHarness(); using var response = await h.Request("POST", S + "/invalid", "{\"recipient_user_id\":7,\"channel\":\"smtp\",\"enabled\":false,\"revision\":1}"); Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); }
    [Theory] [InlineData("smtp_setup_conflict", 409)] [InlineData("smtp_setup_needs_save", 409)] [InlineData("smtp_setup_unavailable", 503)]
    public async Task SmtpErrorsHaveReferenceMessageAndStatus(string code, int status)
    {
        await using var h = new NotificationHarness(); h.Client.Error = code;
        using var response = await h.Request("POST", C + "/smtp/setup/status", "{}"); Assert.Equal(status, (int)response.StatusCode);
        var body = await Json(response); Assert.Equal(code, body["error"]!.GetValue<string>()); Assert.Equal("notifications.smtp.setup." + code[11..], body["message"]!["code"]!.GetValue<string>());
    }
    [Theory] [InlineData("telegram_setup_invalid_token", 400)] [InlineData("telegram_setup_timeout", 504)] [InlineData("telegram_setup_tls", 503)] [InlineData("telegram_setup_rate_limited", 429)] [InlineData("telegram_setup_protocol", 502)]
    public async Task TelegramErrorsHaveReferenceStatus(string code, int status)
    {
        await using var h = new NotificationHarness(); h.Client.Error = code;
        using var response = await h.Request("POST", C + "/telegram/setup/status", "{}"); Assert.Equal(status, (int)response.StatusCode); Assert.Equal(code, (await Json(response))["error"]!.GetValue<string>());
    }
}
