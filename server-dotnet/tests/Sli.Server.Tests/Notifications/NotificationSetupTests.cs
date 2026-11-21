using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Auth;
using Sli.Server.Notifications;
using Xunit;

namespace Sli.Server.Tests.Notifications;

public sealed class NotificationSetupTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static JsonObject J(string value) => JsonNode.Parse(value)!.AsObject();
    private static JsonObject SmtpRequest(long previous = 1, string password = "synthetic-password")
    {
        var body = J(NotificationAdministrationEndpointTests.SmtpSave);
        body.Remove("enabled"); body.Remove("tls_mode"); body["recipients"] = J("{\"7\":\"recipient@example.invalid\"}");
        body["action"] = "smtp_save"; body["user_id"] = 7L; body["previous_revision"] = previous; body["revision"] = previous + 1; body["password"] = password;
        return body;
    }
    [Fact]
    public async Task FreshSetupUsesThePublicOriginForBothChannels()
    {
        var files = new NotificationMemoryFiles();
        var service = new NotificationSetupService(files, new NotificationBotStub(), "https://sli.example.test", native: true);
        await service.HandleAsync(J("""{"action":"token","user_id":7,"token":"1:synthetic"}"""), Ct);
        await service.HandleAsync(SmtpRequest(), Ct);
        foreach (string name in new[] { "telegram.json", "smtp.json" })
            Assert.Equal("https://sli.example.test/app", JsonNode.Parse(files.Read(name))!["base_url"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("https://127.0.0.1:443/app", true)]
    [InlineData("https://127.2.3.4/app", true)]
    [InlineData("https://[::1]:443/app", true)]
    [InlineData("https://localhost/app", true)]
    [InlineData("https://admin.example.test/app", false)]
    public async Task UpgradeRepairsOnlyLoopbackNotificationUrls(string oldUrl, bool repair)
    {
        const string publicOrigin = "https://sli.example.test";
        var files = new NotificationMemoryFiles();
        var bot = new NotificationBotStub();
        await new NotificationSetupService(files, bot, oldUrl).HandleAsync(SmtpRequest(), Ct);
        files.Values["telegram.json"] = Encoding.UTF8.GetBytes(
            $$"""{"recipients": {"7":"123"}, "base_url" : "{{oldUrl}}", "names":{"7":"Example"}, "proxy_url":"http://proxy.example.test:3128"}""");
        files.Values["notification_telegram_token"] = "1:synthetic"u8.ToArray();
        var before = files.Values.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray());
        files.Writes.Clear();

        new NotificationSetupService(files, bot, publicOrigin, native: true).RepairPublicUrls();

        foreach (string name in new[] { "telegram.json", "smtp.json" })
        {
            var expected = repair ? Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(before[name])
                .Replace(oldUrl, publicOrigin + "/app", StringComparison.Ordinal)) : before[name];
            Assert.Equal(expected, files.Read(name));
        }
        Assert.Equal(before["notification_telegram_token"], files.Read("notification_telegram_token"));
        Assert.Equal(before["notification_smtp_password"], files.Read("notification_smtp_password"));
        Assert.DoesNotContain("notification_telegram_token", files.Writes);
        Assert.DoesNotContain("notification_smtp_password", files.Writes);
        Assert.Equal("synthetic-password", SetupSmtpSnapshot.Read(files, 2).Password);
        if (!repair) Assert.Empty(files.Writes);
    }

    [Fact]
    public async Task UpgradeCanResumeBetweenSmtpMarkerAndConfigWrites()
    {
        var files = new NotificationMemoryFiles();
        var bot = new NotificationBotStub();
        await new NotificationSetupService(files, bot, "https://localhost").HandleAsync(SmtpRequest(), Ct);
        var service = new NotificationSetupService(files, bot, "https://sli.example.test", native: true);
        files.FailOn = "smtp.json";
        Assert.Throws<IOException>(service.RepairPublicUrls);
        Assert.Throws<NotificationException>(() => SetupSmtpSnapshot.Read(files, 2));
        files.FailOn = null;
        service.RepairPublicUrls();
        Assert.Equal("https://sli.example.test/app", SetupSmtpSnapshot.Read(files, 2).Config["base_url"]!.GetValue<string>());
        files.Writes.Clear();
        service.RepairPublicUrls();
        Assert.Empty(files.Writes);
    }

    [Fact] public async Task SmtpPublicationUsesReferenceDigestAndIsReadableByExistingSender()
    {
        var files = new NotificationMemoryFiles(); var service = new NotificationSetupService(files, new NotificationBotStub(), "https://sli.invalid");
        await service.HandleAsync(SmtpRequest(), Ct);
        Assert.Equal(new[] { "remove:smtp.ready", "notification_smtp_password", "smtp.json", "smtp.ready" }, files.Writes);
        var marker = JsonNode.Parse(files.Read("smtp.ready"))!.AsObject();
        Assert.Equal("08a62c7beca54bae2be0a007b8c59f3f3fa7033c1012ed4ebdc36eb802ec08da", marker["digest"]!.GetValue<string>());
        var result = SetupSmtpSnapshot.Read(files, 2); Assert.Equal("synthetic-password", result.Password);
        string? Get(string name) => name switch { "SLI_NOTIFICATION_SMTP_CONFIG_FILE" => Path.Combine("synthetic", "smtp.json"), "SLI_NOTIFICATION_SMTP_PASSWORD_FILE" => Path.Combine("synthetic", "notification_smtp_password"), _ => null };
        var settings = SmtpSettingsReader.Read(7, 2, Get, p => files.Read(Path.GetFileName(p)));
        Assert.Equal("mail.invalid", settings.Host); Assert.Equal("recipient@example.invalid", settings.Recipient); Assert.Equal("synthetic-password", settings.Password);
    }
    [Fact] public async Task SmtpPasswordReuseRequiresMatchingPreviousGeneration()
    {
        var files = new NotificationMemoryFiles(); var service = new NotificationSetupService(files, new NotificationBotStub(), "https://sli.invalid");
        await service.HandleAsync(SmtpRequest(), Ct); await service.HandleAsync(SmtpRequest(2, ""), Ct);
        Assert.Equal("synthetic-password", SetupSmtpSnapshot.Read(files, 3).Password);
        var error = await Assert.ThrowsAsync<NotificationException>(() => service.HandleAsync(SmtpRequest(3 + 1, ""), Ct));
        Assert.Equal("smtp_setup_needs_save", error.Code); Assert.Equal(3, JsonNode.Parse(files.Read("smtp.ready"))!["revision"]!.GetValue<int>());
    }
    [Fact] public async Task SmtpCrashCannotPublishMixedPairAsReady()
    {
        var files = new NotificationMemoryFiles(); var service = new NotificationSetupService(files, new NotificationBotStub(), "https://sli.invalid");
        await service.HandleAsync(SmtpRequest(), Ct); files.FailOn = "smtp.json";
        var error = await Assert.ThrowsAsync<NotificationException>(() => service.HandleAsync(SmtpRequest(2, "replacement-synthetic"), Ct));
        Assert.Equal("smtp_setup_unavailable", error.Code); Assert.False(files.Exists("smtp.ready"));
        Assert.Equal("smtp_setup_needs_save", Assert.Throws<NotificationException>(() => SetupSmtpSnapshot.Read(files, 3)).Code);
        var status = await service.HandleAsync(J("{\"action\":\"smtp_status\",\"user_id\":7,\"revision\":3}"), Ct);
        Assert.False(status["secret_set"]!.GetValue<bool>()); Assert.True(status["needs_save"]!.GetValue<bool>()); Assert.Null(status["password"]);
    }
    [Fact] public async Task SmtpStatusIsWriteFreeAndRepairsMalformedMetadataWithoutEchoingBytes()
    {
        var files = new NotificationMemoryFiles(); files.Values["smtp.json"] = Encoding.UTF8.GetBytes("synthetic private malformed bytes");
        var service = new NotificationSetupService(files, new NotificationBotStub(), "https://sli.invalid");
        var status = await service.HandleAsync(J("{\"action\":\"smtp_status\",\"user_id\":7,\"revision\":1}"), Ct);
        Assert.Equal("", status["host"]!.GetValue<string>()); Assert.True(status["needs_save"]!.GetValue<bool>()); Assert.Empty(files.Writes);
        Assert.DoesNotContain("private", status.ToJsonString());
    }
    [Theory] [InlineData("host", "\"host\\r\\nInjected\"")] [InlineData("port", "true")] [InlineData("port", "65536")]
    [InlineData("password", "\"bad\\npassword\"")] [InlineData("sender", "\"bad address\"")] [InlineData("previous_revision", "0")]
    [InlineData("revision", "7")] [InlineData("recipients", "{\"7\":\"=formula\"}")]
    public async Task SmtpMalformedValuesNeverWriteFiles(string key, string value)
    {
        var files = new NotificationMemoryFiles(); var service = new NotificationSetupService(files, new NotificationBotStub(), "https://sli.invalid"); var body = SmtpRequest(); body[key] = JsonNode.Parse(value);
        var error = await Assert.ThrowsAsync<NotificationException>(() => service.HandleAsync(body, Ct)); Assert.Equal("smtp_setup_invalid", error.Code); Assert.Empty(files.Writes);
    }
    [Fact] public async Task TokenVerificationFailureDoesNotDisableExistingChannel()
    {
        await using var h = new NotificationHarness(); h.Bot.Error = "telegram_setup_invalid_token";
        var admin = new NotificationAdministration(h.Repository, h.Client, h.Recipients);
        var error = await Assert.ThrowsAsync<NotificationException>(() => admin.TelegramAsync(h.Principal, "token", J("{\"token\":\"1:synthetic\"}"), Ct));
        Assert.Equal("telegram_setup_invalid_token", error.Code); Assert.True(h.Repository.Enabled); Assert.Equal(1, h.Repository.Revision);
        Assert.Equal(new[] { "telegram:token:requested" }, h.Repository.Operations); Assert.Empty(h.Files.Writes);
    }
    [Fact] public async Task FailedIntentAuditPreventsSecretAndTransportAccess()
    {
        await using var h = new NotificationHarness(); h.Repository.Throw = true;
        var admin = new NotificationAdministration(h.Repository, h.Client, h.Recipients);
        await Assert.ThrowsAsync<IOException>(() => admin.TelegramAsync(h.Principal, "token", J("{\"token\":\"1:synthetic\"}"), Ct));
        Assert.Empty(h.Client.Calls); Assert.Empty(h.Bot.Calls); Assert.Empty(h.Files.Writes);
    }
    [Fact] public async Task SuccessfulTokenReplacementResetsBindingsAndAuditsEveryPhase()
    {
        await using var h = new NotificationHarness(); h.Files.Values["telegram.json"] = Encoding.UTF8.GetBytes("{\"base_url\":\"https://sli.invalid/app\",\"recipients\":{\"7\":\"123\"},\"names\":{\"7\":\"Old\"}}");
        var admin = new NotificationAdministration(h.Repository, h.Client, h.Recipients);
        await admin.TelegramAsync(h.Principal, "token", J("{\"token\":\"2:synthetic-new\"}"), Ct);
        Assert.Equal(new[] { "telegram:token:requested", "telegram:token:verified", "telegram:token:completed" }, h.Repository.Operations);
        Assert.Equal(new[] { "verify", "token" }, h.Client.Calls); Assert.False(h.Repository.Enabled);
        Assert.Empty(JsonNode.Parse(h.Files.Read("telegram.json"))!["recipients"]!.AsObject());
    }
    [Fact] public async Task ChatChoicesOnlyIncludePrivateStartAndAreUserBoundAndSingleUse()
    {
        await using var h = new NotificationHarness();
        var result = await new NotificationAdministration(h.Repository, h.Client, h.Recipients).TelegramAsync(h.Principal, "chats", new(), Ct);
        var chats = result["chats"]!.AsArray(); Assert.Single(chats); Assert.Equal("Synthetic", chats[0]!["name"]!.GetValue<string>());
        Assert.DoesNotContain("123", result.ToJsonString());
        string choice = chats[0]!["choice"]!.GetValue<string>();
        var other = new JsonObject { ["action"] = "bind", ["user_id"] = 8L, ["choice"] = choice };
        Assert.Equal("telegram_setup_failed", (await Assert.ThrowsAsync<NotificationException>(() => h.Service.HandleAsync(other, Ct))).Code);
        other["user_id"] = 7L; await h.Service.HandleAsync(other, Ct);
        Assert.Equal("telegram_setup_failed", (await Assert.ThrowsAsync<NotificationException>(() => h.Service.HandleAsync(other, Ct))).Code);
        Assert.Equal("123", JsonNode.Parse(h.Files.Read("telegram.json"))!["recipients"]!["7"]!.GetValue<string>());
    }
    private sealed class TestClock : TimeProvider { public DateTimeOffset Now = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => Now; }
    [Fact] public async Task ChatChoiceExpiresAfterFiveMinutes()
    {
        var files = new NotificationMemoryFiles(); files.Values["notification_telegram_token"] = Encoding.UTF8.GetBytes("1:synthetic"); var clock = new TestClock();
        var service = new NotificationSetupService(files, new NotificationBotStub(), "https://sli.invalid", clock: clock);
        var probe = await service.HandleAsync(J("{\"action\":\"chat_generation\",\"user_id\":7}"), Ct);
        var chats = await service.HandleAsync(new JsonObject { ["action"] = "chats", ["user_id"] = 7L,
            ["generation"] = probe["generation"]!.DeepClone(),
            ["observations"] = new JsonArray(J("{\"id\":123,\"name\":\"Synthetic\"}")) }, Ct);
        clock.Now += TimeSpan.FromMinutes(5);
        var error = await Assert.ThrowsAsync<NotificationException>(() => service.HandleAsync(new JsonObject { ["action"] = "bind", ["user_id"] = 7L, ["choice"] = chats["chats"]![0]!["choice"]!.DeepClone() }, Ct));
        Assert.Equal("telegram_setup_failed", error.Code); Assert.Empty(files.Writes);
    }
    [Fact] public async Task BindAndSetupTestUseChannelAuditAndAuthenticatedSelf()
    {
        await using var h = new NotificationHarness(); var admin = new NotificationAdministration(h.Repository, h.Client, h.Recipients);
        var chats = await admin.TelegramAsync(h.Principal, "chats", new(), Ct);
        await admin.TelegramAsync(h.Principal, "bind", new JsonObject { ["choice"] = chats["chats"]![0]!["choice"]!.DeepClone() }, Ct);
        await admin.TelegramAsync(h.Principal, "test", new(), Ct);
        Assert.Contains("channel:subscription:save", h.Repository.Operations); Assert.Contains("channel:test:enqueue", h.Repository.Operations);
        Assert.True(h.Repository.Enabled);
    }
    [Fact] public async Task SmtpApiChecksRecipientsBeforeReservingAndFailureLeavesChannelDisabled()
    {
        await using var h = new NotificationHarness(); var admin = new NotificationAdministration(h.Repository, h.Client, h.Recipients);
        h.Recipients.Denied.Add(7);
        var denied = await Assert.ThrowsAsync<NotificationException>(() => admin.SmtpAsync(h.Principal, "save", J(NotificationAdministrationEndpointTests.SmtpSave), Ct));
        Assert.Equal(403, denied.Status); Assert.True(h.Repository.Enabled); Assert.DoesNotContain("smtp:save:reserve", h.Repository.Operations);
        h.Recipients.Denied.Clear(); h.Files.FailOn = "smtp.json";
        await Assert.ThrowsAsync<NotificationException>(() => admin.SmtpAsync(h.Principal, "save", J(NotificationAdministrationEndpointTests.SmtpSave), Ct));
        Assert.False(h.Repository.Enabled); Assert.Equal(2, h.Repository.Revision); Assert.DoesNotContain("smtp:save:completed", h.Repository.Operations); Assert.Contains("channel:subscription:save", h.Repository.Operations);
    }
    [Theory] [InlineData("http://proxy.invalid:8080", true)] [InlineData("http://u:p@proxy.invalid:8080", false)] [InlineData("http://proxy.invalid:8080/", false)] [InlineData("http://999.1.1.1:80", false)] [InlineData("https://proxy.invalid:8080", false)]
    public void ProxyContractIsCredentialFree(string value, bool valid)
    { var error = Record.Exception(() => NotificationInput.Proxy(value)); Assert.Equal(valid, error is null); if (error is NotificationException ex) Assert.Equal("telegram_setup_invalid_proxy", ex.Code); }
    [Theory] [InlineData("smtp_status", "{\"error\":\"untrusted secret\"}", "smtp_setup_unavailable")]
    [InlineData("status", "{\"error\":\"telegram_setup_timeout\"}", "telegram_setup_timeout")]
    [InlineData("status", "{\"error\":\"telegram_setup_timeout\",\"token\":\"synthetic\"}", "telegram_setup_unavailable")]
    [InlineData("status", "{\"secret_set\":true,\"chat_bound\":true,\"token\":\"synthetic\"}", "telegram_setup_unavailable")]
    [InlineData("status", "[]", "telegram_setup_unavailable")]
    public void SocketErrorsAndStatusAreAllowlisted(string action, string raw, string code)
    { Assert.Equal(code, Assert.Throws<NotificationException>(() => NotificationSetupClient.ParseResponse(action, Encoding.UTF8.GetBytes(raw))).Code); }
    [Theory] [InlineData(302, "{}", "telegram_setup_protocol")] [InlineData(429, "{}", "telegram_setup_rate_limited")]
    [InlineData(503, "{}", "telegram_setup_provider_unavailable")] [InlineData(401, "{\"ok\":false,\"error_code\":401}", "telegram_setup_invalid_token")]
    [InlineData(409, "{\"ok\":false,\"error_code\":409}", "telegram_setup_conflict")] [InlineData(200, "{\"ok\":true,\"result\":{\"is_bot\":false}}", "telegram_setup_protocol")]
    public void ProviderResponsesNeverExposeRawBody(int status, string body, string code)
    { Assert.Equal(code, Assert.Throws<NotificationException>(() => NotificationSetupBot.Parse("getMe", status, Encoding.UTF8.GetBytes(body))).Code); }

    [Fact] public void CursorReadsFrozenPythonVectorAndBindsAllFilters()
    {
        const string token = "eyJiaW5kaW5nIjoiMzFkOGJlMTA1OGQwOTQ0NTA5MWZjYTNmOTVlMzNlMjEwYjY5YzA3MTAxYjcyZmM3ZDkzNzljOWEzYTlhZGRkMSIsInBvc2l0aW9uIjp7InRpbWUiOiIyMDI2LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDgifX0";
        var context = new DefaultHttpContext(); context.Request.QueryString = new QueryString("?cursor=" + token);
        var query = NotificationWorkspaceQuery.Parse(context.Request.Query); Assert.NotNull(query.Before); Assert.Equal(Guid.Parse(NotificationRepositoryStub.JobId), query.BeforeId);
        context.Request.QueryString = new QueryString("?days=30&cursor=" + token);
        Assert.Equal("invalid_notification_request", Assert.Throws<NotificationException>(() => NotificationWorkspaceQuery.Parse(context.Request.Query)).Code);
    }
    [Theory] [InlineData("?days=2")] [InlineData("?channel=other")] [InlineData("?status=accepted%27")] [InlineData("?finding_id=0")] [InlineData("?finding_id=9223372036854775808")] [InlineData("?cursor=invalid")]
    public void WorkspaceRejectsMalformedFiltersAndCursor(string query)
    { var c = new DefaultHttpContext(); c.Request.QueryString = new QueryString(query); Assert.Throws<NotificationException>(() => NotificationWorkspaceQuery.Parse(c.Request.Query)); }
    [Theory] [InlineData("?days=0_7&finding_id=1_2")] [InlineData("?days=%D9%A0%D9%A7&finding_id=%D9%A1%D9%A2")]
    public void WorkspaceUsesPythonQueryIntegerSemantics(string query)
    { var c = new DefaultHttpContext(); c.Request.QueryString = new QueryString(query); var parsed = NotificationWorkspaceQuery.Parse(c.Request.Query); Assert.Equal(7, parsed.Days); Assert.Equal(12, parsed.Finding); }

    [Fact] public async Task ActualUnixSocketProtocolIsBoundedAndServiceSurvivesMalformedRequest()
    {
        string path = Path.Combine(Path.GetTempPath(), "sli-setup-" + Guid.NewGuid().ToString("N")[..12]);
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified); listener.Bind(new UnixDomainSocketEndPoint(path)); listener.Listen(4);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct); var files = new NotificationMemoryFiles();
        var service = new NotificationSetupService(files, new NotificationBotStub(), "https://sli.invalid");
        var serving = NotificationSetupCommand.ServeAsync(listener, service, false, stop.Token);
        async Task<JsonObject> Send(byte[] bytes)
        {
            using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified); await client.ConnectAsync(new UnixDomainSocketEndPoint(path), Ct);
            using var stream = new NetworkStream(client); await stream.WriteAsync(bytes, Ct); return JsonNode.Parse(await NotificationSetupClient.ReadLineAsync(stream, Ct))!.AsObject();
        }
        try
        {
            var bad = await Send(Encoding.UTF8.GetBytes("[]\n")); Assert.Equal("telegram_setup_unavailable", bad["error"]!.GetValue<string>());
            var status = await Send(Encoding.UTF8.GetBytes("{\"action\":\"smtp_status\",\"user_id\":7,\"revision\":1}\n")); Assert.False(status["secret_set"]!.GetValue<bool>());
            var tooLarge = new byte[65537]; Array.Fill(tooLarge, (byte)' '); tooLarge[^1] = 10;
            var oversized = await Send(tooLarge); Assert.Equal("telegram_setup_unavailable", oversized["error"]!.GetValue<string>());
        }
        finally { stop.Cancel(); try { await serving; } catch (OperationCanceledException) { } File.Delete(path); }
    }
    [Fact] public async Task SetupCommandRejectsUnknownArgumentsBeforeAnyHostAccess()
    { Assert.Equal(1, await NotificationSetupCommand.RunAsync(["--untrusted"])); }
}
