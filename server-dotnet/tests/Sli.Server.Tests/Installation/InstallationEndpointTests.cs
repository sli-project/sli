using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Auth;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class InstallationEndpointTests
{
    public static TheoryData<string, string, string?, int, string> Routes => new() {
        { "GET", "/api/v1/setup/status", null, 200, "steps" },
        { "GET", "/api/v1/setup/domains", null, 200, "items" },
        { "POST", "/api/v1/setup/domains", "{\"fqdn\":\" NEW.test \",\"netbios_name\":\"new\"}", 201, "item" },
        { "POST", "/api/v1/setup/domains/example.test", "{\"netbios_name\":\"example\"}", 200, "item" },
        { "GET", "/api/v1/setup/domain-controllers", null, 200, "items" },
        { "POST", "/api/v1/setup/domain-controllers", "{\"hostname\":\"dc2.example.test\",\"domain\":\"example.test\"}", 201, "item" },
        { "POST", "/api/v1/setup/domain-controllers/dc", "{\"enabled\":false}", 200, "item" },
        { "GET", "/api/v1/platform-settings", null, 200, "items" },
        { "POST", "/api/v1/platform-settings/ad.inactivity_days", "{\"value\":\"30\"}", 200, "item" },
        { "GET", "/api/v1/plugins", null, 200, "items" },
        { "POST", "/api/v1/plugins/sli.ad", "{\"enabled\":false,\"expected_revision\":1}", 200, "item" },
        { "GET", "/api/v1/operations/plugins", null, 200, "items" },
        { "GET", "/api/v1/operations/plugins/sli.remote-access", null, 200, "item" },
        { "GET", "/api/plugins/sli.ad/settings", null, 200, "values" },
        { "PUT", "/api/plugins/sli.ad/settings", "{\"key\":\"ad.password_max_age_days\",\"value\":30}", 200, "value" },
        { "GET", "/api/v1/ui/plugins/sli.ad/descriptor", null, 200, "entry" },
        { "GET", "/api/v1/ui/plugins/sli.ad/assets/HASH/entry.js", null, 200, "asset" }
    };

    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteRunsTheNativeService(string method, string path, string? body, int expected, string field)
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        var result = await f.SendAsync(method, path, body);
        Assert.Equal(expected, result.Status);
        if (field == "asset") Assert.Equal(Encoding.UTF8.GetString(f.Asset), result.Body.GetValue<string>());
        else Assert.True(result.Body.AsObject().ContainsKey(field), result.Body.ToJsonString());
        if (method is "POST" or "PUT")
        {
            Assert.True(f.Database.Commits > 0);
            if (path.StartsWith("/api/v1/plugins/", StringComparison.Ordinal))
            {
                var call = Assert.Single(f.Database.Calls, c => c.Sql.Contains("set_plugin_enabled_v1", StringComparison.Ordinal));
                Assert.Equal("session", call.Args[3]); Assert.Equal(1L, call.Args[4]);
            }
            else
            {
                var audit = Assert.Single(f.Database.Calls, c => c.Sql.Contains("insert into access_audit_v4", StringComparison.Ordinal));
                Assert.True(audit.Write); Assert.Equal("session", audit.Args[0]); Assert.Equal(1L, audit.Args[1]);
                Assert.StartsWith(path.Contains("platform-settings", StringComparison.Ordinal) || path.StartsWith("/api/plugins/", StringComparison.Ordinal) ? "platform_setting_update" : "setup_", (string)audit.Args[2]!);
            }
        }
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteDeniesBeforeReadingOrWritingData(string method, string path, string? body, int _, string __)
    {
        Assert.True(_ is 200 or 201); Assert.NotEmpty(__);
        await using var f = new InstallationFixture { Deny = true }; await f.StartAsync();
        var result = await f.SendAsync(method, path, method == "GET" ? body : "not JSON");
        Assert.Equal(403, result.Status); Assert.Empty(f.Database.Calls); Assert.NotNull(result.Body["required_capability"]);
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteRequiresAuthentication(string method, string path, string? body, int _, string __)
    {
        Assert.True(_ is 200 or 201); Assert.NotEmpty(__);
        await using var f = new InstallationFixture { Authenticated = false }; await f.StartAsync();
        var result = await f.SendAsync(method, path, body);
        Assert.Equal(401, result.Status); Assert.Empty(f.Database.Calls);
    }

    public static TheoryData<string, string, string?, int, string?> Inputs => new() {
        { "GET", "/api/v1/setup/status?unexpected=%ff&unexpected=x", null, 200, null },
        { "GET", "/api/v1/setup/domains?fqdn=bad!", null, 200, null },
        { "POST", "/api/v1/setup/domains", "{\"fqdn\":\"bad!\"}", 400, "value_must_be_dns_name" },
        { "POST", "/api/v1/setup/domains/bad!", "{}", 400, "value_must_be_dns_name" },
        { "GET", "/api/v1/setup/domain-controllers?enabled=invalid", null, 200, null },
        { "POST", "/api/v1/setup/domain-controllers", "{\"hostname\":\"192.0.2.1\",\"domain\":\"example.test\"}", 400, "connect_address_must_be_fqdn" },
        { "POST", "/api/v1/setup/domain-controllers/dc", "{\"enabled\":1}", 400, "enabled_must_be_boolean" },
        { "GET", "/api/v1/platform-settings?key=unknown", null, 200, null },
        { "POST", "/api/v1/platform-settings/ad.inactivity_days", "{\"value\":0}", 400, "value_must_be_days_1_3650" },
        { "GET", "/api/v1/plugins?enabled=invalid", null, 200, null },
        { "POST", "/api/v1/plugins/sli.ad", "{\"enabled\":true,\"expected_revision\":true}", 400, "plugin_state_request_invalid" },
        { "GET", "/api/v1/operations/plugins?limit=invalid", null, 200, null },
        { "GET", "/api/v1/operations/plugins/%20", null, 400, "invalid_plugin_id" },
        { "GET", "/api/plugins/unknown/settings", null, 404, "plugin_settings_not_found" },
        { "PUT", "/api/plugins/sli.ad/settings", "{\"key\":\"ad.inactivity_days\",\"value\":\"30\"}", 400, "invalid_plugin_setting_value" },
        { "GET", "/api/v1/ui/plugins/invalid!/descriptor", null, 503, "plugin_ui_invalid_descriptor" },
        { "GET", "/api/v1/ui/plugins/sli.ad/assets/wrong/entry.js", null, 409, "plugin_ui_integrity_failed" }
    };
    [Theory, MemberData(nameof(Inputs))]
    public async Task InputErrorsAndIgnoredReadParametersMatchSource(string method, string path, string? body, int expected, string? error)
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        var result = await f.SendAsync(method, path, body);
        Assert.Equal(expected, result.Status);
        if (error is not null) Assert.Equal(error, result.Body["error"]!.GetValue<string>());
        if (method is "POST" or "PUT") Assert.Equal(0, f.Database.Commits);
    }
    [Theory]
    [InlineData("plugin_revision_conflict", 409, "plugin_revision_conflict")]
    [InlineData("plugin_active_leases", 409, "plugin_active_leases")]
    [InlineData("plugin_queue_not_drained", 409, "plugin_queue_not_drained")]
    [InlineData("plugin_not_found", 404, "plugin_not_found")]
    [InlineData("plugin enable precondition failed", 409, "plugin_runtime_precondition_failed")]
    [InlineData("injected private database detail", 409, "plugin_state_conflict")]
    public async Task LifecycleConflictsAreAllowlisted(string message, int status, string error)
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, args) => sql.Contains("set_plugin_enabled_v1", StringComparison.Ordinal) ? throw new PostgresException(message, "ERROR", "ERROR", "P0001") : null;
        await f.StartAsync(); var result = await f.SendAsync("POST", "/api/v1/plugins/sli.ad", "{\"enabled\":false,\"expected_revision\":1}");
        Assert.Equal(status, result.Status); Assert.Equal(error, result.Body["error"]!.GetValue<string>()); Assert.Equal(1, f.Database.Rollbacks);
    }
    [Theory]
    [InlineData("viewer", "api_key", true, false)]
    [InlineData("viewer", "session", true, true)]
    [InlineData("viewer", "session", false, false)]
    [InlineData("admin", "api_key", false, true)]
    public async Task LifecycleAuthorityRequiresOwnerSessionOrAdmin(string role, string type, bool owner, bool allowed)
    {
        await using var f = new InstallationFixture { Principal = new(type, 1, role, "alice"), Owner = owner }; await f.StartAsync();
        var result = await f.SendAsync("POST", "/api/v1/plugins/sli.ad", "{\"enabled\":false,\"expected_revision\":1}");
        Assert.Equal(allowed ? 200 : 403, result.Status);
        if (!allowed) { Assert.Equal("plugin_management_owner_or_admin_required", result.Body["error"]!.GetValue<string>()); Assert.Empty(f.Database.Calls); }
    }
    [Theory]
    [InlineData("POST", "/api/v1/setup/domains", "{\"fqdn\":\"new.test\"}")]
    [InlineData("POST", "/api/v1/setup/domain-controllers", "{\"hostname\":\"dc2.example.test\",\"domain\":\"example.test\"}")]
    [InlineData("POST", "/api/v1/platform-settings/ad.inactivity_days", "{\"value\":\"30\"}")]
    [InlineData("PUT", "/api/plugins/sli.ad/settings", "{\"key\":\"ad.inactivity_days\",\"value\":30}")]
    public async Task AuditFailureRollsBackTheMutation(string method, string path, string body)
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.Contains("insert into access_audit_v4", StringComparison.Ordinal) ? throw new InvalidOperationException("synthetic-audit-failure") : null;
        await f.StartAsync(); var result = await f.SendAsync(method, path, body);
        Assert.Equal(500, result.Status); Assert.Equal("internal_server_error", result.Body["error"]!.GetValue<string>());
        Assert.True(Guid.TryParse(result.Body["internal_error_id"]!.GetValue<string>(), out _));
        Assert.Equal(1, f.Database.Rollbacks); Assert.Equal(0, f.Database.Commits); Assert.Empty(f.Database.Settings);
        Assert.DoesNotContain("synthetic-audit-failure", result.Body.ToJsonString());
    }
    [Fact]
    public async Task DescriptorChecksEveryDeclaredCapability()
    {
        await using var f = new InstallationFixture { Owner = false }; f.WriteUi(["field.ungranted"]); await f.StartAsync();
        foreach (string route in new[] { "/api/v1/ui/plugins/sli.ad/descriptor", "/api/v1/ui/plugins/sli.ad/assets/HASH/entry.js" })
        { var result = await f.SendAsync("GET", route); Assert.Equal(403, result.Status); Assert.Equal("field.ungranted", result.Body["required_capability"]!.GetValue<string>()); }
    }
    [Fact]
    public async Task CrossOriginMutationIsRejectedBeforeBodyAndData()
    {
        await using var f = new InstallationFixture(); await f.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/setup/domains") { Content = new StringContent("not JSON", Encoding.UTF8, "application/json") };
        request.Headers.Add("Origin", "https://untrusted.invalid");
        using var result = await f.Client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, result.StatusCode); Assert.Empty(f.Database.Calls);
    }
    [Theory]
    [InlineData("POST", "/api/v1/setup/domains")]
    [InlineData("POST", "/api/v1/setup/domains/example.test")]
    [InlineData("POST", "/api/v1/setup/domain-controllers")]
    [InlineData("POST", "/api/v1/setup/domain-controllers/dc")]
    [InlineData("POST", "/api/v1/platform-settings/ad.inactivity_days")]
    [InlineData("PUT", "/api/plugins/sli.ad/settings")]
    public async Task SetupAndSettingsRequireAdminEvenWithDelegatedCapabilities(string method, string path)
    {
        await using var f = new InstallationFixture { Principal = new("session", 1, "operator", "alice"), Owner = false }; await f.StartAsync();
        var result = await f.SendAsync(method, path, "not JSON"); Assert.Equal(403, result.Status); Assert.Equal("insufficient_permissions", result.Body["error"]!.GetValue<string>()); Assert.Empty(f.Database.Calls);
    }
}
