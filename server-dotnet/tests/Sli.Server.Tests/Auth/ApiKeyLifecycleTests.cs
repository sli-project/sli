using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Administration.ApiKeys;
using Sli.Server.Auth.Commands;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

[Collection("Owned ordinary API keys")]
public sealed class ApiKeyLifecycleTests
{
    private static readonly UserAdministrationActor Operator = new("session", null, null!);
    private sealed record User(long Id, string Username, string Role, string Token);
    private sealed class Connections(SyntheticDatabase database) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => database.OpenConnectionAsync(ct); }

    private sealed class Fixture : IAsyncDisposable
    {
        public required SyntheticDatabase Database;
        public required Connections Connections;
        public required IUserAdministration Users;
        public required IApiKeyAdministration Keys;
        public readonly CredentialTokens Tokens = new();
        public readonly string Prefix = "api8_" + Guid.NewGuid().ToString("N")[..12] + "_";
        public User Admin = null!, Viewer = null!, Denied = null!, Inactive = null!;
        private const string Password = "Ordinary-Key-Synthetic-Password-🔐";

        public static async Task<Fixture> Create(CancellationToken ct)
        {
            var binding = OwnedDatabaseBinding.FromEnvironment();
            Assert.True(Environment.GetEnvironmentVariable("SLI_API_KEYS_DEDICATED_RUN_ID") == binding.RunId.ToString("D"), "Explicit dedicated key fixture binding required");
            Assert.NotEqual(Guid.Parse("25e9e697-c2d5-4704-a205-aeab5b3f1b5b"), binding.RunId);
            var database = await SyntheticDatabase.BorrowAsync(binding, ct);
            var connections = new Connections(database);
            var audit = new AuthAudit(connections);
            var fixture = new Fixture { Database = database, Connections = connections,
                Users = new UserAdministrationService(connections, new PasswordCodec(), audit), Keys = new ApiKeyAdministrationService(connections, new CredentialTokens(), audit) };
            try
            {
                fixture.Admin = await fixture.AddUser("admin", "admin", ct);
                fixture.Viewer = await fixture.AddUser("viewer", "viewer", ct);
                fixture.Denied = await fixture.AddUser("denied", "admin", ct);
                fixture.Inactive = await fixture.AddUser("inactive", "viewer", ct);
                await using var connection = await database.OpenConnectionAsync(ct);
                await using var deny = new NpgsqlCommand("""
                    insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,scope_json,business_reason)
                    select 'user',@id,id,'deny','{"kind":"all"}'::jsonb,'owned API key capability denial'
                    from access_capabilities where capability_key='access.manage'
                    """, connection);
                deny.Parameters.AddWithValue("id", fixture.Denied.Id);
                Assert.Equal(1, await deny.ExecuteNonQueryAsync(ct));
                await using var inactive = new NpgsqlCommand("update auth_users set is_active=false where id=@id and username=@name", connection);
                inactive.Parameters.AddWithValue("id", fixture.Inactive.Id); inactive.Parameters.AddWithValue("name", fixture.Inactive.Username);
                Assert.Equal(1, await inactive.ExecuteNonQueryAsync(ct));
                return fixture;
            }
            catch { await fixture.DisposeAsync(); throw; }
        }

        private async Task<User> AddUser(string suffix, string role, CancellationToken ct)
        {
            string name = Prefix + suffix;
            var item = await Users.CreateAsync(new(name, Password, role), Operator, ct);
            long id = item.GetProperty("id").GetInt64();
            string token = await new SessionLifecycle(Connections, Tokens, TimeProvider.System).IssueAsync(new("session", id, role, Username: name), false, ct);
            return new(id, name, role, token);
        }

        public async Task<WebApplication> Host(CancellationToken ct, bool auth = true)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory });
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:AuthRequired"] = auth ? "1" : "0", ["Sli:AllowUnauthenticated"] = auth ? "0" : "1",
                ["Sli:OwnerSetup"] = "0", ["Sli:TrustedProxies"] = "127.0.0.1/32", ["Sli:OperatorToken"] = Prefix + "operator"
            });
            builder.WebHost.UseKestrel().UseUrls("http://127.0.0.1:0");
            builder.Services.AddSingleton<IPostgresConnectionFactory>(Connections);
            builder.Services.AddScoped<IPrincipalAuthenticator, PrincipalAuthenticator>(); builder.Services.AddSingleton<TransportGate>();
            builder.Services.AddAuthLifecycle(); builder.Services.AddAuthLoginSecurity(); builder.Services.AddUserAdministration();
            builder.Services.AddApiKeyAdministration(); builder.Services.AddSliIngress(builder.Configuration);
            var app = builder.Build(); app.UseRouting(); app.UseRateLimiter(); app.UseReportKeyRequestGate(); app.UseSliDynamicAdmission();
            app.MapAuthEndpoints(); app.MapApiKeyAdministrationEndpoints();
            await app.StartAsync(ct);
            return app;
        }

        public async ValueTask DisposeAsync()
        {
            await using var connection = await Database.OpenConnectionAsync(CancellationToken.None);
            await using var cleanup = new NpgsqlCommand("""
                delete from auth_api_keys where left(label,length(@prefix))=@prefix;
                delete from access_capability_assignments where subject_type='user' and subject_id in(select id from auth_users where left(username,length(@prefix))=@prefix);
                delete from auth_sessions where user_id in(select id from auth_users where left(username,length(@prefix))=@prefix);
                delete from auth_users where left(username,length(@prefix))=@prefix
                """, connection);
            cleanup.Parameters.AddWithValue("prefix", Prefix);
            await cleanup.ExecuteNonQueryAsync();
            await Database.DisposeAsync();
        }
    }

    private static HttpClient Client(WebApplication app)
    {
        string address = Assert.Single(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        Assert.True(new Uri(address).IsLoopback);
        return new(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
    }
    private static async Task<HttpResponseMessage> Send(HttpClient client, HttpMethod method, string path, CancellationToken ct,
        object? payload = null, string? session = null, string? bearer = null, string? xKey = null, string? origin = null, string? operatorToken = null, string? raw = null)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-Forwarded-Proto", "https");
        if (session is not null) request.Headers.Add("Cookie", "adlog_session=" + session);
        if (bearer is not null) request.Headers.Add("Authorization", "Bearer " + bearer);
        if (xKey is not null) request.Headers.Add("X-ADLog-API-Key", xKey);
        if (origin is not null) request.Headers.Add("Origin", origin);
        if (operatorToken is not null) request.Headers.Add("X-ADLog-Operator-Token", operatorToken);
        if (payload is not null || raw is not null) request.Content = new StringContent(raw ?? JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        return await client.SendAsync(request, ct);
    }
    private static async Task<JsonDocument> Body(HttpResponseMessage response, CancellationToken ct) => JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));

    [Fact]
    public async Task ActualHttpKeyLifecyclePreservesPermissionsSecretVisibilityAndCredentialFallback()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.Create(ct);
        await using var app = await f.Host(ct);
        using var client = Client(app);
        foreach (var scenario in new (string? Token, HttpStatusCode Status, string Error)[] { (null, HttpStatusCode.Unauthorized, "authentication_required"),
            (f.Viewer.Token, HttpStatusCode.Forbidden, "insufficient_permissions"), (f.Denied.Token, HttpStatusCode.Forbidden, "explicit_deny") })
        {
            using var denied = await Send(client, HttpMethod.Get, "/api/auth/api-keys", ct, session: scenario.Token);
            Assert.Equal(scenario.Status, denied.StatusCode);
            using var body = await Body(denied, ct); Assert.Equal(scenario.Error, body.RootElement.GetProperty("error").GetString());
        }
        using (var origin = await Send(client, HttpMethod.Post, "/api/auth/api-keys", ct, new { label = f.Prefix + "origin" }, f.Admin.Token, origin: "https://foreign.example"))
            Assert.Equal(HttpStatusCode.Forbidden, origin.StatusCode);
        using (var malformed = await Send(client, HttpMethod.Post, "/api/auth/api-keys", ct, session: f.Admin.Token, raw: "{"))
        { Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode); using var body = await Body(malformed, ct); Assert.Single(body.RootElement.EnumerateObject()); }
        foreach (var payload in new object[] { new { label = "" }, new { label = new string('x', 121) }, new { label = f.Prefix + "role", role = "root" } })
        { using var invalid = await Send(client, HttpMethod.Post, "/api/auth/api-keys", ct, payload, f.Admin.Token); Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode); }
        string token;
        long id;
        using (var created = await Send(client, HttpMethod.Post, "/api/auth/api-keys", ct,
            new { label = " " + f.Prefix + "viewer ", role = " VIEWER ", expires_at = "2000-01-01" }, f.Admin.Token,
            origin: "https://" + client.BaseAddress!.Authority))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            Assert.False(created.Headers.Contains("Set-Cookie"));
            using var body = await Body(created, ct); token = body.RootElement.GetProperty("token").GetString()!;
            bool validTokenFormat = Regex.IsMatch(token, "\\Aadl_[A-Za-z0-9_-]{43}\\z");
            Assert.True(validTokenFormat, "Expected source-compatible token format");
            var item = body.RootElement.GetProperty("item"); id = item.GetProperty("id").GetInt64();
            Assert.Equal(6, item.EnumerateObject().Count()); Assert.Equal("viewer", item.GetProperty("role").GetString());
            Assert.True(item.GetProperty("key_prefix").GetString() == token[..12]); Assert.Equal(JsonValueKind.Null, item.GetProperty("expires_at").ValueKind);
        }
        await using (var connection = await f.Database.OpenConnectionAsync(ct))
        {
            await using var stored = new NpgsqlCommand("select key_hash,report_subject_id from auth_api_keys where id=@id", connection); stored.Parameters.AddWithValue("id", id);
            await using var reader = await stored.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.True(reader.GetString(0) == f.Tokens.Digest(token)); Assert.True(reader.IsDBNull(1));
        }
        using (var inventory = await Send(client, HttpMethod.Get, "/api/auth/api-keys", ct, session: f.Admin.Token))
        { Assert.Equal(HttpStatusCode.OK, inventory.StatusCode); string body = await inventory.Content.ReadAsStringAsync(ct); Assert.False(body.Contains(token, StringComparison.Ordinal)); Assert.False(body.Contains("key_hash", StringComparison.Ordinal)); }
        using (var precedence = await Send(client, HttpMethod.Get, "/api/auth/me", ct, session: f.Admin.Token, bearer: "invalid", xKey: token))
        { Assert.Equal(HttpStatusCode.OK, precedence.StatusCode); using var body = await Body(precedence, ct); Assert.Equal("api_key", body.RootElement.GetProperty("principal").GetProperty("type").GetString()); Assert.Equal("viewer", body.RootElement.GetProperty("principal").GetProperty("role").GetString()); }
        using (var noInheritance = await Send(client, HttpMethod.Get, "/api/auth/api-keys", ct, session: f.Admin.Token, bearer: token))
            Assert.Equal(HttpStatusCode.Forbidden, noInheritance.StatusCode);
        await f.Users.UpdateAsync(new(f.Admin.Id, null, false), Operator, ct);
        using (var independent = await Send(client, HttpMethod.Get, "/api/auth/me", ct, bearer: token)) Assert.Equal(HttpStatusCode.OK, independent.StatusCode);
        await f.Users.UpdateAsync(new(f.Admin.Id, null, true), Operator, ct);
        f.Admin = f.Admin with { Token = await new SessionLifecycle(f.Connections, f.Tokens, TimeProvider.System).IssueAsync(new("session", f.Admin.Id, "admin", Username: f.Admin.Username), false, ct) };
        var expired = await f.Keys.IssueAsync(new(f.Prefix + "expired", ExpiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)), Operator, ct);
        var inactive = await f.Keys.IssueAsync(new(f.Prefix + "subject"), Operator, ct);
        await using (var connection = await f.Database.OpenConnectionAsync(ct))
        { await using var subject = new NpgsqlCommand("update auth_api_keys set report_subject_id=@subject where id=@id", connection); subject.Parameters.AddWithValue("subject", f.Inactive.Id); subject.Parameters.AddWithValue("id", inactive.Item.GetProperty("id").GetInt64()); Assert.Equal(1, await subject.ExecuteNonQueryAsync(ct)); }
        foreach (string rejected in new[] { expired.Token, inactive.Token })
        {
            using var rejectedOnly = await Send(client, HttpMethod.Get, "/api/auth/me", ct, bearer: rejected); Assert.Equal(HttpStatusCode.Unauthorized, rejectedOnly.StatusCode);
            using var fallback = await Send(client, HttpMethod.Get, "/api/auth/me", ct, session: f.Admin.Token, bearer: rejected); Assert.Equal(HttpStatusCode.OK, fallback.StatusCode);
        }
        using (var revoke = await Send(client, HttpMethod.Post, $"/api/auth/api-keys/{id}/revoke", ct, session: f.Admin.Token)) Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        using (var repeat = await Send(client, HttpMethod.Post, $"/api/auth/api-keys/{id}/revoke", ct, session: f.Admin.Token)) Assert.Equal(HttpStatusCode.NotFound, repeat.StatusCode);
        using (var invalid = await Send(client, HttpMethod.Post, "/api/auth/api-keys/not-an-id/revoke", ct, session: f.Admin.Token)) Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        using (var overflow = await Send(client, HttpMethod.Post, "/api/auth/api-keys/999999999999999999999999999/revoke", ct, session: f.Admin.Token)) Assert.Equal(HttpStatusCode.NotFound, overflow.StatusCode);
        using (var revokedOnly = await Send(client, HttpMethod.Get, "/api/auth/me", ct, bearer: token)) Assert.Equal(HttpStatusCode.Unauthorized, revokedOnly.StatusCode);
        using (var fallback = await Send(client, HttpMethod.Get, "/api/auth/me", ct, session: f.Admin.Token, bearer: token)) Assert.Equal(HttpStatusCode.OK, fallback.StatusCode);
        await using var off = await f.Host(ct, auth: false);
        using var offClient = Client(off);
        using (var missingOperator = await Send(offClient, HttpMethod.Post, "/api/auth/api-keys", ct, new { label = f.Prefix + "off" }, f.Admin.Token))
        { Assert.Equal(HttpStatusCode.Unauthorized, missingOperator.StatusCode); using var body = await Body(missingOperator, ct); Assert.Equal("operator_token_required", body.RootElement.GetProperty("error").GetString()); }
        using (var missingAdmin = await Send(offClient, HttpMethod.Post, "/api/auth/api-keys", ct, new { label = f.Prefix + "off" }, operatorToken: f.Prefix + "operator"))
            Assert.Equal(HttpStatusCode.Unauthorized, missingAdmin.StatusCode);
        using (var admitted = await Send(offClient, HttpMethod.Post, "/api/auth/api-keys", ct, new { label = f.Prefix + "off" }, f.Admin.Token, operatorToken: f.Prefix + "operator"))
            Assert.Equal(HttpStatusCode.Created, admitted.StatusCode);
    }

    private sealed class FailedAudit : IAuthAudit
    {
        public Task WriteAsync(AuthAuditEvent entry, CancellationToken ct) => throw new InvalidOperationException("synthetic_audit_failure");
        public Task AppendAsync(NpgsqlTransaction transaction, AuthAuditEvent entry, CancellationToken ct) => throw new InvalidOperationException("synthetic_audit_failure");
    }

    [Fact]
    public async Task RealTransactionsRollbackAuditFailuresAndArbitrateConcurrentRevocation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.Create(ct);
        var failing = new ApiKeyAdministrationService(f.Connections, f.Tokens, new FailedAudit());
        await Assert.ThrowsAsync<InvalidOperationException>(() => failing.IssueAsync(new(f.Prefix + "rollback"), Operator, ct));
        await using (var connection = await f.Database.OpenConnectionAsync(ct))
        { await using var absent = new NpgsqlCommand("select count(*) from auth_api_keys where label=@label", connection); absent.Parameters.AddWithValue("label", f.Prefix + "rollback"); Assert.Equal(0L, await absent.ExecuteScalarAsync(ct)); }
        var key = await f.Keys.IssueAsync(new(f.Prefix + "revoke"), Operator, ct); long id = key.Item.GetProperty("id").GetInt64();
        await Assert.ThrowsAsync<InvalidOperationException>(() => failing.RevokeAsync(id, Operator, ct));
        await using (var connection = await f.Database.OpenConnectionAsync(ct))
        { await using var intact = new NpgsqlCommand("select is_active and revoked_at is null from auth_api_keys where id=@id", connection); intact.Parameters.AddWithValue("id", id); Assert.True((bool)(await intact.ExecuteScalarAsync(ct))!); }
        var results = await Task.WhenAll(f.Keys.RevokeAsync(id, Operator, ct), f.Keys.RevokeAsync(id, Operator, ct));
        Assert.Single(results, result => result);
        await using (var connection = await f.Database.OpenConnectionAsync(ct))
        { await using var audit = new NpgsqlCommand("select count(*) from auth_audit where action like @action and outcome='ok'", connection); audit.Parameters.AddWithValue("action", $"api_key_revoked:{id}:%"); Assert.Equal(1L, await audit.ExecuteScalarAsync(ct)); }
    }

    private sealed class Channels : IAuthConsoleIO
    {
        public readonly StringWriter Captured = new(), Errors = new();
        public TextWriter Output => Captured; public TextWriter Error => Errors;
        public bool CanPromptPassword => true;
        public Task<string> ReadPasswordAsync(string prompt, CancellationToken ct) => Task.FromResult("Console-Private-Synthetic-Password-🔐");
    }

    [Fact]
    public async Task ConsoleUsesActualUserProducerAndPublishesOnlyOneKeyWithSourceActor()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.Create(ct);
        var io = new Channels();
        var console = new AuthConsole(() => f.Users, () => f.Keys, io);
        Assert.Equal(0, await console.RunAsync(["create-user", "--username=" + f.Prefix + "cli"], ct));
        Assert.False(io.Captured.ToString().Contains("Console-Private-Synthetic-Password", StringComparison.Ordinal));
        io.Captured.GetStringBuilder().Clear();
        Assert.Equal(0, await console.RunAsync(["create-api-key", "--label=" + f.Prefix + "cli"], ct));
        string[] lines = io.Captured.ToString().Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Length); string token = lines[2];
        bool validTokenFormat = Regex.IsMatch(token, "\\Aadl_[A-Za-z0-9_-]{43}\\z");
        Assert.True(validTokenFormat, "Expected source-compatible token format");
        Assert.True(lines.Count(line => line.Contains(token, StringComparison.Ordinal)) == 1);
        long id;
        await using (var connection = await f.Database.OpenConnectionAsync(ct))
        {
            await using var query = new NpgsqlCommand("select id,key_hash from auth_api_keys where label=@label", connection); query.Parameters.AddWithValue("label", f.Prefix + "cli");
            await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct)); id = reader.GetInt64(0); Assert.True(reader.GetString(1) == f.Tokens.Digest(token));
        }
        Assert.True((await f.Keys.ListAsync(ct)).All(item => !item.GetRawText().Contains(token, StringComparison.Ordinal)));
        io.Captured.GetStringBuilder().Clear();
        Assert.Equal(0, await console.RunAsync(["revoke-api-key", "--id=" + id], ct));
        Assert.Equal(1, await console.RunAsync(["revoke-api-key", "--id=" + id], ct));
        Assert.False(io.Captured.ToString().Contains(token, StringComparison.Ordinal)); Assert.True(io.Errors.GetStringBuilder().Length == 0, "Console diagnostics must remain empty");
        await using var connectionAudit = await f.Database.OpenConnectionAsync(ct);
        await using var actor = new NpgsqlCommand("select actor_type,actor_id,remote_address from auth_audit where action like @action order by id desc limit 1", connectionAudit);
        actor.Parameters.AddWithValue("action", $"api_key_issued:{id}:%");
        await using var actorReader = await actor.ExecuteReaderAsync(ct); Assert.True(await actorReader.ReadAsync(ct));
        Assert.Equal("session", actorReader.GetString(0)); Assert.True(actorReader.IsDBNull(1)); Assert.True(actorReader.IsDBNull(2));
    }
}
