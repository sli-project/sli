using System.Net;
using System.Security.Cryptography;
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
using Sli.Server.Auth.InitialOwner;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class InitialOwnerDatabaseTests
{
    private sealed class Connections(SyntheticDatabase database) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => database.OpenConnectionAsync(ct); }

    private sealed class FailingSessions : ISessionLifecycle
    {
        public Task<string> IssueAsync(Principal principal, bool remember, CancellationToken ct) => throw new InvalidOperationException("synthetic_session_failure");
        public Task RevokeAsync(string? token, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class FailingClaimAudit(IAuthAudit audit) : IAuthAudit
    {
        public Task WriteAsync(AuthAuditEvent entry, CancellationToken ct) => audit.WriteAsync(entry, ct);
        public Task AppendAsync(NpgsqlTransaction transaction, AuthAuditEvent entry, CancellationToken ct) =>
            throw new InvalidOperationException("synthetic_claim_audit_failure");
    }

    [Fact]
    public async Task DedicatedPostgresAndRealKestrelActivateOnceWithSourceGatesAndFailureBoundaries()
        => await RunCore(denialsOnly: false);

    [Fact]
    public async Task BootstrapDenialEnvelopesMatchSourceAcrossLocales()
        => await RunCore(denialsOnly: true);

    private async Task RunCore(bool denialsOnly)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.True(Environment.GetEnvironmentVariable("SLI_INITIAL_OWNER_DEDICATED_RUN_ID") == binding.RunId.ToString("D"), "Dedicated initial-owner fixture requires explicit run binding");
        Assert.NotEqual(Guid.Parse("25e9e697-c2d5-4704-a205-aeab5b3f1b5b"), binding.RunId);
        await using var database = await SyntheticDatabase.BorrowAsync(binding, ct);
        long auditBefore;
        await using (var connection = await database.OpenConnectionAsync(ct))
        {
            await using var baseline = new NpgsqlCommand("select coalesce(max(id),0) from auth_audit", connection);
            auditBefore = Convert.ToInt64(await baseline.ExecuteScalarAsync(ct));
        }
        var connections = new Connections(database);
        var passwords = new PasswordCodec();
        string code = new CredentialTokens().NewSessionToken();
        string codeHash = passwords.Hash(code);
        const string newPassword = "Initial-Owner-New-Synthetic-Password-🔐";
        async Task Reset(double issuedOffset = 0, bool active = true, string role = "admin", bool claimed = false)
        {
            await using var connection = await database.OpenConnectionAsync(ct);
            await using var update = new NpgsqlCommand("""
                update auth_users set username='platform-owner',password_hash=@hash,role=@role,is_active=@active,
                    last_login_at=case when @claimed then clock_timestamp() else null end,
                    updated_at=clock_timestamp()+@offset*interval '1 second'
                where id=101 and exists(select 1 from access_platform_owners where user_id=101 and owner_key='primary')
                """, connection);
            update.Parameters.AddWithValue("hash", codeHash); update.Parameters.AddWithValue("role", role);
            update.Parameters.AddWithValue("active", active); update.Parameters.AddWithValue("claimed", claimed);
            update.Parameters.AddWithValue("offset", issuedOffset);
            Assert.Equal(1, await update.ExecuteNonQueryAsync(ct));
        }
        async Task<(bool Claimed, bool NewPassword)> State()
        {
            await using var connection = await database.OpenConnectionAsync(ct);
            await using var query = new NpgsqlCommand("select last_login_at is not null,password_hash from auth_users where id=101 and username='platform-owner'", connection);
            await using var reader = await query.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct));
            return (reader.GetBoolean(0), passwords.Verify(reader.GetString(1), newPassword).Valid);
        }
        async Task<WebApplication> Host(bool setup = true, bool auth = true, int sourceLimit = 30, bool trustedProxy = true)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory });
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:OwnerSetup"] = setup ? "1" : "0", ["Sli:AuthRequired"] = auth ? "1" : "0",
                ["Sli:AllowUnauthenticated"] = auth ? "0" : "1", ["Sli:AuthCookieSecure"] = "1",
                ["Sli:TrustedProxies"] = trustedProxy ? "127.0.0.1/32" : "", ["ADLOG_MAX_LOGIN_FAILURES"] = sourceLimit.ToString(),
                ["Sli:AuthAllowInsecureHttp"] = trustedProxy ? "0" : "1"
            });
            builder.WebHost.UseKestrel().UseUrls("http://127.0.0.1:0");
            builder.Services.AddSingleton<IPostgresConnectionFactory>(connections);
            builder.Services.AddScoped<IPrincipalAuthenticator, PrincipalAuthenticator>();
            builder.Services.AddSingleton<TransportGate>();
            builder.Services.AddAuthLifecycle(); builder.Services.AddAuthLoginSecurity();
            builder.Services.AddInitialOwner(); builder.Services.AddSliIngress(builder.Configuration);
            var app = builder.Build();
            app.UseRouting(); app.UseRateLimiter(); app.UseReportKeyRequestGate(); app.UseSliDynamicAdmission();
            app.MapAuthEndpoints(); app.MapInitialOwnerEndpoints();
            await app.StartAsync(ct);
            return app;
        }
        static HttpClient Client(WebApplication app)
        {
            string address = Assert.Single(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            Assert.True(new Uri(address).IsLoopback);
            return new(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
        }
        static async Task<HttpResponseMessage> Request(HttpClient client, HttpMethod method, string path, object? payload, CancellationToken ct,
            bool secure = true, string? origin = null, string? cookie = null, string? language = null)
        {
            using var request = new HttpRequestMessage(method, path);
            request.Headers.Add("X-Forwarded-Proto", secure ? "https" : "http");
            if (origin is not null) request.Headers.Add("Origin", origin);
            if (cookie is not null) request.Headers.Add("Cookie", cookie);
            if (language is not null) request.Headers.Add("Accept-Language", language);
            if (payload is not null) request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            return await client.SendAsync(request, ct);
        }
        if (denialsOnly)
        {
            async Task AssertEnvelope(HttpResponseMessage response, string error, string key, string text)
            {
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                var root = document.RootElement;
                Assert.Equal(2, root.EnumerateObject().Count());
                Assert.Equal(error, root.GetProperty("error").GetString());
                var message = root.GetProperty("message");
                Assert.Equal("login.error." + key, message.GetProperty("code").GetString());
                Assert.Equal(text, message.GetProperty("text").GetString());
                Assert.Empty(message.GetProperty("params").EnumerateObject());
                Assert.False(root.TryGetProperty("retry_after_seconds", out _));
            }
            await using (var app = await Host(sourceLimit: 3))
            using (var client = Client(app))
            {
                foreach (string language in new[] { "en", "ru" })
                {
                    using var response = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code = "", password = newPassword }, ct,
                        origin: "https://evil.example", language: language);
                    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
                    await AssertEnvelope(response, "cross_origin_request_rejected", "origin", language == "en"
                        ? "Sign-in request rejected. Open the sign-in page from the server address."
                        : "Запрос входа отклонён. Откройте страницу входа с адреса сервера.");
                }
                for (int i = 0; i < 3; i++)
                {
                    using var invalid = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code = "", password = newPassword }, ct);
                    Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
                    using var body = JsonDocument.Parse(await invalid.Content.ReadAsStringAsync(ct));
                    Assert.Single(body.RootElement.EnumerateObject());
                }
                foreach (string language in new[] { "en", "ru" })
                {
                    using var locked = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code = "", password = newPassword }, ct, language: language);
                    Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
                    Assert.True(int.TryParse(Assert.Single(locked.Headers.GetValues("Retry-After")), out int seconds) && seconds > 0);
                    await AssertEnvelope(locked, "login_temporarily_locked", "locked", language == "en"
                        ? "Too many sign-in attempts. Try again later." : "Слишком много попыток входа. Повторите позже.");
                }
            }
            await using (var app = await Host(trustedProxy: false))
            using (var client = Client(app))
                foreach (string language in new[] { "en", "ru" })
                {
                    using var response = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code = "", password = newPassword }, ct, secure: false, language: language);
                    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
                    await AssertEnvelope(response, "secure_transport_required", "https", language == "en"
                        ? "Sign-in requires a secure HTTPS connection." : "Вход разрешён только через защищённое HTTPS-соединение.");
                }
            return;
        }
        await Reset();
        await using (var off = await Host(setup: false))
        using (var client = Client(off))
        {
            using var get = await Request(client, HttpMethod.Get, "/api/auth/bootstrap", null, ct);
            Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
            using var post = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct);
            Assert.Equal(HttpStatusCode.NotFound, post.StatusCode);
        }
        await using (var off = await Host(auth: false))
        using (var client = Client(off))
        {
            using var post = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct);
            Assert.Equal(HttpStatusCode.NotFound, post.StatusCode);
        }
        await using (var app = await Host())
        using (var client = Client(app))
        {
            using (var pending = await Request(client, HttpMethod.Get, "/api/auth/bootstrap", null, ct))
            {
                Assert.Equal(HttpStatusCode.OK, pending.StatusCode);
                byte[] htmlBytes = await pending.Content.ReadAsByteArrayAsync(ct);
                Assert.Equal(2134, htmlBytes.Length); // 2093 frozen UTF-8 bytes plus the 41-byte nonce attribute.
                Assert.Equal((long)htmlBytes.Length, pending.Content.Headers.ContentLength);
                string html = Encoding.UTF8.GetString(htmlBytes);
                Assert.Contains("Create owner", html);
                Assert.Contains("<script nonce=", html);
                string frozenHtml = Regex.Replace(html, " nonce=\"[A-Za-z0-9_-]+\"", "");
                Assert.True(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(frozenHtml)))
                    == "be5752f7b3d02d68074315dbf9db090b46705b53a44fd3e624df0cd6fc45174b", "Bootstrap HTML must match frozen source bytes apart from nonce");
                Assert.Contains("'nonce-", Assert.Single(pending.Headers.GetValues("Content-Security-Policy")));
            }
            using (var insecure = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct, secure: false))
                Assert.Equal(HttpStatusCode.Forbidden, insecure.StatusCode);
            using (var origin = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct, origin: "https://evil.example"))
                Assert.Equal(HttpStatusCode.Forbidden, origin.StatusCode);
            using (var ordinary = await Request(client, HttpMethod.Post, "/api/auth/login", new { username = "platform-owner", password = code }, ct))
                Assert.Equal(HttpStatusCode.Unauthorized, ordinary.StatusCode);
            foreach (object payload in new object[] { new { code, password = "short" }, new { code, password = code }, new { code, password = "abcdefghijkl\0" }, new { code, password = 123 } })
            {
                using var invalid = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", payload, ct);
                Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
            }
            using (var invalid = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code = "wrong-synthetic-code", password = newPassword }, ct))
                Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
            foreach (var variation in new (double Offset, bool Active, string Role, bool Claimed)[] { (-86400d, true, "admin", false), (3600d, true, "admin", false), (0d, false, "admin", false), (0d, true, "viewer", false), (0d, true, "admin", true) })
            {
                await Reset(variation.Offset, variation.Active, variation.Role, variation.Claimed);
                using var invalid = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct);
                Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
            }
            await Reset();
            using (var oversized = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword, padding = new string('x', 17000) }, ct))
                Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);
            using (var success = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct))
            {
                Assert.Equal(HttpStatusCode.OK, success.StatusCode);
                string cookie = Assert.Single(success.Headers.GetValues("Set-Cookie")).Split(';')[0];
                using var me = await Request(client, HttpMethod.Get, "/api/auth/me", null, ct, cookie: cookie);
                Assert.Equal(HttpStatusCode.OK, me.StatusCode);
            }
            Assert.Equal((true, true), await State());
            using (var replay = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct))
                Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
            using (var closed = await Request(client, HttpMethod.Get, "/api/auth/bootstrap", null, ct))
                Assert.Equal(HttpStatusCode.NotFound, closed.StatusCode);
        }
        await Reset();
        await using (var app = await Host())
        using (var client = Client(app))
        {
            var requests = new[] { Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct),
                Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct) };
            var responses = await Task.WhenAll(requests);
            try { Assert.Single(responses, result => result.StatusCode == HttpStatusCode.OK); Assert.Single(responses, result => result.StatusCode == HttpStatusCode.Unauthorized); }
            finally { foreach (var response in responses) response.Dispose(); }
            Assert.Equal((true, true), await State());
        }
        await Reset();
        var policy = new AuthRequestPolicy(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:OwnerSetup"] = "1" }).Build());
        var actualAudit = new AuthAudit(connections);
        var actualSessions = new SessionLifecycle(connections, new CredentialTokens(), TimeProvider.System);
        var failedAudit = new InitialOwnerSetup(connections, passwords, new FailingClaimAudit(actualAudit), actualSessions, policy);
        await Assert.ThrowsAsync<InvalidOperationException>(() => failedAudit.ClaimAsync(new(code, newPassword), new("192.0.2.99"), ct));
        Assert.Equal((false, false), await State());
        Assert.True(await failedAudit.IsPendingAsync(ct));
        var failedSession = new InitialOwnerSetup(connections, passwords, new AuthAudit(connections), new FailingSessions(), policy);
        await Assert.ThrowsAsync<InvalidOperationException>(() => failedSession.ClaimAsync(new(code, newPassword), new("192.0.2.100"), ct));
        Assert.Equal((true, true), await State());
        Assert.False(await failedSession.IsPendingAsync(ct));
        await using (var connection = await database.OpenConnectionAsync(ct))
        {
            await using var audit = new NpgsqlCommand("""
                select count(*) from auth_audit where actor_type='session' and actor_id=101
                    and action='initial_owner_claimed' and outcome='ok' and remote_address='192.0.2.100' and id>@before
                """, connection);
            audit.Parameters.AddWithValue("before", auditBefore);
            Assert.Equal(1L, await audit.ExecuteScalarAsync(ct));
        }
        await Reset();
        await using (var app = await Host(sourceLimit: 3))
        using (var client = Client(app))
        {
            for (int i = 0; i < 3; i++)
            { using var invalid = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code = "invalid-code-synthetic", password = newPassword }, ct); Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode); }
            using var blocked = await Request(client, HttpMethod.Post, "/api/auth/bootstrap", new { code, password = newPassword }, ct);
            Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
            Assert.True(blocked.Headers.Contains("Retry-After"));
            Assert.False((await State()).Claimed);
        }
    }
}
