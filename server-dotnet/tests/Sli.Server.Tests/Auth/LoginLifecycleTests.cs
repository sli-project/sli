using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class LoginLifecycleTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualHttpLoginIdentityLogoutAndPersistedSessions(bool kestrel)
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        await using var admitted = await SyntheticDatabase.BorrowAsync(binding, ct);
        string configPath = Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json");
        byte[] config = await File.ReadAllBytesAsync(configPath, ct);
        Assert.True(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256") == Convert.ToHexStringLower(SHA256.HashData(config)), "Owned config hash mismatch.");
        string username = "netlogin_" + Guid.NewGuid().ToString("N")[..16];
        const string password = "Published-Synthetic-Password-🔐";
        string accountKey = AccountThrottle.AccountKey(username);
        long userId;
        await using (var connection = await admitted.OpenConnectionAsync(ct))
        {
            await using var insert = new NpgsqlCommand("""
                insert into auth_users(username,password_hash,role,is_active,last_login_at)
                values(@username,@hash,'viewer',true,now()-interval '1 day') returning id
                """, connection);
            insert.Parameters.AddWithValue("username", username);
            insert.Parameters.AddWithValue("hash", new PasswordCodec().Hash(password));
            userId = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
        }
        try
        {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, settings) =>
        {
            settings.AddJsonStream(new MemoryStream(config));
            settings.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1", ["Sli:OwnerSetup"] = "0",
                // Existing diagnostic policy only on the owned loopback socket test.
                ["Sli:AuthAllowInsecureHttp"] = kestrel ? "1" : "0", ["Sli:AuthCookieSecure"] = "1"
            });
        }));
        if (kestrel) factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        using var client = Client(factory, kestrel);
        string? cookie = null;
            using (var unauthenticated = await client.GetAsync("/api/auth/me", ct)) Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
            using (var crossOrigin = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login") { Content = JsonContent.Create(new { username, password }) })
            {
                crossOrigin.Headers.Add("Origin", "https://evil.example");
                using var rejected = await client.SendAsync(crossOrigin, ct);
                Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
            }
            using (var result = await PostJsonAsync(client, "/api/auth/login", new { username = " " + username.ToUpperInvariant() + " ", password }, ct))
            {
                Assert.Equal(HttpStatusCode.OK, result.StatusCode);
                string setCookie = Assert.Single(result.Headers.GetValues("Set-Cookie"));
                Assert.Contains("Max-Age=43200; HttpOnly; SameSite=Strict; Secure", setCookie);
                cookie = setCookie.Split(';')[0];
                using var body = JsonDocument.Parse(await result.Content.ReadAsStringAsync(ct));
                Assert.Equal(userId, body.RootElement.GetProperty("principal").GetProperty("id").GetInt64());
            }
            async Task<HttpResponseMessage> MeAsync(string value)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
                request.Headers.Add("Cookie", value);
                return await client.SendAsync(request, ct);
            }
            using (var me = await MeAsync(cookie!)) Assert.Equal(HttpStatusCode.OK, me.StatusCode);
            using (var logoutRequest = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout"))
            {
                logoutRequest.Headers.Add("Cookie", cookie);
                using var logout = await client.SendAsync(logoutRequest, ct);
                Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
                Assert.Equal("adlog_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure", Assert.Single(logout.Headers.GetValues("Set-Cookie")));
            }
            using (var old = await MeAsync(cookie!)) Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
            using (var duplicate = await client.PostAsync("/api/auth/logout", null, ct)) Assert.Equal(HttpStatusCode.OK, duplicate.StatusCode);
            using (var remembered = await PostJsonAsync(client, "/api/auth/login", new { username, password, remember = "false" }, ct))
            {
                Assert.Equal(HttpStatusCode.OK, remembered.StatusCode);
                string setCookie = Assert.Single(remembered.Headers.GetValues("Set-Cookie"));
                Assert.Contains("Max-Age=1209600", setCookie);
                cookie = setCookie.Split(';')[0];
            }
            await using (var connection = await admitted.OpenConnectionAsync(ct))
            {
                await using var state = new NpgsqlCommand("""
                    select previous_login_at is not null,last_login_at is not null,
                      (select count(*) from auth_audit where actor_type='session' and actor_id=@id and action='login' and outcome='ok'),
                      (select count(*) from auth_sessions where user_id=@id and revoked_at is null and expires_at>now()+interval '13 days')
                    from auth_users where id=@id
                    """, connection);
                state.Parameters.AddWithValue("id", userId);
                await using var reader = await state.ExecuteReaderAsync(ct);
                Assert.True(await reader.ReadAsync(ct)); Assert.True(reader.GetBoolean(0)); Assert.True(reader.GetBoolean(1));
                Assert.Equal(2, reader.GetInt64(2)); Assert.Equal(1, reader.GetInt64(3));
            }
            // A new host reads the same stored session; no process-local credential state.
            using (var restartedFactory = factory.WithWebHostBuilder(_ => { }))
            using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me"))
            {
                if (kestrel) restartedFactory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
                using var restarted = Client(restartedFactory, kestrel);
                request.Headers.Add("Cookie", cookie);
                using var me = await restarted.SendAsync(request, ct);
                Assert.Equal(HttpStatusCode.OK, me.StatusCode);
            }
            await using (var connection = await admitted.OpenConnectionAsync(ct))
            {
                await using var deactivate = new NpgsqlCommand("update auth_users set is_active=false where id=@id and username=@name", connection);
                deactivate.Parameters.AddWithValue("id", userId); deactivate.Parameters.AddWithValue("name", username);
                Assert.Equal(1, await deactivate.ExecuteNonQueryAsync(ct));
            }
            using (var disabled = await MeAsync(cookie!)) Assert.Equal(HttpStatusCode.Unauthorized, disabled.StatusCode);
            using (var invalid = await PostJsonAsync(client, "/api/auth/login", new { username, password }, ct)) Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
        }
        finally
        {
            // Exact identifiers belong to this invocation. No reset, shared seed or other actor's rows.
            await using var connection = await admitted.OpenConnectionAsync(ct);
            await using var cleanup = new NpgsqlCommand("""
                delete from auth_sessions where user_id=@id;
                delete from auth_audit where actor_type='session' and actor_id=@id;
                delete from auth_login_throttle where account_key=@key;
                delete from auth_users where id=@id and username=@name
                """, connection);
            cleanup.Parameters.AddWithValue("id", userId); cleanup.Parameters.AddWithValue("name", username); cleanup.Parameters.AddWithValue("key", accountKey);
            await cleanup.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task<HttpResponseMessage> PostJsonAsync(HttpClient client, string path, object payload, CancellationToken ct)
    {
        // Python's production body contract rejects Transfer-Encoding. Browser-style
        // known-length UTF-8 JSON is required on the actual socket as well as TestServer.
        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        return await client.PostAsync(path, content, ct);
    }

    private static HttpClient Client(WebApplicationFactory<Program> factory, bool kestrel)
    {
        if (!kestrel) return factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        factory.StartServer();
        var addresses = factory.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!;
        string address = Assert.Single(addresses.Addresses);
        Assert.True(Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.IsLoopback && uri.Port != 0, "Owned Kestrel must bind a dynamic loopback address.");
        return new HttpClient(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
    }
}
