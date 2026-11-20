using System.Net;
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

[Collection("Owned owner recovery")]
public sealed class OwnerRecoveryHttpTests
{
    [Fact]
    public async Task RealKestrelRecoveryLoginMeReplayAndBudgetsPreserveBlockedAccount()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        await using var database = await SyntheticDatabase.BorrowAsync(binding, ct);
        byte[] config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json"), ct);
        Assert.True(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256") == Convert.ToHexStringLower(SHA256.HashData(config)), "Owned config hash mismatch");
        string username = Environment.GetEnvironmentVariable("SLI_RECOVERY_FIXTURE_USERNAME") ?? throw new InvalidOperationException("Owned fixture required");
        long id = long.Parse(Environment.GetEnvironmentVariable("SLI_RECOVERY_FIXTURE_USER_ID") ?? throw new InvalidOperationException("Owned fixture required"));
        Assert.StartsWith("netrecovery_", username);
        const string password = "Owned-Recovery-Synthetic-Password-🔐";
        string accountKey = AccountThrottle.AccountKey(username);
        var tokens = new CredentialTokens();
        string code = tokens.NewSessionToken();
        await using (var connection = await database.OpenConnectionAsync(ct))
        {
            await using var validate = new NpgsqlCommand("""
                select exists(select 1 from auth_users u join access_platform_owners o on o.user_id=u.id
                where u.id=@id and u.username=@name and o.owner_key=@name and u.is_active=true)
                """, connection);
            validate.Parameters.AddWithValue("id", id); validate.Parameters.AddWithValue("name", username);
            Assert.True((bool)(await validate.ExecuteScalarAsync(ct))!);
            await using var seed = new NpgsqlCommand("""
                insert into auth_owner_recovery(user_id,code_hash,expires_at)
                values(@id,@hash,clock_timestamp()+interval '10 minutes')
                on conflict(user_id) do update set code_hash=excluded.code_hash,expires_at=excluded.expires_at
                """, connection);
            seed.Parameters.AddWithValue("id", id); seed.Parameters.AddWithValue("hash", tokens.Digest(code));
            await seed.ExecuteNonQueryAsync(ct);
        }
        var throttle = new AccountThrottle();
        for (int i = 0; i < 5; i++)
        {
            await using var connection = await database.OpenConnectionAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            await using var attempt = await throttle.BeginAsync(transaction, username, ct);
            await attempt.FailAsync(ct);
            await transaction.CommitAsync(ct);
        }
        WebApplicationFactory<Program> Host(int sourceLimit) => new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, settings) =>
            {
                settings.AddJsonStream(new MemoryStream(config));
                settings.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1", ["Sli:OwnerSetup"] = "0",
                    ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:AuthCookieSecure"] = "1",
                    ["ADLOG_MAX_LOGIN_FAILURES"] = sourceLimit.ToString()
                });
            }));
        static HttpClient Client(WebApplicationFactory<Program> factory)
        {
            factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
            factory.StartServer();
            string address = Assert.Single(factory.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            Assert.True(new Uri(address).IsLoopback);
            return new HttpClient(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
        }
        static async Task<HttpResponseMessage> Post(HttpClient client, object payload, CancellationToken ct)
        {
            using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            return await client.PostAsync("/api/auth/login", content, ct);
        }
        try
        {
            using (var factory = Host(30))
            using (var client = Client(factory))
            {
                using (var blocked = await Post(client, new { username, password }, ct)) Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
                using (var recovered = await Post(client, new { username, password, recovery_code = code }, ct))
                {
                    Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
                    string cookie = Assert.Single(recovered.Headers.GetValues("Set-Cookie")).Split(';')[0];
                    using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
                    meRequest.Headers.Add("Cookie", cookie);
                    using var me = await client.SendAsync(meRequest, ct);
                    Assert.Equal(HttpStatusCode.OK, me.StatusCode);
                    using var body = JsonDocument.Parse(await me.Content.ReadAsStringAsync(ct));
                    Assert.Equal(id, body.RootElement.GetProperty("principal").GetProperty("id").GetInt64());
                }
                using (var blocked = await Post(client, new { username, password }, ct)) Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
                using (var replay = await Post(client, new { username, password, recovery_code = code }, ct)) Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
                using (var empty = await Post(client, new { username, password, recovery_code = "" }, ct)) Assert.Equal(HttpStatusCode.Unauthorized, empty.StatusCode);
                using var issuance = await client.PostAsync("/api/auth/owner-recovery", new StringContent("{}", Encoding.UTF8, "application/json"), ct);
                Assert.Equal(HttpStatusCode.NotImplemented, issuance.StatusCode);
            }
            using (var factory = Host(30))
            using (var client = Client(factory))
            {
                for (int i = 0; i < 5; i++)
                {
                    using var wrong = await Post(client, new { username, password, recovery_code = "guess" }, ct);
                    Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
                }
                using var budget = await Post(client, new { username, password, recovery_code = "guess" }, ct);
                Assert.Equal(HttpStatusCode.TooManyRequests, budget.StatusCode);
                Assert.Equal("900", Assert.Single(budget.Headers.GetValues("Retry-After")));
            }
            using (var factory = Host(3))
            using (var client = Client(factory))
            {
                for (int i = 0; i < 3; i++)
                {
                    using var wrong = await Post(client, new { username, password, recovery_code = "guess" }, ct);
                    Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
                }
                using var source = await Post(client, new { username, password, recovery_code = "guess" }, ct);
                Assert.Equal(HttpStatusCode.TooManyRequests, source.StatusCode);
            }
            await using var connection = await database.OpenConnectionAsync(ct);
            await using var check = new NpgsqlCommand("select failures,blocked_until>clock_timestamp() from auth_login_throttle where account_key=@key", connection);
            check.Parameters.AddWithValue("key", accountKey);
            await using var reader = await check.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal(5, reader.GetInt32(0)); Assert.True(reader.GetBoolean(1));
        }
        finally
        {
            await using var connection = await database.OpenConnectionAsync(ct);
            await using var cleanup = new NpgsqlCommand("""
                delete from auth_sessions where user_id=@id;
                delete from auth_owner_recovery where user_id=@id;
                delete from auth_login_throttle where account_key=@key;
                delete from auth_audit where actor_type='session' and actor_id=@id
                """, connection);
            cleanup.Parameters.AddWithValue("id", id); cleanup.Parameters.AddWithValue("key", accountKey);
            await cleanup.ExecuteNonQueryAsync(ct);
        }
    }
}
