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

public sealed class ReportKeyRequestGateTests
{
    [Fact]
    public async Task RestrictedKeyIsDeniedBeforePublicAndMutationRoutesWithoutSessionEffects()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        await using var db = await SyntheticDatabase.BorrowAsync(binding, ct);
        byte[] config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json"), ct);
        Assert.True(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256") == Convert.ToHexStringLower(SHA256.HashData(config)), "Owned configuration hash mismatch.");
        string name = "netgate_" + Guid.NewGuid().ToString("N")[..16];
        var tokens = new CredentialTokens();
        string reportToken = "adl_" + tokens.NewSessionToken(), ordinaryToken = "adl_" + tokens.NewSessionToken(), session = tokens.NewSessionToken();
        long user = 0, reportKey = 0, ordinaryKey = 0;
        await using var connection = await db.OpenConnectionAsync(ct);
        try
        {
            await using (var command = new NpgsqlCommand("insert into auth_users(username,password_hash,role,is_active) values(@name,'synthetic-no-password','viewer',true) returning id", connection))
            { command.Parameters.AddWithValue("name", name); user = Convert.ToInt64(await command.ExecuteScalarAsync(ct)); }
            foreach (bool restricted in new[] { true, false })
            {
                await using var command = new NpgsqlCommand("insert into auth_api_keys(key_prefix,key_hash,label,role,is_active,report_subject_id,last_used_at) values(@prefix,@hash,@label,'viewer',true,@subject,now()-interval '10 minutes') returning id", connection);
                string token = restricted ? reportToken : ordinaryToken;
                command.Parameters.AddWithValue("prefix", token[..12]); command.Parameters.AddWithValue("hash", tokens.Digest(token)); command.Parameters.AddWithValue("label", name);
                command.Parameters.AddWithValue("subject", NpgsqlTypes.NpgsqlDbType.Bigint, restricted ? user : DBNull.Value);
                long id = Convert.ToInt64(await command.ExecuteScalarAsync(ct)); if (restricted) reportKey = id; else ordinaryKey = id;
            }
            await using (var command = new NpgsqlCommand("insert into auth_sessions(user_id,token_hash,expires_at,last_used_at) values(@user,@hash,now()+interval '1 day',now()-interval '10 minutes')", connection))
            { command.Parameters.AddWithValue("user", user); command.Parameters.AddWithValue("hash", tokens.Digest(session)); await command.ExecuteNonQueryAsync(ct); }
            async Task<(long Audit, long Throttle, DateTime? Used, bool Revoked)> StateAsync()
            {
                await using var command = new NpgsqlCommand("select (select count(*) from auth_audit),(select count(*) from auth_login_throttle),last_used_at,revoked_at is not null from auth_sessions where user_id=@user and token_hash=@hash", connection);
                command.Parameters.AddWithValue("user", user); command.Parameters.AddWithValue("hash", tokens.Digest(session));
                await using var reader = await command.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
                return (reader.GetInt64(0), reader.GetInt64(1), reader.IsDBNull(2) ? null : reader.GetDateTime(2), reader.GetBoolean(3));
            }
            using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, settings) =>
            {
                settings.AddJsonStream(new MemoryStream(config));
                settings.AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1", ["Sli:OwnerSetup"] = "0" });
            }));
            factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
            factory.StartServer();
            string address = Assert.Single(factory.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            Assert.True(new Uri(address).IsLoopback);
            using var client = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false }) { BaseAddress = new Uri(address) };
            var before = await StateAsync();
            foreach ((string method, string path) in new[] { ("POST", "/api/auth/logout"), ("POST", "/api/auth/login"), ("GET", "/login"), ("GET", "/sli-login.js"), ("GET", "/api/auth/me") })
            {
                using var request = new HttpRequestMessage(new HttpMethod(method), path);
                request.Headers.Authorization = new("Bearer", reportToken); request.Headers.Add("Cookie", "adlog_session=" + session);
                // Logout proves report-key denial precedes bad Origin; login has
                // no Origin so an incorrect gate would reach admission/body parsing.
                if (path != "/api/auth/login") request.Headers.Add("Origin", "https://bad.example");
                if (method == "POST") request.Content = new StringContent("invalid JSON", Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(request, ct);
                Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                Assert.Equal("report_key_route_denied", body.RootElement.GetProperty("error").GetString());
                Assert.False(response.Headers.Contains("Set-Cookie"));
                Assert.Equal(before, await StateAsync());
            }
            // Candidate key metadata still uses the existing five-minute SQL update.
            await using (var used = new NpgsqlCommand("select last_used_at > now()-interval '1 minute' from auth_api_keys where id=@id", connection))
            { used.Parameters.AddWithValue("id", reportKey); Assert.True(await used.ExecuteScalarAsync(ct) is true); }
            // Invalid earlier credentials fall through to the ordinary cookie on /me.
            using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me"))
            {
                request.Headers.Authorization = new("Bearer", "adl_invalid"); request.Headers.Add("X-ADLog-API-Key", "adl_invalid"); request.Headers.Add("Cookie", "adlog_session=" + session);
                using var response = await client.SendAsync(request, ct); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
            // Ordinary Bearer takes precedence over a later restricted X key.
            using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me"))
            {
                request.Headers.Authorization = new("Bearer", ordinaryToken); request.Headers.Add("X-ADLog-API-Key", reportToken);
                using var response = await client.SendAsync(request, ct); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
            // Ordinary keys still reach the real domain access engine. Report keys
            // do not gain /domains access: that route is outside their frozen allowlist.
            using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/domains"))
            {
                request.Headers.Authorization = new("Bearer", ordinaryToken);
                using var response = await client.SendAsync(request, ct); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
            using (var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout"))
            {
                request.Headers.Authorization = new("Bearer", "adl_invalid"); request.Headers.Add("Cookie", "adlog_session=" + session);
                using var response = await client.SendAsync(request, ct); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
            Assert.True((await StateAsync()).Revoked);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("delete from auth_sessions where user_id=@user; delete from auth_api_keys where id=@report or id=@ordinary; delete from auth_users where id=@user and username=@name", connection);
            cleanup.Parameters.AddWithValue("user", user); cleanup.Parameters.AddWithValue("name", name); cleanup.Parameters.AddWithValue("report", reportKey); cleanup.Parameters.AddWithValue("ordinary", ordinaryKey);
            await cleanup.ExecuteNonQueryAsync(ct);
        }
    }
}
