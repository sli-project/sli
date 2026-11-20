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
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

[Collection("Owned user administration response")]
public sealed class UserAdministrationResponseTests
{
    // Break caught: routing a non-login parser/provider error through login-only
    // envelopes, or suppressing global auth messages/correlation while fixing it.
    [Theory]
    [InlineData("ru")]
    [InlineData("en")]
    public async Task ActualUserHttpErrorsHaveSourceNonLoginShapesAndGlobalMessages(string locale)
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal(binding.RunId.ToString("D"), Environment.GetEnvironmentVariable("SLI_ACCESS_WRITES_EXCLUSIVE_RUN"));
        await using var database = await SyntheticDatabase.BorrowAsync(binding, ct);
        byte[] config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json"), ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(config)));
        string name = "ushape_" + Guid.NewGuid().ToString("N");
        string token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        long id = 0;
        await using var connection = await database.OpenConnectionAsync(ct);
        try
        {
            await using (var insert = new NpgsqlCommand("insert into auth_users(username,password_hash,role) values(@name,'synthetic-no-password','admin') returning id", connection))
            { insert.Parameters.AddWithValue("name", name); id = Convert.ToInt64(await insert.ExecuteScalarAsync(ct)); }
            await using (var session = new NpgsqlCommand("insert into auth_sessions(user_id,token_hash,expires_at) values(@id,@hash,now()+interval '1 day')", connection))
            { session.Parameters.AddWithValue("id", id); session.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)))); await session.ExecuteNonQueryAsync(ct); }
            using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, settings) =>
            {
                settings.AddJsonStream(new MemoryStream(config));
                settings.AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1", ["Sli:OwnerSetup"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1" });
            }));
            factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0)); factory.StartServer();
            string address = Assert.Single(factory.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            Assert.True(new Uri(address).IsLoopback);
            using var client = new HttpClient(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
            async Task<(HttpStatusCode Status, JsonElement Body)> Request(string? json, bool authenticated = true, string? origin = null)
            {
                using var request = new HttpRequestMessage(json is null ? HttpMethod.Get : HttpMethod.Post, "/api/auth/users");
                request.Headers.AcceptLanguage.ParseAdd(locale);
                if (authenticated) request.Headers.Add("Cookie", "adlog_session=" + token);
                if (origin is not null) request.Headers.Add("Origin", origin);
                if (json is not null) request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(request, ct);
                Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
                using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));
                return (response.StatusCode, body.RootElement.Clone());
            }
            foreach ((string input, string error) in new[] { ("{", "invalid_json"), ("[]", "json_object_required") })
            {
                var response = await Request(input);
                Assert.Equal(HttpStatusCode.BadRequest, response.Status);
                Assert.True(JsonElement.DeepEquals(JsonSerializer.SerializeToElement(new { error }), response.Body), "Non-login parser response must contain exactly the source error property");
            }
            var anonymous = await Request(null, false);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.Status);
            var expectedAnonymous = new { error = "authentication_required", message = new { code = "login.error.authenticationRequired", @params = new { }, text = locale == "en" ? "Sign in to continue." : "Необходимо войти в систему." } };
            Assert.True(JsonElement.DeepEquals(JsonSerializer.SerializeToElement(expectedAnonymous), anonymous.Body));
            var originDenied = await Request("{}", origin: "https://foreign.example");
            Assert.Equal(HttpStatusCode.Forbidden, originDenied.Status);
            var expectedOrigin = new { error = "cross_origin_request_rejected", message = new { code = "login.error.origin", @params = new { }, text = locale == "en" ? "Sign-in request rejected. Open the sign-in page from the server address." : "Запрос входа отклонён. Откройте страницу входа с адреса сервера." } };
            Assert.True(JsonElement.DeepEquals(JsonSerializer.SerializeToElement(expectedOrigin), originDenied.Body));
            // Real unique violation preserves GAP037's500, with only the safe
            // source error and volatile correlation id; no login unavailable envelope.
            var duplicate = await Request(JsonSerializer.Serialize(new { username = name.ToUpperInvariant(), password = "Owned-User-Response-Synthetic-Password" }));
            Assert.Equal(HttpStatusCode.InternalServerError, duplicate.Status);
            Assert.Equal(new[] { "error", "internal_error_id" }, duplicate.Body.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
            Assert.Equal("internal_server_error", duplicate.Body.GetProperty("error").GetString());
            Assert.True(Guid.TryParse(duplicate.Body.GetProperty("internal_error_id").GetString(), out var correlation) && correlation != Guid.Empty);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("delete from auth_sessions where user_id=@id; delete from auth_users where id=@id and username=@name", connection);
            cleanup.Parameters.AddWithValue("id", id); cleanup.Parameters.AddWithValue("name", name); await cleanup.ExecuteNonQueryAsync(ct);
        }
    }
}
