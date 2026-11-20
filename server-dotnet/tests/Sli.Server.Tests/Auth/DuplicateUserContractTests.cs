using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Auth.Administration;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class DuplicateUserContractTests
{
    private const string Password = "Duplicate-User-Synthetic-Password";

    // A collision must preserve the user and audit row and return a safe HTTP error.
    [Fact]
    public async Task NativeCollisionsKeep23505OneUserOneAuditAndHttp500()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        string token = await fixture.SeedOwnerAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);
        var before = await Totals(db, ct);

        using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder => builder
            .ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureAppConfiguration((_, settings) => settings.AddInMemoryCollection(new Dictionary<string, string?> {
                ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"), ["Sli:TrustedProxies"] = "",
                ["Sli:AuthRequired"] = "1", ["Sli:OwnerSetup"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1"
            })));
        host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        host.StartServer();
        string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        Assert.True(new Uri(address).IsLoopback);
        using var client = new HttpClient(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
        using var scope = host.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserAdministration>();
        var actor = new UserAdministrationActor("session", null, "192.0.2.61");
        var created = await users.CreateAsync(new("gap037-native", Password, "viewer"), actor, ct);
        long nativeId = created.GetProperty("id").GetInt64();
        var afterCreate = await Totals(db, ct);
        Assert.Equal((before.Users + 1, before.Audits + 1), afterCreate);

        var collision = await Assert.ThrowsAsync<PostgresException>(() =>
            users.CreateAsync(new("GAP037-NATIVE", Password, "admin"), actor, ct));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, collision.SqlState);
        Assert.False(string.IsNullOrWhiteSpace(collision.ConstraintName));
        await AssertSingleCreation(db, "gap037-native", nativeId, ct);
        Assert.Equal(afterCreate, await Totals(db, ct));

        // Exercise the collision through HTTP without exposing database details.
        foreach (string name in new[] { "GAP037-NATIVE" })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/users");
            request.Headers.Add("Cookie", "adlog_session=" + token);
            request.Content = new StringContent(JsonSerializer.Serialize(new { username = name, password = Password, role = "admin" }), Encoding.UTF8, "application/json");
            using var response = await client.SendAsync(request, ct);
            Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
            Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
            using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));
            Assert.Equal(new[] { "error", "internal_error_id" }, body.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
            Assert.Equal("internal_server_error", body.RootElement.GetProperty("error").GetString());
            Assert.True(Guid.TryParse(body.RootElement.GetProperty("internal_error_id").GetString(), out var correlation) && correlation != Guid.Empty);
            Assert.Equal(afterCreate, await Totals(db, ct));
        }
        await AssertSingleCreation(db, "gap037-native", nativeId, ct);
    }

    private static async Task<(long Users, long Audits)> Totals(NpgsqlConnection db, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select (select count(*) from auth_users),(select count(*) from auth_audit)", db);
        await using var reader = await command.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct));
        return (reader.GetInt64(0), reader.GetInt64(1));
    }

    private static async Task AssertSingleCreation(NpgsqlConnection db, string name, long id, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select (select count(*) from auth_users where lower(username)=lower(@name)),
                (select count(*) from auth_users where id=@id and username=@name and role='viewer' and is_active),
                (select count(*) from auth_audit where action=@action and outcome='ok')
            """, db);
        command.Parameters.AddWithValue("name", name); command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("action", $"user_created:{id}:{name}");
        await using var reader = await command.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct));
        Assert.Equal(1L, reader.GetInt64(0)); Assert.Equal(1L, reader.GetInt64(1)); Assert.Equal(1L, reader.GetInt64(2));
    }
}
