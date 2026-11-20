using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Auth.InitialOwner;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class NativeOwnerSetupPostgresTests
{
    // tests/access/test_native_owner_setup_postgres.py: real claim, audit bridge,
    // password codec and session persistence on the migrated schema as adlog_user.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Owner_activation_commits_exact_audit_and_credential_state(bool validCode)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var passwords = new PasswordCodec();
        const string code = "synthetic-onetime-code";
        const string password = "synthetic-new-owner-password-xxxxxxxxxxxxxxxxxxxx";
        string codeHash = passwords.Hash(code);
        long userId, auditBefore;
        await using (var admin = new NpgsqlConnection(fixture.Pg.ConnectionString))
        {
            await admin.OpenAsync(ct);
            await using var seed = new NpgsqlCommand("""
                update auth_users set password_hash=@hash,role='admin',is_active=true,
                    last_login_at=null,updated_at=clock_timestamp()
                where username='platform-owner' returning id
                """, admin);
            seed.Parameters.AddWithValue("hash", codeHash);
            userId = Convert.ToInt64(await seed.ExecuteScalarAsync(ct));
            Assert.True(userId > 0);
            await using var owner = new NpgsqlCommand("""
                insert into access_platform_owners(user_id,owner_key,business_reason)
                values(@id,'primary','synthetic owner activation')
                on conflict(owner_key) do update set user_id=excluded.user_id
                """, admin);
            owner.Parameters.AddWithValue("id", userId);
            await owner.ExecuteNonQueryAsync(ct);
            await using var before = new NpgsqlCommand("select coalesce(max(id),0) from auth_audit", admin);
            auditBefore = Convert.ToInt64(await before.ExecuteScalarAsync(ct));
        }

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        { EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
            ["Sli:OwnerSetup"] = "1", ["Sli:AuthRequired"] = "1",
            ["Sli:AllowUnauthenticated"] = "0", ["Sli:AuthCookieSecure"] = "1",
            ["Sli:TrustedProxies"] = "127.0.0.1/32", ["ADLOG_MAX_LOGIN_FAILURES"] = "30"
        });
        builder.WebHost.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        builder.Services.AddSingleton<IPostgresConnectionFactory, PostgresConnectionFactory>();
        builder.Services.AddSingleton<TransportGate>();
        builder.Services.AddAuthLifecycle();
        builder.Services.AddAuthLoginSecurity();
        builder.Services.AddInitialOwner();
        await using var app = builder.Build();
        app.MapInitialOwnerEndpoints();
        await app.StartAsync(ct);
        string address = Assert.Single(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        Assert.True(new Uri(address).IsLoopback);
        using var client = new HttpClient(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
        client.DefaultRequestHeaders.Add("X-Forwarded-Proto", "https");
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "192.0.2.1");

        // No replacement of InitialOwnerSetup, AuthAudit (including its mapping), or sessions.
        using var content = new StringContent(JsonSerializer.Serialize(
            new { code = validCode ? code : "synthetic-wrong-code", password }), Encoding.UTF8, "application/json");
        using var response = await client.PostAsync("/api/auth/bootstrap", content, ct);
        Assert.Equal(validCode ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, response.StatusCode);
        await using (var runtime = await app.Services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(ct))
        {
            await using (var role = new NpgsqlCommand("select current_user,rolsuper,rolbypassrls from pg_roles where rolname=current_user", runtime))
            await using (var reader = await role.ExecuteReaderAsync(ct))
            {
                Assert.True(await reader.ReadAsync(ct));
                Assert.Equal("adlog_user", reader.GetString(0));
                Assert.False(reader.GetBoolean(1));
                Assert.False(reader.GetBoolean(2));
            }
            await using (var audit = new NpgsqlCommand("""
                select actor_type,actor_id,action,outcome from auth_audit where id>@before order by id
                """, runtime))
            {
                audit.Parameters.AddWithValue("before", auditBefore);
                await using var reader = await audit.ExecuteReaderAsync(ct);
                Assert.True(await reader.ReadAsync(ct));
                Assert.Equal(validCode ? "session" : "anonymous", reader.GetString(0));
                if (validCode) Assert.Equal(userId, reader.GetInt64(1));
                else Assert.True(reader.IsDBNull(1));
                Assert.Equal("initial_owner_claimed", reader.GetString(2));
                Assert.Equal(validCode ? "ok" : "failed", reader.GetString(3));
                Assert.False(await reader.ReadAsync(ct));
            }
            await using var state = new NpgsqlCommand("select password_hash,last_login_at from auth_users where id=@id", runtime);
            state.Parameters.AddWithValue("id", userId);
            await using var user = await state.ExecuteReaderAsync(ct);
            Assert.True(await user.ReadAsync(ct));
            Assert.True(passwords.Verify(user.GetString(0), validCode ? password : code).Valid);
            Assert.Equal(validCode, !user.IsDBNull(1));
            if (!validCode) Assert.Equal(codeHash, user.GetString(0));
        }
        if (validCode)
        {
            using var scope = app.Services.CreateScope();
            var replay = await scope.ServiceProvider.GetRequiredService<IInitialOwnerSetup>()
                .ClaimAsync(new(code, password), new("192.0.2.1"), ct);
            Assert.False(replay.Succeeded);
            Assert.Null(replay.Principal);
            Assert.Null(replay.SessionToken);
        }
        await app.StopAsync(ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
