using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class PrincipalAuthenticatorTests
{
    [Fact]
    public async Task RealPostgresCredentialsFallbackRevocationAndMetadata()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        await using var admitted = await SyntheticDatabase.BorrowAsync(binding, ct);
        Assert.Equal(300, (await admitted.ReadBaselineAsync(ct)).SchemaVersion);
        string sideDirectory = Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side);
        byte[] configBytes = await File.ReadAllBytesAsync(Path.Combine(sideDirectory, "dotnet-test-config.json"), ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"),
            Convert.ToHexStringLower(SHA256.HashData(configBytes)));
        var config = new ConfigurationBuilder().AddJsonStream(new MemoryStream(configBytes)).Build();
        var factory = new PostgresConnectionFactory(config);
        var authenticator = new PrincipalAuthenticator(factory);
        using var fixtures = JsonDocument.Parse(await File.ReadAllBytesAsync(
            Path.Combine(binding.Root, binding.RunId.ToString("D"), "fixture-secrets.json"), ct));
        var tokens = fixtures.RootElement.GetProperty("tokens");
        string Token(string name) => tokens.GetProperty(name).GetString()!;

        async Task<AuthenticationResult> Authenticate(string? cookie = null, string? key = null, string? bearer = null, string? rawCookie = null)
        {
            await admitted.AssertProofAsync(binding.ProofSha256, ct);
            var context = new DefaultHttpContext();
            context.Request.Method = "GET";
            context.Request.Path = "/api/v1/domains";
            if (rawCookie is not null) context.Request.Headers.Cookie = rawCookie;
            else if (cookie is not null) context.Request.Headers.Cookie = "adlog_session=" + cookie;
            if (key is not null) context.Request.Headers["X-ADLog-API-Key"] = key;
            if (bearer is not null) context.Request.Headers.Authorization = "Bearer " + bearer;
            return await authenticator.AuthenticateAsync(context, ct);
        }

        Assert.Equal("authentication_required", (await Authenticate()).Failure?.Code);
        foreach (string name in new[] { "inactive_session", "expired_session", "revoked_session" })
            Assert.Equal(401, (await Authenticate(cookie: Token(name))).Failure?.StatusCode);
        foreach (string name in new[] { "inactive_key", "expired_key", "revoked_key", "inactive_subject_key" })
            Assert.Equal(401, (await Authenticate(key: Token(name))).Failure?.StatusCode);

        await using var metadataConnection = await factory.OpenAsync(ct);
        await using var rejectedSessionTime = new NpgsqlCommand("select last_used_at from auth_sessions where id=201", metadataConnection);
        object? beforeRejected = await rejectedSessionTime.ExecuteScalarAsync(ct);
        string validCookie = "adlog_session=" + Token("owner_session");
        foreach (string malformed in new[] { "broken; " + validCookie, validCookie + "; broken" })
        {
            var rejected = await Authenticate(rawCookie: malformed);
            Assert.Equal(401, rejected.Failure?.StatusCode);
            Assert.Equal("authentication_required", rejected.Failure?.Code);
            Assert.Equal(beforeRejected, await rejectedSessionTime.ExecuteScalarAsync(ct));
            Assert.Equal(401, (await Authenticate(rawCookie: malformed, bearer: "adl_invalid", key: "adl_invalid")).Failure?.StatusCode);
            Assert.Equal(beforeRejected, await rejectedSessionTime.ExecuteScalarAsync(ct));
        }
        Assert.Equal(301L, (await Authenticate(rawCookie: "broken; " + validCookie, key: Token("viewer_key"))).Principal?.Id);
        Assert.Equal(301L, (await Authenticate(rawCookie: validCookie + "; broken", bearer: Token("viewer_key"))).Principal?.Id);
        Assert.Equal(beforeRejected, await rejectedSessionTime.ExecuteScalarAsync(ct));

        var owner = await Authenticate(cookie: Token("owner_session"));
        Assert.True(owner.Succeeded);
        Assert.Equal(101L, owner.Principal!.UserId);
        Assert.Equal("session", owner.Principal.Type);
        Assert.Equal(101L, (await Authenticate(cookie: "\"" + Token("owner_session") + "\"")).Principal?.Id);
        string octalCookie = "\"\\" + Convert.ToString(Token("owner_session")[0], 8).PadLeft(3, '0') + Token("owner_session")[1..] + "\"";
        Assert.Equal(101L, (await Authenticate(cookie: octalCookie)).Principal?.Id);
        Assert.Equal(102L, (await Authenticate(rawCookie: validCookie + "; adlog_session=" + Token("viewer_session"))).Principal?.Id);
        Assert.Equal(101L, (await Authenticate(rawCookie: "adlog_session=invalid; " + validCookie)).Principal?.Id);
        string encodedCookie = "%" + ((int)Token("owner_session")[0]).ToString("X2") + Token("owner_session")[1..];
        Assert.Equal(401, (await Authenticate(cookie: encodedCookie)).Failure?.StatusCode);
        Assert.Equal(101L, (await Authenticate(cookie: Token("owner_session"), key: "adl_invalid", bearer: "invalid")).Principal?.Id);
        var bearerWinner = await Authenticate(cookie: Token("owner_session"), key: Token("admin_key"), bearer: Token("viewer_key"));
        Assert.Equal("api_key", bearerWinner.Principal?.Type);
        Assert.Equal(301L, bearerWinner.Principal?.Id);
        Assert.Null(bearerWinner.Principal?.UserId);
        Assert.Equal(302L, (await Authenticate(cookie: Token("owner_session"), key: Token("admin_key"), bearer: "adl_invalid")).Principal?.Id);

        await using var connection = await factory.OpenAsync(ct);
        await using var sessionTime = new NpgsqlCommand("select last_used_at from auth_sessions where id=201", connection);
        var firstUsed = Assert.IsType<DateTime>(await sessionTime.ExecuteScalarAsync(ct));
        Assert.InRange(DateTime.UtcNow - firstUsed, TimeSpan.Zero, TimeSpan.FromMinutes(1));
        await Authenticate(cookie: Token("owner_session"));
        Assert.Equal(firstUsed, await sessionTime.ExecuteScalarAsync(ct));
        await using var rejectedTimes = new NpgsqlCommand("""
            select count(*) from auth_sessions where id in (204,206,207) and last_used_at is not null
            """, connection);
        Assert.Equal(0L, await rejectedTimes.ExecuteScalarAsync(ct));
        await using var usedKey = new NpgsqlCommand("select last_used_at from auth_api_keys where id=301", connection);
        Assert.IsType<DateTime>(await usedKey.ExecuteScalarAsync(ct));

        // A genuine temporary key exercises report-only restriction before general access.
        string reportToken = "adl_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        string hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(reportToken)));
        await using var insert = new NpgsqlCommand("""
            insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id,expires_at)
            values(@prefix,@hash,'auth synthetic report test','viewer',106,now()+interval '5 minutes') returning id
            """, connection);
        insert.Parameters.AddWithValue("prefix", reportToken[..12]);
        insert.Parameters.AddWithValue("hash", hash);
        long reportKeyId = Assert.IsType<long>(await insert.ExecuteScalarAsync(ct));
        try
        {
            var restricted = await Authenticate(key: reportToken, cookie: Token("owner_session"));
            Assert.Equal(403, restricted.Failure?.StatusCode);
            Assert.Equal("report_key_route_denied", restricted.Failure?.Code);
        }
        finally
        {
            await using var delete = new NpgsqlCommand("delete from auth_api_keys where id=@id and key_hash=@hash", connection);
            delete.Parameters.AddWithValue("id", reportKeyId);
            delete.Parameters.AddWithValue("hash", hash);
            await delete.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }

    [Fact]
    public void TransportTrustAndCoarseRoleFailClosed()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:TrustedProxies"] = "127.0.0.1/32" }).Build();
        var gate = new TransportGate(configuration);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/domains";
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.1");
        context.Request.Headers["X-Forwarded-Proto"] = "https";
        Assert.Equal("secure_transport_required", gate.CheckTransport(context)?.Code);
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        Assert.Null(gate.CheckTransport(context));
        context.Request.Headers["X-Forwarded-Proto"] = new[] { "https", "http" };
        Assert.Equal("secure_transport_required", gate.CheckTransport(context)?.Code);
        Assert.Null(TransportGate.CheckViewerRole(new("session", 1, "viewer")));
        Assert.Equal("insufficient_permissions", TransportGate.CheckViewerRole(new("session", 1, "unknown"))?.Code);
        Assert.Throws<InvalidOperationException>(() => new PostgresConnectionFactory(new ConfigurationBuilder().Build()));
    }
}
