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
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

[Collection("Owned user administration")]
public sealed class UserAdministrationTests
{
    private const string Password = "User-Administration-Synthetic-🔐";

    // Break caught: missing admin/capability/origin guards, payload validation,
    // source methods/coercion, safe inventory or transaction-bound audit.
    [Fact]
    public async Task HttpUsersPreservePermissionsValidationInventoryAndAuditedWrites()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.OpenAsync(ct);
        using var host = f.Host();
        using var client = f.Client(host);
        async Task<JsonElement> Expect(string method, string path, object? body, HttpStatusCode status, string? error = null,
            string? cookie = null, string? origin = null, string? key = null)
        {
            var response = await Send(client, method, path, body, cookie ?? f.AdminSession, origin, key, ct);
            Assert.Equal(status, response.Status);
            if (error is not null) Assert.Equal(error, response.Body.GetProperty("error").GetString());
            return response.Body;
        }
        var anonymous = await Send(client, "GET", "/api/auth/users", null, null, null, null, ct);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.Status);
        await Expect("GET", "/api/auth/users", null, HttpStatusCode.Forbidden, "insufficient_permissions", f.ViewerSession);
        await Expect("POST", "/api/auth/users", new { }, HttpStatusCode.Forbidden, "cross_origin_request_rejected", origin: "https://foreign.example");
        await Expect("POST", "/api/auth/users", new { }, HttpStatusCode.Forbidden, "insufficient_permissions", f.ViewerSession);
        await Expect("GET", "/api/auth/users", null, HttpStatusCode.Forbidden, "explicit_deny", f.DeniedSession);
        await Expect("POST", "/api/auth/users", new { username = "!!", password = Password }, HttpStatusCode.BadRequest, "username_must_be_3_to_64_characters");
        await Expect("POST", "/api/auth/users", new { username = f.Prefix + "role", password = Password, role = "root" }, HttpStatusCode.BadRequest, "invalid_role");
        await Expect("POST", "/api/auth/users", new { username = f.Prefix + "short", password = string.Concat(Enumerable.Repeat("🔐", 11)) }, HttpStatusCode.BadRequest, "password_must_be_at_least_12_characters");
        await Expect("POST", "/api/auth/users/not-an-id", new { }, HttpStatusCode.BadRequest, "invalid_user_id");
        await Expect("POST", "/api/auth/users/-1", new { role = "viewer" }, HttpStatusCode.BadRequest, "user_not_found");
        await Expect("POST", "/api/auth/users/999999999999999999999999999999999", new { role = "viewer" }, HttpStatusCode.BadRequest, "user_not_found");
        await Expect("POST", "/api/auth/users/" + f.AdminId, new { is_active = false }, HttpStatusCode.BadRequest, "cannot_disable_current_user");
        await Expect("POST", "/api/auth/users/" + f.ViewerId, new { is_active = "false" }, HttpStatusCode.BadRequest, "is_active_must_be_boolean");
        await Expect("POST", "/api/auth/users/" + f.ViewerId, new { role = (string?)null, is_active = (bool?)null }, HttpStatusCode.BadRequest, "user_update_required");
        await Expect("POST", "/api/auth/users/" + f.ViewerId, new { role = true }, HttpStatusCode.BadRequest, "invalid_role");
        var malformed = await Send(client, "POST", "/api/auth/users", "not JSON", f.AdminSession, null, null, ct, raw: true);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.Status); Assert.Equal("invalid_json", malformed.Body.GetProperty("error").GetString());
        var nonObject = await Send(client, "POST", "/api/auth/users", new[] { 1 }, f.AdminSession, null, null, ct);
        Assert.Equal("json_object_required", nonObject.Body.GetProperty("error").GetString());
        // Twelve supplementary code points are sufficient even though UTF16 length is24.
        string name = f.Prefix + "created";
        string unicodePassword = string.Concat(Enumerable.Repeat("🔐", 12));
        var created = await Expect("POST", "/api/auth/users", new { username = "\u001c " + name + " \u001f", password = unicodePassword, role = " ADMIN ", is_service = true }, HttpStatusCode.Created);
        long id = created.GetProperty("item").GetProperty("id").GetInt64();
        Assert.Equal(name, created.GetProperty("item").GetProperty("username").GetString());
        Assert.Equal("admin", created.GetProperty("item").GetProperty("role").GetString());
        Assert.False(created.GetProperty("item").TryGetProperty("password_hash", out _));
        Assert.False(created.GetProperty("item").TryGetProperty("is_service", out _));
        Assert.Matches(@"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d{6})?\+00:00$", created.GetProperty("item").GetProperty("created_at").GetString()!);
        Assert.True(await f.CheckPasswordAsync(id, unicodePassword, ct));
        // Source does not catch the case-insensitive unique violation; keep500 pending GAP037.
        await Expect("POST", "/api/auth/users", new { username = name.ToUpperInvariant(), password = Password }, HttpStatusCode.InternalServerError, "internal_server_error");
        var updated = await Expect("POST", "/api/auth/users/" + id, new { role = "operator" }, HttpStatusCode.OK);
        Assert.Equal("operator", updated.GetProperty("item").GetProperty("role").GetString());
        // Empty/false role on create uses source's default viewer; is_service body is ignored.
        string maxName = f.Prefix + new string('x', 64 - f.Prefix.Length);
        var maximum = await Expect("POST", "/api/auth/users", new { username = maxName, password = Password, role = false }, HttpStatusCode.Created);
        Assert.Equal("viewer", maximum.GetProperty("item").GetProperty("role").GetString());
        await Expect("POST", "/api/auth/users", new { username = maxName + "x", password = Password }, HttpStatusCode.BadRequest, "username_must_be_3_to_64_characters");
        var list = await Expect("GET", "/api/auth/users?ignored=1", null, HttpStatusCode.OK);
        Assert.Equal(new[] { "viewer", "operator", "admin" }, list.GetProperty("roles").EnumerateArray().Select(r => r.GetProperty("id").GetString()));
        Assert.Equal("ИБ", list.GetProperty("roles")[0].GetProperty("label").GetString());
        var listed = Assert.Single(list.GetProperty("items").EnumerateArray(), u => u.GetProperty("id").GetInt64() == id);
        Assert.False(listed.GetProperty("is_service").GetBoolean());
        Assert.True(Assert.Single(list.GetProperty("items").EnumerateArray(), u => u.GetProperty("id").GetInt64() == f.ServiceId).GetProperty("is_service").GetBoolean());
        Assert.True(Assert.Single(list.GetProperty("items").EnumerateArray(), u => u.GetProperty("id").GetInt64() == f.LegacyServiceId).GetProperty("is_service").GetBoolean());
        Assert.All(list.GetProperty("items").EnumerateArray(), u => Assert.False(u.TryGetProperty("password_hash", out _)));
        await f.AssertAuditAsync("user_created:" + id + ":" + name, f.AdminId, ct);
        await f.AssertAuditAsync("user_updated:" + id + ":" + name, f.AdminId, ct);
        // No PATCH route is registered by the frozen source.
        Assert.NotEqual(HttpStatusCode.OK, (await Send(client, "PATCH", "/api/auth/users/" + id, new { role = "admin" }, f.AdminSession, null, null, ct)).Status);
        using var offHost = f.Host(authRequired: false);
        using var offClient = f.Client(offHost);
        var tokenFailure = await Send(offClient, "POST", "/api/auth/users", new { }, f.AdminSession, null, null, ct);
        Assert.Equal("operator_token_required", tokenFailure.Body.GetProperty("error").GetString());
    }

    // Break caught: disable/reset that leave old sessions usable, revoke other
    // accounts or keys, reset disabled users, or lose atomic audit.
    [Fact]
    public async Task DisableAndPasswordResetRevokeOnlyTargetsAndImmediatelyDenyMeAndDomains()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.OpenAsync(ct);
        using var host = f.Host(); using var client = f.Client(host);
        foreach (string route in new[] { "/api/auth/me", "/api/v1/domains" })
            Assert.Equal(HttpStatusCode.OK, (await Send(client, "GET", route, null, f.ViewerSession, null, null, ct)).Status);
        var disabled = await Send(client, "POST", "/api/auth/users/" + f.ViewerId, new { is_active = false }, f.AdminSession, null, null, ct);
        Assert.Equal(HttpStatusCode.OK, disabled.Status);
        foreach (string route in new[] { "/api/auth/me", "/api/v1/domains" })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await Send(client, "GET", route, null, f.ViewerSession, null, null, ct)).Status);
            Assert.Equal(HttpStatusCode.OK, (await Send(client, "GET", route, null, f.AdminSession, null, null, ct)).Status);
        }
        var deniedReset = await Send(client, "POST", "/api/auth/users/" + f.ViewerId + "/password", new { password = Password }, f.AdminSession, null, null, ct);
        Assert.Equal("cannot_reset_password_for_disabled_user", deniedReset.Body.GetProperty("error").GetString());
        string replacement = "Replacement-Only-Synthetic-🔐";
        var reset = await Send(client, "POST", "/api/auth/users/" + f.ResetId + "/password", new { password = replacement }, f.AdminSession, null, null, ct);
        Assert.Equal(HttpStatusCode.OK, reset.Status); Assert.True(reset.Body.GetProperty("item").GetProperty("sessions_revoked").GetBoolean());
        Assert.True(await f.CheckPasswordAsync(f.ResetId, replacement, ct)); Assert.False(await f.CheckPasswordAsync(f.ResetId, Password, ct));
        foreach (string route in new[] { "/api/auth/me", "/api/v1/domains" })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await Send(client, "GET", route, null, f.ResetSession, null, null, ct)).Status);
            Assert.Equal(HttpStatusCode.OK, (await Send(client, "GET", route, null, f.AdminSession, null, null, ct)).Status);
            Assert.Equal(HttpStatusCode.OK, (await Send(client, "GET", route, null, null, null, f.AdminKey, ct)).Status);
        }
        await f.AssertAuditAsync("user_password_reset:" + f.ResetId + ":" + f.Prefix + "reset", f.AdminId, ct);
        using var scope = host.Services.CreateScope();
        var login = await scope.ServiceProvider.GetRequiredService<ILoginService>().LoginAsync(new(f.Prefix + "reset", replacement, false), new("192.0.2.61"), ct);
        Assert.True(login.Succeeded);
        Assert.Equal(HttpStatusCode.OK, (await Send(client, "GET", "/api/v1/domains", null, login.SessionToken, null, null, ct)).Status);
    }

    // Break caught: two concurrent active-admin demotions both committing and
    // leaving no active user administrator. Uses only a separately owned side.
    [Fact]
    public async Task ConcurrentLastAdministratorDemotionsHaveExactlyOneWinner()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.OpenAsync(ct);
        await f.ExclusiveAdminPairAsync(ct);
        using var host = f.Host(); using var client = f.Client(host);
        try
        {
            await using var blocker = await f.Database.OpenConnectionAsync(ct);
            await using var transaction = await blocker.BeginTransactionAsync(ct);
            await using (var hold = new NpgsqlCommand("select id from auth_users where role='admin' and is_active=true order by id for update", blocker, transaction))
            { await using var reader = await hold.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) { } }
            var first = Send(client, "POST", "/api/auth/users/" + f.AdminId, new { role = "viewer" }, null, null, f.AdminKey, ct);
            var second = Send(client, "POST", "/api/auth/users/" + f.ResetId, new { role = "viewer" }, null, null, f.AdminKey, ct);
            bool bothWaiting = false;
            await using (var observer = await f.Database.OpenConnectionAsync(ct))
            {
                for (int attempt = 0; attempt < 100; attempt++)
                {
                    await using var query = new NpgsqlCommand("select count(*) from pg_stat_activity where application_name=@app and wait_event_type='Lock' and query like 'select id from auth_users where role=%'", observer);
                    query.Parameters.AddWithValue("app", f.ApplicationName);
                    if (Convert.ToInt64(await query.ExecuteScalarAsync(ct)) == 2) { bothWaiting = true; break; }
                    await Task.Delay(20, ct);
                }
            }
            await transaction.CommitAsync(ct);
            var results = await Task.WhenAll(first, second);
            Assert.True(bothWaiting, "Both production admin checks must wait on actual PostgreSQL row locks before release");
            Assert.Single(results, r => r.Status == HttpStatusCode.OK);
            Assert.Equal("last_active_admin_required", Assert.Single(results, r => r.Status == HttpStatusCode.BadRequest).Body.GetProperty("error").GetString());
            await using var check = new NpgsqlCommand("select count(*) from auth_users where role='admin' and is_active=true", blocker);
            Assert.Equal(1L, await check.ExecuteScalarAsync(ct));
        }
        finally { await f.RestoreExclusiveAdminsAsync(ct); }
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> Send(HttpClient client, string method, string path, object? payload,
        string? cookie, string? origin, string? key, CancellationToken ct, bool raw = false)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (cookie is not null) request.Headers.Add("Cookie", "adlog_session=" + cookie);
        if (origin is not null) request.Headers.Add("Origin", origin);
        if (key is not null) request.Headers.Add("X-ADLog-API-Key", key);
        if (payload is not null) request.Content = new StringContent(raw ? (string)payload : JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, ct);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));
        return (response.StatusCode, body.RootElement.Clone());
    }

    private sealed class Fixture(SyntheticDatabase database, byte[] config) : IAsyncDisposable
    {
        public SyntheticDatabase Database { get; } = database;
        public string Prefix { get; } = "uadmin_" + Guid.NewGuid().ToString("N")[..16] + "_";
        public string ApplicationName => Prefix + "host";
        private readonly CredentialTokens tokens = new();
        public string AdminSession { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public string ViewerSession { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public string ResetSession { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public string DeniedSession { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public string AdminKey { get; } = "adl_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public long AdminId, ViewerId, ResetId, DeniedId, ServiceId, LegacyServiceId;
        private readonly List<long> previousAdmins = [];

        public static async Task<Fixture> OpenAsync(CancellationToken ct)
        {
            var binding = OwnedDatabaseBinding.FromEnvironment();
            Assert.Equal(binding.RunId.ToString("D"), Environment.GetEnvironmentVariable("SLI_USER_ADMIN_EXCLUSIVE_RUN"));
            Assert.NotEqual("25e9e697-c2d5-4704-a205-aeab5b3f1b5b", binding.RunId.ToString("D"));
            var db = await SyntheticDatabase.BorrowAsync(binding, ct);
            byte[] config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json"), ct);
            Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(config)));
            var fixture = new Fixture(db, config);
            try { await fixture.SeedAsync(ct); return fixture; }
            catch { await fixture.DisposeAsync(); throw; }
        }

        private async Task SeedAsync(CancellationToken ct)
        {
            string hash = new PasswordCodec().Hash(Password);
            await using var connection = await Database.OpenConnectionAsync(ct);
            async Task<long> User(string suffix, string role, bool service, string? session)
            {
                await using var insert = new NpgsqlCommand("insert into auth_users(username,password_hash,role,is_service) values(@name,@hash,@role,@service) returning id", connection);
                insert.Parameters.AddWithValue("name", Prefix + suffix); insert.Parameters.AddWithValue("hash", hash);
                insert.Parameters.AddWithValue("role", role); insert.Parameters.AddWithValue("service", service);
                long id = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
                if (session is not null)
                {
                    await using var add = new NpgsqlCommand("insert into auth_sessions(user_id,token_hash,expires_at) values(@id,@hash,now()+interval '1 day')", connection);
                    add.Parameters.AddWithValue("id", id); add.Parameters.AddWithValue("hash", tokens.Digest(session)); await add.ExecuteNonQueryAsync(ct);
                }
                return id;
            }
            AdminId = await User("admin", "admin", false, AdminSession);
            ViewerId = await User("viewer", "viewer", false, ViewerSession);
            ResetId = await User("reset", "admin", false, ResetSession);
            DeniedId = await User("denied", "admin", false, DeniedSession);
            ServiceId = await User("service", "viewer", true, null);
            LegacyServiceId = await User("legacy", "viewer", false, null);
            await using (var deny = new NpgsqlCommand("insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,scope_json,business_reason) select 'user',@id,id,'deny','{" + "\"kind\":\"all\"" + "}'::jsonb,'owned user-administration deny' from access_capabilities where capability_key='access.manage'", connection))
            { deny.Parameters.AddWithValue("id", DeniedId); Assert.Equal(1, await deny.ExecuteNonQueryAsync(ct)); }
            foreach (bool restricted in new[] { false, true })
            {
                string key = restricted ? "adl_" + tokens.NewSessionToken() : AdminKey;
                await using var insert = new NpgsqlCommand("insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id) values(@prefix,@hash,@label,'admin',@subject)", connection);
                insert.Parameters.AddWithValue("prefix", key[..12]); insert.Parameters.AddWithValue("hash", tokens.Digest(key)); insert.Parameters.AddWithValue("label", Prefix + "key");
                insert.Parameters.AddWithValue("subject", NpgsqlTypes.NpgsqlDbType.Bigint, restricted ? LegacyServiceId : DBNull.Value);
                await insert.ExecuteNonQueryAsync(ct);
            }
        }

        public WebApplicationFactory<Program> Host(bool authRequired = true) => new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, settings) =>
            {
                settings.AddJsonStream(new MemoryStream(config));
                using var json = JsonDocument.Parse(config);
                var cs = new NpgsqlConnectionStringBuilder(json.RootElement.GetProperty("ConnectionStrings").GetProperty("Sli").GetString()) { ApplicationName = ApplicationName };
                settings.AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = cs.ConnectionString,
                    ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = authRequired ? "1" : "0", ["Sli:AllowUnauthenticated"] = "1",
                    ["Sli:OwnerSetup"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:OperatorToken"] = "owned-user-admin-operator-token" });
            }));

        public HttpClient Client(WebApplicationFactory<Program> factory)
        {
            factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0)); factory.StartServer();
            string address = Assert.Single(factory.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            Assert.True(new Uri(address).IsLoopback);
            return new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false }) { BaseAddress = new Uri(address) };
        }

        public async Task<bool> CheckPasswordAsync(long id, string password, CancellationToken ct)
        {
            await using var connection = await Database.OpenConnectionAsync(ct);
            await using var command = new NpgsqlCommand("select password_hash from auth_users where id=@id", connection); command.Parameters.AddWithValue("id", id);
            return new PasswordCodec().Verify((string)(await command.ExecuteScalarAsync(ct))!, password).Valid;
        }

        public async Task AssertAuditAsync(string action, long actor, CancellationToken ct)
        {
            await using var connection = await Database.OpenConnectionAsync(ct);
            await using var command = new NpgsqlCommand("select count(*) from auth_audit where action=@action and actor_type='session' and actor_id=@actor and outcome='ok'", connection);
            command.Parameters.AddWithValue("action", action); command.Parameters.AddWithValue("actor", actor);
            Assert.Equal(1L, await command.ExecuteScalarAsync(ct));
        }

        public async Task ExclusiveAdminPairAsync(CancellationToken ct)
        {
            await using var connection = await Database.OpenConnectionAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            await using (var select = new NpgsqlCommand("select id from auth_users where role='admin' and is_active=true and id<>@a and id<>@b order by id for update", connection, transaction))
            { select.Parameters.AddWithValue("a", AdminId); select.Parameters.AddWithValue("b", ResetId); await using var reader = await select.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) previousAdmins.Add(reader.GetInt64(0)); }
            foreach (long id in previousAdmins)
            { await using var update = new NpgsqlCommand("update auth_users set role='viewer' where id=@id", connection, transaction); update.Parameters.AddWithValue("id", id); await update.ExecuteNonQueryAsync(ct); }
            await transaction.CommitAsync(ct);
        }

        public async Task RestoreExclusiveAdminsAsync(CancellationToken ct)
        {
            if (previousAdmins.Count == 0) return;
            await using var connection = await Database.OpenConnectionAsync(ct);
            await using var command = new NpgsqlCommand("update auth_users set role='admin' where id=any(@ids)", connection);
            command.Parameters.AddWithValue("ids", previousAdmins.ToArray()); await command.ExecuteNonQueryAsync(ct); previousAdmins.Clear();
        }

        public async ValueTask DisposeAsync()
        {
            await RestoreExclusiveAdminsAsync(CancellationToken.None);
            await using var connection = await Database.OpenConnectionAsync(CancellationToken.None);
            await using var cleanup = new NpgsqlCommand("""
                delete from auth_audit where actor_type='session' and actor_id in(select id from auth_users where left(username,length(@prefix))=@prefix);
                delete from auth_api_keys where left(label,length(@prefix))=@prefix;
                delete from access_capability_assignments where subject_type='user' and subject_id in(select id from auth_users where left(username,length(@prefix))=@prefix);
                delete from auth_sessions where user_id in(select id from auth_users where left(username,length(@prefix))=@prefix);
                delete from auth_users where left(username,length(@prefix))=@prefix
                """, connection);
            cleanup.Parameters.AddWithValue("prefix", Prefix); await cleanup.ExecuteNonQueryAsync();
            await Database.DisposeAsync();
        }
    }
}
