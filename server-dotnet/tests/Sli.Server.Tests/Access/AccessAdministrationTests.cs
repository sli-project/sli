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
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Access;

[Collection("Owned access writes")]
public sealed class AccessAdministrationTests
{
    [Fact]
    public async Task IntegratedProgramComposesLoginUsersAssignmentAndBootstrap()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.OpenAsync(ct);
        const string password = "Integration-Synthetic-Password-123";
        bool pending;
        await using (var connection = await f.OpenConnectionAsync(ct))
        {
            await using var update = new NpgsqlCommand("update auth_users set password_hash=@hash where id=@id and username=@name", connection);
            update.Parameters.AddWithValue("hash", new PasswordCodec().Hash(password));
            update.Parameters.AddWithValue("id", f.AdminId);
            update.Parameters.AddWithValue("name", f.Marker + "admin");
            Assert.Equal(1, await update.ExecuteNonQueryAsync(ct));
            await using var query = new NpgsqlCommand("select exists(select 1 from auth_users u join access_platform_owners o on o.user_id=u.id where u.username='platform-owner' and o.owner_key='primary' and u.role='admin' and u.is_active and u.last_login_at is null)", connection);
            pending = (bool)(await query.ExecuteScalarAsync(ct))!;
        }
        using var host = f.Host(ownerSetup: true);
        using var client = f.Client(host);
        using var loginBody = new StringContent(JsonSerializer.Serialize(new { username = f.Marker + "admin", password }), Encoding.UTF8, "application/json");
        using var login = await client.PostAsync("/api/auth/login", loginBody, ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        string cookie = Assert.Single(login.Headers.GetValues("Set-Cookie")).Split(';')[0].Split('=', 2)[1];
        Assert.Equal(HttpStatusCode.OK, (await Send(client, "GET", "/api/auth/me", null, cookie, null, null, ct)).Status);
        Assert.Equal(HttpStatusCode.OK, (await Send(client, "GET", "/api/auth/users", null, cookie, null, null, ct)).Status);
        Assert.Equal(HttpStatusCode.Created, (await Send(client, "POST", "/api/v1/access/assignments", Report(f), cookie, null, null, ct)).Status);
        using var bootstrap = await client.GetAsync("/api/auth/bootstrap", ct);
        Assert.Equal(pending ? HttpStatusCode.OK : HttpStatusCode.NotFound, bootstrap.StatusCode);
    }

    [Fact]
    public async Task HttpAssignmentGatesAndSourceValidationPreserveStatusesAndEnvelopes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        async Task<JsonElement> Post(Dictionary<string, object?> payload, string? error = null, string? cookie = null, string? route = null)
        {
            var result = await Send(client, "POST", route ?? "/api/v1/access/assignments", payload, cookie ?? f.AdminSession, null, null, ct);
            Assert.Equal(error is null ? HttpStatusCode.Created : HttpStatusCode.BadRequest, result.Status);
            if (error is not null) { Assert.Equal(error, result.Body.GetProperty("error").GetString()); Assert.False(result.Body.TryGetProperty("message", out _)); }
            return result.Body;
        }
        var missing = await Send(client, "POST", "/api/v1/access/assignments", Report(f), null, null, null, ct);
        Assert.Equal(HttpStatusCode.Unauthorized, missing.Status); Assert.Equal("login.error.authenticationRequired", missing.Body.GetProperty("message").GetProperty("code").GetString());
        var viewer = await Send(client, "POST", "/api/v1/access/assignments", Report(f), f.TargetSession, null, null, ct);
        Assert.Equal(HttpStatusCode.Forbidden, viewer.Status); Assert.Equal("insufficient_permissions", viewer.Body.GetProperty("error").GetString());
        var denied = await Send(client, "POST", "/api/v1/access/assignments", Report(f), f.DeniedSession, null, null, ct);
        Assert.Equal("reports.assign", denied.Body.GetProperty("required_capability").GetString());
        var origin = await Send(client, "POST", "/api/v1/access/assignments", Report(f), f.AdminSession, "https://foreign.example", null, ct);
        Assert.Equal("login.error.origin", origin.Body.GetProperty("message").GetProperty("code").GetString());
        var restricted = await Send(client, "POST", "/api/v1/access/assignments", Report(f), f.AdminSession, "https://foreign.example", f.ReportKey, ct);
        Assert.Equal("report_key_route_denied", restricted.Body.GetProperty("error").GetString());
        foreach ((string field, object? value, string error) in new (string, object?, string)[] {
            ("subject_type", "device", "invalid_subject_type"), ("subject_id", 0, "invalid_report_assignment"),
            ("subject_id", "bad", "invalid literal for int() with base 10: 'bad'"), ("effect", "other", "invalid_report_assignment"),
            ("subject_id", "\u001c1", "invalid literal for int() with base 10: '\\x1c1'"),
            ("business_reason", " ", "invalid_report_assignment"), ("source_type", "other", "invalid_report_assignment"),
            ("report_key", "missing.owned.report", "report_not_found"), ("subject_id", long.MaxValue, "access_subject_not_found"),
            ("field_categories", new[] { "nonexistent" }, "unknown_report_field_category"),
            ("allowed_actions", new[] { "nonexistent" }, "unknown_report_action"), ("allowed_actions", new[] { "export" }, "report_view_action_required"),
            ("scope", new { kind = "planet" }, "unsupported_report_scope"), ("scope", new { kind = "domain", ids = Array.Empty<int>() }, "invalid_report_scope_values"),
            ("scope", new { kind = "server", ids = new[] { 101 } }, "scope_not_supported_by_dataset"),
            ("scope", new { kind = "domain", ids = new[] { -1 } }, "report_scope_target_not_found"),
            ("valid_from", "2026-01-01T00:00:00", "invalid_valid_from"), ("valid_until", "not-a-date", "invalid_valid_until"),
            ("valid_from", "2026-0102T03:04:05+00:00", "invalid_valid_from"), ("valid_from", "20260102T0304:05+0000", "invalid_valid_from"),
            ("valid_from", "2026-01-02T03.5+00:00", "invalid_valid_from"), ("valid_from", "2021-W53-1T03:04:05+00:00", "invalid_valid_from"),
            ("source_type", "temporary", "temporary_assignment_requires_expiry") })
        { var payload = Report(f); payload[field] = value; await Post(payload, error); }
        var window = Report(f); window["valid_from"] = "2026-01-02T00:00:00Z"; window["valid_until"] = "2026-01-01T00:00:00Z"; await Post(window, "invalid_assignment_window");
        var dates = Report(f); dates["valid_from"] = "2026-01-02T03:04:05.123456+07:00"; dates["valid_until"] = "20260103T030405+0700";
        var dated = await Post(dates); Assert.Equal("2026-01-01 20:04:05.123456+00:00", dated.GetProperty("item").GetProperty("valid_from").GetString());
        Assert.Equal("2026-01-02 20:04:05+00:00", dated.GetProperty("item").GetProperty("valid_until").GetString());
        foreach ((string value, string expected) in new[] {
            ("2026-01-02\n03:04:05+00:00", "2026-01-02 03:04:05+00:00"),
            ("2026-W01T03:04:05+00:00", "2025-12-29 03:04:05+00:00"),
            ("2026-01-02T03:04:05+00:00:00.5", "2026-01-02 03:04:05+00:00"),
            ("2026-01-02T03:04:05+00:60", "2026-01-02 02:04:05+00:00") })
        { var timestamp = Report(f); timestamp["valid_from"] = value; Assert.Equal(expected, (await Post(timestamp)).GetProperty("item").GetProperty("valid_from").GetString()); }
        var group = Report(f); group["subject_type"] = "group"; group["subject_id"] = f.GroupId; Assert.Equal("group", (await Post(group)).GetProperty("item").GetProperty("subject_type").GetString());
        // A package assignment uses its own upsert key and audit, not the report writer.
        var package = Package(f); package["subject_type"] = "group"; package["subject_id"] = f.GroupId;
        // reports.assign denial does not deny this route's independent access.manage.
        var first = await Post(package, cookie: f.DeniedSession, route: "/api/v1/access/package-assignments");
        package["business_reason"] = f.Marker + "replaced";
        var second = await Post(package, route: "/api/v1/access/package-assignments");
        Assert.Equal(first.GetProperty("item").GetProperty("id").GetInt64(), second.GetProperty("item").GetProperty("id").GetInt64());
        Assert.Equal(f.Marker + "replaced", second.GetProperty("item").GetProperty("business_reason").GetString());
        var malformed = await Send(client, "POST", "/api/v1/access/assignments", "not JSON", f.AdminSession, null, null, ct, raw: true);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.Status); Assert.Equal("invalid_json", malformed.Body.GetProperty("error").GetString()); Assert.False(malformed.Body.TryGetProperty("message", out _));
        using var offHost = f.Host(false); using var off = f.Client(offHost);
        var offDenied = await Send(off, "POST", "/api/v1/access/assignments", Report(f), f.AdminSession, null, null, ct);
        Assert.Equal("operator_token_required", offDenied.Body.GetProperty("error").GetString());
        var local = await Send(off, "POST", "/api/v1/access/assignments", Report(f), f.AdminSession, null, null, ct, operatorToken: "owned-access-writes-token");
        Assert.Equal(HttpStatusCode.Forbidden, local.Status); Assert.Equal("reports.assign", local.Body.GetProperty("required_capability").GetString());
    }

    [Fact]
    public async Task RealWritesChangeWarmEffectiveAndDomainsWithoutCombiningAtomicFields()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        async Task<JsonElement> Read(string path) { var r = await Send(client, "GET", path, null, f.TargetSession, null, null, ct); Assert.Equal(HttpStatusCode.OK, r.Status); return r.Body; }
        async Task Write(Dictionary<string, object?> payload, bool package = false)
        { var r = await Send(client, "POST", "/api/v1/access/" + (package ? "package-assignments" : "assignments"), payload, null, null, f.AdminKey, ct); Assert.Equal(HttpStatusCode.Created, r.Status); }
        var denyPackage = Package(f); denyPackage["effect"] = "deny"; await Write(denyPackage, true);
        Assert.Empty((await Read("/api/v1/domains")).GetProperty("items").EnumerateArray());
        await Read("/api/v1/access/effective"); await Read("/api/v1/access/effective");
        await Write(Report(f));
        Assert.Equal(new long[] { 101 }, (await Read("/api/v1/domains")).GetProperty("items").EnumerateArray().Select(d => d.GetProperty("id").GetInt64()));
        var left = Report(f); left["report_key"] = "ad.state"; left["field_categories"] = new[] { "identity_basic", "security" }; await Write(left);
        var right = Report(f); right["report_key"] = "ad.state"; right["field_categories"] = new[] { "technical" }; right["scope"] = new { kind = "domain", ids = new[] { 102 } }; await Write(right);
        var effective = await Read("/api/v1/access/effective");
        var state = Assert.Single(effective.GetProperty("reports").EnumerateArray(), r => r.GetProperty("report_key").GetString() == "ad.state");
        Assert.Equal(2, state.GetProperty("grants").GetArrayLength());
        Assert.All(state.GetProperty("grants").EnumerateArray(), g => Assert.Equal(state.GetProperty("version").GetInt64(), g.GetProperty("validated_report_version").GetInt64()));
        Assert.Equal(new long[] { 101 }, (await Read("/api/v1/domains")).GetProperty("items").EnumerateArray().Select(d => d.GetProperty("id").GetInt64()));
        var whole = Report(f); whole["report_key"] = "ad.state"; whole["field_categories"] = new[] { "identity_basic", "security", "technical" }; whole["scope"] = new { kind = "domain", ids = new[] { 102 } }; await Write(whole);
        Assert.Equal(new long[] { 101, 102 }, (await Read("/api/v1/domains")).GetProperty("items").EnumerateArray().Select(d => d.GetProperty("id").GetInt64()));
        var deny = Report(f); deny["effect"] = "deny"; deny["field_categories"] = new[] { "ignored" }; deny["allowed_actions"] = new[] { "ignored" }; await Write(deny);
        Assert.Equal(new long[] { 102 }, (await Read("/api/v1/domains")).GetProperty("items").EnumerateArray().Select(d => d.GetProperty("id").GetInt64()));
        var future = Report(f); future["valid_from"] = DateTimeOffset.UtcNow.AddDays(1).ToString("o"); await Write(future);
        Assert.Equal(new long[] { 102 }, (await Read("/api/v1/domains")).GetProperty("items").EnumerateArray().Select(d => d.GetProperty("id").GetInt64()));
        var audit = await Send(client, "GET", "/api/v1/access/audit", null, f.AdminSession, null, null, ct); Assert.Equal(HttpStatusCode.OK, audit.Status);
        Assert.Contains(audit.Body.GetProperty("items").EnumerateArray(), a => a.GetProperty("actor_type").GetString() == "api_key" && a.GetProperty("actor_id").GetInt64() == f.AdminKeyId && a.GetProperty("reason").GetString() == f.Marker);
    }

    [Fact]
    public async Task SoleSharedWriterCommitsEachCallAndRollsBackInvalidAuditAndGenericTargets()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await Fixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        using var scope = host.Services.CreateScope(); var writer = scope.ServiceProvider.GetRequiredService<IReportAssignmentWriter>();
        Task<ReportAssignmentResult> Create(Dictionary<string, object?> payload, AssignmentActor? actor = null) => writer.CreateAsync(new(JsonSerializer.SerializeToElement(payload)), actor ?? new("session", f.AdminId), "192.0.2.71", ct);
        var first = await Create(Report(f));
        Assert.True(first.Item.GetProperty("id").GetInt64() > 0);
        var bad = Report(f); bad["allowed_actions"] = new[] { "not_supported" };
        Assert.Equal("unknown_report_action", (await Assert.ThrowsAsync<AssignmentValidationException>(() => Create(bad))).Message);
        Assert.Equal(1L, await f.AssignmentCountAsync(ct));
        Assert.Equal("administrative_activity_access_actor_not_allowlisted", (await Assert.ThrowsAsync<AssignmentValidationException>(() => Create(Report(f), new("invalid", null)))).Message);
        Assert.Equal(1L, await f.AssignmentCountAsync(ct));
        var generic = Report(f); generic["report_key"] = "workstations.logons"; generic["scope"] = new { mode = "restricted", clauses = new[] { new { collection_scope_ids = new[] { "ad-domain:101" } } } };
        var valid = await Create(generic); Assert.Equal("restricted", valid.Item.GetProperty("scope_json").GetProperty("mode").GetString());
        generic["scope"] = new { mode = "restricted", clauses = new[] { new { plugin_ids = new[] { "sli.file-audit" }, source_instance_ids = new[] { "missing-own-agent-source" } } } };
        generic["report_key"] = "file-audit.overview";
        Assert.Equal("report_scope_target_not_found", (await Assert.ThrowsAsync<AssignmentValidationException>(() => Create(generic))).Message);
        generic["scope"] = new { mode = "restricted", clauses = new[] { new { collection_scope_ids = new[] { "ad-domain:99999999" } } } };
        generic["report_key"] = "workstations.logons";
        Assert.Equal("report_scope_target_not_found", (await Assert.ThrowsAsync<AssignmentValidationException>(() => Create(generic))).Message);
        generic["scope"] = new { mode = "restricted", clauses = new[] { new { entity_ids = new object[] { true } } } };
        Assert.Equal("invalid_scope_dimension", (await Assert.ThrowsAsync<AssignmentValidationException>(() => Create(generic))).Message);
        generic["scope"] = new { mode = "restricted", clauses = new object[] { new { } } };
        Assert.Equal("empty_scope_clause", (await Assert.ThrowsAsync<AssignmentValidationException>(() => Create(generic))).Message);
        Assert.Equal(2L, await f.AssignmentCountAsync(ct));
    }

    private static Dictionary<string, object?> Report(Fixture f) => new() { ["subject_type"] = "user", ["subject_id"] = f.TargetId,
        ["report_key"] = "ad.users.v2", ["business_reason"] = f.Marker, ["field_categories"] = new[] { "identity_basic" },
        ["allowed_actions"] = new[] { "view" }, ["scope"] = new { kind = "domain", ids = new[] { 101 } } };
    private static Dictionary<string, object?> Package(Fixture f) => new() { ["subject_type"] = "user", ["subject_id"] = f.TargetId, ["package_key"] = "security_analyst", ["business_reason"] = f.Marker };

    private static async Task<(HttpStatusCode Status, JsonElement Body)> Send(HttpClient client, string method, string path, object? payload,
        string? cookie, string? origin, string? key, CancellationToken ct, bool raw = false, string? operatorToken = null)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        request.Headers.AcceptLanguage.ParseAdd("ru;q=0.1,en;q=1");
        if (cookie is not null) request.Headers.Add("Cookie", "adlog_session=" + cookie);
        if (origin is not null) request.Headers.Add("Origin", origin);
        if (key is not null) request.Headers.Add("X-ADLog-API-Key", key);
        if (operatorToken is not null) request.Headers.Add("X-ADLog-Operator-Token", operatorToken);
        if (payload is not null) request.Content = new StringContent(raw ? (string)payload : JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, ct); Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct)); return (response.StatusCode, body.RootElement.Clone());
    }

    private sealed class Fixture(SyntheticDatabase database, byte[] config) : IAsyncDisposable
    {
        public string Marker { get; } = "awrite_" + Guid.NewGuid().ToString("N")[..16];
        public long AdminId, TargetId, DeniedId, GroupId, AdminKeyId;
        public string AdminSession { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public string TargetSession { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public string DeniedSession { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public string AdminKey { get; } = "adl_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        public string ReportKey { get; } = "adl_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        private static string Digest(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        public static async Task<Fixture> OpenAsync(CancellationToken ct)
        {
            var binding = OwnedDatabaseBinding.FromEnvironment(); Assert.Equal(binding.RunId.ToString("D"), Environment.GetEnvironmentVariable("SLI_ACCESS_WRITES_EXCLUSIVE_RUN"));
            var db = await SyntheticDatabase.BorrowAsync(binding, ct);
            var config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), "dotnet", "dotnet-test-config.json"), ct);
            Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(config)));
            var f = new Fixture(db, config); try { await f.SeedAsync(ct); return f; } catch { await f.DisposeAsync(); throw; }
        }
        private async Task SeedAsync(CancellationToken ct)
        {
            await using var connection = await database.OpenConnectionAsync(ct);
            async Task<long> User(string suffix, string role, string token)
            {
                await using var insert = new NpgsqlCommand("insert into auth_users(username,password_hash,role) values(@name,'synthetic-no-password',@role) returning id", connection);
                insert.Parameters.AddWithValue("name", Marker + suffix); insert.Parameters.AddWithValue("role", role);
                long id = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
                await using var session = new NpgsqlCommand("insert into auth_sessions(user_id,token_hash,expires_at) values(@id,@hash,now()+interval '1 day')", connection);
                session.Parameters.AddWithValue("id", id); session.Parameters.AddWithValue("hash", Digest(token)); await session.ExecuteNonQueryAsync(ct); return id;
            }
            AdminId = await User("admin", "admin", AdminSession); TargetId = await User("target", "viewer", TargetSession); DeniedId = await User("denied", "admin", DeniedSession);
            await using (var group = new NpgsqlCommand("insert into access_groups(group_key,name) values(@key,@key) returning id", connection))
            { group.Parameters.AddWithValue("key", Marker); GroupId = Convert.ToInt64(await group.ExecuteScalarAsync(ct)); }
            await using (var caps = new NpgsqlCommand("""
                insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,business_reason)
                select 'user',@target,id,'allow',@reason from access_capabilities where capability_key in ('workspace.view','objects.view','field.identity_basic','field.technical','field.security');
                insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,business_reason)
                select 'user',@denied,id,'deny',@reason from access_capabilities where capability_key='reports.assign'
                """, connection))
            { caps.Parameters.AddWithValue("target", TargetId); caps.Parameters.AddWithValue("denied", DeniedId); caps.Parameters.AddWithValue("reason", Marker); await caps.ExecuteNonQueryAsync(ct); }
            foreach (bool restricted in new[] { false, true })
            {
                string token = restricted ? ReportKey : AdminKey;
                await using var key = new NpgsqlCommand("insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id) values(@prefix,@hash,@label,'admin',@subject) returning id", connection);
                key.Parameters.AddWithValue("prefix", token[..12]); key.Parameters.AddWithValue("hash", Digest(token)); key.Parameters.AddWithValue("label", Marker);
                key.Parameters.AddWithValue("subject", NpgsqlTypes.NpgsqlDbType.Bigint, restricted ? TargetId : DBNull.Value);
                long id = Convert.ToInt64(await key.ExecuteScalarAsync(ct)); if (!restricted) AdminKeyId = id;
            }
        }
        public Task<NpgsqlConnection> OpenConnectionAsync(CancellationToken ct) => database.OpenConnectionAsync(ct);
        public WebApplicationFactory<Program> Host(bool auth = true, bool ownerSetup = false) => new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, settings) =>
        { settings.AddJsonStream(new MemoryStream(config)); settings.AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = auth ? "1" : "0", ["Sli:AllowUnauthenticated"] = "1", ["Sli:OwnerSetup"] = ownerSetup ? "1" : "0", ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:OperatorToken"] = "owned-access-writes-token" }); }));
        public HttpClient Client(WebApplicationFactory<Program> host)
        {
            host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0)); host.StartServer();
            string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses); Assert.True(new Uri(address).IsLoopback);
            return new HttpClient(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
        }
        public async Task<long> AssignmentCountAsync(CancellationToken ct)
        { await using var connection = await database.OpenConnectionAsync(ct); await using var query = new NpgsqlCommand("select count(*) from access_report_assignments where subject_type='user' and subject_id=@id", connection); query.Parameters.AddWithValue("id", TargetId); return Convert.ToInt64(await query.ExecuteScalarAsync(ct)); }
        public async ValueTask DisposeAsync()
        {
            await using var connection = await database.OpenConnectionAsync(CancellationToken.None);
            await using var cleanup = new NpgsqlCommand("""
                delete from access_audit_v4 where left(reason,length(@marker))=@marker;
                delete from access_report_assignments where subject_type='user' and subject_id=any(@users) or subject_type='group' and subject_id=@group;
                delete from access_subject_packages where subject_type='user' and subject_id=any(@users) or subject_type='group' and subject_id=@group;
                delete from access_capability_assignments where subject_type='user' and subject_id=any(@users);
                delete from auth_api_keys where label=@marker;
                delete from auth_sessions where user_id=any(@users);
                delete from auth_audit where actor_type='session' and actor_id=any(@users);
                delete from auth_login_throttle where account_key=@account;
                delete from auth_users where id=any(@users) and left(username,length(@marker))=@marker;
                delete from access_groups where id=@group and group_key=@marker
                """, connection);
            cleanup.Parameters.AddWithValue("marker", Marker); cleanup.Parameters.AddWithValue("users", new[] { AdminId, TargetId, DeniedId }); cleanup.Parameters.AddWithValue("group", GroupId);
            cleanup.Parameters.AddWithValue("account", AccountThrottle.AccountKey(Marker + "admin"));
            await cleanup.ExecuteNonQueryAsync(); await database.DisposeAsync();
        }
    }
}
