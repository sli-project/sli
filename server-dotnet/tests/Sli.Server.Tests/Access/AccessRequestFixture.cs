using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Access;

internal sealed class AccessRequestFixture(SyntheticDatabase database, byte[] config) : IAsyncDisposable
{
    internal const string ReportKey = "ad.state";
    internal string Marker { get; } = "rqn_" + Guid.NewGuid().ToString("N")[..16];
    internal Principal Requester = null!, Other = null!, Reviewer = null!, MissingAssign = null!, Operator = null!;
    internal string RequesterCookie { get; } = NewToken();
    internal string OtherCookie { get; } = NewToken();
    internal string ReviewerCookie { get; } = NewToken();
    internal string MissingAssignCookie { get; } = NewToken();
    internal string OperatorCookie { get; } = NewToken();
    internal string OrdinaryKey { get; } = "adl_" + NewToken();
    internal string RestrictedKey { get; } = "adl_" + NewToken();
    internal long ReportId;
    internal int ReportVersion;
    internal long[] AllDomainIds = [];
    internal static readonly string[] Fields = ["identity_basic", "security", "technical"];
    private readonly List<long> users = [];
    private static string NewToken() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
    private static string Digest(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    internal async Task SetReviewerPasswordAsync(string password, CancellationToken ct)
    {
        await using var connection = await database.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand("update auth_users set password_hash=@hash where id=@id and username=@name", connection);
        command.Parameters.AddWithValue("hash", new PasswordCodec().Hash(password));
        command.Parameters.AddWithValue("id", Reviewer.Id);
        command.Parameters.AddWithValue("name", Marker + "reviewer");
        Assert.Equal(1, await command.ExecuteNonQueryAsync(ct));
    }
    private sealed class Connections(SyntheticDatabase db) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => db.OpenConnectionAsync(ct); }

    internal static async Task<AccessRequestFixture> OpenAsync(CancellationToken ct)
    {
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal(binding.RunId.ToString("D"), Environment.GetEnvironmentVariable("SLI_REQUEST_EXCLUSIVE_RUN"));
        var db = await SyntheticDatabase.BorrowAsync(binding, ct);
        var config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json"), ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(config)));
        var fixture = new AccessRequestFixture(db, config);
        try { await fixture.SeedAsync(ct); return fixture; }
        catch { await fixture.DisposeAsync(); throw; }
    }

    private async Task SeedAsync(CancellationToken ct)
    {
        await using var connection = await database.OpenConnectionAsync(ct);
        await using (var domains = new NpgsqlCommand("select id from domains order by id", connection))
        {
            var ids = new List<long>(); await using var rows = await domains.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) ids.Add(rows.GetInt64(0)); AllDomainIds = ids.ToArray();
        }
        async Task<Principal> User(string suffix, string role, string cookie)
        {
            await using var insert = new NpgsqlCommand("insert into auth_users(username,password_hash,role) values(@name,'synthetic-no-password',@role) returning id", connection);
            insert.Parameters.AddWithValue("name", Marker + suffix); insert.Parameters.AddWithValue("role", role);
            long id = Convert.ToInt64(await insert.ExecuteScalarAsync(ct)); users.Add(id);
            await using var session = new NpgsqlCommand("insert into auth_sessions(user_id,token_hash,expires_at) values(@id,@hash,now()+interval '1 day')", connection);
            session.Parameters.AddWithValue("id", id); session.Parameters.AddWithValue("hash", Digest(cookie)); await session.ExecuteNonQueryAsync(ct);
            return new("session", id, role, Username: Marker + suffix);
        }
        Requester = await User("requester", "viewer", RequesterCookie); Other = await User("other", "viewer", OtherCookie);
        Reviewer = await User("reviewer", "admin", ReviewerCookie); MissingAssign = await User("limited", "admin", MissingAssignCookie);
        Operator = await User("operator", "operator", OperatorCookie);
        foreach (long id in new[] { Requester.Id, Other.Id, Operator.Id })
        {
            await using var caps = new NpgsqlCommand("""
                insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,business_reason)
                select 'user',@id,id,'allow',@reason from access_capabilities where capability_key in
                  ('workspace.view','reports.catalog','objects.view','field.identity_basic','field.security','field.technical')
                """, connection);
            caps.Parameters.AddWithValue("id", id); caps.Parameters.AddWithValue("reason", Marker); await caps.ExecuteNonQueryAsync(ct);
        }
        await using (var deny = new NpgsqlCommand("""
            insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,business_reason)
            select 'user',@id,id,'deny',@reason from access_capabilities where capability_key='reports.assign'
            """, connection))
        { deny.Parameters.AddWithValue("id", MissingAssign.Id); deny.Parameters.AddWithValue("reason", Marker); await deny.ExecuteNonQueryAsync(ct); }
        // Exercise the unchanged T9 package wrapper through the shared audit
        // adapter too; no duplicate package-assignment SQL in the new service.
        var packages = new AssignmentPackageWriter(new Connections(database));
        foreach (long id in new[] { Requester.Id, Other.Id })
            await packages.CreateAsync(JsonSerializer.SerializeToElement(new { subject_type = "user", subject_id = id,
                package_key = "security_analyst", effect = "deny", business_reason = Marker }), new("session", Reviewer.Id), null, ct);
        foreach (bool restricted in new[] { false, true })
        {
            string token = restricted ? RestrictedKey : OrdinaryKey;
            await using var key = new NpgsqlCommand("insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id) values(@prefix,@hash,@label,'admin',@subject)", connection);
            key.Parameters.AddWithValue("prefix", token[..12]); key.Parameters.AddWithValue("hash", Digest(token)); key.Parameters.AddWithValue("label", Marker);
            key.Parameters.AddWithValue("subject", NpgsqlTypes.NpgsqlDbType.Bigint, restricted ? Requester.Id : DBNull.Value); await key.ExecuteNonQueryAsync(ct);
        }
        await using var report = new NpgsqlCommand("""
            insert into report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at,discoverable,requestable,request_profile_json)
            select report_key,(select max(version)+1000 from report_registry_v4 where report_key='ad.state'),@name,@name,purpose,dataset_id,
                definition_json || '{"dashboard_metrics":[{"key":"owned.metric","kind":"optional","label":"Owned optional metric"}]}'::jsonb,
                sensitivity,'published',now(),true,true,@profile::jsonb
            from report_registry_v4 where report_key='ad.state' and status='published' order by version desc limit 1
            returning id,version
            """, connection);
        report.Parameters.AddWithValue("name", Marker + "published"); report.Parameters.AddWithValue("profile", Profile(Fields));
        await using var reader = await report.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct)); ReportId = reader.GetInt64(0); ReportVersion = reader.GetInt32(1);
    }

    private static string Profile(string[] fields) => JsonSerializer.Serialize(new { scope_kinds = new[] { "all", "domain", "server" },
        field_categories = fields, allowed_actions = new[] { "view" }, max_duration_days = 30 });
    internal async Task ProfileFieldsAsync(string[] fields, CancellationToken ct)
    {
        await using var connection = await database.OpenConnectionAsync(ct);
        await using var update = new NpgsqlCommand("update report_registry_v4 set request_profile_json=@profile::jsonb where id=@id and owner_name=@owner", connection);
        update.Parameters.AddWithValue("profile", Profile(fields)); update.Parameters.AddWithValue("id", ReportId); update.Parameters.AddWithValue("owner", Marker + "published");
        Assert.Equal(1, await update.ExecuteNonQueryAsync(ct));
    }

    internal Dictionary<string, object?> Request(string kind = "all", string id = "101") => new()
    {
        ["report_key"] = ReportKey, ["business_reason"] = Marker + " business justification",
        ["scope"] = kind == "all" ? new { kind } : new Dictionary<string, object> { ["kind"] = kind, ["ids"] = new[] { id } },
        ["valid_until"] = DateTimeOffset.UtcNow.AddDays(2).ToString("o")
    };
    internal Dictionary<string, object?> Decision(string decision = "approve") => new() { ["decision"] = decision, ["decision_reason"] = Marker + " reviewed" };

    internal WebApplicationFactory<Program> Host(Action<IServiceCollection>? overrides = null, bool auth = true) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, settings) =>
            {
                settings.AddJsonStream(new MemoryStream(config)); settings.AddInMemoryCollection(new Dictionary<string, string?> {
                    ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = auth ? "1" : "0", ["Sli:AllowUnauthenticated"] = "1",
                    ["Sli:OwnerSetup"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:OperatorToken"] = "owned-request-operator-token" });
            });
            if (overrides is not null) builder.ConfigureTestServices(overrides);
        });
    internal HttpClient Client(WebApplicationFactory<Program> host)
    {
        host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0)); host.StartServer();
        string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        Assert.True(new Uri(address).IsLoopback);
        return new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false }) { BaseAddress = new Uri(address) };
    }
    internal async Task<(HttpStatusCode Status, JsonElement Body)> Send(HttpClient client, string method, string path, object? payload,
        string? cookie = null, string? key = null, string? origin = null, string language = "en", string? operatorToken = null, bool raw = false)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path); request.Headers.AcceptLanguage.ParseAdd(language);
        if (cookie is not null) request.Headers.Add("Cookie", "adlog_session=" + cookie);
        if (key is not null) request.Headers.Add("X-ADLog-API-Key", key);
        if (origin is not null) request.Headers.Add("Origin", origin);
        if (operatorToken is not null) request.Headers.Add("X-ADLog-Operator-Token", operatorToken);
        if (payload is not null) request.Content = new StringContent(raw ? (string)payload : JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));
        return (response.StatusCode, body.RootElement.Clone());
    }
    internal async Task<JsonElement> EffectiveAsync(HttpClient client)
    {
        var result = await Send(client, "GET", "/api/v1/access/effective", null, RequesterCookie); Assert.Equal(HttpStatusCode.OK, result.Status);
        return Assert.Single(result.Body.GetProperty("reports").EnumerateArray(), r => r.GetProperty("report_key").GetString() == ReportKey).Clone();
    }
    internal async Task<long[]> DomainsAsync(HttpClient client)
    {
        var result = await Send(client, "GET", "/api/v1/domains", null, RequesterCookie); Assert.Equal(HttpStatusCode.OK, result.Status);
        return result.Body.GetProperty("items").EnumerateArray().Select(d => d.GetProperty("id").GetInt64()).Order().ToArray();
    }

    internal sealed record State(string Status, long? DecidedBy, long? AssignmentId, long Grants, long DecisionAudits, long AssignmentAudits);
    internal async Task<State> StateAsync(long requestId, CancellationToken ct)
    {
        await using var connection = await database.OpenConnectionAsync(ct);
        await using var query = new NpgsqlCommand("""
            select status,decided_by,assignment_id,
                (select count(*) from access_report_assignments where subject_type='user' and subject_id=@user and report_key='ad.state'),
                (select count(*) from access_audit_v4 where subject_type='user' and subject_id=@user and action in ('report_access_request_approved','report_access_request_rejected')),
                (select count(*) from access_audit_v4 where subject_type='user' and subject_id=@user and action='report_assignment_created')
            from report_access_requests_v4 where id=@id and requester_user_id=@user
            """, connection);
        query.Parameters.AddWithValue("user", Requester.Id); query.Parameters.AddWithValue("id", requestId);
        await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
        return new(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetInt64(1), reader.IsDBNull(2) ? null : reader.GetInt64(2), reader.GetInt64(3), reader.GetInt64(4), reader.GetInt64(5));
    }
    internal async Task<JsonElement> AssignmentScopeAsync(long id, CancellationToken ct)
    {
        await using var connection = await database.OpenConnectionAsync(ct);
        await using var query = new NpgsqlCommand("select scope_json from access_report_assignments where id=@id and subject_type='user' and subject_id=@user", connection);
        query.Parameters.AddWithValue("id", id); query.Parameters.AddWithValue("user", Requester.Id);
        using var json = JsonDocument.Parse((string)(await query.ExecuteScalarAsync(ct))!); return json.RootElement.Clone();
    }
    internal async Task ResetOwnRequestsAsync(CancellationToken ct)
    {
        await using var connection = await database.OpenConnectionAsync(ct);
        await using var cleanup = new NpgsqlCommand("""
            delete from access_audit_v4 where subject_type='user' and subject_id=@user and action<>'package_assignment_created';
            delete from report_access_requests_v4 where requester_user_id=@user;
            delete from access_report_assignments where subject_type='user' and subject_id=@user
            """, connection);
        cleanup.Parameters.AddWithValue("user", Requester.Id); await cleanup.ExecuteNonQueryAsync(ct);
    }
    internal async Task<(long Requests, long Grants, long Preferences, long Audits)> CountsAsync(CancellationToken ct)
    {
        await using var connection = await database.OpenConnectionAsync(ct);
        await using var query = new NpgsqlCommand("""
            select (select count(*) from report_access_requests_v4 where requester_user_id=@user),
                (select count(*) from access_report_assignments where subject_type='user' and subject_id=@user),
                (select count(*) from user_report_preferences where user_id=@user),
                (select count(*) from access_audit_v4 where subject_type='user' and subject_id=@user and action<>'package_assignment_created')
            """, connection);
        query.Parameters.AddWithValue("user", Requester.Id); await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
        return (reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
    }
    internal static async Task RecordAsync(string name, object value)
    {
        string root = Environment.GetEnvironmentVariable("SLI_REQUEST_EVIDENCE_DIR") ?? throw new InvalidOperationException("Owned evidence path required");
        Assert.True(Path.IsPathFullyQualified(root));
        await File.WriteAllTextAsync(Path.Combine(root, name + ".json"), JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true }));
    }
    public async ValueTask DisposeAsync()
    {
        await using var connection = await database.OpenConnectionAsync(CancellationToken.None);
        await using var cleanup = new NpgsqlCommand("""
            delete from access_audit_v4 where subject_type='user' and subject_id=any(@users);
            delete from report_access_requests_v4 where requester_user_id=any(@users);
            delete from access_report_assignments where subject_type='user' and subject_id=any(@users);
            delete from access_subject_packages where subject_type='user' and subject_id=any(@users);
            delete from access_capability_assignments where subject_type='user' and subject_id=any(@users);
            delete from user_report_preferences where user_id=any(@users);
            delete from auth_api_keys where label=@marker;
            delete from auth_sessions where user_id=any(@users);
            delete from auth_audit where actor_type='session' and actor_id=any(@users);
            delete from auth_login_throttle where account_key=@account;
            delete from report_registry_v4 where id=@report and owner_name=@owner;
            delete from auth_users where id=any(@users) and left(username,length(@marker))=@marker
            """, connection);
        cleanup.Parameters.AddWithValue("users", users.ToArray()); cleanup.Parameters.AddWithValue("marker", Marker); cleanup.Parameters.AddWithValue("report", ReportId); cleanup.Parameters.AddWithValue("owner", Marker + "published");
        cleanup.Parameters.AddWithValue("account", AccountThrottle.AccountKey(Marker + "reviewer"));
        await cleanup.ExecuteNonQueryAsync(); await database.DisposeAsync();
    }
}
