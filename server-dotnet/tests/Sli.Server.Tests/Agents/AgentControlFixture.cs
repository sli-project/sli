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
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

internal sealed class AgentControlFixture(SyntheticDatabase database, byte[] config) : IAsyncDisposable
{
    internal string Marker { get; } = "actl_" + Guid.NewGuid().ToString("N")[..16];
    internal Guid Agent { get; } = Guid.NewGuid();
    internal Guid OtherAgent { get; } = Guid.NewGuid();
    internal Guid ExpiredAgent { get; } = Guid.NewGuid();
    internal Guid RetiredAgent { get; } = Guid.NewGuid();
    internal Guid TokenHost { get; } = Guid.ParseExact(string.Concat(Enumerable.Range(0, 32).Select(_ => (char)('1' + RandomNumberGenerator.GetInt32(9)))), "N");
    internal string Serial { get; } = Guid.NewGuid().ToString("N");
    internal string RevokedSerial { get; } = Guid.NewGuid().ToString("N");
    internal string OtherSerial { get; } = Guid.NewGuid().ToString("N");
    internal string AdminCookie { get; } = Token();
    internal string ViewerCookie { get; } = Token();
    internal string ManagerCookie { get; } = Token();
    internal string DeniedCookie { get; } = Token();
    internal string AdminKey { get; } = "adl_" + Token();
    internal string ReportKey { get; } = "adl_" + Token();
    internal long AdminId = OwnId(), ViewerId = OwnId(), ManagerId = OwnId(), DeniedId = OwnId();
    private long[] Users => [AdminId, ViewerId, ManagerId, DeniedId];
    private string[] Names => [Marker + "admin", Marker + "viewer", Marker + "manager", Marker + "denied"];
    private Guid[] Agents => [Agent, OtherAgent, ExpiredAgent, RetiredAgent];
    private static string Token() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
    private static long OwnId() => RandomNumberGenerator.GetInt32(1000000, 2000000000);
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string EvidenceRoot => Environment.GetEnvironmentVariable("SLI_AGENT_CONTROL_EVIDENCE_DIR") ?? throw new InvalidOperationException("Explicit owned evidence required");
    internal static async Task<AgentControlFixture> OpenAsync(CancellationToken ct)
    {
        var binding = OwnedDatabaseBinding.FromEnvironment(); Assert.Equal(binding.RunId.ToString("D"), Environment.GetEnvironmentVariable("SLI_AGENT_CONTROL_EXCLUSIVE_RUN"));
        var db = await SyntheticDatabase.BorrowAsync(binding, ct);
        byte[] config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json"), ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(config)));
        var f = new AgentControlFixture(db, config); await f.ManifestAsync();
        try { await f.SeedAsync(ct); await f.ManifestAsync(); return f; } catch { await f.ManifestAsync(); await f.DisposeAsync(); throw; }
    }
    private Task ManifestAsync() => File.WriteAllTextAsync(Path.Combine(EvidenceRoot, Marker + "-intent.json"), JsonSerializer.Serialize(new {
        run_id = "a3fcc413-8980-4cd8-ba5d-ebe374f7b864", marker = Marker, agent_ids = Agents, token_host = TokenHost,
        usernames = Names, user_ids = Users, cleanup = "pending exact trusted CONTROL cleanup; API and SQL use adlog_user only" }, new JsonSerializerOptions { WriteIndented = true }));
    private async Task SeedAsync(CancellationToken ct)
    {
        await using var db = await database.OpenConnectionAsync(ct);
        await using (var proof = new NpgsqlCommand("select current_user,has_table_privilege(current_user,'sli_agents','DELETE'),has_table_privilege(current_user,'sli_agent_policy_history','INSERT'),has_column_privilege(current_user,'sli_agents','collection_policy','UPDATE')", db))
        {
            await using var reader = await proof.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct)); Assert.Equal("adlog_user", reader.GetString(0)); Assert.True(reader.GetBoolean(2)); Assert.True(reader.GetBoolean(3));
            await RecordAsync(Marker + "-runtime-role", new { current_user = reader.GetString(0), agent_delete = reader.GetBoolean(1), policy_history_insert = reader.GetBoolean(2), collection_policy_update = reader.GetBoolean(3) });
        }
        async Task User(long id, string name, string role, string cookie)
        {
            await using var insert = new NpgsqlCommand("insert into auth_users(id,username,password_hash,role) values(@id,@name,'synthetic-no-password',@role)", db);
            insert.Parameters.AddWithValue("id", id); insert.Parameters.AddWithValue("name", name); insert.Parameters.AddWithValue("role", role); await insert.ExecuteNonQueryAsync(ct);
            await using var session = new NpgsqlCommand("insert into auth_sessions(id,user_id,token_hash,expires_at) values(@session,@id,@hash,now()+interval '1 day')", db);
            session.Parameters.AddWithValue("session", OwnId()); session.Parameters.AddWithValue("id", id); session.Parameters.AddWithValue("hash", Hash(cookie)); await session.ExecuteNonQueryAsync(ct);
        }
        await User(AdminId, Names[0], "admin", AdminCookie); await User(ViewerId, Names[1], "viewer", ViewerCookie);
        await User(ManagerId, Names[2], "viewer", ManagerCookie); await User(DeniedId, Names[3], "admin", DeniedCookie);
        foreach ((long user, string effect) in new[] { (ManagerId, "allow"), (DeniedId, "deny") })
        {
            await using var cap = new NpgsqlCommand("insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,business_reason) select 'user',@user,id,@effect,@reason from access_capabilities where capability_key='access.manage'", db);
            cap.Parameters.AddWithValue("user", user); cap.Parameters.AddWithValue("effect", effect); cap.Parameters.AddWithValue("reason", Marker); await cap.ExecuteNonQueryAsync(ct);
        }
        foreach (bool restricted in new[] { false, true })
        {
            string key = restricted ? ReportKey : AdminKey;
            await using var insert = new NpgsqlCommand("insert into auth_api_keys(id,key_prefix,key_hash,label,role,report_subject_id) values(@id,@prefix,@hash,@label,'admin',@subject)", db);
            insert.Parameters.AddWithValue("id", OwnId());
            insert.Parameters.AddWithValue("prefix", key[..12]); insert.Parameters.AddWithValue("hash", Hash(key)); insert.Parameters.AddWithValue("label", Marker);
            insert.Parameters.AddWithValue("subject", NpgsqlTypes.NpgsqlDbType.Bigint, restricted ? ViewerId : DBNull.Value); await insert.ExecuteNonQueryAsync(ct);
        }
        foreach (Guid id in Agents)
        {
            await using var insert = new NpgsqlCommand("""
                insert into sli_agents(id,host_id,key_fingerprint,created_at,last_seen,registration_host_name,rights_probe,status)
                values(@id,@host,@fp,clock_timestamp()-@age,case when @seen then clock_timestamp() else null end,@name,
                    '{"eventlog_diagnostics":{"items":[]},"delivery_diagnostics":{"items":[]},"pending":{"request_id":"owned"}}'::jsonb,@status)
                """, db);
            insert.Parameters.AddWithValue("id", id); insert.Parameters.AddWithValue("host", Guid.NewGuid()); insert.Parameters.AddWithValue("fp", Hash(id.ToString()));
            insert.Parameters.AddWithValue("age", id == ExpiredAgent ? TimeSpan.FromHours(25) : TimeSpan.FromMinutes(1)); insert.Parameters.AddWithValue("seen", id != ExpiredAgent);
            insert.Parameters.AddWithValue("name", "owned-control.example"); insert.Parameters.AddWithValue("status", id == RetiredAgent ? "disabled" : "active"); await insert.ExecuteNonQueryAsync(ct);
        }
        foreach ((Guid id, string serial, bool revoked) in new[] { (Agent, Serial, false), (Agent, RevokedSerial, true), (OtherAgent, OtherSerial, false) })
        {
            await using var cert = new NpgsqlCommand("insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after,revoked_at) values(@id,@serial,@fp,now()-interval '1 day',now()+interval '1 day',case when @revoked then now()-interval '1 hour' else null end)", db);
            cert.Parameters.AddWithValue("id", id); cert.Parameters.AddWithValue("serial", serial); cert.Parameters.AddWithValue("fp", Hash(serial)); cert.Parameters.AddWithValue("revoked", revoked); await cert.ExecuteNonQueryAsync(ct);
        }
        await using var audit = new NpgsqlCommand("insert into sli_agent_audit(action,actor,target,details) values('disable',@actor,@id,'{\"reason\":\"registration_replaced\"}'::jsonb)", db);
        audit.Parameters.AddWithValue("actor", "session:" + AdminId); audit.Parameters.AddWithValue("id", RetiredAgent.ToString()); await audit.ExecuteNonQueryAsync(ct);
    }
    internal WebApplicationFactory<Program> Host(Action<IServiceCollection>? overrides = null, bool auth = true) => new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
    {
        builder.ConfigureAppConfiguration((_, settings) => { settings.AddJsonStream(new MemoryStream(config)); settings.AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:TrustedProxies"]="", ["Sli:AuthRequired"]=auth ? "1" : "0", ["Sli:AllowUnauthenticated"]="1", ["Sli:OwnerSetup"]="0", ["Sli:AuthAllowInsecureHttp"]="1", ["Sli:OperatorToken"]="owned-agent-control-operator" }); });
        if (overrides is not null) builder.ConfigureTestServices(overrides);
    });
    internal HttpClient Client(WebApplicationFactory<Program> host)
    {
        host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0)); host.StartServer();
        string url = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses); Assert.True(new Uri(url).IsLoopback);
        return new(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false }) { BaseAddress = new Uri(url) };
    }
    internal async Task<(HttpStatusCode Status, JsonElement Body)> Send(HttpClient client, string method, string route, object? payload = null, string? cookie = null, string? key = null, string? origin = null, string? operatorToken = null, string language = "en")
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), route); request.Headers.AcceptLanguage.ParseAdd(language);
        if (cookie is not null) request.Headers.Add("Cookie", "adlog_session=" + cookie); if (key is not null) request.Headers.Add("X-ADLog-API-Key", key);
        if (origin is not null) request.Headers.Add("Origin", origin); if (operatorToken is not null) request.Headers.Add("X-ADLog-Operator-Token", operatorToken);
        if (payload is not null) request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken); Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString() ?? ""); using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()); return (response.StatusCode, json.RootElement.Clone());
    }
    internal object TokenPayload(object? ttl = null) => new { host_id = TokenHost, key_fingerprint = new string('a', 64), ttl_seconds = ttl ?? 900, registration_host_name = "OWNED-CONTROL.example" };
    internal object Policy(long revision, object control) => new { agent_id = Agent, expected_revision = revision, collection_policy = control };
    internal async Task<JsonElement> TokenStateAsync(Guid id, string token, CancellationToken ct)
    {
        await using var db = await database.OpenConnectionAsync(ct);
        await using var q = new NpgsqlCommand("""
            select token_hash,revoked_at is not null,
                (select count(*) from sli_agent_audit where target=t.id::text and action='token_revoke'),
                (select actor from sli_agent_audit where target=t.id::text and action='token_create' order by id limit 1),
                (select details from sli_agent_audit where target=t.id::text and action='token_create' order by id limit 1)
            from sli_agent_enrollment_tokens t where id=@id and host_id=@host
            """, db);
        q.Parameters.AddWithValue("id", id); q.Parameters.AddWithValue("host", TokenHost); await using var reader = await q.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
        bool matches = CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(token)), Encoding.ASCII.GetBytes(reader.GetString(0)));
        using var details = JsonDocument.Parse(reader.GetString(4));
        return JsonSerializer.SerializeToElement(new { digest_matches = matches, revoked = reader.GetBoolean(1), revoke_audits = reader.GetInt64(2), actor = reader.GetString(3), create_details = details.RootElement.Clone() });
    }
    internal async Task<JsonElement> StateAsync(CancellationToken ct)
    {
        await using var db = await database.OpenConnectionAsync(ct);
        await using var q = new NpgsqlCommand("""
            select jsonb_build_object('current_user',current_user,'status',a.status,'revision',a.policy_revision,'applied_revision',a.applied_policy_revision,'control',a.collection_policy,
                'history',(select coalesce(jsonb_agg(jsonb_build_object('revision',revision,'modules',assigned_modules,'control',collection_policy) order by revision),'[]'::jsonb) from sli_agent_policy_history where agent_id=a.id),
                'audits',(select coalesce(jsonb_agg(jsonb_build_object('action',action,'actor',actor,'details',details) order by id),'[]'::jsonb) from sli_agent_audit where target=a.id::text),
                'active_certificates',(select count(*) from sli_agent_certificates where agent_id=a.id and revoked_at is null),
                'other_active_certificates',(select count(*) from sli_agent_certificates where agent_id=@other and revoked_at is null),
                'tokens',(select count(*) from sli_agent_enrollment_tokens where host_id=@host)) from sli_agents a where id=@id
            """, db);
        q.Parameters.AddWithValue("id", Agent); q.Parameters.AddWithValue("other", OtherAgent); q.Parameters.AddWithValue("host", TokenHost);
        using var doc = JsonDocument.Parse((string)(await q.ExecuteScalarAsync(ct))!); return doc.RootElement.Clone();
    }
    internal static Task RecordAsync(string name, object data) => File.WriteAllTextAsync(Path.Combine(EvidenceRoot, name + ".json"), JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
    public async ValueTask DisposeAsync() { await ManifestAsync(); await database.DisposeAsync(); }
}
