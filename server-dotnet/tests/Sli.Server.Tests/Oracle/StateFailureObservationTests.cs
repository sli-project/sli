using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Oracle;

public sealed class StateFailureObservationTests
{
    [Fact]
    public async Task Actual_requests_and_restoration_keep_per_request_control_and_auth_observations()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        string session = await fixture.SeedOwnerAsync(ct);
        string key = "adl_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        await using var control = await fixture.Pg.OpenAsync(ct);
        long sessionId, keyId;
        await using (var command = new NpgsqlCommand("select id from auth_sessions where token_hash=@hash", control))
        {
            command.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(session))));
            sessionId = Convert.ToInt64(await command.ExecuteScalarAsync(ct));
        }
        await using (var command = new NpgsqlCommand("""
            insert into auth_api_keys(key_prefix,key_hash,label,role,is_active)
            values(@prefix,@hash,'synthetic oracle key','admin',true) returning id
            """, control))
        {
            command.Parameters.AddWithValue("prefix", key[..12]);
            command.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key))));
            keyId = Convert.ToInt64(await command.ExecuteScalarAsync(ct));
        }
        var observer = new RequestObservation(fixture, [sessionId], [keyId]);
        var runtime = new NpgsqlConnectionStringBuilder(fixture.Dsn("adlog_user")) { Pooling = false, CommandTimeout = 0 };
        using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
            .ConfigureLogging(l => l.ClearProviders())
            .ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?> {
                ["ConnectionStrings:Sli"] = runtime.ConnectionString, ["Sli:AgentMtlsCaFile"] = "", ["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"] = "",
                ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1",
                ["Sli:ProjectRoot"] = SqlPostgresFixture.Repository(), ["Sli:OwnerSetup"] = "0",
                ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "app-data"),
                ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "app-logs")
            }))).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
            foreach (var worker in services.Where(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && (d.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyJobWorker)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyScheduler)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyPostCollectionHostedService))).ToArray())
                services.Remove(worker);
        }));
        host.UseKestrel(k => k.Listen(IPAddress.Loopback, 0)); host.StartServer();
        string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        Assert.True(new Uri(address).IsLoopback);
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false }) {
            BaseAddress = new Uri(address), Timeout = Timeout.InfiniteTimeSpan
        };
        var records = new List<RequestObservation.Observation>();
        async Task<RequestObservation.Observation> Request(string id, int status, bool apiKey = false)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/domains");
            if (apiKey) request.Headers.Authorization = new("Bearer", key);
            else request.Headers.Add("Cookie", "adlog_session=" + session);
            var record = await observer.RequestAsync(id, client, request, ct);
            records.Add(record);
            Assert.Equal(status, record.Http!.Status);
            Assert.Equal(record.Before.Tables, record.After.Tables);
            Assert.InRange(record.Before.ClockEnd, record.Before.ClockStart, record.After.ClockStart);
            Assert.True(record.After.ClockEnd >= record.After.ClockStart);
            foreach (string table in RequestObservation.InsertOnlyTables) Assert.True(record.Before.Tables.ContainsKey(table));
            return record;
        }
        async Task<RequestObservation.Observation> Action(string id, string sql)
        {
            var record = await observer.ActionAsync(id, () => PostCollectionPostgres.Sql(control, sql, ct), ct);
            records.Add(record); return record;
        }
        static JsonNode? Used(RequestObservation.Snapshot s, string table) => s.Auth[table]![0]!["last_used_at"];
        static void UnchangedAuth(RequestObservation.Observation r) => Assert.True(JsonNode.DeepEquals(r.Before.Auth, r.After.Auth));
        static void BoundedUsage(RequestObservation.Observation r, string table)
        {
            Assert.Null(Used(r.Before, table));
            var used = DateTimeOffset.Parse(Used(r.After, table)!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture).UtcDateTime;
            Assert.InRange(used, r.Before.ClockEnd, r.After.ClockStart);
            string other = table == "auth_sessions" ? "auth_api_keys" : "auth_sessions";
            Assert.True(JsonNode.DeepEquals(r.Before.Auth[other], r.After.Auth[other]));
        }
        BoundedUsage(await Request("state_session_cold", 200), "auth_sessions");
        UnchangedAuth(await Request("state_session_warm", 200));
        var revoked = await Action("state_revoke", $"update auth_sessions set revoked_at=clock_timestamp() where id={sessionId}");
        Assert.NotEqual(revoked.Before.Tables["public.auth_sessions"], revoked.After.Tables["public.auth_sessions"]);
        Assert.Equal(revoked.Before.Tables["$privileges"], revoked.After.Tables["$privileges"]);
        try { UnchangedAuth(await Request("state_revoked", 401)); }
        finally { await Action("state_restore", $"update auth_sessions set revoked_at=null where id={sessionId}"); }
        UnchangedAuth(await Request("state_restored", 200));
        BoundedUsage(await Request("state_key_cold", 200, apiKey: true), "auth_api_keys");
        UnchangedAuth(await Request("state_key_warm", 200, apiKey: true));

        // No timeout, new grant, fake authenticator or database provider. A genuine
        // PostgreSQL login refusal reaches the ordinary production error handler.
        var disabled = await Action("failure_disable_login", "alter role adlog_user nologin");
        Assert.NotEqual(disabled.Before.Tables["$privileges"], disabled.After.Tables["$privileges"]);
        try
        {
            var failure = await Request("failure_runtime_auth_disabled", 500);
            UnchangedAuth(failure);
            var body = JsonNode.Parse(Convert.FromBase64String(failure.Http!.BodyBase64))!;
            Assert.Equal("internal_server_error", body["error"]!.GetValue<string>());
            Assert.Equal("$internal_error_id", body["internal_error_id"]!.GetValue<string>());
        }
        finally
        {
            var restored = await Action("failure_restore_login", "alter role adlog_user login");
            Assert.Equal(disabled.Before.Tables, restored.After.Tables);
            UnchangedAuth(restored);
        }
        UnchangedAuth(await Request("failure_runtime_auth_restored", 200));

        // Counts alone miss updates. Fingerprints catch a non-auth mutation while
        // retaining the unchanged auth metadata and all INSERT-only fingerprints.
        var nonAuth = await Action("fingerprint_non_auth_update", "update domains set fqdn='changed.example.test' where fqdn='example.test'");
        UnchangedAuth(nonAuth);
        Assert.Equal(nonAuth.Before.Tables["public.domains"].Rows, nonAuth.After.Tables["public.domains"].Rows);
        Assert.NotEqual(nonAuth.Before.Tables["public.domains"], nonAuth.After.Tables["public.domains"]);
        foreach (string table in RequestObservation.InsertOnlyTables) Assert.Equal(nonAuth.Before.Tables[table], nonAuth.After.Tables[table]);

        await using (var runtimeDb = new NpgsqlConnection(runtime.ConnectionString))
        {
            await runtimeDb.OpenAsync(ct);
            foreach (string table in RequestObservation.InsertOnlyTables)
            {
                await using var acl = new NpgsqlCommand("select has_table_privilege(current_user,@table,'INSERT'),has_table_privilege(current_user,@table,'SELECT')", runtimeDb);
                acl.Parameters.AddWithValue("table", table);
                await using var row = await acl.ExecuteReaderAsync(ct);
                Assert.True(await row.ReadAsync(ct)); Assert.True(row.GetBoolean(0)); Assert.False(row.GetBoolean(1));
            }
            var inserted = await observer.ActionAsync("fingerprint_insert_only", () => PostCollectionPostgres.Sql(runtimeDb, """
                insert into sli_ad_credential_audit(actor,action,result) values('synthetic-oracle','denied','synthetic');
                insert into sli_agent_gpo_plan_audit(actor,action,result) values('synthetic-oracle','denied','synthetic');
                insert into storage_v2_shadow_results(query_kind,sample_key_sha256,v1_result_sha256,v2_result_sha256,
                    identity_match,count_match,v1_duration_ms,v2_duration_ms)
                values('synthetic-oracle',sha256('sample'::bytea),sha256('v1'::bytea),sha256('v2'::bytea),false,true,0,0);
                """, ct), ct);
            records.Add(inserted); UnchangedAuth(inserted);
            Assert.Equal(inserted.Before.Tables["$privileges"], inserted.After.Tables["$privileges"]);
            foreach (string table in RequestObservation.InsertOnlyTables)
            {
                Assert.Equal(inserted.Before.Tables[table].Rows + 1, inserted.After.Tables[table].Rows);
                Assert.NotEqual(inserted.Before.Tables[table].Sha256, inserted.After.Tables[table].Sha256);
            }
        }

        // Serialization must retain unchanged rows, clocks, control coverage and the
        // entire normalized HTTP result. Never persist credentials or auth hashes.
        string serialized = JsonSerializer.Serialize(records);
        Assert.DoesNotContain(session, serialized); Assert.DoesNotContain(key, serialized);
        Assert.DoesNotContain("token_hash", serialized); Assert.DoesNotContain("key_hash", serialized);
        var roundtrip = JsonSerializer.Deserialize<RequestObservation.Observation[]>(serialized)!;
        Assert.Equal(records.Count, roundtrip.Length);
        for (int i = 0; i < roundtrip.Length; i++)
        {
            Assert.Equal(JsonSerializer.Serialize(records[i]), JsonSerializer.Serialize(roundtrip[i]));
            Assert.Equal(records[i].Before.Tables["$privileges"], roundtrip[i].Before.Tables["$privileges"]);
        }
    }

    [Fact]
    public async Task Normalization_retains_full_body_and_significant_headers()
    {
        var ct = TestContext.Current.CancellationToken;
        byte[] bytes = [0, 255, 13, 10, 128];
        using var binary = new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new ByteArrayContent(bytes) };
        binary.Headers.Add("X-Observed", ["one", "two"]);
        binary.Headers.Add("Date", "Sun, 08 Nov 2026 00:00:00 GMT");
        binary.Headers.Add("Server", "synthetic");
        var observed = await RequestObservation.NormalizeAsync(binary, ct);
        Assert.Equal(bytes, Convert.FromBase64String(observed.BodyBase64));
        Assert.Equal(new[] { "one", "two" }, Assert.Single(observed.Headers, h => h.Key == "x-observed").Value);
        Assert.DoesNotContain(observed.Headers, h => h.Key is "date" or "server");
        using var json = new HttpResponseMessage(HttpStatusCode.InternalServerError) {
            Content = new StringContent("""{"error":"internal_server_error","internal_error_id":"variable","nested":{"internal_error_id":"preserved"}}""", Encoding.UTF8, "application/json")
        };
        var normalized = await RequestObservation.NormalizeAsync(json, ct);
        var body = JsonNode.Parse(Convert.FromBase64String(normalized.BodyBase64))!;
        Assert.Equal("$internal_error_id", body["internal_error_id"]!.GetValue<string>());
        Assert.Equal("preserved", body["nested"]!["internal_error_id"]!.GetValue<string>());
        Assert.Contains("body.internal_error_id", normalized.Normalizations);
        using var malformed = new HttpResponseMessage(HttpStatusCode.InternalServerError) {
            Content = new StringContent("{incomplete", Encoding.UTF8, "application/json")
        };
        Assert.Equal("{incomplete", Encoding.UTF8.GetString(Convert.FromBase64String((await RequestObservation.NormalizeAsync(malformed, ct)).BodyBase64)));
    }
}
