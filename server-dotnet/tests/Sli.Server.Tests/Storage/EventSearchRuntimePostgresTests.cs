using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Parity: tests/events/test_evsearch_runtime_postgres.py. Each case owns a
// disposable migrated cluster; no inherited DSN, substitute PG tables or grants.
public sealed class EventSearchRuntimePostgresTests
{
    static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    static readonly DateTimeOffset Stamp = Now.AddHours(-1);
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    [Fact]
    public async Task Existing_runtime_role_reads_published_jsonb_event_projection_and_recordset_without_grants()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var role = new NpgsqlCommand("select current_user,rolsuper from pg_roles where rolname=current_user", db, tx))
        await using (var rows = await role.ExecuteReaderAsync(ct)) {
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal("adlog_user", rows.GetString(0));
            Assert.False(rows.GetBoolean(1));
            Assert.False(await rows.ReadAsync(ct));
        }
        await using (var publication = new NpgsqlCommand("""
            select r.definition_json,d.dataset_key,d.fields_json,r.version,pg_typeof(d.fields_json)::text
            from public.report_registry_v4 r join public.report_datasets_v4 d on d.id=r.dataset_id
            where r.report_key='events.explorer' and r.version=1
              and r.status='published' and d.status='published' limit 1
            """, db, tx))
        await using (var rows = await publication.ExecuteReaderAsync(ct)) {
            Assert.True(await rows.ReadAsync(ct));
            using var definition = rows.GetFieldValue<JsonDocument>(0);
            using var fields = rows.GetFieldValue<JsonDocument>(2);
            Assert.Equal(JsonValueKind.Object, definition.RootElement.ValueKind);
            Assert.Equal("events.v2", rows.GetString(1));
            Assert.Equal(JsonValueKind.Array, fields.RootElement.ValueKind);
            Assert.NotEmpty(fields.RootElement.EnumerateArray());
            Assert.All(fields.RootElement.EnumerateArray(), field => Assert.Equal(JsonValueKind.Object, field.ValueKind));
            Assert.Equal(1L, rows.GetInt64(3));
            Assert.Equal("jsonb", rows.GetString(4));
        }
        // LIMIT 0 proves the exact source projection is readable without event data.
        await using (var projection = new NpgsqlCommand("""
            select event_id,time_created_utc,event_kind,method from public.event_hot limit 0
            """, db, tx))
        await using (var rows = await projection.ExecuteReaderAsync(ct)) Assert.False(await rows.ReadAsync(ct));
        await using (var aggregate = new NpgsqlCommand("""
            select group_key,count(*) as n from jsonb_to_recordset(@capture::jsonb)
            as captured(group_key text,stamp timestamptz) group by group_key
            """, db, tx)) {
            aggregate.Parameters.AddWithValue("capture", """[{"group_key":"synthetic","stamp":"2026-10-18T12:00:00Z"}]""");
            await using var rows = await aggregate.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal("synthetic", rows.GetString(0));
            Assert.Equal(1L, rows.GetInt64(1));
            Assert.False(await rows.ReadAsync(ct));
        }
        await tx.RollbackAsync(ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Http_query_page_members_capture_real_postgres_rows_with_published_contract()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        string token = await fixture.SeedOwnerAsync(ct);
        var archivedStamp = Now.AddDays(-20);
        await using (var admin = await fixture.Pg.OpenAsync(ct)) {
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(admin, ct, eventKinds: [4740, 4740, 4740],
                nativeTimestamps: [SemanticJson.Stamp(Stamp), SemanticJson.Stamp(Stamp), SemanticJson.Stamp(archivedStamp)]);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            await PostCollectionPostgres.Sql(admin, "delete from event_hot where event_id=900003", ct);
            await using var stored = new NpgsqlCommand("""
                select (select count(*) from public.semantic_event_source355 where id in (900001,900002,900003))=3
                   and exists(select 1 from public.event_cold_facts where event_id=900003 and source_sha256 is not null)
                   and to_regclass('public.events_v2_core') is null and to_regclass('public.event_facts_v2') is null
                """, admin);
            Assert.Equal(true, await stored.ExecuteScalarAsync(ct));
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"]=fixture.Dsn("adlog_user"),["Sli:AuthRequired"]="true",
            ["Sli:Storage:ShortEventReads"]="false",["Sli:Storage:HistoryReadMode"]="primary",
            ["Sli:Storage:HistoryClickHousePort"]="invalid"
        }).Build();
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services => {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddScoped<IPrincipalAuthenticator, PrincipalAuthenticator>();
            services.AddSingleton<IPostgresConnectionFactory>(new PostgresConnectionFactory(config));
            services.AddSingleton<TimeProvider>(new Clock()); services.AddEventReads();
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(routes => routes.MapEventReads()); })).StartAsync(ct);
        using var client = host.GetTestClient();
        using (var unauthenticated = await client.PostAsync("/api/v1/event-search/query",
            new StringContent("{\"contract_version\":\"evsearch.v1\"}", Encoding.UTF8, "application/json"), ct))
            Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        client.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + token);

        async Task<JsonObject> Call(string operation, object body)
        {
            using var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var response = await client.PostAsync("/api/v1/event-search/" + operation, content, ct);
            string text = await response.Content.ReadAsStringAsync(ct);
            Assert.True(response.StatusCode == HttpStatusCode.OK, text);
            return JsonNode.Parse(text)!.AsObject();
        }
        var result = await Call("query", new { contract_version = "evsearch.v1", page_size = 1, period=EventSearchInput.Period(Now.AddDays(-30),Now,"UTC") });
        Assert.NotNull(result["next_cursor"]);
        var seen = new List<long>();
        int pages = 0;
        do {
            pages++;
            var group = Assert.Single(result["items"]!.AsArray())!;
            Assert.Equal(1, group["count"]!.GetValue<int>());
            var members = await Call("members", new { execution_id = result["execution_id"]!.ToString(), group_key = group["group_key"]!.ToString() });
            var member = Assert.Single(members["items"]!.AsArray())!;
            long id = member["event_db_id"]!.GetValue<long>();
            seen.Add(id);
            Assert.Equal("postgres", member["source_store"]!.ToString());
            Assert.Equal(4740, member["fields"]!["event_id"]!.GetValue<int>());
            Assert.Equal("Security", member["fields"]!["channel"]!.ToString());
            Assert.Equal((id==900003 ? archivedStamp : Stamp).ToUnixTimeMilliseconds(),DateTimeOffset.Parse(member["fields"]!["time_created_utc"]!.ToString()).ToUnixTimeMilliseconds());
            if (result["next_cursor"] is not {} cursor) break;
            result = await Call("page", new { execution_id = result["execution_id"]!.ToString(), cursor = cursor.ToString() });
        } while (true);
        Assert.Equal(3, pages);
        Assert.Equal(new long[] { 900001, 900002, 900003 }, seen.Order());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
