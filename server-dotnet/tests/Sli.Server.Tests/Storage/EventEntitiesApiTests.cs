using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Source vectors: tests/events/test_event_entities_api.py. The real reader and
// SQL run against an owned disposable cluster; only query failures are injected.
public sealed class EventEntitiesApiTests
{
    const long EventId = 900001;
    const string Path = "/api/v1/events/900001/entities";
    const string Identity = "sid:S-1-5-21-100000001-200000002-300000003-1001";
    sealed class Authentication : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "operator")));
    }
    sealed class Facts : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct) =>
            Task.FromResult(EventQueryEndpointTests.MakeFacts());
    }
    sealed class Connections(SqlPostgresFixture database) : IPostgresConnectionFactory
    {
        internal int Calls, FailAt;
        internal Exception? Error;
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            if (++Calls == FailAt && Error is {} error) throw error;
            var connection = new NpgsqlConnection(database.Dsn("adlog_user"));
            try { await connection.OpenAsync(ct); return connection; }
            catch { await connection.DisposeAsync(); throw; }
        }
    }
    sealed class Fixture : IAsyncDisposable
    {
        readonly SqlPostgresFixture database = new();
        internal readonly Connections Connections;
        internal IHost Host = null!;
        internal HttpClient Client = null!;
        internal Fixture() { Connections = new(database); }
        internal async Task<Fixture> Start()
        {
            var ct = TestContext.Current.CancellationToken;
            await database.StartAsync(ct);
            await using (var db = await database.Pg.OpenAsync(ct))
            {
                var events = await ShortEventAdmissionPostgresTests.SeedAsync(db, ct, eventKinds: [4625]);
                Assert.Equal(EventId, Assert.Single(events).EventId);
                await ShortEventAdmissionPostgresTests.WriteAsync(database, events, ct);
                await using var seed = new NpgsqlCommand("""
                    insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
                    insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                        select 7,id,@identity,'Synthetic user',1,sha256('synthetic-entity'::bytea)
                        from storage_v2_entity_type where value='ad_user';
                    """, db);
                seed.Parameters.AddWithValue("identity", Identity);
                await seed.ExecuteNonQueryAsync(ct);
            }
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
                ["Sli:AuthRequired"] = "true", ["Sli:Storage:HistoryReadMode"] = "disabled"
            }).Build();
            Host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services => {
                services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
                services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
                services.AddSingleton<IPrincipalAuthenticator,Authentication>(); services.AddSingleton<IAccessFactsRepository,Facts>();
                services.AddSingleton<IPostgresConnectionFactory>(Connections); services.AddEventReads();
            }).Configure(app => { app.UseRouting(); app.UseEndpoints(routes => routes.MapEventReads()); })).StartAsync(ct);
            Client = Host.GetTestClient();
            return this;
        }
        internal async Task Sql(string sql)
        {
            await using var db = await database.Pg.OpenAsync(TestContext.Current.CancellationToken);
            await PostCollectionPostgres.Sql(db, sql, TestContext.Current.CancellationToken);
        }
        internal async Task<JsonObject> Get(HttpStatusCode status = HttpStatusCode.OK)
        {
            using var response = await Client.GetAsync(Path, TestContext.Current.CancellationToken);
            Assert.Equal(status, response.StatusCode);
            return JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        }
        public async ValueTask DisposeAsync()
        {
            Client?.Dispose(); Host?.Dispose(); await database.DisposeAsync();
        }
    }
    static void Envelope(JsonObject body)
    {
        Assert.Equal("v1", body["api_version"]!.GetValue<string>());
        Assert.Equal(EventId, body["event_db_id"]!.GetValue<long>());
        Assert.Equal(30, body["limit"]!.GetValue<int>());
    }
    [Theory]
    [InlineData(1, false)] [InlineData(2, false)]
    [InlineData(1, true)] [InlineData(2, true)]
    public async Task Either_query_timeout_is_unknown_evidence_and_next_request_recovers(int query, bool postgres)
    {
        await using var fixture = new Fixture(); await fixture.Start();
        // Resource authorization opens one connection before the two entity queries.
        fixture.Connections.FailAt = query + 1;
        fixture.Connections.Error = postgres
            ? new PostgresException("synthetic-query-detail", "ERROR", "ERROR", "57014")
            : new TimeoutException("synthetic-query-detail");
        var unavailable = await fixture.Get();
        Assert.Equal(query + 1, fixture.Connections.Calls);
        Envelope(unavailable);
        Assert.True(unavailable.ContainsKey("event_found")); Assert.Null(unavailable["event_found"]);
        Assert.Equal("timeout", unavailable["evidence_status"]!.GetValue<string>());
        Assert.Empty(unavailable["items"]!.AsArray());
        Assert.Contains("временно недоступны", unavailable["warning"]!.GetValue<string>());
        Assert.DoesNotContain("synthetic-query-detail", unavailable.ToJsonString());

        var recovered = await fixture.Get();
        Assert.Equal(query + 4, fixture.Connections.Calls);
        Envelope(recovered);
        Assert.True(recovered["event_found"]!.GetValue<bool>());
        Assert.Equal("present", recovered["evidence_status"]!.GetValue<string>());
        Assert.Null(recovered["warning"]);
        var entity = Assert.Single(recovered["items"]!.AsArray())!;
        Assert.Equal(7, entity["id"]!.GetValue<long>());
        Assert.Equal("ad_user", entity["type"]!.GetValue<string>());
        Assert.Equal(Identity, entity["natural_key"]!.GetValue<string>());
        Assert.Equal("Synthetic user", entity["display_name"]!.GetValue<string>());
        Assert.Equal("target", entity["link_role"]!.GetValue<string>());
        Assert.Equal(1.0, entity["confidence"]!.GetValue<double>());
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task Empty_entities_and_missing_event_have_distinct_states(bool found)
    {
        await using var fixture = new Fixture(); await fixture.Start();
        await fixture.Sql("delete from entities_v2 where id=7" + (found ? "" :
            $"; delete from event_hot where event_id={EventId}; delete from event_cold_facts where event_id={EventId}"));
        var body = await fixture.Get();
        Envelope(body);
        Assert.Equal(found, body["event_found"]!.GetValue<bool>());
        Assert.Equal(found ? "zero_extracted" : "event_not_found", body["evidence_status"]!.GetValue<string>());
        Assert.Empty(body["items"]!.AsArray()); Assert.Null(body["warning"]);
        Assert.Equal(found ? 3 : 2, fixture.Connections.Calls);
    }
    [Fact]
    public async Task Unexpected_failure_propagates_from_reader_and_is_http_500()
    {
        await using var fixture = new Fixture(); await fixture.Start();
        var failure = new InvalidOperationException("synthetic-unexpected-failure");
        fixture.Connections.Error = failure; fixture.Connections.FailAt = 1;
        await using (var scope = fixture.Host.Services.CreateAsyncScope())
            Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() =>
                scope.ServiceProvider.GetRequiredService<IEventQueryStore>().EntitiesAsync(EventId, TestContext.Current.CancellationToken)));
        fixture.Connections.Calls = 0; fixture.Connections.FailAt = 2;
        var body = await fixture.Get(HttpStatusCode.InternalServerError);
        Assert.Equal("internal_server_error", body["error"]!.GetValue<string>());
        Assert.False(body.ContainsKey("evidence_status"));
        Assert.DoesNotContain("synthetic-unexpected-failure", body.ToJsonString());
    }
}
