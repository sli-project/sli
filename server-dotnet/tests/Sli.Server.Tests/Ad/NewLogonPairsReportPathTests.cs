using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

// Parity with tests/reporting/test_new_logon_pairs_report_path.py. The HTTP
// dispatcher, access checks, PG context, publication verification and comparison
// are real; only the external ClickHouse HTTP boundary returns fixture rows.
public sealed class NewLogonPairsReportPathTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly DateTimeOffset Start = new(2026, 10, 6, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset End = Start.AddDays(1);
    static readonly DateTimeOffset Baseline = Start.AddDays(-30);
    const string Path = "/api/v2/reports/ad.new-logon-pairs/data?period=custom&from=2026-10-06T00:00:00Z&to=2026-10-07T00:00:00Z&baseline_days=30";

    [Theory]
    [InlineData(false, false, "partial")]
    [InlineData(true, false, "empty")]
    [InlineData(false, true, "partial")]
    public async Task Dispatcher_reaches_verified_history_and_comparison(bool empty, bool known, string expected)
    {
        var history = new History(empty, known);
        await using var transport = await HistoryHost(history);
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await Seed(pg);
        await SeedEvents(pg,history);
        using var host = await ReportHost(pg, transport, 7);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync(Path, Ct);
        var payload = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!.AsObject();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(payload["state"]!.ToString() == expected, payload.ToJsonString());
        Assert.Equal(empty, payload["limitations"]!.AsArray().Any(item => item!["code"]!.ToString() == "history_empty"));
        Assert.False(payload["coverage"]!["baseline_covered"]!.GetValue<bool>());
        if (!empty && !known)
        {
            var row = Assert.Single(payload["items"]!.AsArray())!;
            Assert.Equal("PC-2", row["computer"]!.ToString());
            Assert.Equal("no_baseline", row["novelty"]!.ToString());
            Assert.Equal("yes", row["prior_user_logon"]!.ToString());
            Assert.Equal(2, row["source_event_id"]!.GetValue<int>());
            Assert.Equal(1, row["count"]!.GetValue<int>());
        }
        else Assert.Empty(payload["items"]!.AsArray());

        Assert.Empty(history.Calls);
    }

    [Fact]
    public async Task Dispatcher_preserves_context_integrity_failure()
    {
        var history = new History(Corrupt: true);
        await using var transport = await HistoryHost(history);
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await Seed(pg);
        await SeedEvents(pg,history);
        await using(var db=await pg.OpenAsync(Ct))await PostCollectionPostgres.Sql(db,"update users_report_v2_snapshots set payload_sha256=decode(repeat('00',32),'hex')",Ct);
        using var host = await ReportHost(pg, transport, 7);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync(Path, Ct);
        string body = await response.Content.ReadAsStringAsync(Ct);
        var payload = JsonNode.Parse(body)!;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("error", payload["state"]!.ToString());
        Assert.Empty(payload["items"]!.AsArray());
        Assert.Equal("context_verification_failed", payload["limitations"]![0]!["code"]!.ToString());
        Assert.DoesNotContain("bad-hash", body);
        Assert.Empty(history.Calls);
    }

    [Fact]
    public async Task Dispatcher_denial_never_reaches_history_transport()
    {
        var history = new History();
        await using var transport = await HistoryHost(history);
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await Seed(pg);
        await SeedEvents(pg,history);
        using var host = await ReportHost(pg, transport, 8);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync(Path, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("report_scope_not_executable", JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!["error"]!.ToString());
        Assert.Empty(history.Calls);
    }

    static string Stamp(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
    sealed class History(bool Empty = false, bool Known = false, bool Corrupt = false)
    {
        internal bool IsEmpty => Empty;
        internal bool IsKnown => Known;
        internal readonly ConcurrentQueue<string> Calls = new();
        internal string Execute(string sql)
        {
            Calls.Enqueue(sql);
            string Row(object value) => JsonSerializer.Serialize(value) + "\n";
            if (sql.Contains("FROM sli_warm.session_lifecycle_revisions") || sql.Contains("FROM sli_warm.primary_sessions_effective_v1") || sql.Contains("FROM sli_warm.event_session_placement_revisions")) return "";
            if (sql.Contains("GROUP BY server_id"))
                return Empty ? "" : Row(new { server_id = 10, first_utc = Stamp(Baseline), last_utc = Stamp(End) });
            if (sql.StartsWith("SELECT event_db_id FROM", StringComparison.Ordinal))
                return Empty ? "" : Row(new { event_db_id = sql.Contains($">=toDateTime64('{Stamp(Baseline)}'") ? 1 : 2 });
            if (sql.StartsWith("SELECT event_db_id,time_created_utc", StringComparison.Ordinal))
            {
                long id = long.Parse(Regex.Match(sql, @"event_db_id IN \(([0-9]+)\)").Groups[1].Value, CultureInfo.InvariantCulture);
                var core = new JsonObject {
                    ["id"] = id, ["event_id"] = 4624, ["server_id"] = 10, ["domain_id"] = 7, ["channel"] = "Security",
                    ["time_created_utc"] = (id == 1 ? Baseline : Start).ToString("O"), ["target_domain_name"] = "example.test",
                    ["target_user_name"] = "user-1", ["target_user_sid"] = "S-1-5-21-100000001-200000002-300000003-1001",
                    ["workstation_name"] = id == 1 || Known ? "PC-1" : "PC-2", ["computer"] = "DC-1", ["logon_type"] = "3"
                };
                var canonical = new JsonObject { ["core"] = core.DeepClone(), ["facts"] = new JsonObject() };
                string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(canonical, ensureAscii: false))));
                return Row(new { event_db_id = id, time_created_utc = core["time_created_utc"]!.ToString(), event_key = 4624, server_id = 10,
                    noise_class = "", core_json = core.ToJsonString(), facts_json = "{}", row_sha256 = Corrupt ? "bad-hash" : hash, batch_sha256 = new string('0', 64) });
            }
            if (sql.StartsWith("SELECT batch_sha256,first_event_db_id,last_event_db_id", StringComparison.Ordinal))
                return Row(new { batch_sha256 = new string('0', 64), first_event_db_id = 1, last_event_db_id = 2 });
            throw new InvalidOperationException("Unexpected fixture history query: " + sql);
        }
    }

    static async Task<WebApplication> HistoryHost(History history)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(k => k.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();
        app.MapPost("/", async context => {
            using var reader = new StreamReader(context.Request.Body);
            await context.Response.WriteAsync(history.Execute(await reader.ReadToEndAsync(context.RequestAborted)), context.RequestAborted);
        });
        await app.StartAsync(Ct);
        return app;
    }

    sealed class Auth : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "operator")));
    }
    sealed class Facts(long domain) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            string[] fields = ["computer_logon_observation"];
            var definition = JsonSerializer.SerializeToElement(new { report_key = "ad.computer-logons", version = 1, dataset_version = 1,
                definition_json = new { field_categories = fields, actions = new[] { "view" } }, fields_json = fields.Select(category => new { category }), actions_json = new[] { "view" } });
            var policies = new[] { "workspace.view", "events.view", "evidence.exact", "field.computer_logon_observation" }
                .Select(key => JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray();
            var assignment = JsonSerializer.SerializeToElement(new { report_key = "ad.computer-logons", effect = "allow", scope_json = new { kind = "domain", ids = new[] { domain } }, field_categories = fields, allowed_actions = new[] { "view" } });
            return Task.FromResult(new AccessFacts(false, "operator", [], [], policies, [], [], [assignment], [definition]));
        }
    }
    sealed class Catalog : IReportCatalogProvider
    {
        public ReportCatalogSnapshot Capture() => new([new ReportRule("ad.new-logon-pairs", "ad.computer-logons", "domain", new HashSet<string>(), new HashSet<string>(), null, false) { OwnerId = "sli.ad" }], new Dictionary<string, PluginGeneration>(), new Dictionary<string, string>());
        public ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured) => captured;
    }
    static async Task<IHost> ReportHost(PostCollectionPostgres pg, WebApplication transport, long domain)
    {
        var endpoint = new Uri(Assert.Single(transport.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses));
        string userFile = System.IO.Path.Combine(pg.Root, "history-user");
        string passwordFile = System.IO.Path.Combine(pg.Root, "history-password");
        await File.WriteAllTextAsync(userFile, "synthetic", Ct);
        await File.WriteAllTextAsync(passwordFile, "synthetic", Ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:AuthRequired"] = "true", ["ConnectionStrings:Sli"] = pg.ConnectionString, ["Sli:Storage:HistoryReadMode"] = "primary",
            ["Sli:Storage:ShortEventReads"] = "false",["Sli:Storage:HotRetentionDays"]="365",
            ["Sli:Storage:HistoryClickHouseHost"] = "127.0.0.1", ["Sli:Storage:HistoryClickHousePort"] = endpoint.Port.ToString(CultureInfo.InvariantCulture),
            ["Sli:Storage:HistoryClickHouseUser"] = "", ["Sli:Storage:HistoryClickHousePassword"] = "",
            ["Sli:Storage:HistoryClickHouseUserFile"] = userFile, ["Sli:Storage:HistoryClickHousePasswordFile"] = passwordFile, ["CREDENTIALS_DIRECTORY"] = ""
        }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services => {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Auth()); services.AddSingleton<IAccessFactsRepository>(new Facts(domain));
            services.AddSingleton<IReportCatalogProvider>(new Catalog()); services.AddSingleton<IPostgresConnectionFactory>(new PostgresConnectionFactory(config));
            services.AddSingleton<IAdV2Store, AdV2Store>();
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapAdV2()); })).StartAsync(Ct);
    }

    static async Task Seed(PostCollectionPostgres pg)
    {
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key,fqdn text,is_archived boolean default false);
            insert into domains(id,fqdn) values(7,'example.test'),(8,'other.example.test');
            create table platform_settings(key text,value text);
            insert into platform_settings values('reports.domain_fqdn','example.test');
            create table ad_context_runs(domain_id bigint,status text,observed_at_utc timestamptz);
            create table servers(id bigint,domain_id bigint,role text);
            insert into servers values(10,7,'domain_controller'),(11,8,'domain_controller');
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
            create table event_cold_facts(like event_hot);
            create table event_cold_daily(day date,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,grouping_key bytea,event_count bigint,first_seen_utc timestamptz,last_seen_utc timestamptz);
            create table storage_v2_entity_type(id bigint,value text);
            create table entities_v2(id bigint,domain_id bigint,entity_type_id bigint);

            create table computers_v6_source_snapshots(source_snapshot_id bigint,domain_id bigint,snapshot_uuid uuid,source_completed_at_utc timestamptz,
                collection_status text,base_inventory_status text,object_count int,payload_json jsonb,payload_sha256 bytea);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,captured_at_utc timestamptz,source_state text,payload_json jsonb,payload_sha256 bytea);
            create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,entity_id bigint);
            """, Ct);
        using var stream = typeof(NewLogonPairsReportPathTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Domains.home-computer-source.json")!;
        var payload = (await JsonNode.ParseAsync(stream, cancellationToken: Ct))!.AsObject();
        var prototype = payload["objects"]![0]!.AsObject();
        var objects = new JsonArray();
        for (int i = 1; i <= 2; i++)
        {
            var computer = (JsonObject)prototype.DeepClone();
            computer["id"] = $"00000000-0000-4000-8000-{i:D12}";
            computer["objectGuid"] = $"00000000-0000-4000-8000-{i:D12}";
            computer["name"] = $"PC-{i}"; computer["dnsHostName"] = $"pc-{i}.example.test";
            computer["classification"]!["result"] = "workstation";
            computer["ipv4s"] = new JsonArray($"192.0.2.{i}");
            objects.Add(computer);
            await using var alias = new NpgsqlCommand("insert into ad_context_entity_aliases values(7,'object_guid',$1,$2)", db);
            alias.Parameters.AddWithValue(computer["objectGuid"]!.ToString()); alias.Parameters.AddWithValue(100 + i);
            await alias.ExecuteNonQueryAsync(Ct);
        }
        payload["objects"] = objects; payload["metadata"]!["object_count"] = 2;
        var users = JsonNode.Parse("""{"users":[{"samAccountName":"user-1","sid":"S-1-5-21-100000001-200000002-300000003-1001"}]}""")!.AsObject();
        await using var seed = new NpgsqlCommand("""
            insert into computers_v6_source_snapshots values(1,7,@uuid,now(),'complete','observed',2,@payload,decode(@hash,'hex'));
            insert into users_report_v2_snapshots values(1,7,now(),'complete',@users,decode(@userHash,'hex'));
            """, db);
        seed.Parameters.AddWithValue("uuid", Guid.Parse(payload["metadata"]!["snapshot_id"]!.ToString()));
        seed.Parameters.AddWithValue("payload", NpgsqlTypes.NpgsqlDbType.Jsonb, payload.ToJsonString());
        seed.Parameters.AddWithValue("users", NpgsqlTypes.NpgsqlDbType.Jsonb, users.ToJsonString());
        seed.Parameters.AddWithValue("hash", AdJobPlugin.Digest(payload)); seed.Parameters.AddWithValue("userHash", AdJobPlugin.Digest(users));
        await seed.ExecuteNonQueryAsync(Ct);
    }
    static async Task SeedEvents(PostCollectionPostgres pg,History history)
    {
        if(history.IsEmpty)return;
        await using var db=await pg.OpenAsync(Ct);
        await using var seed=new NpgsqlCommand("""
            insert into event_hot values
                (1,@baseline,4624,7,'S-1-5-21-100000001-200000002-300000003-1001',null,'PC-1','DC-1','{"$server_id":10,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","LogonType":"3"}','{}','{}'),
                (2,@start,4624,7,'S-1-5-21-100000001-200000002-300000003-1001',null,@computer,'DC-1','{"$server_id":10,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","LogonType":"3"}','{}','{}')
            """,db);
        seed.Parameters.AddWithValue("baseline",Baseline);seed.Parameters.AddWithValue("start",Start);seed.Parameters.AddWithValue("computer",history.IsKnown?"PC-1":"PC-2");await seed.ExecuteNonQueryAsync(Ct);
    }

}
