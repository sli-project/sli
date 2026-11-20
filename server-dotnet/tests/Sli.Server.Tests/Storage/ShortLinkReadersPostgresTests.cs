using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Investigations;
using Sli.Server.Reports.SecurityCandidates;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ShortLinkReadersPostgresTests
{
    static IConfiguration Config(string dsn, bool shortReads = true, int port = 1) => new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string,string?> { ["ConnectionStrings:Sli"]=dsn, ["Sli:Storage:ShortEventReads"]=shortReads.ToString(),
            ["Sli:Storage:HistoryReadMode"]="primary", ["Sli:Storage:HistoryClickHouseHost"]="127.0.0.1",
            ["Sli:Storage:HistoryClickHousePort"]=port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Sli:Storage:HistoryClickHouseUser"]="synthetic", ["Sli:Storage:HistoryClickHousePassword"]="synthetic" }).Build();

    static async Task Seed(SqlPostgresFixture fixture, CancellationToken ct)
    {
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            insert into servers(id,domain_id,hostname,role,is_active) values(900001,1,'dc.example.test','domain_controller',true);
            insert into storage_v2_entity_type(value) values('ad_user'),('ad_computer'),('ip_address') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select n,t.id,k,'synthetic',d,sha256(n::text::bytea) from (values
                  (10001,'ad_user','sam:example:operator',1),
                  (10002,'ad_user','sid:S-1-5-21-100000001-200000002-300000003-1001',2),
                  (10003,'ad_computer','sid:S-1-5-21-100000001-200000002-300000003-1004',1),
                  (10004,'ip_address','ip:192.0.2.1',null::bigint)) e(n,type,k,d)
                join storage_v2_entity_type t on t.value=e.type;
            insert into entity_details_v2(entity_id,attributes_json,source_details_sha256)
                values(10001,'{"identity_aliases":["sid:S-1-5-21-100000001-200000002-300000003-1001"]}',sha256('synthetic'::bytea));
            """,ct);
        var at = DateTime.UtcNow.Date.AddDays(-20).AddHours(1);
        var machine = EntityShortReadsPostgresTests.Row(1003) with {
            Actor="S-1-5-21-100000001-200000002-300000003-1004",
            Method=JsonNode.Parse(EntityShortReadsPostgresTests.Row(1003).Method)!.AsObject().ToJsonString()
                .Replace("300000003-1001","300000003-1004",StringComparison.Ordinal) };
        await EntityShortReadsPostgresTests.Write(fixture,[EntityShortReadsPostgresTests.Row(1001),machine,
            EntityShortReadsPostgresTests.Row(2001,4728,at),EntityShortReadsPostgresTests.Row(2002,at:at)],ct);
    }

    static EventSearchInput Input(bool exclude = false) => new(new(DateTime.UtcNow.Date.AddDays(-30)),
        new(DateTime.UtcNow.Date.AddDays(1)),"UTC","time_desc",100,[],null,exclude,"actor",null,new());
    static EventSearchPolicy Policy(object scope) => new(JsonSerializer.SerializeToElement(new { }),
        [..EventSearchPolicy.BaseFields,"provider","account","account_kind","related_object","source_station","reason","logon_type","action","outcome","title"],
        [JsonSerializer.SerializeToElement(scope)],"synthetic");

    [Fact]
    public async Task Capture_reads_hot_and_individual_cold_facts_with_entity_scope_and_machine_exclusion_without_blocks()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct); await Seed(fixture,ct);
        var builder=WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(k=>k.Listen(System.Net.IPAddress.Loopback,0));
        int coldRequests=0;
        await using var cold=builder.Build(); cold.MapPost("/",()=> { Interlocked.Increment(ref coldRequests); return Results.Text(""); }); await cold.StartAsync(ct);
        int port=new Uri(Assert.Single(cold.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses)).Port;
        var config=Config(fixture.Dsn("adlog_user"),port:port);
        using var host=new HostBuilder().Build();
        await using var reader=new EventReadService(new PostgresConnectionFactory(config),config,host.Services.GetRequiredService<IHostEnvironment>());
        var all=await reader.CaptureAsync(Input(),Policy(new {kind="domain",ids=new[]{1}}),ct);
        Assert.Equal(new long[]{1001,1003,2001},all.Select(r=>r.Id).Order());
        Assert.All(all,r=> { Assert.Equal(64,r.Fingerprint.Length); Assert.All(r.Fingerprint,c=>Assert.True(Uri.IsHexDigit(c))); });
        var scoped=await reader.CaptureAsync(Input(true),Policy(new {mode="restricted",clauses=new[]{new {entity_ids=new[]{10001}}}}),ct);
        Assert.Equal(new long[]{1001,2001},scoped.Select(r=>r.Id).Order());
        Assert.All(scoped,r=>Assert.Contains(r.Fields["account"]!.AsArray(),v=>v!["entity_id"]!.GetValue<long>()==10001));
        var sourceScope=await reader.CaptureAsync(Input(),Policy(new {mode="restricted",clauses=new[]{new {entity_ids=new[]{10004}}}}),ct);
        Assert.Equal(new long[]{1001,1003,2001},sourceScope.Select(r=>r.Id).Order());
        Assert.Empty(await reader.CaptureAsync(Input(),Policy(new {mode="restricted",clauses=new[]{new {entity_ids=new[]{10002}}}}),ct));
        Assert.Empty(await reader.CaptureAsync(Input(),Policy(new {mode="restricted",clauses=new[]{new {entity_ids=new[]{9007199254740991L}}}}),ct));
        Assert.DoesNotContain(await reader.CaptureAsync(Input(true),Policy(new {kind="domain",ids=new[]{1}}),ct),r=>r.Id==1003);
        var filtered=Input() with { Conditions=[new("account","eq",[JsonValue.Create(10001L)!],"actor")] };
        Assert.Equal(new long[]{1001,2001},(await reader.CaptureAsync(filtered,Policy(new {kind="all"}),ct)).Select(r=>r.Id).Order());
        Assert.Equal(0,coldRequests);
        var legacy=Config(fixture.Dsn("adlog_user"),false,port);
        await using var old=new EventReadService(new PostgresConnectionFactory(legacy),legacy,host.Services.GetRequiredService<IHostEnvironment>());
        Assert.Equal(all.Select(r=>r.Id).Order(),(await old.CaptureAsync(Input(),Policy(new {kind="domain",ids=new[]{1}}),ct)).Select(r=>r.Id).Order());
        Assert.Equal(0,coldRequests);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Unbounded_entity_history_reads_aliases_and_cold_facts_but_never_another_domain_or_daily_group()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct); await Seed(fixture,ct);
        var config=Config(fixture.Dsn("adlog_user")); var connections=new PostgresConnectionFactory(config);
        var reader=new InvestigationEntityHistory(connections,new SecurityCandidateOwner(new SecurityCandidateStore(connections)),config);
        var input=new InvestigationWorkspaceInput(null,10001,"",null,null,null,"UTC",null);
        var access=new AccessDecision("admin",new(true,new HashSet<string>(),new HashSet<string>(),[],new Dictionary<string,JsonElement>()),[]);
        Assert.Equal(new long[]{1001,2001},await reader.CandidatesAsync(input,access,"investigations.workspace",ct));
        var metadata=await reader.MetadataAsync(input,[1001,1003,2001,2002],ct);
        Assert.Equal(new long[]{1001,2001},metadata.Select(r=>r["event_db_id"]!.GetValue<long>()));
        Assert.Equal("dc.example.test",metadata[0]["server"]!.ToString());
        Assert.Equal("operator",metadata[0]["subject_user_name"]!.ToString());
        Assert.Empty(await reader.CandidatesAsync(input with {Entity=10002},access,"investigations.workspace",ct));
        Assert.Empty(await reader.MetadataAsync(input with {Entity=10002},[1001,2001],ct));
        Assert.Single(await reader.CandidatesAsync(input with {From=DateTime.UtcNow.Date.AddDays(-1).ToString("O")},access,"investigations.workspace",ct));
        var legacy=new InvestigationEntityHistory(connections,new SecurityCandidateOwner(new SecurityCandidateStore(connections)),Config(fixture.Dsn("adlog_user"),false));
        Assert.Equal(new long[]{1001,2001},await legacy.CandidatesAsync(input,access,"investigations.workspace",ct));
        Assert.Equal(new long[]{1001,2001},(await legacy.MetadataAsync(input,[1001,2001],ct)).Select(r=>r["event_db_id"]!.GetValue<long>()));
        Assert.Empty(await legacy.CandidatesAsync(input with {Entity=10002},access,"investigations.workspace",ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
