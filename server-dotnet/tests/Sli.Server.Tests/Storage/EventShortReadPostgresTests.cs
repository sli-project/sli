using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class EventShortReadPostgresTests(ITestOutputHelper output)
{
    sealed class Host : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Sli.Server";
        public string ContentRootPath { get; set; } = PostCollectionPostgres.Repository();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
    sealed class Facts(AccessFacts facts) : IAccessFactsRepository {
        public Task<AccessFacts> LoadAsync(Principal principal,CancellationToken ct) => Task.FromResult(facts);
    }
    static IConfiguration Configuration(string dsn, bool? shortReads = null) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string,string?> { ["ConnectionStrings:Sli"]=dsn,
            ["Sli:Storage:ShortEventReads"]=shortReads?.ToString(), ["Sli:Storage:HistoryReadMode"]="disabled" }).Build();
    static EventListInput Input(string query) => EventListInput.Parse(new QueryCollection(QueryHelpers.ParseQuery("?"+query)),DateTimeOffset.UtcNow);
    static JsonObject[] Items(JsonObject page) => page["items"]!.AsArray().OfType<JsonObject>().ToArray();
    static CapabilityDecisionSet Caps(params (string Effect,object Scope)[] policies) => new CapabilityComposer().Compose(
        policies.Length==0 ? EventQueryEndpointTests.MakeFacts(owner:true) : new AccessFacts(false,"operator",[],[],
            policies.Select(p=>JsonSerializer.SerializeToElement(new { capability_key="events.view",effect=p.Effect,scope_json=p.Scope })).ToArray(),[],[],[],[]));

    internal static async Task<long> SeedRecorderAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into servers(id,domain_id,hostname,fqdn,role)
            select 1,id,'dc01','dc01.example.test','domain_controller' from domains where fqdn='example.test'
            returning domain_id
            """, db);
        return Assert.IsType<long>(await command.ExecuteScalarAsync(ct));
    }

    internal static (JsonObject Native,Direct4624Projection Projection,ShortEventRow Short) Event(long id,int kind,DateTimeOffset time,long domain,
        string user="synthetic-user",long server=1,bool sid=false,IReadOnlyDictionary<string,string>? fields=null)
    {
        XNamespace ns=EventXml.Namespace;
        var data=new Dictionary<string,string> { ["SubjectUserName"]="synthetic-admin",["TargetUserName"]=user,
            ["SubjectDomainName"]="example.test",["TargetDomainName"]="example.test",["IpAddress"]="192.0.2.10",
            ["SamAccountName"]=user,["DisplayName"]="Synthetic user",["UserPrincipalName"]=user+"@example.test",
            ["LogonType"]="3",["Status"]="0xC000006A",["SubStatus"]="0x0",["AuthenticationPackageName"]="NTLM" };
        if(fields is not null) foreach(var (key,value) in fields) data[key]=value;
        if(sid) data["TargetUserSid"]="S-1-5-21-100000001-200000002-300000003-1002";
        var xml=new XElement(ns+"Event",new XElement(ns+"System",
            new XElement(ns+"Provider",new XAttribute("Name","Microsoft-Windows-Security-Auditing")),
            new XElement(ns+"EventID",kind),new XElement(ns+"EventRecordID",id),
            new XElement(ns+"TimeCreated",new XAttribute("SystemTime",time.ToString("O",CultureInfo.InvariantCulture))),
            new XElement(ns+"Channel","Security"),new XElement(ns+"Computer","dc01.example.test")),
            new XElement(ns+"EventData",data.Select(p=>new XElement(ns+"Data",new XAttribute("Name",p.Key),p.Value))));
        var native=EventXml.Parse(xml.ToString(),"dc01.example.test","dc01.example.test","Security");
        var projection=Direct4624Projection.Create(native);
        return (native,projection,ShortEventRow.Create(id,domain,native,projection,server)!);
    }

    [Theory]
    [InlineData(null,true)] [InlineData(true,true)] [InlineData(false,true)]
    public void Retired_setting_cannot_select_the_removed_store(bool? setting,bool expected)
    {
        var config=Configuration("Host=synthetic;Database=synthetic;Username=synthetic",setting);
        Assert.Equal(expected,EventReadService.ShortReads(config));
    }

    [Theory]
    [InlineData("2026-10-30")] [InlineData("2026-10-30T00:00:00")] [InlineData("2026-10-30T00:00:00Z")]
    public void Daily_calendar_date_survives_json_and_host_timezone(string day)
    {
        var row=JsonNode.Parse(JsonSerializer.Serialize(new { event_id=4625,day }))!.AsObject();
        Assert.Equal("2026-10-30",EventReadService.ShortRow(row)["day"]!.ToString());
    }

    [Fact]
    public async Task Logins_are_individual_hot_events_and_daily_totals_under_application_role_without_clickhouse()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        long domain = await SeedRecorderAsync(db, ct);
        var config=new ConfigurationBuilder().AddConfiguration(Configuration(fixture.Dsn("adlog_user"),true))
            .AddInMemoryCollection(new Dictionary<string,string?> {
                ["Sli:Storage:HistoryReadMode"]="primary",
                ["Sli:Storage:HistoryClickHousePort"]="invalid"
            }).Build();
        var boundary=EventReadService.ShortBoundary(config);
        var old1=Event(800,4624,boundary.AddDays(-2).AddHours(1),domain,sid:true);
        var old2=Event(801,4624,boundary.AddDays(-2).AddHours(2),domain,sid:true);
        var hot=Event(802,4624,boundary.AddHours(1),domain,sid:true);
        var edge=Event(803,4624,boundary,domain,sid:true);
        var otherDomain=Event(804,4624,boundary.AddHours(2),domain+1,sid:true);
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",ct);
            await ShortEventWriter.WriteAsync(db,tx,[old1.Short,old2.Short,hot.Short,edge.Short,otherDomain.Short],ct);
            await ShortEventWriter.WriteAsync(db,tx,[old1.Short,old2.Short],ct);
            await tx.CommitAsync(ct);
        }
        await using(var command=new NpgsqlCommand("delete from event_hot where time_created_utc<@boundary",db)) {
            command.Parameters.AddWithValue("boundary",boundary); await command.ExecuteNonQueryAsync(ct);
        }
        await using var reader=new EventReadService(new PostgresConnectionFactory(config),config,new Host());
        string query="event_id=4624&domain_id="+domain+"&time_from="+Uri.EscapeDataString(boundary.AddDays(-3).ToString("O"))+
            "&time_to="+Uri.EscapeDataString(boundary.AddDays(1).ToString("O"));
        var rows=Items(await reader.ListAsync(Input(query),Caps(("allow",new { kind="domain",ids=new[]{domain} })),ct));
        Assert.Equal(3,rows.Length);
        var daily=Assert.Single(rows,r=>r["day"] is not null);
        Assert.Equal(2,daily["event_count"]!.GetValue<long>());
        Assert.Null(daily["event_db_id"]);
        Assert.Equal(new long[]{802,803},rows.Where(r=>r["day"] is null).Select(r=>r["event_db_id"]!.GetValue<long>()));
        Assert.All(rows,r=> {
            Assert.Equal("192.0.2.10",r["source"]!.ToString());
            Assert.Equal("dc01.example.test",r["computer"]!.ToString());
            Assert.Null(r["authentication_session"]); Assert.Null(r["duration_s"]); Assert.Null(r["logoff_time_utc"]);
        });
        var denied=await reader.ListAsync(Input(query),Caps(("allow",new { kind="domain",ids=new[]{domain+1} })),ct);
        Assert.Empty(Items(denied));
        // AD reports share the same domain/server-scoped login observations.
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var observations=await AdAuthenticationHistory.ReadAsync(app,domain,[1],boundary.AddDays(-3),boundary.AddDays(1),ct,
            config:config);
        Assert.Equal(3,observations.Events.Count); Assert.Empty(observations.Bounds); Assert.False(observations.Truncated);
        Assert.Equal(2,Assert.Single(observations.Events,r=>r["day"] is not null)["event_count"]!.GetValue<long>());
        var reports=new AdReportStore(new PostgresConnectionFactory(config),reader,config);
        Assert.True(await reports.HasSourceAsync("security",domain,ct));
        // PowerShell origin still needs an owner decision (4634 is no longer collected),
        // but its retained legacy report must not initialize the CH session reader.
        var power=await reports.ReadAsync(new("powershell",false,false,domain,new(boundary.AddDays(-3),boundary.AddDays(1)),50,new(),null),false,ct);
        Assert.Empty(power["items"]!.AsArray());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Writer_rows_feed_hot_details_daily_filters_and_stable_pages_without_legacy_events()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        long domain = await SeedRecorderAsync(db, ct);
        var config=Configuration(fixture.Pg.ConnectionString);
        var boundary=EventReadService.ShortBoundary(config);
        var hot=Event(10,4720,boundary.AddDays(2).AddHours(3),domain);
        var login=Event(11,4625,boundary.AddDays(2).AddHours(4),domain);
        // Same UTC day/time, distinct grouping dimensions exercise the group key cursor.
        var old1=Event(20,4625,boundary.AddDays(-2).AddHours(3),domain);
        var old2=Event(21,4625,boundary.AddDays(-2).AddHours(4),domain);
        var old3=Event(22,4625,boundary.AddDays(-2).AddHours(5),domain,"synthetic-other",sid:true);
        var edge=Event(23,4625,boundary,domain);
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",ct);
            await ShortEventWriter.WriteAsync(db,tx,[hot.Short,login.Short,old1.Short,old2.Short,old3.Short,edge.Short],ct);
            await ShortEventWriter.WriteAsync(db,tx,[old1.Short,old2.Short],ct); // replay must not inflate daily totals
            await tx.CommitAsync(ct);
        }
        // Even a leftover rollback setting cannot route this reader to old tables.
        var retiredConfig=Configuration(fixture.Pg.ConnectionString,false);
        await using var reader=new EventReadService(new PostgresConnectionFactory(retiredConfig),retiredConfig,new Host());
        string window="time_from="+Uri.EscapeDataString(boundary.ToString("O"));
        var after=Items(await reader.ListAsync(Input(window+"&limit=50"),Caps(),ct));
        Assert.Equal(new long[]{11,10,23},after.Select(r=>r["event_db_id"]!.GetValue<long>()));
        Assert.All(after,r=>Assert.Equal("Security",r["channel"]!.ToString()));
        var resources=await reader.ResourcesAsync(10,ct);
        Assert.Contains(resources,r=>r.Kind=="server" && r.Id==1);
        var details=await reader.DetailsAsync([10,11],true,async (id,token)=>(await reader.ResourcesAsync(id,token)).Count>0,ct);
        foreach(var row in new[]{hot,login}) {
            var current=details[row.Short.EventId];
            Assert.Equal(row.Short.Kind,current["event_id"]!.GetValue<int>());
            Assert.Equal(row.Short.Time,EventReadService.Stamp(current["time_created_utc"]).UtcDateTime);
            Assert.Equal("dc01",current["server"]!.ToString());
            foreach(var (key,value) in row.Short.Fields) Assert.Equal(value,current["event_data"]![key]?.ToString());
            Assert.Null(current["xml"]); Assert.Null(current["message_sample"]); Assert.Null(current["raw_log_file_id"]);
        }
        // The list and card must work on the schema after retirement of the former event store.
        await using (var retired = new NpgsqlCommand("select to_regclass('public.events_v2_core') is null", db))
            Assert.Equal(true, await retired.ExecuteScalarAsync(ct));
        await using(var remove=new NpgsqlCommand("delete from event_hot where time_created_utc<@boundary",db)) {
            remove.Parameters.AddWithValue("boundary",boundary); await remove.ExecuteNonQueryAsync(ct);
        }
        Assert.Equal(3,Items(await reader.ListAsync(Input(window+"&limit=50"),Caps(),ct)).Length);
        Assert.Single(await reader.DetailsAsync([10],true,(_,_)=>Task.FromResult(true),ct));
        Assert.Empty(await reader.DetailsAsync([10],true,(_,_)=>Task.FromResult(false),ct));
        Assert.Empty(await reader.ResourcesAsync(20,ct)); // daily totals have no event card

        string cold="time_from="+Uri.EscapeDataString(boundary.AddDays(-3).ToString("O"))+"&time_to="+Uri.EscapeDataString(boundary.ToString("O"));
        var daily=Items(await reader.ListAsync(Input(cold+"&limit=50"),Caps(),ct));
        Assert.Equal(2,daily.Length); Assert.Equal(3,daily.Sum(r=>r["event_count"]!.GetValue<long>()));
        Assert.All(daily,r=>Assert.Null(r["event_db_id"]));
        Assert.Equal(old1.Short.Time,EventReadService.Stamp(daily.Single(r=>r["event_count"]!.GetValue<long>()==2)["first_seen_utc"]).UtcDateTime);
        foreach(string filter in new[]{"event_id=4625","channel=Security","provider=Microsoft-Windows-Security-Auditing","q=192.0.2.10","server=dc01"})
            Assert.Equal(2,Items(await reader.ListAsync(Input(cold+"&"+filter),Caps(),ct)).Length);
        Assert.Single(Items(await reader.ListAsync(Input(cold+"&account=synthetic-user"),Caps(),ct)));
        Assert.Empty(Items(await reader.ListAsync(Input(cold+"&q=synthetic-absent"),Caps(),ct)));
        foreach(string order in new[]{"asc","desc"}) {
            var first=await reader.ListAsync(Input(cold+"&limit=1&order="+order),Caps(),ct);
            Assert.True(first["has_more"]!.GetValue<bool>());
            var next=await reader.ListAsync(Input(cold+"&limit=1&order="+order+"&cursor="+first["next_cursor"]),Caps(),ct);
            Assert.False(next["has_more"]!.GetValue<bool>());
            Assert.NotEqual(Items(first)[0]["actor"]!.ToString(),Items(next)[0]["actor"]!.ToString());
        }
        var denied=Caps(("allow",new {kind="all"}),("deny",new {kind="server",ids=new[]{1}}));
        Assert.Empty(Items(await reader.ListAsync(Input(cold),denied,ct)));
        var scoped=Caps(("allow",new {kind="domain",ids=new[]{domain}}));
        Assert.Equal(2,Items(await reader.ListAsync(Input(cold),scoped,ct)).Length);
        var other=Caps(("allow",new {kind="domain",ids=new[]{domain+1}}));
        Assert.Empty(Items(await reader.ListAsync(Input(cold),other,ct)));

        // The journal's actual published report path also reads only the new tables.
        await fixture.SeedOwnerAsync(ct);
        long ownerId;
        await using(var owner=new NpgsqlCommand("select id from auth_users where username='platform-owner'",db)) ownerId=Convert.ToInt64(await owner.ExecuteScalarAsync(ct));
        var principal=new Principal("session",ownerId,"admin");
        var facts=await new AccessFactsRepository(new PostgresConnectionFactory(config)).LoadAsync(principal,ct);
        Assert.True(facts.IsOwner);
        var capabilities=new CapabilityComposer().Compose(facts);
        var access=new ReportEligibility().Compose(facts,capabilities);
        var projection=JsonSerializer.SerializeToNode(AccessReadProjection.Compose(principal,facts,capabilities,access,false))!.AsObject();
        var caller=new ReportCaller(principal,facts,capabilities,projection);
        // Reporting always reads the new layer, even with an old switch value.
        var runner=new ReportRunner(new ReportDatabase(new PostgresConnectionFactory(config)),Configuration(fixture.Pg.ConnectionString,false));
        var period=new Dictionary<string,string> { ["time_from"]=boundary.AddDays(-3).ToString("O"),["time_to"]=boundary.ToString("O") };
        var page=await runner.ExecuteAsync(caller,"events.explorer",1,null,"view",period,ct);
        Assert.Single(Items(page)); Assert.True(page["has_more"]!.GetValue<bool>());
        Assert.Equal(boundary.AddDays(-2).ToString("yyyy-MM-dd",CultureInfo.InvariantCulture),Items(page)[0]["day"]!.ToString());
        Assert.Null(Items(page)[0]["id"]);
        period["cursor"]=page["next_cursor"]!.ToString();
        var page2=await runner.ExecuteAsync(caller,"events.explorer",1,null,"view",period,ct);
        Assert.False(page2["has_more"]!.GetValue<bool>());
        Assert.NotEqual(Items(page)[0]["actor"]!.ToString(),Items(page2)[0]["actor"]!.ToString());
        var definitions=new ReportDefinitionRegistry();
        var definition=definitions.Get("events.journal")!;
        var parameters=new JsonObject { ["period"]=new JsonObject { ["from_utc"]=period["time_from"],["to_utc"]=period["time_to"] } };
        var context=new ReportQueryContext(definition,access,principal,parameters,new(null,50,"UTC",null,"desc",null),ReportScope.All,null,"view",_=>true,access.Reports.Single(r=>r.ReportKey=="events.explorer").Grants);
        var repository=new Facts(facts); var semantic=new SemanticDatabase(new PostgresConnectionFactory(config));
        var journal=new EventsJournalReader(runner,repository,semantic,new BuiltinReportExports(runner,repository,null!,semantic));
        var journalPage=await journal.QueryAsync(context,ct);
        Assert.Equal(2,Items(journalPage).Length);
        Assert.Equal(3,Items(journalPage).Sum(r=>r["event_count"]!.GetValue<long>()));
        Assert.All(Items(journalPage),r=>Assert.NotEqual("неизвестный тип события",r["title_text"]!.ToString()));
        Assert.Contains(Items(journalPage),r=>r["participant"]?.ToString()=="S-1-5-21-100000001-200000002-300000003-1002");

        await using(var privilege=new NpgsqlCommand("select has_table_privilege('adlog_user','event_hot','SELECT'),has_table_privilege('adlog_user','event_cold_daily','SELECT')",db)) {
            await using var result=await privilege.ExecuteReaderAsync(ct); Assert.True(await result.ReadAsync(ct));
            output.WriteLine($"Installed application SELECT hot/daily: {result.GetBoolean(0)}/{result.GetBoolean(1)}. Reader behavior above uses the isolated fixture administrator; no grants were added.");
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
