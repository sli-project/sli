using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class SecurityChainsShortReadsPostgresTests
{
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    static readonly DateTimeOffset Start = new(DateTime.UtcNow.Date, TimeSpan.Zero);
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static IConfiguration Config(string dsn, bool shortReads, bool brokenHistory = false) => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
        ["ConnectionStrings:Sli"] = dsn, ["Sli:Storage:ShortEventReads"] = shortReads.ToString(),
        ["Sli:Storage:HistoryReadMode"] = brokenHistory ? "primary" : "disabled",
        ["Sli:Storage:HistoryClickHousePort"] = "invalid"
    }).Build();
    static AccessDecision Access(long domain = 1, bool fields = true, bool export = true) => new("viewer",
        new(false,new HashSet<string> { "events.view" },new HashSet<string>(),[],new Dictionary<string,JsonElement>()),
        [new("security.events.chains",true,[new(JsonSerializer.SerializeToElement(new { kind="domain",ids=new[] { domain } }),
            new HashSet<string>(fields ? ["security","technical","raw_evidence"] : ["security"]),
            new HashSet<string>(export ? ["view","export"] : ["view"]),1,1)])]);
    static ReportQueryContext Context(string tab, DateTimeOffset? start = null, long domain = 1, AccessDecision? access = null, string action = "view") => new(
        new ReportDefinitionRegistry().Get("security.events.chains")!, access ?? Access(),new Principal("user",1,"viewer"),
        new JsonObject { ["domain"] = domain, ["period"] = new JsonObject { ["from_utc"] = (start ?? Start).ToString("O"),
            ["to_utc"] = (start ?? Start).AddHours(1).ToString("O") }, ["min_repeats"] = 2, ["failure_window"] = 15,
            ["revocation_window"] = 60 },new(null,100,"UTC",null,"asc",tab),ReportScope.All,[domain],action,_=>true,[]);
    sealed class Domains : IAdReportStore
    {
        public Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>([]);
        public Task<bool> HasSourceAsync(string kind,long domain,CancellationToken ct) => throw new InvalidOperationException("unexpected main report read");
        public Task<JsonObject> ReadAsync(AdReportRequest request,bool sensitive,CancellationToken ct) => throw new InvalidOperationException("unexpected main report read");
    }
    static SecurityEventsReader Reader(IConfiguration config)
    {
        var db = new SemanticDatabase(new PostgresConnectionFactory(config));
        return new(new Domains(),db,new BuiltinReportExports(null!,null!,new Domains(),db,config),config);
    }
    static JsonArray Rows(JsonObject result,string tab) => result["collections"]![tab.Replace('-','_')]!.AsArray();
    internal static ShortEventRow Row(long id,int code,int minute,DateTimeOffset? start = null,long domain = 1, Dictionary<string,string>? extra = null)
    {
        var data = new Dictionary<string,string> { ["TargetUserSid"] = Sid, ["TargetUserName"] = "account-a",
            ["SubjectUserSid"] = Sid, ["SubjectUserName"] = "operator", ["SubjectDomainName"] = "example.test" };
        if (code == 7045) { data.Remove("SubjectUserSid"); data.Remove("SubjectUserName"); data.Remove("SubjectDomainName"); }
        foreach (var (key,value) in extra ?? []) data[key] = value;
        XNamespace ns = EventXml.Namespace;
        string channel = code == 7045 ? "System" : "Security", provider = code == 7045 ? "Service Control Manager" : "Microsoft-Windows-Security-Auditing";
        var xml = new XElement(ns+"Event",new XElement(ns+"System",new XElement(ns+"Provider",new XAttribute("Name",provider)),
            new XElement(ns+"EventID",code),new XElement(ns+"EventRecordID",id),new XElement(ns+"TimeCreated",new XAttribute("SystemTime",(start ?? Start).AddMinutes(minute).ToString("O"))),
            new XElement(ns+"Channel",channel),new XElement(ns+"Computer","dc.example.test")),
            new XElement(ns+"EventData",data.Select(d=>new XElement(ns+"Data",new XAttribute("Name",d.Key),d.Value))));
        var native = EventXml.Parse(xml.ToString(),"dc.example.test","dc.example.test",channel);
        return ShortEventRow.Create(id,domain,native,Direct4624Projection.Create(native),domain == 1 ? 900001 : 900002)!;
    }
    static async Task Write(SqlPostgresFixture fixture, ShortEventRow[] rows)
    {
        await using var db = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await db.OpenAsync(Ct);
        await using var tx = await db.BeginTransactionAsync(Ct);
        await PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",Ct);
        await ShortEventWriter.WriteAsync(db,tx,rows,Ct); await tx.CommitAsync(Ct);
    }
    [Fact]
    public async Task Three_tabs_read_only_new_rows_under_app_role_even_with_old_switch_and_broken_history()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(owner,"""
            insert into domains(id,forest_id,domain_sid,fqdn) select 2,forest_id,'S-1-5-21-100000001-200000002-300000003','other.example.test' from domains where id=1;
            insert into servers(id,domain_id,hostname,role,is_active) values(900001,1,'dc.example.test','domain_controller',true),(900002,2,'dc.example.test','domain_controller',true);
            insert into log_sources(name) values('synthetic');
            insert into storage_v2_channel(value) values('Security'),('System') on conflict do nothing;
            insert into storage_v2_provider(value) values('Microsoft-Windows-Security-Auditing'),('Service Control Manager') on conflict do nothing;
            insert into storage_v2_computer(value) values('dc.example.test') on conflict do nothing;
            """,Ct);
        const string task = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Principals><Principal><UserId>synthetic-run-as</UserId></Principal></Principals><Actions><Exec><Command>C:/synthetic/task.exe</Command><Arguments>--check</Arguments></Exec></Actions></Task>";
        ShortEventRow[] rows = [Row(1,4625,0,extra:new() { ["Status"]="0xC000006D",["SubStatus"]="0xC000006A",["IpAddress"]="192.0.2.1" }),
            Row(2,4740,1,extra:new() { ["CallerComputerName"]="client.example.test" }),Row(3,4767,2),Row(4,4740,5),
            Row(5,4725,10),Row(6,4624,12,extra:new() { ["LogonType"]="3" }),Row(7,4722,13),Row(8,4726,20),Row(9,4624,22,extra:new() { ["LogonType"]="3" }),
            Row(10,4698,25,extra:new() { ["TaskName"]="=synthetic-task",["TaskContent"]=task }),
            Row(11,4697,30,extra:new() { ["ServiceName"]="synthetic-service",["ServiceFileName"]="C:/synthetic/service.exe",["ServiceAccount"]="synthetic-run-as",["ServiceStartType"]="2" }),
            Row(12,7045,30,extra:new() { ["ServiceName"]="synthetic-service",["ImagePath"]="C:/synthetic/service.exe",["AccountName"]="synthetic-run-as",["StartType"]="2" })];
        await Write(fixture,rows);
        await Write(fixture,rows.Select(r=>r with { EventId=r.EventId+100,DomainId=2,Method=r.Method.Replace("900001","900002",StringComparison.Ordinal) }).ToArray());
        var current = Reader(Config(fixture.Dsn("adlog_user"),false,brokenHistory:true));
        var expected = new Dictionary<string,JsonArray>();
        foreach (string tab in new[] { "lockout-recurring","account-revocation","persistence-changes" })
        {
            expected[tab] = Rows(await current.QueryAsync(Context(tab),Ct),tab);
            Assert.NotEmpty(expected[tab]);
            var actual = Rows(await current.QueryAsync(Context(tab),Ct),tab);
            Assert.True(JsonNode.DeepEquals(expected[tab],actual),tab+"\n"+expected[tab].ToJsonString()+"\n"+actual.ToJsonString());
            Assert.True(JsonNode.DeepEquals(actual,Rows(await current.QueryAsync(Context(tab,action:"export"),Ct),tab)));
            foreach (var access in new[] { Access(2),Access(fields:false) })
                Assert.Equal("denied",(await current.QueryAsync(Context(tab,access:access),Ct))["state"]!.ToString());
            Assert.Equal("denied",(await current.QueryAsync(Context(tab,domain:2),Ct))["state"]!.ToString());
            if (tab == "persistence-changes")
                await Assert.ThrowsAsync<ReportRequestException>(()=>current.QueryAsync(Context(tab,access:Access(export:false),action:"export"),Ct));
            else Assert.Equal("denied",(await current.QueryAsync(Context(tab,access:Access(export:false),action:"export"),Ct))["state"]!.ToString());
        }
        // These tabs are hidden by the beta report definition. Exercise the
        // shared CSV encoder directly without reintroducing screen declarations.
        JsonObject[] columns = [new() { ["key"]="object",["label"]="object" },new() { ["key"]="action",["label"]="action" }];
        string csv = ReportCsv.FromColumns(columns,Rows(await current.QueryAsync(Context("persistence-changes"),Ct),"persistence-changes").OfType<JsonObject>());
        Assert.Equal(ReportCsv.FromColumns(columns,expected["persistence-changes"].OfType<JsonObject>()),csv);
        Assert.Contains("'=synthetic-task",csv);
        await using (var retired = new NpgsqlCommand("""
            select to_regclass('public.event_facts_v2') is null and to_regclass('public.events_v2_core') is null
            """, owner))
            Assert.Equal(true, await retired.ExecuteScalarAsync(Ct));
        await PostCollectionPostgres.Sql(owner,"delete from normalized_events",Ct);
        foreach (string tab in expected.Keys)
            Assert.True(JsonNode.DeepEquals(expected[tab],Rows(await current.QueryAsync(Context(tab),Ct),tab)),tab);
        // Rare facts remain individual after hot retention. Authentication is a
        // daily group: preserve count and bounds, never invent an exact event.
        var old = Start.AddDays(-20);
        await Write(fixture,rows.Select(r=>r with { EventId=r.EventId+200,Time=r.Time.AddDays(-20) }).ToArray());
        await PostCollectionPostgres.Sql(owner,"delete from event_hot where time_created_utc < current_date-14",Ct);
        var locks = Rows(await current.QueryAsync(Context("lockout-recurring",old),Ct),"lockout-recurring");
        Assert.Equal(2,Assert.Single(locks)!["lockouts"]!.GetValue<int>());
        Assert.Equal("partial",locks[0]!["matching"]!.ToString());
        Assert.Equal(2,Rows(await current.QueryAsync(Context("persistence-changes",old),Ct),"persistence-changes").Count);
        var daily = Rows(await current.QueryAsync(Context("account-revocation",old),Ct),"account-revocation");
        Assert.NotEmpty(daily);
        Assert.All(daily,row=> { Assert.Equal("daily_summary",row!["read_representation"]!.ToString()); Assert.Null(row["activity_event"]); Assert.Null(row["activity_at"]); Assert.Null(row["delay_seconds"]); });
        Assert.All(daily,row=>Assert.Equal(2,row!["event_count"]!.GetValue<long>()));
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }
}
