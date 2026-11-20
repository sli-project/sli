using System.Reflection;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Reports.SecurityCandidates;
using Sli.Server.Workspace;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Entities;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.EventReports;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class EntityShortReadsPostgresTests(ITestOutputHelper output)
{
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    static readonly DateTime Now = DateTime.UtcNow.Date.AddHours(1);
    static IConfiguration Config(string dsn) => new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string,string?> { ["ConnectionStrings:Sli"] = dsn }).Build();

    internal static ShortEventRow Row(long id, int kind = 4625, DateTime? at = null, long domain = 1)
    {
        XNamespace ns = EventXml.Namespace;
        var xml = new XElement(ns+"Event", new XElement(ns+"System",
            new XElement(ns+"Provider",new XAttribute("Name","Microsoft-Windows-Security-Auditing")),
            new XElement(ns+"EventID",kind),new XElement(ns+"EventRecordID",id),
            new XElement(ns+"TimeCreated",new XAttribute("SystemTime",(at ?? Now).ToString("O"))),
            new XElement(ns+"Channel","Security"),new XElement(ns+"Computer","dc.example.test")),
            new XElement(ns+"EventData",new Dictionary<string,string> {
                ["SubjectUserSid"]=Sid,["SubjectUserName"]="operator",["SubjectDomainName"]="example.test",
                ["TargetUserSid"]="S-1-5-21-100000001-200000002-300000003-"+(kind==4728 ? "1002" : kind==4741 ? "1004" : "1008"),
                ["TargetUserName"]=kind == 4728 ? "synthetic-group" : kind==4741 ? "synthetic-computer$" : "synthetic-user",["TargetDomainName"]="example.test",
                ["MemberSid"]="S-1-5-21-100000001-200000002-300000003-1003",["MemberName"]="synthetic-member",
                ["TargetServerName"]="target.example.test",["ServiceName"]="target.example.test",
                ["IpAddress"]="192.0.2.1"
            }.Select(p => new XElement(ns+"Data",new XAttribute("Name",p.Key),p.Value))));
        var native = EventXml.Parse(xml.ToString(),"dc.example.test","dc.example.test","Security");
        return ShortEventRow.Create(id,domain,native,Direct4624Projection.Create(native),900001)!;
    }

    internal static async Task Write(SqlPostgresFixture fixture, IReadOnlyList<ShortEventRow> rows, CancellationToken ct)
    {
        await using var db = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await db.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",ct);
        await ShortEventWriter.WriteAsync(db,tx,rows,ct); await tx.CommitAsync(ct);
    }

    [Fact]
    public async Task Database_with_migration_338_accepts_339()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:338);
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/339_short_entity_reads.sql"),null,ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await using var cmd = new NpgsqlCommand("select count(*) from schema_migrations where version in (338,339)",db);
        Assert.Equal(2L,await cmd.ExecuteScalarAsync(ct));
        // Test the historical rollback on its own installed version. The current
        // packet writer requires 349 and belongs to the application test below.
        await PostCollectionPostgres.Sql(db,"""
            select public.create_event_storage_partitions(current_date,current_date);
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields)
                select n,now(),4625,n,'dc.example.test','{}','{}','{}' from generate_series(1,2) n;
            """,ct);
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/339_short_entity_reads.sql");
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        await using(var retained=new NpgsqlCommand("select count(*) from event_hot",db)) Assert.Equal(2L,await retained.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await fixture.AssertNoSqlErrorsAsync(ct);

    }

    [Fact]
    public async Task Application_reader_finds_writer_events_without_legacy_links_and_keeps_domain_boundary()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db,"""
            insert into servers(id,domain_id,hostname,role,is_active) values(900001,1,'dc.example.test','domain_controller',true);
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select n,t.id,'sid:S-1-5-21-100000001-200000002-300000003-1001','synthetic',d,sha256(n::text::bytea)
                from (values(10001,1)) e(n,d) cross join storage_v2_entity_type t where t.value='ad_user';
            """,ct);
        await Write(fixture,[Row(1001),Row(1002,domain:2)],ct);
        using var host = new HostBuilder().ConfigureAppConfiguration(c => c.AddConfiguration(Config(fixture.Dsn("adlog_user")))).Build();
        await using var store = new EntityReadStore(new PostgresConnectionFactory(Config(fixture.Dsn("adlog_user"))));
        var reader = new EntityReader(store,new EntityDirectoryReader(store,host.Services.GetRequiredService<IHostEnvironment>()),host.Services);
        var candidates = typeof(EntityReader).GetMethod("EvidenceCandidates",BindingFlags.Instance|BindingFlags.NonPublic)!
            .CreateDelegate<Func<int,EntityReadOptions,int,CancellationToken,Task<JsonArray>>>(reader);
        var rows = await candidates(10001,new(),20,ct);
        Assert.Equal(1001,EntityReader.Number(Assert.Single(rows)!.AsObject(),"event_db_id"));
        // Future partitions inherit lookup indexes without an operations step.
        await store.DisposeAsync();
        var future = Now.AddDays(60);
        await Write(fixture,[Row(1003,at:future)],ct);
        await using(var plan = new NpgsqlCommand($"""
            set enable_seqscan=off;
            explain (costs off) select event_id from event_hot_d{future:yyyyMMdd}
            where public.short_event_entity_keys339(event_kind,actor,target,source,computer,method,fields) && array[lower('sid:{Sid}')]
            """,db)) {
            var lines = new List<string>(); await using var read = await plan.ExecuteReaderAsync(ct);
            while(await read.ReadAsync(ct)) lines.Add(read.GetString(0));
            Assert.Contains(lines,l=>l.Contains("Bitmap Index Scan",StringComparison.Ordinal));
            output.WriteLine("Future partition indexed lookup (seqscan disabled for tiny fixture):\n"+string.Join('\n',lines));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    static EntityReader Reader(IEntityReadStore store,IServiceProvider services) =>
        new(store,new EntityDirectoryReader(store,services.GetRequiredService<IHostEnvironment>()),services);
    static CapabilityDecisionSet Caps => new(false,new HashSet<string> { "evidence.exact","field.security","field.technical" },new HashSet<string>(),[],new Dictionary<string,JsonElement>());

    [Fact]
    public async Task Entity_object_security_and_dashboard_reads_keep_events_roles_access_and_daily_groups()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner,"""
            insert into servers(id,domain_id,hostname,role,is_active) values(900001,1,'dc.example.test','domain_controller',true);
            insert into storage_v2_entity_type(value) values('ad_user'),('ad_group'),('ad_computer'),('asset'),('ip_address') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,server_id,source_core_sha256)
                select n,t.id,k,'synthetic',1,s,sha256(n::text::bytea) from (values
                  (10001,'ad_user','sid:S-1-5-21-100000001-200000002-300000003-1001',null::bigint),
                  (10003,'ad_group','sid:S-1-5-21-100000001-200000002-300000003-1002',null::bigint),
                  (10004,'ad_computer','sid:S-1-5-21-100000001-200000002-300000003-1004',null::bigint),
                  (10005,'asset','server:dc.example.test',900001::bigint),
                  (10006,'ad_user','sid:S-1-5-21-100000001-200000002-300000003-1003',null::bigint)) e(n,type,k,s)
                join storage_v2_entity_type t on t.value=e.type;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,source_core_sha256)
                select 10010,id,'ip:192.0.2.1','synthetic source',sha256('source'::bytea) from storage_v2_entity_type where value='ip_address';
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select 10011,id,'sam:example:foreign-operator','foreign actor',2,sha256('foreign'::bytea) from storage_v2_entity_type where value='ad_user';
            insert into entity_details_v2(entity_id,attributes_json,source_details_sha256)
                values(10011,'{"identity_aliases":["sid:S-1-5-21-100000001-200000002-300000003-1001"]}'::jsonb,sha256('foreign-alias'::bytea));
            """,ct);
        ShortEventRow[] hot = [Row(1001),Row(1003,4728,Now.AddHours(-1)),Row(1004,4741,Now.AddHours(-2))];
        await Write(fixture,hot,ct);
        await using(var retired=new NpgsqlCommand("""
            select count(*) from unnest(array['public.events_v2_core','public.raw_log_files','public.event_entity_link_blocks_v2']) relation
            where to_regclass(relation) is not null
            """,owner)) Assert.Equal(0L,await retired.ExecuteScalarAsync(ct));
        using var eventHost=new HostBuilder().UseContentRoot(PostCollectionPostgres.Repository()).Build();
        var eventEnvironment=eventHost.Services.GetRequiredService<IHostEnvironment>();
        var entityConfig=Config(fixture.Dsn("adlog_user"));
        await using var newEvents=new EventReadService(new PostgresConnectionFactory(entityConfig),entityConfig,eventEnvironment);
        var eventEntities=new Dictionary<long,JsonArray>();
        foreach(long eventId in new long[]{1001,1003,1004}) {
            var data=await newEvents.EntitiesAsync(eventId,ct);
            Assert.True(data["event_found"]!.GetValue<bool>());
            eventEntities[eventId]=data["items"]!.AsArray();
            Assert.Contains(eventEntities[eventId],e=>e!["id"]!.ToString()=="10001" && e["link_role"]!.ToString()=="actor");
            Assert.Contains(eventEntities[eventId],e=>e!["id"]!.ToString()=="10005" && e["link_role"]!.ToString()=="recorder");
            Assert.DoesNotContain(eventEntities[eventId],e=>e!["id"]!.ToString()=="10011");
        }
        Assert.Contains(eventEntities[1003],e=>e!["id"]!.ToString()=="10003" && e["link_role"]!.ToString()=="affected");
        Assert.Contains(eventEntities[1003],e=>e!["id"]!.ToString()=="10006" && e["link_role"]!.ToString()=="affected");
        Assert.Contains(eventEntities[1004],e=>e!["id"]!.ToString()=="10004" && e["link_role"]!.ToString()=="target");
        using var newHost = new HostBuilder().ConfigureAppConfiguration(c=>c.AddConfiguration(entityConfig))
            .ConfigureServices(s=>s.AddSingleton<IEventReadService>(newEvents)).Build();
        var actionScope=JsonSerializer.SerializeToElement(new { kind="domain",ids=new[]{1} });
        var actionCaps=Caps with { Capabilities=Caps.Capabilities.Concat(new[]{"events.view","semantic.review"}).ToHashSet() };
        AccessDecision access=new("operator",actionCaps,[new("security.events.chains",true,
            [new(actionScope,new HashSet<string>{"security","technical","raw_evidence"},new HashSet<string>{"view"},1,1)])]);
        var options=new EntityReadOptions(100,From:Now.AddDays(-1).ToString("O"),To:Now.AddDays(1).ToString("O"));
        async Task<string[]> Actions(EntityReader reader,int id,long domain=1,AccessDecision? decision=null) {
            var payload=new JsonObject();
            await reader.Interpretation(payload,new JsonObject { ["id"]=id,["domain_id"]=domain },options,
                (decision??access).Capabilities,decision??access,ct);
            return payload["security_actions"]!.AsArray().Select(a=>a!["event_db_id"]+":"+a["event_family"]).ToArray();
        }
        async Task<long[]> RelationEvents(int id,long domain=1) {
            var relations=new SemanticRelations(new SemanticDatabase(new PostgresConnectionFactory(entityConfig)),configuration:entityConfig);
            var values=new List<object?>();
            string Param(object? value) { values.Add(value);return "@p"+(values.Count-1); }
            string filter=(string)typeof(SemanticRelations).GetMethod("SecurityPredicate",BindingFlags.NonPublic|BindingFlags.Static|BindingFlags.Instance)!
                .Invoke(relations,[new JsonObject { ["entity_id"]=id },(Func<object?,string>)Param])!;
            await using var db=await fixture.Pg.OpenAsync(ct,"adlog_user");
            await using var command=new NpgsqlCommand("with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") "+
                "select ev.id from short_events ev where ev.domain_id=@domain "+filter+" order by ev.id",db);
            command.Parameters.AddWithValue("domain",domain);
            command.Parameters.AddWithValue("boundary",Now.Date.AddDays(-14));
            for(int i=0;i<values.Count;i++) command.Parameters.AddWithValue("p"+i,values[i]!);
            var ids=new List<long>();await using var rows=await command.ExecuteReaderAsync(ct);
            while(await rows.ReadAsync(ct)) ids.Add(rows.GetInt64(0));return ids.ToArray();
        }
        Assert.Equal(new long[]{1001,1003,1004},await RelationEvents(10001));
        Assert.Empty(await RelationEvents(10001,2));
        await using(var newStore = new EntityReadStore(new PostgresConnectionFactory(entityConfig))) {
            var current=Reader(newStore,newHost.Services);
            Assert.Equal(new[]{"1001:authentication","1003:group_membership"},await Actions(current,10001));
            Assert.Equal(new[]{"1003:group_membership"},await Actions(current,10003));
            Assert.Empty(await Actions(current,10001,2));
            var denied=actionCaps with { Policies=[new("events.view","deny",true,false,actionScope)] };
            Assert.Empty(await Actions(current,10001,decision:access with { Capabilities=denied }));
            foreach(var (id,role,ids) in new (int,string,long[])[] {
                (10001,"actor",[1001,1003,1004]),(10003,"affected",[1003]),(10004,"target",[1004]),
                (10005,"recorder",[1001,1003,1004]),(10006,"affected",[1003]) }) {
                var preflight=(await current.Preflight(id,ct))!;
                var after=(await current.Detail(preflight,new(),Caps,true,ct))!["events"]!.AsArray();
                Assert.Equal(ids,after.Select(e=>e!["event_db_id"]!.GetValue<long>()));
                Assert.All(after,e=>Assert.Equal(role,e!["link_role"]!.ToString()));
            }
            var actor=(await current.Preflight(10001,ct))!;
            var restricted=Caps with { Policies=[new("evidence.exact","deny",true,false,JsonSerializer.SerializeToElement(new { kind="domain",ids=new[]{1} }))] };
            Assert.Empty((await current.Detail(actor,new(),restricted,true,ct))!["events"]!.AsArray());
            foreach(var scope in new[] { new { kind="server",ids=new[]{900001} },new { kind="domain",ids=new[]{1} } }) {
                restricted=Caps with { Policies=[new("evidence.exact","deny",true,false,JsonSerializer.SerializeToElement(scope))] };
                Assert.Empty((await current.Detail(actor,new(),restricted,true,ct))!["events"]!.AsArray());
            }
            restricted=Caps with { Policies=[new("evidence.exact","deny",true,false,JsonSerializer.SerializeToElement(new { kind="channel",values=new[]{"Security"} }))] };
            Assert.Empty((await current.Detail(actor,new(),restricted,true,ct))!["events"]!.AsArray());
            var metadata=Caps with { Capabilities=new HashSet<string> { "evidence.exact" } };
            var metadataEvents=(await current.Detail(actor,new(),metadata,true,ct))!["events"]!.AsArray();
            Assert.NotEmpty(metadataEvents);Assert.All(metadataEvents,e=> {
                Assert.Null(e!["event_id"]);Assert.Null(e["actor"]);Assert.Null(e["provider_name"]);Assert.Null(e["time_utc"]);
            });
            var facade=(await current.Object(actor,"ad_user",20,Caps,ct))!;
            Assert.NotEmpty(facade["provenance"]!.AsArray());
            var candidates=new SecurityCandidateStore(new PostgresConnectionFactory(Config(fixture.Dsn("adlog_user"))));
            Assert.Equal(new long[]{1001,1003},await candidates.CandidatesAsync(10001,1,new(Now.AddDays(-1)),new(Now.AddDays(1)),20,ct));
            Assert.Empty(await candidates.CandidatesAsync(10001,2,new(Now.AddDays(-1)),new(Now.AddDays(1)),20,ct));
        }
        // The same roles must resolve for a retained fact after the hot window.
        var old=Now.AddDays(-20);
        await Write(fixture,[Row(2001,4728,old),Row(2002,at:old),Row(2003,at:old),Row(2004,at:old) with { Source="192.0.2.2" }],ct);
        var coldEntities=await newEvents.EntitiesAsync(2001,ct);
        Assert.True(coldEntities["event_found"]!.GetValue<bool>());
        Assert.True(JsonNode.DeepEquals(eventEntities[1003],coldEntities["items"]));
        Assert.Contains(await newEvents.ResourcesAsync(2001,ct),r=>r.Kind=="domain" && r.Id==1);
        Assert.False((await newEvents.EntitiesAsync(2002,ct))["event_found"]!.GetValue<bool>());
        Assert.False((await newEvents.EntitiesAsync(long.MaxValue,ct))["event_found"]!.GetValue<bool>());
        await using(var store=new EntityReadStore(new PostgresConnectionFactory(entityConfig))) {
            var payload=new JsonObject();
            await Reader(store,newHost.Services).Interpretation(payload,new JsonObject { ["id"]=10003,["domain_id"]=1 },
                options with { From=old.AddDays(-1).ToString("O") },actionCaps,access,ct);
            var action=Assert.Single(payload["security_actions"]!.AsArray(),a=>a!["event_db_id"]!.ToString()=="2001")!;
            Assert.Equal("group_membership",action["event_family"]!.ToString());
            Assert.Equal(Sid,action["actor"]!["sid"]!.ToString());
            Assert.Equal("S-1-5-21-100000001-200000002-300000003-1002",action["group"]!["sid"]!.ToString());
            Assert.Equal("S-1-5-21-100000001-200000002-300000003-1003",action["member"]!["sid"]!.ToString());
        }
        await using(var db = await fixture.Pg.OpenAsync(ct,"adlog_user")) {
            var period=new AdPeriod(new(old.AddDays(-1)),new(Now.AddDays(1)));
            foreach(bool useColdFacts in new[]{false,true}) {
                var request=new AdReportRequest("security",false,false,1,period,100,new JsonObject { ["entity_id"]=10001 },null);
                var query=AdSecurityQuery.Create(request,useColdFacts:useColdFacts,config:Config(fixture.Dsn("adlog_user")));
                var found=await AdJson.ReadAsync(db,query.SelectSql,ct,query.Args.ToArray());
                Assert.Contains(found,r=>AdJson.Int(r,"event_db_id")==2001);
                Assert.Equal(3,found.Where(r=>r["day"] is not null).Sum(r=>AdJson.Int(r,"event_count")));
                request=request with { Domain=2 };
                query=AdSecurityQuery.Create(request,useColdFacts:useColdFacts,config:Config(fixture.Dsn("adlog_user")));
                Assert.Empty(await AdJson.ReadAsync(db,query.SelectSql,ct,query.Args.ToArray()));
            }
            await using var count=new NpgsqlCommand(DashboardSnapshotReader.ShortLinkCountSql,db);count.Parameters.AddWithValue("p0",Now.Date.AddDays(-14));
            Assert.Equal(44,Convert.ToInt64(await count.ExecuteScalarAsync(ct)));
        }
        await using(var store=new EntityReadStore(new PostgresConnectionFactory(Config(fixture.Dsn("adlog_user"))))) {
            var reader=Reader(store,newHost.Services);var actor=(await reader.Preflight(10001,ct))!;
            var all=(await reader.Detail(actor,new(100),Caps,true,ct))!["events"]!.AsArray();
            Assert.Contains(all,e=>e!["event_db_id"]?.ToString()=="2001");
            var summaries=all.Where(e=>e!["day"] is not null).ToArray();Assert.Equal(2,summaries.Length);
            Assert.All(summaries,e=>Assert.Equal(old.ToString("yyyy-MM-dd"),e!["day"]!.ToString()));
            Assert.All(summaries,e=>Assert.Null(e!["event_db_id"]));Assert.Equal(3,summaries.Sum(e=>e!["event_count"]!.GetValue<long>()));
            var first=(await reader.Detail(actor,new(1,BeforeTime:old.Date.ToString("O"),BeforeId:long.MaxValue),Caps,true,ct))!;
            var cursor=first["next_cursor"]!;
            var second=(await reader.Detail(actor,new(1,BeforeTime:cursor["time_utc"]!.ToString(),BeforeId:0,BeforeSummaryKey:cursor["summary_key"]!.ToString()),Caps,true,ct))!;
            Assert.NotEqual(first["events"]![0]!["summary_key"]!.ToString(),second["events"]![0]!["summary_key"]!.ToString());
        }
        await Write(fixture,[Row(2005,at:old.AddDays(-1))],ct);
        await using(var store=new EntityReadStore(new PostgresConnectionFactory(Config(fixture.Dsn("adlog_user"))))) {
            var reader=Reader(store,newHost.Services);var actor=(await reader.Preflight(10001,ct))!;
            var all=(await reader.Detail(actor,new(100),Caps,true,ct))!["events"]!.AsArray();
            var summaries=all.Where(e=>e!["day"] is not null).ToArray();
            Assert.Equal(3,summaries.Length);Assert.Equal(3,summaries.Select(e=>e!["summary_key"]!.ToString()).Distinct().Count());
            Assert.Equal(4,summaries.Sum(e=>e!["event_count"]!.GetValue<long>()));
        }
        await PostCollectionPostgres.Sql(owner,"""
            insert into servers(id,domain_id,hostname,role,is_active) values(900002,1,'target.example.test','domain_controller',true);
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,server_id,source_core_sha256)
                select 10007,id,'server:target.example.test','synthetic destination',1,900002,sha256('destination'::bytea)
                from storage_v2_entity_type where value='asset'
            """,ct);
        await Write(fixture,[Row(3001,4648),Row(3002,4769,old)],ct);
        await using(var store=new EntityReadStore(new PostgresConnectionFactory(Config(fixture.Dsn("adlog_user"))))) {
            var reader=Reader(store,newHost.Services);var computer=(await reader.Preflight(10007,ct))!;
            var events=(await reader.Detail(computer,new(100),Caps,true,ct))!["events"]!.AsArray();
            Assert.Equal(2,events.Count);Assert.All(events,e=>Assert.Equal("target",e!["link_role"]!.ToString()));
            Assert.Contains(events,e=>e!["event_db_id"]?.ToString()=="3001");
            Assert.Contains(events,e=>e!["day"] is not null && e["event_db_id"] is null && e["event_id"]!.ToString()=="4769");
        }
        var unnamed=Row(4001);var unnamedMethod=JsonNode.Parse(unnamed.Method)!.AsObject();
        unnamedMethod["$principals"]!.AsObject().Remove("SubjectUserName");
        await Write(fixture,[unnamed with { Method=unnamedMethod.ToJsonString() }],ct);
        await using(var store=new EntityReadStore(new PostgresConnectionFactory(Config(fixture.Dsn("adlog_user"))))) {
            var reader=Reader(store,newHost.Services);var actor=(await reader.Preflight(10001,ct))!;
            var events=(await reader.Detail(actor,new(100),Caps,true,ct))!["events"]!.AsArray();
            Assert.Null(events.Single(e=>e!["event_db_id"]?.ToString()=="4001")!["actor"]);
        }
        var self=Row(4002);var selfMethod=JsonNode.Parse(self.Method)!.AsObject();
        selfMethod["$principals"]!["TargetUserSid"]=Sid;selfMethod["$principals"]!["TargetUserName"]="operator";
        await Write(fixture,[self with { Actor=Sid,Method=selfMethod.ToJsonString() }],ct);
        var dashboardConfig=Config(fixture.Dsn("adlog_user"));
        using(var dashboardRows=new PostgresLegacyRows(new PostgresConnectionFactory(dashboardConfig))) {
            var dashboard=new DashboardSnapshotReader(dashboardRows,null!,null!,new LegacySettings(dashboardConfig),null!,null!,config:dashboardConfig);
            var summary=await dashboard.Entities(ct);
            Assert.NotEmpty(summary["by_role"]!.AsArray());
            Assert.Equal(summary["by_role"]!.AsArray().Sum(r=>EntityReader.Number(r!.AsObject(),"count")),summary["total_event_entity_links"]!.GetValue<long>());
        }
        var seed=Row(30000);
        var noise=Enumerable.Range(30000,2048).Select(n=> {
            string sid="S-1-5-21-100000001-200000002-300000003-"+n;
            var method=JsonNode.Parse(seed.Method)!.AsObject();method["$principals"]!["SubjectUserSid"]=sid;
            return seed with { EventId=n,Actor=sid,Method=method.ToJsonString() };
        }).ToArray();
        await Write(fixture,noise,ct);
        await PostCollectionPostgres.Sql(owner,"analyze event_hot",ct);
        await using(var app=await fixture.Pg.OpenAsync(ct,"adlog_user"))
        await using(var explain=new NpgsqlCommand("explain (analyze,buffers,costs off) "+EntityShortSql.Cte("@boundary","@id")+"""
            select e.id from short_events e join servers s on s.id=e.server_id and s.domain_id=e.domain_id
            where e.time_created_utc>=@start and e.id is not null
            order by e.time_created_utc desc,e.id desc limit 20
            """,app)) {
            explain.Parameters.AddWithValue("id",10001);explain.Parameters.AddWithValue("boundary",Now.Date.AddDays(-14));explain.Parameters.AddWithValue("start",Now.Date);
            var plan=new List<string>();await using var read=await explain.ExecuteReaderAsync(ct);while(await read.ReadAsync(ct)) plan.Add(read.GetString(0));
            output.WriteLine("Entity lookup, normal planner, 2048 unrelated writer events:\n"+string.Join('\n',plan.Where(l=>
                l.Contains("Bitmap",StringComparison.Ordinal) || l.Contains("Index Cond:",StringComparison.Ordinal) || l.StartsWith("Planning Time:",StringComparison.Ordinal) || l.StartsWith("Execution Time:",StringComparison.Ordinal))));
            Assert.Contains(plan,l=>l.Contains("Bitmap Index Scan",StringComparison.Ordinal));
        }
        var compact=Row(5001);var compactMethod=JsonNode.Parse(compact.Method)!.AsObject();compactMethod.Remove("$principals");
        await Write(fixture,[compact with { Actor=Sid,Method=compactMethod.ToJsonString() }],ct);
        await using(var store=new EntityReadStore(new PostgresConnectionFactory(entityConfig))) {
            var payload=new JsonObject();
            await Reader(store,newHost.Services).Interpretation(payload,new JsonObject { ["id"]=10001,["domain_id"]=1 },options,actionCaps,access,ct);
            var action=Assert.Single(payload["security_actions"]!.AsArray(),a=>a!["event_db_id"]!.ToString()=="5001")!;
            Assert.Equal("unknown",action["actor"]!["state"]!.ToString());
            Assert.Equal(Sid,action["affected_account"]!["sid"]!.ToString());
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
