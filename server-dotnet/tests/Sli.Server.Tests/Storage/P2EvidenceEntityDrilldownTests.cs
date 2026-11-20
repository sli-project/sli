using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Sli.Agent.Core;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Vectors from tests/events/test_p2_evidence_entity_drilldown.py.
public sealed class P2EvidenceEntityDrilldownTests
{
    const string TaskName = @"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant";
    const string Actor = @"EXAMPLE\DC1$";
    const string Title = "Изменено задание планировщика Windows";
    const string Channel = "Microsoft-Windows-TaskScheduler/Operational";

    static JsonObject TaskEvent(string task = TaskName) => new()
    {
        ["id"] = 42, ["event_id"] = 140, ["provider_name"] = "Microsoft-Windows-TaskScheduler",
        ["channel"] = Channel, ["server"] = "DC1", ["time_created_utc"] = "2026-07-16T00:00:00Z",
        ["event_data"] = new JsonObject { ["TaskName"] = task, ["UserName"] = Actor }
    };

    [Fact]
    public void Detail_url_keeps_multiple_event_types_and_time_window()
    {
        var url = EventDetailProjection.Detail(eventIds: [4624, 4625], server: "DCX", from: "2026-07-07T09:55:00Z");
        Assert.Contains("event_id=4624%2C4625", url);
        Assert.Contains("time_from=2026-07-07T09%3A55%3A00Z", url);
        Assert.Contains("server=DCX", url);
    }

    [Theory]
    [InlineData(TaskName)]
    [InlineData(@"\Microsoft\Windows\FakeBackdoor")]
    public async Task Scheduler_card_keeps_catalogue_meaning_without_trusting_namespace(string task)
    {
        var card = await new KnownBundleNormalizer(EventCardSemanticsTests.Repository(), null, null)
            .CardAsync(TaskEvent(task), TestContext.Current.CancellationToken);
        Assert.True(card["known"]!.GetValue<bool>());
        Assert.Equal(Title, card["title"]!.ToString());
        Assert.Equal("Требует проверки", card["risk"]!.ToString());
        Assert.Equal("medium", card["severity"]!.ToString());
        Assert.Equal("low", card["assessment_confidence"]!.ToString());
        Assert.Equal("низкая", card["assessment_confidence_label"]!.ToString());
        var facts = card["facts"]!.AsArray();
        Assert.Contains(facts, f => f![0]!.ToString() == "Задание" && f[1]!.ToString() == task);
        Assert.Contains(facts, f => f![0]!.ToString() == "Кто выполнил изменение" && f[1]!.ToString() == Actor);
        Assert.Contains(facts, f => f![1]!.ToString() == "Регистрация задания успешно обновлена");
        Assert.Contains(card["checks"]!.AsArray(), c => c!.ToString().Contains("цифровую подпись", StringComparison.Ordinal));
    }

    [Fact]
    public void Fast_search_preserves_verified_scheduler_action_name()
    {
        var row = TaskEvent();
        row.Remove("event_data");
        row["event_data_json"] = "{\"TaskName\":\"\\\\Microsoft\\\\Windows\\\\Task\"}";
        Assert.Equal(Title, EventListProjection.Project(row)["label"]!.ToString());
        Assert.Equal(Title, EventSearchProjection.History(row)["title"]!.ToString());
        row["provider_name"] = "Unknown";
        Assert.Null(EventSearchProjection.History(row)["title"]);
    }

    [Fact]
    public void Scheduler_ingress_extracts_catalogue_actor_and_projects_target_state()
    {
        string xml = $"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>140</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime='2026-07-16T00:00:00Z'/><Channel>{Channel}</Channel><Computer>DC1</Computer></System><EventData><Data Name='TaskName'>{TaskName}</Data><Data Name='UserName'>{Actor}</Data></EventData></Event>";
        var row = EventXml.Parse(xml, "DC1", "fixture", Channel);
        var projection = Direct4624Projection.Create(row);
        Assert.Contains(projection.Entities, e => e.Type == "scheduled_task" && e.Role == "target" && e.DisplayName == TaskName);
        var actor = Assert.Single(projection.Entities, e => e.Role == "actor");
        Assert.Equal("ad_computer", actor.Type);
        Assert.Equal(Actor, actor.DisplayName);
        var state = DirectStateProjection.Candidate(row, projection, 42, 7)!;
        Assert.NotNull(state);
        Assert.Equal("scheduled_task.configuration", state["state_type"]!.ToString());
        Assert.Equal("changed", state["status"]!.ToString());
        Assert.Equal("scheduled-task-changed-140", state["rule_id"]!.ToString());
        Assert.Equal("2026-07-16T00:00:00Z", state["observed_at_utc"]!.ToString());
        Assert.Equal(Title, state["summary"]!.ToString());
        Assert.Null(DirectStateProjection.Candidate(row, projection, 42, 7, "actor"));
    }

    [Fact]
    public async Task Related_evidence_never_returns_the_anchor_even_if_adapter_does()
    {
        var candidate = new RelationCandidate(20, 4624, null, "auth_session", "0x1", "same_logon_id_same_server", 0);
        Assert.Empty(EventRelationContract.Build(20, [candidate], 30)["items"]!.AsArray());
        var reader = new EventRelationsReader((_, _, _, _) => Task.FromResult<IReadOnlyList<RelationCandidate>>([candidate]), (_, _) => Task.FromResult(true));
        Assert.Empty((await reader.ReadAsync(20, 30, null, TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken))["items"]!.AsArray());
    }

    sealed class Environment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "Sli.Server";
        public string ContentRootPath { get; set; } = EventCardSemanticsTests.Repository();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    [Fact]
    public void Event_evidence_requires_explicit_postgres_identity()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = "Database=synthetic;Username=synthetic"
        }).Build();
        var error = Assert.Throws<Sli.Server.Hosting.ServerConfigurationException>(() => new PostgresConnectionFactory(config));
        Assert.Equal("server_configuration_invalid:ConnectionStrings:Sli:host_database_user_required", error.Message);
    }

    [Fact]
    public async Task Short_rows_read_active_entities_and_correlate_only_same_server_logon()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new Npgsql.NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        long domain=await EventShortReadPostgresTests.SeedRecorderAsync(db,ct);
        await using(var retired=new Npgsql.NpgsqlCommand(
            "select to_regclass('public.events_v2_core') is null and to_regclass('public.event_facts_v2') is null",db))
            Assert.Equal(true,await retired.ExecuteScalarAsync(ct));
        await PostCollectionPostgres.Sql(db,"""
            insert into servers(id,domain_id,hostname,role,is_active) select 2,domain_id,'dc02.example.test','domain_controller',true from servers where id=1;
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select n,t.id,k,'Synthetic',(select domain_id from servers where id=1),sha256(n::text::bytea) from (values
                    (70001,'sid:S-1-5-21-100000001-200000002-300000003-1002'),(70002,'synthetic:merged')) e(n,k)
                join storage_v2_entity_type t on t.value='ad_user';
            insert into entity_details_v2(entity_id,attributes_json,source_details_sha256)
                values(70002,'{"identity_aliases":["sid:S-1-5-21-100000001-200000002-300000003-1002"]}',sha256('synthetic'::bytea));
            insert into entity_identity_merges_v2(merge_id,source_entity_id,target_entity_id,source_natural_key,target_natural_key,
                plan_sha256,source_core_sha256_before,target_core_sha256_before,source_links_before,target_links_before,target_links_after,
                source_links_sha256,target_links_before_sha256,target_links_after_sha256,affected_events,affected_events_sha256,semantic_replay_events,evidence_json)
                select md5('synthetic-merge')::uuid,70002,70001,'synthetic:merged','sid:S-1-5-21-100000001-200000002-300000003-1002',
                    h,h,h,0,0,0,h,h,h,0,h,0,'{}'::jsonb from (select sha256('synthetic'::bytea) h) s;
            """,ct);
        var stamp=DateTimeOffset.UtcNow.AddMinutes(-2);
        ShortEventRow Row(long id,string logon,long server=1,bool sid=false) => EventShortReadPostgresTests.Event(id,4624,
            stamp.AddSeconds(91-id),domain,server:server,sid:sid,fields:new Dictionary<string,string> { ["TargetLogonId"]=logon }).Short;
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",ct);
            await ShortEventWriter.WriteAsync(db,tx,[Row(91,"0x123",sid:true),Row(90,"0x123"),Row(89,"0x123",2),Row(88,"0x456")],ct);
            await tx.CommitAsync(ct);
        }
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"]=fixture.Dsn("adlog_user"),["Sli:Storage:ShortEventReads"]="false" }).Build();
        await using var reads=new EventReadService(new PostgresConnectionFactory(config),config,new Environment());
        var result=await reads.EntitiesAsync(91,ct);
        Assert.True(result["event_found"]!.GetValue<bool>());
        var entity=Assert.Single(result["items"]!.AsArray());
        Assert.Equal(70001,entity!["id"]!.GetValue<int>()); Assert.Equal("target",entity["link_role"]!.ToString());
        var empty=await reads.EntitiesAsync(90,ct);
        Assert.True(empty["event_found"]!.GetValue<bool>()); Assert.Empty(empty["items"]!.AsArray());
        Assert.False((await reads.EntitiesAsync(404,ct))["event_found"]!.GetValue<bool>());
        var page=await reads.RelationsAsync(91,(_,_)=>Task.FromResult(true),ct);
        var related=Assert.Single(page["items"]!.AsArray())!;
        Assert.Equal(90,related["related_event_db_id"]!.GetValue<long>());
        Assert.Equal("same_logon_id_same_server",related["relation_rule"]!.ToString());
        Assert.Equal("Совпали LogonId и сервер; разница во времени 1 с.",related["reason"]!.ToString());
        Assert.Empty((await reads.RelationsAsync(91,(id,_)=>Task.FromResult(id==91),ct))["items"]!.AsArray());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
    [Fact]
    public async Task Task_relations_use_retained_facts_and_page_microsecond_ties_after_hot_retention()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new Npgsql.NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        long domain=await EventShortReadPostgresTests.SeedRecorderAsync(db,ct);
        await using(var retired=new Npgsql.NpgsqlCommand(
            "select to_regclass('public.events_v2_core') is null and to_regclass('public.event_facts_v2') is null",db))
            Assert.Equal(true,await retired.ExecuteScalarAsync(ct));
        var at=EventReadService.ShortBoundary(null).AddDays(-2);
        const long anchor=3_000_000_000;
        ShortEventRow Row(long id,int kind,DateTimeOffset time) => EventShortReadPostgresTests.Event(id,kind,time,domain,
            fields:new Dictionary<string,string> { ["TaskName"]="synthetic-task" }).Short;
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",ct);
            await ShortEventWriter.WriteAsync(db,tx,[Row(anchor,4698,at),Row(anchor+1,4702,at.AddTicks(10)),
                Row(anchor+2,4698,at.AddTicks(10))],ct); await tx.CommitAsync(ct);
        }
        await PostCollectionPostgres.Sql(db,"delete from event_hot",ct);
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"]=fixture.Dsn("adlog_user") }).Build();
        await using var reads=new EventReadService(new PostgresConnectionFactory(config),config,new Environment());
        var first=await reads.RelationsPageAsync(anchor,1,null,(_,_)=>Task.FromResult(true),ct);
        Assert.Equal(anchor+2,Assert.Single(first["items"]!.AsArray())!["related_event_db_id"]!.GetValue<long>());
        string cursor=first["next_cursor"]!.ToString();
        Assert.Equal((0.000001m,anchor+2),EventRelationCursor.Decode(anchor,cursor));
        var second=await reads.RelationsPageAsync(anchor,1,cursor,(_,_)=>Task.FromResult(true),ct);
        var related=Assert.Single(second["items"]!.AsArray())!;
        Assert.Equal(anchor+1,related["related_event_db_id"]!.GetValue<long>());
        Assert.Equal("same_task_same_server_time_window",related["relation_rule"]!.ToString());
        Assert.Null(second["next_cursor"]);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

}
