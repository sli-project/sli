using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Entities;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

[Collection("Semantic producer environment")]
public sealed class SemanticShortHistoryPostgresTests
{
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    static readonly DateTime Now = DateTime.UtcNow.Date.AddHours(1);
    internal static IConfiguration Config(string dsn) => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
        ["ConnectionStrings:Sli"]=dsn,["Sli:Storage:ShortEventReads"]="true",
        ["Sli:Storage:HistoryReadMode"]="primary",["Sli:Storage:HistoryClickHouseHost"]="127.0.0.1",
        ["Sli:Storage:HistoryClickHousePort"]="1",["Sli:Storage:HistoryClickHouseUser"]="synthetic",
        ["Sli:Storage:HistoryClickHousePassword"]="synthetic"
    }).Build();

    [Theory]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData(null)]
    public async Task Semantic_reads_use_short_rows_and_problem_copies_without_ClickHouse_or_legacy_events(string? setting)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner,"""
            insert into servers(id,domain_id,hostname,role,is_active) values(900001,1,'dc01.example.test','domain_controller',true);
            insert into storage_v2_channel(value) values('Security') on conflict do nothing;
            insert into storage_v2_provider(value) values('Microsoft-Windows-Security-Auditing') on conflict do nothing;
            """,ct);
        var method=new JsonObject { ["$server_id"]=900001,["$channel"]="Security",["$provider"]="Microsoft-Windows-Security-Auditing",
            ["$principals"]=new JsonObject { ["SubjectUserSid"]=Sid,["SubjectUserName"]="operator",["TargetUserName"]="target" } }.ToJsonString();
        await using(var db=await fixture.Pg.OpenAsync(ct))
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",ct);
            await ShortEventWriter.WriteAsync(db,tx,[new ShortEventRow(41,Now,4740,"fact",Sid,"target","192.0.2.1","dc01.example.test",1,method,"{}",new Dictionary<string,string?> { ["WorkstationName"]="client.example.test" })],ct);
            await tx.CommitAsync(ct);
        }
        var config=Config(fixture.Dsn("adlog_user"));
        config["Sli:Storage:ShortEventReads"]=setting;
        await using(var seed=new NpgsqlCommand("""
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,source_ingested_at,source_identity_json)
            values('00000000-0000-0000-0000-000000000041',41,1,'synthetic','1','normalized',sha256('source'::bytea),sha256('meaning'::bytea),
                'account.locked',@at,@at,jsonb_build_object('id',41,'server_id',900001,'domain_id',1,'log_source_id',1,'event_id',4740,
                    'time_created_utc',@at,'migrated_at',@at,'normalized_hash',repeat('a',64),'channel','Security'));
            insert into canonical_actions(canonical_action_id,action_kind,action_status,semantic_contract_version,assembler_id,assembler_version,
                occurred_at_utc,contribution_key,canonical_deduplication_key,action_sha256)
            values('10000000-0000-0000-0000-000000000041','account.locked','observed',1,'synthetic','1',@at,
                sha256('action'::bytea),sha256('action'::bytea),sha256('action'::bytea));
            insert into canonical_action_evidence(canonical_action_id,normalized_event_id,evidence_role,evidence_order)
            values('10000000-0000-0000-0000-000000000041','00000000-0000-0000-0000-000000000041','primary',0);
            insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,lifecycle_status,definition_json,definition_sha256)
            values('investigation.account.unlock.after-lock',1,'sequence','enabled','{}',sha256('synthetic-rule'::bytea));
            insert into semantic_correlation_candidates(candidate_id,rule_id,rule_version,relation_kind,candidate_key,partition_key,
                window_start_utc,window_end_utc,confidence,explanation,evidence_count)
            values('20000000-0000-0000-0000-000000000041','investigation.account.unlock.after-lock',1,'account.unlocked',
                sha256('synthetic-candidate'::bytea),'domain:1|account_sid:S-1-5-21-100000001-200000002-300000003-1001',@at,@at,'medium','synthetic',1);
            insert into semantic_correlation_candidate_evidence(candidate_id,normalized_event_id,evidence_order)
            values('20000000-0000-0000-0000-000000000041','00000000-0000-0000-0000-000000000041',0);
            """,owner)) { seed.Parameters.AddWithValue("at",Now); await seed.ExecuteNonQueryAsync(ct); }
        var access=new CapabilityDecisionSet(true,new HashSet<string>(),new HashSet<string>(),[],new Dictionary<string,System.Text.Json.JsonElement>());
        var dbFactory=new PostgresConnectionFactory(config); var database=new SemanticDatabase(dbFactory);
        string bounds="domain_id=1&time_from="+Now.AddDays(-1).ToString("O")+"&time_to="+Now.AddDays(1).ToString("O")+"&timezone=UTC";
        var decision=new AccessDecision("operator",access,[new(SemanticRelations.Report,true,[new(
            System.Text.Json.JsonSerializer.SerializeToElement(new { kind="all" }),new HashSet<string>{"security","technical","raw_evidence"},new HashSet<string>{"view"},1,1)])]);
        async Task AssertEvent(bool entityRetained=true)
        {
            await using var pg=await new SemanticDatabase(new PostgresConnectionFactory(config)).OpenAsync(false,ct);
            await using var session=await SemanticHistorySession.CreateAsync(pg,config,ct);
            Assert.NotNull(session);
            await session.ReportAsync(1,new(Now.AddDays(-30)),new(Now.AddDays(1)),ct);
            var rows=await session.QueryAsync("""
                select core.id,core.domain_id,core.subject_user_sid,core.subject_user_name,facts.event_id as fact_id,channel.value as channel
                from semantic_event_rows core join storage_v2_channel channel on channel.id=core.channel_id
                left join semantic_event_fields facts on facts.event_id=core.id where core.id=$1
                """,ct,41L);
            var row=Assert.Single(rows); Assert.Equal("41",row!["id"]!.ToString());
            Assert.Equal(Sid,row["subject_user_sid"]!.ToString()); Assert.Equal("operator",row["subject_user_name"]!.ToString());
            Assert.Equal("Security",row["channel"]!.ToString()); Assert.Equal("41",row["fact_id"]!.ToString());
            Assert.True(await SemanticWorkspace.EventAllowed(session,41,access,ct));
            Assert.False(await SemanticWorkspace.EventAllowed(session,42,access,ct));
            var actions=await new SemanticWorkspace(database,config).ReadAsync("actions",new("event_db_id=41"),access,ct);
            Assert.Equal("10000000-0000-0000-0000-000000000041",Assert.Single(actions["items"]!.AsArray())!["canonical_action_id"]!.ToString());
            var relations=await new SemanticRelations(database,configuration:config).ReadAsync(new(bounds),decision,ct);
            Assert.Equal("41",Assert.Single(Assert.Single(relations["items"]!.AsArray())!["evidence"]!.AsArray())!["event_db_id"]!.ToString());
            var denied=access with { IsOwner=false,Capabilities=SemanticWorkspace.ExactCapabilities.ToHashSet(),Policies=[new("evidence.exact","deny",true,false,
                System.Text.Json.JsonSerializer.SerializeToElement(new { kind="domain",ids=new[]{1} }))] };
            Assert.False(await SemanticWorkspace.EventAllowed(session,41,denied,ct));
            var serverDenied=denied with { Policies=[new("evidence.exact","deny",true,false,
                System.Text.Json.JsonSerializer.SerializeToElement(new { kind="server",ids=new[]{900001} }))] };
            Assert.False(await SemanticWorkspace.EventAllowed(session,41,serverDenied,ct));
            await using var entities=new EntityReadStore(dbFactory,config);
            var entityRelations=await entities.ReadAsync("with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") select core.id from normalized_events n join short_events core on core.id=n.source_event_id where core.id=@id",
                new Dictionary<string,object>{["id"]=41L,["boundary"]=Now.Date.AddDays(-14)},0,ct);
            if(entityRetained) Assert.Equal("41",Assert.Single(entityRelations)!["id"]!.ToString());
            else Assert.Empty(entityRelations);
        }
        await AssertEvent();
        await using (var reporting = await database.OpenAsync(false,ct)) {
            var export=await Sli.Server.Reporting.V2.SecurityObservationReader.ShortEvents(reporting,1,[4740],
                new DateTimeOffset(Now.AddDays(-1)),new DateTimeOffset(Now.AddDays(1)),config,ct,100);
            Assert.Equal("41",Assert.Single(export)!["event_db_id"]!.ToString());
        }
        // Daily authentication is a count, never an exact archived event.
        await EntityShortReadsPostgresTests.Write(fixture,[EntityShortReadsPostgresTests.Row(42,4624,Now.AddDays(-20)),
            EntityShortReadsPostgresTests.Row(43,4740,Now,domain:2)],ct);
        await using(var pg=await database.OpenAsync(false,ct)) {
            await using var session=await SemanticHistorySession.CreateAsync(pg,config,ct);
            Assert.Empty(await session!.QueryAsync("select id from semantic_event_rows where id=42",ct));
            Assert.False(await SemanticWorkspace.EventAllowed(session,43,access,ct));
        }
        // Cold facts survive hot expiry and are never counted twice.
        await PostCollectionPostgres.Sql(owner,"delete from event_hot",ct);
        await AssertEvent();
        // A problem keeps its own events even after both event layers expire.
        await PostCollectionPostgres.Sql(owner,"""
            insert into findings(id,fingerprint,rule_code,title,severity,status,evidence_count) values(123,'synthetic-semantic-history','synthetic','synthetic','high','new',1);
            insert into finding_event_copies337 select 123,event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields,sha256('synthetic'::bytea),'semantic_scenario',null,null from event_cold_facts;
            insert into findings(id,fingerprint,rule_code,title,severity,status,evidence_count) values(124,'synthetic-semantic-history-2','synthetic','synthetic','high','new',1);
            insert into finding_event_copies337 select 124,event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields,source_sha256,evidence_role,note,event_record_id from finding_event_copies337 where finding_id=123;
            delete from event_cold_facts;
            """,ct);
        await AssertEvent(entityRetained:false);
        // An expired proof cannot disappear from a relation's resource guard.
        await PostCollectionPostgres.Sql(owner,"""
            insert into normalized_events select replacement.* from normalized_events n cross join lateral
                jsonb_populate_record(null::normalized_events,to_jsonb(n)||jsonb_build_object(
                    'normalized_event_id','00000000-0000-0000-0000-000000000042','source_event_id',42,
                    'source_identity_json',jsonb_set(n.source_identity_json,'{id}','42'))) replacement;
            insert into semantic_correlation_candidate_evidence(candidate_id,normalized_event_id,evidence_order)
            values('20000000-0000-0000-0000-000000000041','00000000-0000-0000-0000-000000000042',1);
            """,ct);
        var incomplete=await new SemanticRelations(database,configuration:config).ReadAsync(new(bounds),decision,ct);
        Assert.Empty(incomplete["items"]!.AsArray());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Missing_entities_do_not_probe_ClickHouse_on_short_reads()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        var config=Config(fixture.Dsn("adlog_user"));
        await using var store=new EntityReadStore(new PostgresConnectionFactory(config),config);
        Assert.Empty(await store.ReadAsync("select id from entities_v2_active where id=@id",new Dictionary<string,object> { ["id"]=19999 },0,ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData(null)]
    public async Task Dispatch_uses_PostgreSQL_semantics_without_initializing_ClickHouse_history(string? setting)
    {
        using var environment=new Sli.Server.Tests.Semantic.SemanticProducerPostgresTests.Admission();
        environment.Set("Sli__Storage__ShortEventReads",setting);
        environment.Set("ADLOG_HISTORY_READ_MODE","primary");
        environment.Set("ADLOG_HISTORY_CLICKHOUSE_PORT","invalid");
        await using var session=new UnusedSession();
        Assert.Null(await SemanticHistorySession.CreateWorkerAsync(session,TestContext.Current.CancellationToken));
    }

    sealed class UnusedSession : ISemanticSession
    {
        public Task<JsonArray> QueryAsync(string sql,CancellationToken ct,params object?[] values) => throw new InvalidOperationException("History must use the caller's PostgreSQL semantic session");
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("read only");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
