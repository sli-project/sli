using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordWindowUpgradePostgresTests(ITestOutputHelper output)
{
    [Fact] public async Task Indivisible_overflow_is_rejected_without_committing_empty_progress()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var start=DateTimeOffset.UtcNow.AddDays(-2);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:start,eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner,ct,10001,0,noise:true,missingTargets:true);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var source=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);await bind.ExecuteNonQueryAsync(ct);
        }
        foreach(string kind in new[]{"brute","spray"}) {
            var rejected=await new PasswordProducer().RunAsync(worker,new PasswordRule(scope,kind),ct);
            Assert.True(rejected.Failed);Assert.True(rejected.FailureObserved);
            Assert.Equal("CountBound",rejected.Diagnostic?["window_check"]?.GetValue<string>());
        }
        await using(var state=new NpgsqlCommand("select bool_and(watermark is null and state_revision=0) from semantic_password_checkpoints",owner))
            Assert.Equal(true,await state.ExecuteScalarAsync(ct));
        await using(var jobs=new NpgsqlCommand("select count(*) from semantic_risk_evaluation_jobs",owner))
            Assert.Equal(0L,await jobs.ExecuteScalarAsync(ct));
        await using(var count=new NpgsqlCommand("select count(*) from event_hot",owner))
            Assert.Equal(10001L,await count.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact] public async Task Legacy_checkpoints_resume_both_rules_without_overflowing_the_full_reader_horizon()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:384);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var start=DateTimeOffset.UtcNow.AddDays(-2);
        start=start.AddTicks(-start.Ticks%TimeSpan.TicksPerSecond);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:start,eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner,ct,11000,0.1,noise:true,clients:71,missingTargets:true);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var source=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);await bind.ExecuteNonQueryAsync(ct);
        }
        var producer=new PasswordProducer();var rules=new[]{new PasswordRule(scope),new PasswordRule(scope,"spray")};
        var marks=new Dictionary<string,DateTimeOffset>();
        foreach(var rule in rules) {
            for(int cycle=0;cycle<2;cycle++) {
                var old=await producer.RunAsync(worker,rule,ct);
                Assert.False(old.Failed,old.Diagnostic?.ToJsonString());
                marks[rule.Id]=PasswordJson.Time(old.Work!["watermark"]);
            }
            Assert.InRange((marks[rule.Id]-start).TotalSeconds,1,600);
        }
        await using(var state=new NpgsqlCommand("select bool_and(not (state_document#>'{episodes,0}' ? 'witnesses')) from semantic_password_checkpoints",owner))
            Assert.Equal(true,await state.ExecuteScalarAsync(ct));
        foreach(string file in new[]{"385_password_state_and_step.sql","386_password_live_state_bound.sql"})
            await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations",file),null,ct);
        foreach(var rule in rules) {
            await using var read=new NpgsqlCommand("select metadata::text from public.read_password_event_window362(@s::jsonb,@e::jsonb) where record_kind='metadata'",worker);
            read.Parameters.AddWithValue("s",scope.Document.ToJsonString());read.Parameters.AddWithValue("e",rule.Execution.ToJsonString());
            var metadata=JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!;
            Assert.Equal(10001,metadata["candidate_count"]!.GetValue<int>());
            Assert.True(metadata["truncated"]!.GetValue<bool>());
        }
        async Task<string> DefinitionAndCheckpoints() {
            await using var query=new NpgsqlCommand("""
                select jsonb_build_array((select jsonb_build_array(pg_get_functiondef(oid),proowner,proacl) from pg_proc
                    where oid='public.password_event_clock362(jsonb,jsonb)'::regprocedure),
                    (select jsonb_agg(to_jsonb(c) order by pin) from semantic_password_checkpoints c))::text
                """,owner);
            return (string)(await query.ExecuteScalarAsync(ct))!;
        }
        var before=await DefinitionAndCheckpoints();
        var path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/387_password_window_capacity.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        Assert.Equal(before,await DefinitionAndCheckpoints());
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        var watch=Stopwatch.StartNew();var advances=new Dictionary<string,double>();var cache=new Dictionary<long,PasswordNative>();
        async Task<PasswordProducerOutcome> Run(PasswordRule rule,CancellationToken token) {
            var next=await producer.RunAsync(worker,rule,token,cache);
            Assert.False(next.Failed,next.Diagnostic?.ToJsonString());
            Assert.Equal("committed",next.Status);
            if(next.Work is {} work) {
                advances.TryAdd(rule.Id,(PasswordJson.Time(work["watermark"])-marks[rule.Id]).TotalSeconds);
                Assert.InRange(work["native_items"]!.GetValue<int>(),0,10000);
                Assert.InRange(work["xml_bytes"]!.GetValue<int>(),0,33554432);
            }
            return next;
        }
        await PasswordProducerPoller.RunBatchesAsync(scope,Run,ct);
        watch.Stop();double speed=advances.Values.Min()/watch.Elapsed.TotalSeconds;
        output.WriteLine($"Both rules resumed in {watch.Elapsed.TotalSeconds:F3}s; minimum first advance={advances.Values.Min():F3}s; speed={speed:F3}x");
        Assert.True(speed>1,$"Catch-up speed {speed:F3}x");
        await using(var checkpoint=new NpgsqlCommand("select min(watermark) from semantic_password_checkpoints",owner))
            Assert.True((DateTime)(await checkpoint.ExecuteScalarAsync(ct))!>=DateTime.UtcNow.AddMinutes(-12));
        await using var count=new NpgsqlCommand("select count(*) from event_hot",owner);Assert.Equal(11000L,await count.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
