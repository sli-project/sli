using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordStateAndStepPostgresTests(ITestOutputHelper output)
{
    [Fact] public async Task Closed_confirmations_reject_live_or_frozen_endpoints()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var db=await fixture.Pg.OpenAsync(ct);
        var rows=Enumerable.Range(1,10).Select(i=>PasswordRuleTests.Event(i,i))
            .Concat(Enumerable.Range(11,10).Select(i=>PasswordRuleTests.Event(i,1200+i))).ToArray();
        var rule=new PasswordRule(rows[0].Witness.Scope);var start=rows[0].Witness.At.AddSeconds(-1);
        var state=rule.Advance(new(),rows,start.AddSeconds(1920),readFrom:start).State.Document;
        async Task Check(JsonObject document) {
            await using var q=new NpgsqlCommand("select public.password_v2_check_state(@st::jsonb,@s::jsonb,@pin)",db);
            q.Parameters.AddWithValue("st",document.ToJsonString());q.Parameters.AddWithValue("s",rule.Scope.Document.ToJsonString());q.Parameters.AddWithValue("pin",rule.Pin);
            await q.ExecuteScalarAsync(ct);
        }
        await Check(state);
        foreach(bool frozen in new[]{false,true}) {
            var damaged=state.DeepClone().AsObject();var closed=damaged["closed_admissions"]![0]!;
            if(frozen)closed["frozen"]=true;
            else closed["witnesses"]![closed["last"]!.GetValue<int>()]!["at"]=damaged["watermark"]!.DeepClone();
            var error=await Assert.ThrowsAsync<PostgresException>(()=>Check(damaged));
            Assert.Equal("password_v2_state_invalid",error.MessageText);
        }
    }

    [Fact] public async Task Previous_maximum_accepts_385_and_rollback_restores_definitions_and_acl()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:384);
        await using var db=await fixture.Pg.OpenAsync(ct);
        async Task<string> Definitions() {
            await using var q=new NpgsqlCommand("""
                select jsonb_object_agg(oid::regprocedure::text,jsonb_build_array(pg_get_functiondef(oid),proowner,proacl))::text
                from pg_proc where pronamespace='public'::regnamespace and proname like '%password%'
                """,db);
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        var before=await Definitions();var path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/385_password_state_and_step.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        Assert.Equal(before,await Definitions());await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact(Explicit=true)] public async Task Six_hours_at_215_events_per_minute_catch_up_faster_than_five_times_realtime()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var duration=TimeSpan.FromHours(6);const int total=77400;
        var now=DateTimeOffset.UtcNow;var start=(now-duration).AddTicks(-now.Ticks%TimeSpan.TicksPerSecond);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:start,eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner,ct,total,(duration.TotalSeconds-180)/(total-1),noise:true,clients:71);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var read=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);await bind.ExecuteNonQueryAsync(ct);
        }
        var producer=new PasswordProducer();var cache=new Dictionary<long,PasswordNative>();
        var watch=Stopwatch.StartNew();
        async Task<PasswordProducerOutcome> Run(PasswordRule rule,CancellationToken token) {
            var result=await producer.RunAsync(worker,rule,token,cache);
            output.WriteLine($"catchup {rule.Id}: {result.Status}; elapsed={watch.Elapsed.TotalSeconds:F3}s; watermark={result.Work?["watermark"]}; rows={result.Work?["window_items"]}; native={result.Work?["native_items"]}; xml_bytes={result.Work?["xml_bytes"]}; diagnostic={result.Diagnostic}");
            Assert.False(result.Failed,result.Diagnostic?.ToJsonString());
            return result;
        }
        var results=(await PasswordProducerPoller.RunBatchesAsync(scope,Run,ct)).ToList();
        // The next poll consumes the final <=12-minute tail as in production.
        results.AddRange(await PasswordProducerPoller.RunBatchesAsync(scope,Run,ct));
        watch.Stop();
        Assert.All(results,r=>Assert.False(r.Failed,r.Diagnostic?.ToJsonString()));
        await using var checkpoints=new NpgsqlCommand("select min(watermark),max(octet_length(state_document::text)) from semantic_password_checkpoints",owner);
        DateTimeOffset through;int size;
        await using(var reader=await checkpoints.ExecuteReaderAsync(ct)) {
            Assert.True(await reader.ReadAsync(ct));through=reader.GetFieldValue<DateTimeOffset>(0);size=reader.GetInt32(1);
        }
        double eventSeconds=(now.AddSeconds(-180)-start).TotalSeconds;
        double speed=eventSeconds/watch.Elapsed.TotalSeconds;
        output.WriteLine($"events={total}; event_seconds={eventSeconds:F3}; seconds={watch.Elapsed.TotalSeconds:F3}; speed={speed:F3}x; batches={results.Count}; largest_state={size}");
        Assert.True(through>=now.AddMinutes(-12));Assert.True(speed>=5,$"Catch-up speed {speed:F3}x");
        Assert.InRange(size,1,4194304);
        foreach(string id in new[]{PasswordRule.RuleId,"qw.password-spray"}) {
            await using var signals=new NpgsqlCommand("select count(*) from semantic_qw_signals where document_json->>'rule_id'=@id",owner);
            signals.Parameters.AddWithValue("id",id);Assert.True((long)(await signals.ExecuteScalarAsync(ct))!>0);
        }
        await using var count=new NpgsqlCommand("select count(*) from event_hot",owner);Assert.Equal((long)total,await count.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
