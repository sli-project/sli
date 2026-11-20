using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Detections;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordClockCatchUpPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Previous_maximum_accepts_migration_and_rollback_preserves_function_and_acl()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:381);
        await using var db=await fixture.Pg.OpenAsync(ct);
        async Task<string> Definition() {
            await using var query=new NpgsqlCommand("select jsonb_build_array(pg_get_functiondef(oid),proowner,proacl)::text from pg_proc where oid='public.password_event_clock362(jsonb,jsonb)'::regprocedure",db);
            return (string)(await query.ExecuteScalarAsync(ct))!;
        }
        var before=await Definition();var path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/382_password_clock_catch_up.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        Assert.Equal(before,await Definition());await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public Task Two_day_noise_backlog_6000_catches_up_in_one_cycle()=>RunBacklog(6000);

    [Fact]
    public Task Dense_noise_catches_up_without_pooling_unrelated_chain_proofs()=>RunBacklog(13000,TimeSpan.FromHours(2),clients:2);

    [Fact]
    public Task Stand_noise_71_ips_with_392_failures_per_ten_minutes_catches_up()=>RunBacklog(1000,TimeSpan.FromMinutes(30),clients:71,standNoise:true);

    private async Task RunBacklog(int total,TimeSpan? horizon=null,int clients=40,bool standNoise=false)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var duration=horizon??TimeSpan.FromDays(2);
        var now=DateTimeOffset.UtcNow;var start=(now-duration).AddTicks(-now.Ticks%TimeSpan.TicksPerSecond);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:start,eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner,ct,total,(duration.TotalSeconds-180)/(total-1),noise:true,clients:clients,standNoise:standNoise);
        if(standNoise) {
            await using var profile=new NpgsqlCommand("""
                select count(distinct ip),max(failures) from (
                    select method#>>'{$principals,IpAddress}' ip,
                        count(*) over(partition by method#>>'{$principals,IpAddress}' order by time_created_utc
                            range between interval '600 seconds' preceding and current row) failures
                    from event_hot) density
                """,owner);
            await using var density=await profile.ExecuteReaderAsync(ct);Assert.True(await density.ReadAsync(ct));
            Assert.Equal(71L,density.GetInt64(0));Assert.Equal(392L,density.GetInt64(1));
        }
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var read=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')::text",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);
            Assert.Equal("configured",JsonNode.Parse((string)(await bind.ExecuteScalarAsync(ct))!)!["status"]!.GetValue<string>());
        }
        var poller=new PasswordProducerPoller(runtime,new PasswordProducer(),new DetectionProducer(new(),new()));
        async Task<bool> SourceLock(bool acquire) {
            await using var command=new NpgsqlCommand("select public.password_producer_source382(@s::jsonb,@a)",worker){CommandTimeout=0};
            command.Parameters.AddWithValue("s",scope.Document.ToJsonString());command.Parameters.AddWithValue("a",acquire);
            return await command.ExecuteScalarAsync(ct) is true;
        }
        Assert.True(await SourceLock(true));
        var target=DateTimeOffset.UtcNow.AddSeconds(-120);var watch=Stopwatch.StartNew();
        var queued=poller.RunSourceAsync(scope,ct);
        try {
            while(!queued.IsCompleted) {
                await using var waiting=new NpgsqlCommand("select exists(select 1 from pg_locks where not granted and @pid=any(pg_blocking_pids(pid)))",owner);
                waiting.Parameters.AddWithValue("pid",worker.ProcessID);
                if(await waiting.ExecuteScalarAsync(ct) is true)break;
                await Task.Yield();ct.ThrowIfCancellationRequested();
            }
            Assert.False(queued.IsCompleted,"The second password producer must queue behind its source owner");
        }
        finally {Assert.True(await SourceLock(false));}
        var results=(await queued).ToList();int cycles=1;
        while(results.Any(r=>r.Work?["watermark"] is {} watermark&&PasswordJson.Time(watermark)<target)) {
            var next=await poller.RunSourceAsync(scope,ct);cycles++;
            Assert.All(next,r=>Assert.False(r.Failed,r.Diagnostic?.ToJsonString()));
            results.AddRange(next);
            if(next.All(r=>r.Work==null||PasswordJson.Time(r.Work["watermark"])>=target))break;
        }
        watch.Stop();
        output.WriteLine($"events={total}; cycles={cycles}; batches={results.Count}; seconds={watch.Elapsed.TotalSeconds:F3}; events/s={total/watch.Elapsed.TotalSeconds:F1}");
        output.WriteLine($"300000 events at measured rate: {300000*watch.Elapsed.TotalSeconds/total:F1} seconds (linear estimate)");
        Assert.All(results,r=>Assert.False(r.Failed,r.Diagnostic?.ToJsonString()));
        Assert.All(results,r=>Assert.Equal("committed",r.Status));
        Assert.All(results.Where(r=>r.Work!=null),r=> {
            Assert.InRange(r.Work!["native_items"]!.GetValue<int>(),0,10000);
            Assert.InRange(r.Work["xml_bytes"]!.GetValue<int>(),0,33554432);
        });
        await using(var checkpoint=new NpgsqlCommand("""
            select min(c.watermark),max(c.watermark) from semantic_password_checkpoints c
            where not exists(select 1 from password_passes388 p where p.scope_digest=c.scope_digest and p.previous_pin=c.pin)
            """,owner)) {
            await using var reader=await checkpoint.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));
            Assert.True(reader.GetFieldValue<DateTimeOffset>(0)>=target);
            output.WriteLine($"oldest live watermark={reader.GetFieldValue<DateTimeOffset>(0):O}");
        }
        await using(var signals=new NpgsqlCommand("select count(*) from semantic_qw_signals where document_json->>'rule_id'='qw.password-brute-force'",owner))
            Assert.True((long)(await signals.ExecuteScalarAsync(ct))!>0);
        if(horizon.HasValue)await using(var signals=new NpgsqlCommand("select count(*) from semantic_qw_signals where document_json->>'rule_id'='qw.password-spray'",owner))
            Assert.True((long)(await signals.ExecuteScalarAsync(ct))!>0);
        if(clients==2) {
            await using var budget=new NpgsqlCommand("""
                select sum(reserved_ref_occurrences),max(reserved_ref_occurrences),max(reserved_xml_bytes),
                    sum(reserved_ref_occurrences-last_sequence+1)
                from semantic_password_episode_budgets where execution_json->>'rule_id'='qw.password-spray'
                """,owner);
            await using var ledger=await budget.ExecuteReaderAsync(ct);Assert.True(await ledger.ReadAsync(ct));
            Assert.True(ledger.GetDecimal(0)>10000);Assert.InRange(ledger.GetInt64(1),1,10000);
            Assert.InRange(ledger.GetInt64(2),1,33554432);
            // Pass overlap may prove the same native event twice. Coverage is
            // distinct input identities, independent of reservation accounting.
            await ledger.DisposeAsync();
            await using var covered=new NpgsqlCommand("""
                select count(distinct ref->>'native_id') from semantic_qw_signals s
                cross join lateral jsonb_array_elements(s.document_json->'evidence_refs') ref
                where s.document_json->>'rule_id'='qw.password-spray'
                """,owner);
            Assert.Equal((long)total,await covered.ExecuteScalarAsync(ct));
        }
        // A second cycle has no new finalizable events and terminates without replaying jobs.
        var idle=await poller.RunSourceAsync(scope,ct);Assert.All(idle,r=>Assert.False(r.Failed,r.Diagnostic?.ToJsonString()));Assert.Equal(0,idle.Sum(r=>r.Jobs));
        await using(var count=new NpgsqlCommand("select count(*) from event_hot",owner))Assert.Equal((long)total,await count.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public void Proposal_failure_reports_only_known_diagnostic_counts_and_watermark_check()
    {
        var error=new PasswordFailure("password_v2_proposal_unavailable") {WatermarkMatches=false,
            ProposalDiagnostics=new Dictionary<string,int>{{"state_bound",1},{"prequalification_native_unavailable",2},{"synthetic-private-event",99}}};
        var diagnostic=DetectionDiagnostics.Describe(error,"password_proposal");
        Assert.False(diagnostic["watermark_matches"]!.GetValue<bool>());
        Assert.Equal(1,diagnostic["proposal_diagnostics"]!["state_bound"]!.GetValue<int>());
        Assert.Equal(2,diagnostic["proposal_diagnostics"]!["prequalification_native_unavailable"]!.GetValue<int>());
        Assert.DoesNotContain("synthetic-private-event",diagnostic.ToJsonString());
    }
}
