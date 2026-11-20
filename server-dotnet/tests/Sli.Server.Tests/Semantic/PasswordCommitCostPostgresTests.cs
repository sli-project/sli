using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordCommitCostPostgresTests(ITestOutputHelper output)
{
    [Fact] public async Task Previous_maximum_upgrades_and_rollback_restores_guards_and_permissions()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:383);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        async Task<string> Definitions() {
            await using var q=new NpgsqlCommand("""
                select jsonb_build_object('functions',(select jsonb_object_agg(oid::regprocedure::text,
                    jsonb_build_array(pg_get_functiondef(oid),proowner,proacl)) from pg_proc where oid=any(array[
                    'public.password_v2_assert_episode(semantic_password_episode_budgets)'::regprocedure,
                    'public.password_v2_deferred()'::regprocedure,'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
                    'public.password_v2_assert_checkpoint(semantic_password_checkpoints)'::regprocedure,
                    'public.password_schedule_state_check375()'::regprocedure,
                    'public.password_v2_state_ledger_complete()'::regprocedure,
                    'public.prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[])'::regprocedure,
                    'public.read_password_event_window362(jsonb,jsonb)'::regprocedure])),
                    'triggers',(select jsonb_object_agg(tgname,pg_get_triggerdef(oid)) from pg_trigger
                    where tgname in ('password_v2_ledger_complete','password_v2_qw_complete','password_v2_jobs_complete')))::text
                """,owner);
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        var before=await Definitions();var path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/384_password_commit_cost.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await using(var access=new NpgsqlCommand("select has_table_privilege('adlog_semantic_worker','password_episode_checks384','INSERT,UPDATE,DELETE,SELECT')",owner))
            Assert.Equal(false,await access.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);Assert.Equal(before,await Definitions());
        await fixture.Pg.ApplyFileAsync(path,null,ct);await fixture.AssertNoSqlErrorsAsync(ct);
    }
    [Fact(Explicit=true)] public Task Before_384_stand_volume() => Profile(false);
    [Fact] public Task After_384_stand_volume() => Profile(true);

    [Fact] public async Task Job_removed_after_cached_validation_rejects_commit_and_same_source_can_retry()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:DateTimeOffset.UtcNow.AddMinutes(-10),eventKinds:Enumerable.Repeat(4625,20).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var source=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);await bind.ExecuteNonQueryAsync(ct);
        }
        await PostCollectionPostgres.Sql(owner,"""
            create function public.password_test_remove_job384() returns trigger language plpgsql security definer as $$
            begin
                delete from public.semantic_risk_evaluation_jobs j using public.semantic_qw_signals s
                where j.qw_signal_id=s.signal_id and s.document_json#>>'{password_context,episode_key}'=new.episode_key;
                return null;
            end $$;
            create trigger password_test_remove_job384 after update on public.password_episode_checks384
                for each row when (new.checked_ledger is not null) execute function public.password_test_remove_job384();
            """,ct);
        var producer=new PasswordProducer();var rule=new PasswordRule(scope);
        var failed=await producer.RunAsync(worker,rule,ct);
        Assert.True(failed.Failed);Assert.True(failed.FailureObserved);Assert.Equal("55000",failed.Diagnostic!["sql_state"]!.GetValue<string>());
        string log=await fixture.Pg.DiagnosticsAsync(ct);Assert.Contains("password_v2_jobs_incomplete",log);
        await using(var count=new NpgsqlCommand("select (select count(*) from semantic_qw_signals)+(select count(*) from semantic_password_episode_budgets)+(select count(*) from password_episode_checks384)",owner))
            Assert.Equal(0L,await count.ExecuteScalarAsync(ct));
        await PostCollectionPostgres.Sql(owner,"drop trigger password_test_remove_job384 on password_episode_checks384; drop function password_test_remove_job384()",ct);
        var retried=await producer.RunAsync(worker,rule,ct);Assert.False(retried.Failed,retried.Diagnostic?.ToJsonString());Assert.True(retried.Jobs>0);
    }

    private async Task Profile(bool migrated)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:migrated?384:383);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var start=DateTimeOffset.UtcNow.AddDays(-2);start=start.AddTicks(-start.Ticks%TimeSpan.TicksPerSecond);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,occurredAt:start,eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner,ct,3000,0.2,noise:true,clients:70);
        await PostCollectionPostgres.Sql(owner,"alter role sli_semantic_login set log_min_duration_statement=0",ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var source=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker);
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')",app);
            bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);await bind.ExecuteNonQueryAsync(ct);
        }
        var producer=new PasswordProducer();var rule=new PasswordRule(scope,"spray");var cache=new Dictionary<long,PasswordNative>();
        var watch=Stopwatch.StartNew();var first=await producer.RunAsync(worker,rule,ct,cache);watch.Stop();
        Assert.False(first.Failed,first.Diagnostic?.ToJsonString());Assert.True(first.Jobs>0);
        output.WriteLine($"migration={(migrated?384:383)} first batch: total={watch.Elapsed.TotalSeconds:F3}s; jobs={first.Jobs}; work={first.Work}");
        double total=watch.Elapsed.TotalSeconds;
        watch.Restart();var nextBatch=producer.RunAsync(worker,rule,ct,cache);
        var riskWatch=Stopwatch.StartNew();
        var risk=migrated?new PasswordRiskConsumer(runtime,new PasswordRiskOptions(MaxJobs:1)).RunOnceAsync(ct):null;
        var next=await nextBatch;watch.Stop();
        Assert.False(next.Failed,next.Diagnostic?.ToJsonString());total+=watch.Elapsed.TotalSeconds;
        output.WriteLine($"second batch: total={watch.Elapsed.TotalSeconds:F3}s; jobs={next.Jobs}; work={next.Work}");
        if(risk!=null) {
            var result=await risk;riskWatch.Stop();
            output.WriteLine($"concurrent risk: {riskWatch.Elapsed.TotalSeconds:F3}s; completed={result.Completed}; failed={result.Failed}");
            Assert.Equal(1,result.Completed);Assert.Equal(0,result.Failed);Assert.InRange(riskWatch.Elapsed.TotalSeconds,0,60);
        }
        string log=await fixture.Pg.DiagnosticsAsync(ct);
        var commits=Regex.Matches(log,@"duration:\s*([0-9.]+) ms\s+statement:\s*COMMIT",RegexOptions.IgnoreCase)
            .Select(m=>double.Parse(m.Groups[1].Value,CultureInfo.InvariantCulture)).ToArray();
        output.WriteLine($"COMMIT max={commits.DefaultIfEmpty().Max():F3}ms; 600 event seconds / {total:F3}s = {600/total:F3} event minutes/minute");
        await using(var count=new NpgsqlCommand("select count(*),count(distinct method#>>'{$principals,IpAddress}') from event_hot",owner)) {
            await using var r=await count.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal(3000L,r.GetInt64(0));Assert.Equal(70L,r.GetInt64(1));
        }
        if(migrated) {
            Assert.InRange(commits.Max(),0,10000);
            Assert.True(next.Work!["window_items"]!.GetValue<int>()<first.Work!["window_items"]!.GetValue<int>());
            await PostCollectionPostgres.Sql(owner,"grant adlog_storage_owner to sli_semantic_login",ct);
            await PostCollectionPostgres.Sql(worker,"set role adlog_storage_owner",ct);
            await using(var tx=await worker.BeginTransactionAsync(ct)) {
                await PostCollectionPostgres.Sql(worker,"update semantic_password_episode_budgets set tracking_through=tracking_through; set constraints all immediate; set constraints all deferred",ct);
                await PostCollectionPostgres.Sql(worker,"update semantic_password_episode_budgets set reserved_ref_occurrences=reserved_ref_occurrences+1 where episode_key=(select episode_key from semantic_password_episode_budgets order by episode_key limit 1)",ct);
                var error=await Assert.ThrowsAsync<PostgresException>(()=>tx.CommitAsync(ct));
                Assert.Equal("password_v2_admission_incomplete",error.MessageText);
            }
            await using var queue=new NpgsqlCommand("select count(*) from password_episode_checks384",owner);
            Assert.Equal(0L,await queue.ExecuteScalarAsync(ct));
        }
        if(!migrated)await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
