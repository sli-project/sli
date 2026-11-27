using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class DetectionSourceLockPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Previous_source_lock_reproduces_zero_password_work_during_both_reads()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:382);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:Enumerable.Repeat(4625,10).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var runtime=Runtime(fixture);
        await using var detector=await runtime.OpenAsync(ct);await using var password=await runtime.OpenAsync(ct);
        var source=await Source(detector,ct);var scope=PasswordScope.Read(source["scope"]);await Bind(fixture,ct);
        var gates=new[]{new ReadGate(),new ReadGate()};int worked=0;
        async Task Detect() {
            await using var tx=await detector.BeginTransactionAsync(ct);
            var session=new SemanticSession(detector,tx);
            // Reproduce the source-wide transaction held by the installed 382
            // producer, while using the real account readers and checkpoints.
            await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))",ct,PasswordJson.Hash(scope.Document));
            await SemanticProduction.RunDefaultSource(new SlowAccounts(session,gates),source,ct);await tx.CommitAsync(ct);
        }
        var detecting=Detect();
        try {
            foreach(var gate in gates) {
                Assert.Same(gate.Entered.Task,await Task.WhenAny(gate.Entered.Task,detecting));
                var result=await new PasswordProducer().RunAsync(password,new PasswordRule(scope),ct);
                if(result.Status=="committed"&&result.Work is not null)worked++;
                Assert.Equal("busy",result.Status);Assert.Equal("55P03",result.Diagnostic!["sql_state"]!.GetValue<string>());
                gate.Release.TrySetResult();
            }
        } finally {foreach(var gate in gates)gate.Release.TrySetResult();await detecting;}
        output.WriteLine($"before migration 383: password cycles with work={worked}/2");Assert.Equal(0,worked);
        // Both 55P03 errors above are intentional observations of the old behavior.
    }

    [Fact]
    public async Task Previous_maximum_accepts_migration_and_rollback_restores_definitions_and_acl()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:382);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        async Task<string> Definitions() {
            await using var query=new NpgsqlCommand("""
                select jsonb_object_agg(oid::regprocedure::text,jsonb_build_array(pg_get_functiondef(oid),proowner,proacl))::text
                from pg_proc where oid=any(array['public.password_v2_locked_checkpoint(jsonb,jsonb,boolean)'::regprocedure,
                    'public.password_policy_ensure_v275(text,integer,text)'::regprocedure,
                    'public.lock_password_reservation_entities_v2(jsonb,jsonb,bigint,bigint,text[])'::regprocedure,
                    'public.password_producer_source382(jsonb,boolean)'::regprocedure])
                """,owner);
            return (string)(await query.ExecuteScalarAsync(ct))!;
        }
        string before=await Definitions();
        string path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/383_detection_source_lock.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        Assert.Equal(before,await Definitions());
        await fixture.Pg.ApplyFileAsync(path,null,ct);await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Password_watermarks_advance_during_both_long_account_reads()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:Enumerable.Repeat(4625,10).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var runtime=Runtime(fixture);
        await using var detector=await runtime.OpenAsync(ct);
        var source=await Source(detector,ct);var scope=PasswordScope.Read(source["scope"]);
        await Bind(fixture,ct);
        var poller=new PasswordProducerPoller(runtime,new(),new DetectionProducer(new(),new()));
        var gates=new[]{new ReadGate(),new ReadGate()};int cycles=0,worked=0;
        async Task<SemanticProduction.DetectionOutcome> Detect() {
            await using var tx=await detector.BeginTransactionAsync(ct);
            var result=await SemanticProduction.RunDefaultSource(new SlowAccounts(new SemanticSession(detector,tx),gates),source,ct);
            await tx.CommitAsync(ct);return result;
        }
        var detecting=Detect();
        try {
            for(int i=0;i<gates.Length;i++) {
                Assert.Same(gates[i].Entered.Task,await Task.WhenAny(gates[i].Entered.Task,detecting));
                var target=DateTimeOffset.UtcNow.AddMinutes(-12); // 223: a cycle stops once the watermark is within twelve minutes
                var pending=poller.RunSourceAsync(scope,ct);
                bool blocked=false;
                while(!pending.IsCompleted) {
                    await using var wait=new NpgsqlCommand("select exists(select 1 from pg_locks where not granted and @pid=any(pg_blocking_pids(pid)))",owner);
                    wait.Parameters.AddWithValue("pid",detector.ProcessID);
                    if(await wait.ExecuteScalarAsync(ct) is true) {blocked=true;break;}
                    await Task.Yield();ct.ThrowIfCancellationRequested();
                }
                cycles++;
                if(!blocked) {
                    var results=await pending;
                    await using var watermark=new NpgsqlCommand("""
                        select count(distinct p.rule_id)=2 and bool_and(coalesce(c.watermark>=@target,false))
                        from password_pass_state393 p join semantic_password_checkpoints c
                          on c.scope_digest=p.scope_digest and c.pin=p.live_pin
                        """,owner);
                    watermark.Parameters.AddWithValue("target",target);
                    if(results.All(r=>r.Status=="committed")&&await watermark.ExecuteScalarAsync(ct) is true)worked++;
                }
                output.WriteLine($"reader={(i==0?"decoy":"watch")}; password cycles with work={worked}/{cycles}");
                // Release in finally even if the source lock regresses to a long wait.
                gates[i].Release.TrySetResult();await pending;
                Assert.False(blocked,"Password publication waited for the long account reader");
                Assert.Equal(cycles,worked);
            }
        } finally {foreach(var gate in gates)gate.Release.TrySetResult();await detecting;}
        Assert.Equal(0,(await detecting).Failed);
        foreach(string family in new[]{"decoy","watch"}) {
            await using var checkpoint=new NpgsqlCommand("""
                select last_evaluated_event_id from account_detection_checkpoints451 where family=@family
                """, owner);
            checkpoint.Parameters.AddWithValue("family", family);
            Assert.Contains(Assert.IsType<long>(await checkpoint.ExecuteScalarAsync(ct)), rows.Select(row => row.EventId));
        }
        await using(var pending=new NpgsqlCommand("select count(*) from account_detection_pending451",owner))
            Assert.Equal(0L,await pending.ExecuteScalarAsync(ct));
        await using(var count=new NpgsqlCommand("select count(*) from event_hot",owner))Assert.Equal(10L,await count.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Password_waits_for_family_before_source_and_queues_behind_source_owner()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:[4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var runtime=Runtime(fixture);
        await using var worker=await runtime.OpenAsync(ct);
        var scope=PasswordScope.Read((await Source(worker,ct))["scope"]);var rule=new PasswordRule(scope);
        await Bind(fixture,ct);
        await using(var tx=await owner.BeginTransactionAsync(ct)) {
            await using(var family=new NpgsqlCommand("select pg_advisory_xact_lock(hashtextextended(@key,0))",owner,tx)) {
                family.Parameters.AddWithValue("key",PasswordSignal.FamilyKey(scope,rule.Id));await family.ExecuteNonQueryAsync(ct);
            }
            var pending=new PasswordProducer().RunAsync(worker,rule,ct);
            try {
                Assert.True(await BlockedOrCompleted(owner,worker.ProcessID,pending,ct));
                // A policy writer holding the family can still take the source:
                // publication has not acquired it in the opposite order.
                await using var source=new NpgsqlCommand("select pg_try_advisory_xact_lock(hashtextextended(@key,0))",owner,tx);
                source.Parameters.AddWithValue("key",PasswordJson.Hash(scope.Document));
                Assert.Equal(true,await source.ExecuteScalarAsync(ct));
            } finally {await tx.RollbackAsync(ct);await pending;}
            Assert.Equal("committed",(await pending).Status);
        }
        await using(var tx=await owner.BeginTransactionAsync(ct)) {
            await using(var source=new NpgsqlCommand("select pg_advisory_xact_lock(hashtextextended(@key,0))",owner,tx)) {
                source.Parameters.AddWithValue("key",PasswordJson.Hash(scope.Document));await source.ExecuteNonQueryAsync(ct);
            }
            var poller=new PasswordProducerPoller(runtime,new(),new DetectionProducer(new(),new()));
            var pending=poller.RunSourceAsync(scope,ct);
            try {
                while(!pending.IsCompleted) {
                    await using var wait=new NpgsqlCommand("select exists(select 1 from pg_locks where not granted and @pid=any(pg_blocking_pids(pid)))",owner,tx);
                    wait.Parameters.AddWithValue("pid",owner.ProcessID);
                    if(await wait.ExecuteScalarAsync(ct) is true)break;
                    await Task.Yield();ct.ThrowIfCancellationRequested();
                }
                Assert.False(pending.IsCompleted,"Busy must remain queued in the same cycle");
            } finally {await tx.RollbackAsync(ct);await pending;}
            Assert.All(await pending,r=>Assert.Equal("committed",r.Status));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static PasswordProducerRuntime Runtime(SqlPostgresFixture fixture)=>PasswordProducerRuntime.Create(
        n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
    private static async Task<JsonObject> Source(NpgsqlConnection db,CancellationToken ct) {
        await using var source=new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",db);
        return JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!.AsObject();
    }
    private static async Task Bind(SqlPostgresFixture fixture,CancellationToken ct) {
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        await using var bind=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')::text",app);
        bind.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent);
        Assert.Equal("configured",JsonNode.Parse((string)(await bind.ExecuteScalarAsync(ct))!)!["status"]!.GetValue<string>());
    }
    private static async Task<bool> BlockedOrCompleted(NpgsqlConnection observer,int pid,Task pending,CancellationToken ct) {
        while(!pending.IsCompleted) {
            await using var wait=new NpgsqlCommand("select cardinality(pg_blocking_pids(@pid))>0",observer);
            wait.Parameters.AddWithValue("pid",pid);
            if(await wait.ExecuteScalarAsync(ct) is true)return true;
            await Task.Yield();ct.ThrowIfCancellationRequested();
        }
        await pending;return false;
    }
    private sealed class ReadGate {
        internal readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    private sealed class SlowAccounts(ISemanticSession inner,ReadGate[] gates):ISemanticSession {
        public async Task<JsonArray> QueryAsync(string sql,CancellationToken ct,params object?[] values) {
            var result=await inner.QueryAsync(sql,ct,values);
            int i=sql.Contains("read_account_decoy_events")?0:sql.Contains("read_account_watch_events")?1:-1;
            if(i>=0) {Assert.Equal(10,result.Count);gates[i].Entered.TrySetResult();await gates[i].Release.Task.WaitAsync(ct);}
            return result;
        }
        public Task CommitAsync(CancellationToken ct)=>throw new InvalidOperationException("caller_owns_transaction");
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
    }
}
