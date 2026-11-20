using Microsoft.Extensions.Configuration;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol.Compatibility;
using Sli.Agent.Protocol;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Detections;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests;

public sealed class SemanticRuntimePostgresTests(ITestOutputHelper output)
{
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Dead_continuous_pump_is_replaced_and_faulted_pulse_does_not_skip_disposal(bool beforeReady)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        var production = new SemanticProduction(runtime, new(true,true,false,false,false,false), "facts-v1", 1);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bool stopped = false;
        try {
            if (beforeReady) await PostCollectionPostgres.Sql(owner, "alter role sli_semantic_login nologin", ct);
            var first = await production.ContinuousPumpAsync(ct);
            if (beforeReady) {
                await Assert.ThrowsAsync<Sli.Server.Hosting.WorkerFailure>(() => first.Ready);
                await PostCollectionPostgres.Sql(owner, "alter role sli_semantic_login login", ct);
            }
            else {
                await first.Ready.WaitAsync(ct);
                Assert.Same(first, await production.ContinuousPumpAsync(ct));
                await using var kill = new NpgsqlCommand("select pg_terminate_backend(pid) from pg_stat_activity where usename='sli_semantic_login'", owner);
                Assert.True((bool)(await kill.ExecuteScalarAsync(ct))!);
            }
            await Assert.ThrowsAsync<Sli.Server.Hosting.WorkerFailure>(async () => {
                while (true) { await first.ProgressAsync(); await Task.Delay(10, ct); }
            });
            var replacement = await production.ContinuousPumpAsync(ct);
            Assert.NotSame(first, replacement);
            await replacement.Ready.WaitAsync(ct); Assert.Equal(0, (await replacement.ProgressAsync()).Number("failed"));
            var failure = new IOException("synthetic pulse failure");
            Assert.Same(failure, await Assert.ThrowsAsync<IOException>(() => production.StopAsync(Task.FromException(failure), stop)));
            stopped = true;
            // Unlike cancellation of the worker token, disposal must actually join
            // the pump, which here runs with the independent test token.
            await replacement.ProgressAsync();
            await using var sessions = new NpgsqlCommand("select count(*) from pg_stat_activity where usename='sli_semantic_login'", owner);
            while ((long)(await sessions.ExecuteScalarAsync(ct))! != 0) await Task.Delay(10, ct);
        }
        finally { if (!stopped) try { await production.StopAsync(Task.CompletedTask, stop); } catch (Sli.Server.Hosting.WorkerFailure) { } }
    }

    [Fact]
    public async Task Small_postgres_caps_sources_drains_each_detector_and_keeps_pump_and_storage_connected()
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var ct = timeout.Token;
        await using var fixture = new SqlPostgresFixture(maxConnections: 28); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        var work = new SemanticWork(independent: true, concurrency: 1);
        // Actual control sessions and production outbox pump stay outside source admission.
        await using var coordinator = await runtime.OpenAsync(ct);
        await using var heartbeat = await runtime.OpenAsync(ct);
        var pump = new SemanticOutboxPump(runtime, new(true,true,false,false,false,false), "facts-v1", 1, null, new(), ct);
        await pump.Ready;
        var others = new List<NpgsqlConnection>();
        var completed = new System.Collections.Concurrent.ConcurrentDictionary<int, bool>();
        var started = Enumerable.Range(0, 6).Select(_ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).ToArray();
        int running = 0, peak = 0;
        async Task<string> Source(int id) {
            await using var db = await runtime.OpenAsync(ct);
            int count = Interlocked.Increment(ref running);
            InterlockedExtensionsMax(count);
            try {
                await using var tx = await db.BeginTransactionAsync(ct);
                await using var command = new NpgsqlCommand("select pg_advisory_xact_lock(@key)", db, tx) { CommandTimeout = 0 };
                command.Parameters.AddWithValue("key", 900000L + id);
                SemanticWork.Query(db, command.CommandText); started[id].TrySetResult();
                await command.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
                completed[id] = true; return "committed";
            } finally { Interlocked.Decrement(ref running); }
        }
        void InterlockedExtensionsMax(int value) { int prior; do { prior = Volatile.Read(ref peak); if (prior >= value) return; } while (Interlocked.CompareExchange(ref peak, value, prior) != prior); }
        async Task<long> SemanticConnections() {
            await using var query = new NpgsqlCommand("select count(*) from pg_stat_activity where usename='sli_semantic_login'", owner);
            return (long)(await query.ExecuteScalarAsync(ct))!;
        }
        async Task AssertSemanticConnectionsAfterClose(long expected, long maximum) {
            // Client disposal finishes before PostgreSQL necessarily removes the backend.
            // Wait for server-side closure without allowing extra semantic connections.
            while (true) {
                long count = await SemanticConnections();
                Assert.InRange(count, expected, maximum);
                if (count == expected) return;
                await Task.Delay(10, ct);
            }
        }
        try {
            // Count the owner, eighteen other sessions and a real storage session.
            // Twenty occupied slots leave three controls and two sources (28 - 3).
            for (int i = 0; i < 18; i++) { var db = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await db.OpenAsync(ct); others.Add(db); }
            await using var storage = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await storage.OpenAsync(ct);
            var capacity = await SemanticCapacity.ReadAsync(coordinator, 4, ct);
            Assert.Equal(20, capacity.OtherServices); Assert.Equal(2, capacity.Sources); output.WriteLine(capacity.Json().ToJsonString());
            work.SetConcurrency(capacity.Sources);
            await PostCollectionPostgres.Sql(owner, "select pg_advisory_lock(k) from generate_series(900000::bigint,900005::bigint) k", ct);
            for (int i = 0; i < 6; i++) { int id = i; await work.Run("detector:" + id, () => Source(id), ct); }
            await Task.WhenAll(started[0].Task, started[1].Task).WaitAsync(ct);
            Assert.Equal(5L, await SemanticConnections()); Assert.Equal(4, work.Snapshot().Count(x => x.Text("status") == "queued"));
            await PostCollectionPostgres.Sql(storage, "select 1", ct);
            // Keep the heavy first source alive while every other detector gets its turn.
            for (int id = 1; id < 6; id++) {
                await started[id].Task.WaitAsync(ct);
                Assert.Equal(2, Volatile.Read(ref running)); Assert.True(await SemanticConnections() <= 5);
                await PostCollectionPostgres.Sql(owner, "select pg_advisory_unlock(" + (900000L + id) + ")", ct);
            }
            Assert.False(completed.ContainsKey(0));
            await PostCollectionPostgres.Sql(owner, "select pg_advisory_unlock(900000::bigint)", ct);
            await work.Drain().WaitAsync(ct);
            Assert.Equal(6, completed.Count); Assert.Equal(2, peak); Assert.Empty(work.Snapshot());
            await AssertSemanticConnectionsAfterClose(3, capacity.Sources + 3); // Every idle source session really closed.
            await pump.ProgressAsync();
            await pump.StopAsync(); await AssertSemanticConnectionsAfterClose(2, 3);
            // Source draining and pump shutdown must leave all other services connected.
            foreach (var db in others) await PostCollectionPostgres.Sql(db, "select 1", ct);
            await PostCollectionPostgres.Sql(storage, "select 1", ct);
            await PostCollectionPostgres.Sql(coordinator, "select 1", ct);
            await PostCollectionPostgres.Sql(heartbeat, "select 1", ct);
            await fixture.AssertNoSqlErrorsAsync(ct);
        }
        finally {
            await PostCollectionPostgres.Sql(owner, "select pg_advisory_unlock_all()", CancellationToken.None);
            timeout.Cancel(); await work.Drain();
            try { await pump.DisposeAsync(); } catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            foreach (var db in others) await db.DisposeAsync();
        }
    }

    [Fact]
    public async Task Real_53300_waits_then_retries_the_same_source_after_a_slot_is_released()
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30)); var ct = timeout.Token;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true, maxConnections: 40); await pg.StartAsync(ct);
        await using var owner = new NpgsqlConnection(pg.ConnectionString); await owner.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, "create role adlog_semantic_worker nologin; create role sli_semantic_login login noinherit; grant adlog_semantic_worker to sli_semantic_login; create role synthetic_other login", ct);
        string Dsn(string login) => new NpgsqlConnectionStringBuilder(pg.ConnectionString) { Username = login }.ConnectionString;
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using (var probe = await runtime.OpenAsync(ct)) {
            var capacity = await SemanticCapacity.ReadAsync(probe, 64, ct);
            Assert.Equal(1, capacity.OtherServices); Assert.Equal(33, capacity.Sources);
        }
        var occupied = new List<NpgsqlConnection>(); var work = new SemanticWork(independent: true, concurrency: 1); int commits = 0;
        async Task<string> Source() {
            await using var db = await runtime.OpenAsync(ct);
            // The restricted semantic role must count OTHER users' connections
            // without pg_read_all_stats or any added privileges.
            var budget = await SemanticCapacity.ReadAsync(db, 4, ct);
            Assert.Equal(33, budget.OtherServices); Assert.Equal(1, budget.Sources);
            await PostCollectionPostgres.Sql(db, "select 1", ct); commits++; return "committed";
        }
        try {
            for (int i = 0; i < 36; i++) { var db = new NpgsqlConnection(Dsn("synthetic_other")); await db.OpenAsync(ct); occupied.Add(db); }
            Assert.Null(await work.Run("synthetic", Source, ct)); await work.Drain();
            Assert.Null(await work.Run("synthetic", Source, ct)); Assert.Equal(0, commits);
            for (int i = 0; i < 4; i++) { await occupied[^1].DisposeAsync(); occupied.RemoveAt(occupied.Count - 1); }
            // Dispose sends Terminate; PostgreSQL removes its backend asynchronously.
            await using (var released = new NpgsqlCommand("select count(*) from pg_stat_activity where backend_type='client backend' and usename='synthetic_other'", owner))
                while ((long)(await released.ExecuteScalarAsync(ct))! != 32) await Task.Delay(10, ct);
            await work.Run("synthetic", Source, ct); await work.Drain();
            Assert.Equal("committed", await work.Run("synthetic", Source, ct)); Assert.Equal(1, commits);
        }
        finally { timeout.Cancel(); await work.Drain(); foreach (var db in occupied) await db.DisposeAsync(); }
    }

    [Fact]
    public async Task Every_production_mode_drains_short_event_backfill()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        async Task<JsonNode> RunMode(string mode)
        {
            var info = NativeProcess(fixture, mode == "findings-v1", bundle: true);
            info.Environment["ADLOG_SEMANTIC_RUNTIME_MODE"] = mode;
            if (mode == "investigation-v1") info.Environment["ADLOG_SEMANTIC_CORRELATION_ENABLED"] = "1";
            info.ArgumentList.Add("--once");
            using var process = Process.Start(info)!;
            var stdout = process.StandardOutput.ReadToEndAsync(ct); var stderr = process.StandardError.ReadToEndAsync(ct);
            try { await process.WaitForExitAsync(ct); }
            finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
            string text = await stdout, errors = await stderr;
            Assert.True(errors.Length == 0, errors); Assert.Equal(0, process.ExitCode);
            return JsonNode.Parse(text.Trim())!;
        }
        var ids = new List<long>();
        int source = 0;
        foreach (string mode in new[] { "facts-v1", "investigation-v1", "findings-v1" }) {
            var (_, rows) = await SeedShortAsync(fixture, owner, source++, ct);
            ids.AddRange(rows.Select(r => r.EventId));
            await using var coverage = new NpgsqlCommand("""
                select count(*) from unnest(@ids::bigint[]) input(event_id)
                where exists (select 1 from semantic_producer_coverage c where c.runtime_mode=@mode and c.decided_ids @> input.event_id)
                """, owner);
            coverage.Parameters.AddWithValue("ids", ids.ToArray());
            coverage.Parameters.AddWithValue("mode", mode);
            Assert.Equal(0L, await coverage.ExecuteScalarAsync(ct));
            var first = await RunMode(mode);
            Assert.Equal("short_events", first["producer_backfill"].Text("status"));
            Assert.Equal(ids.Count, first["producer_backfill"].Number("scanned"));
            long queued = first["producer_backfill"].Number("queued");
            Assert.Equal(mode == "facts-v1" ? 3L : 2L, queued);
            Assert.Equal((long)ids.Count, await coverage.ExecuteScalarAsync(ct));
            // A bounded --once can finish before its background normalizer sees
            // newly queued jobs. The next cycle drains them without queueing twice.
            var next = await RunMode(mode);
            Assert.Equal(0L, next["producer_backfill"].Number("scanned"));
            Assert.Equal(0L, next["producer_backfill"].Number("queued"));
            Assert.Equal(queued, first["processing"].Number("completed") + next["processing"].Number("completed"));
            foreach (var result in new[] { first, next }) {
                Assert.Equal(mode, result.Text("runtime_mode"));
                Assert.Equal(0L, result.Number("failed"));
                Assert.Equal(result["processing"].Number("completed") + result["dispatch"].Number("completed") + result["risk"].Number("completed"), result.Number("completed"));
                if (mode != "findings-v1") {
                    Assert.Equal(0L, result.Number("risk_queued")); Assert.Equal(0L, result.Number("findings_created"));
                    Assert.Null(result["risk"]); Assert.Null(result["detections"]); Assert.Null(result["sigma"]);
                    Assert.True(JsonNode.DeepEquals(new JsonObject { ["shadow"] = 0, ["enabled"] = 0 }, result["modes"]));
                }
                if (mode == "facts-v1") Assert.Equal(0L, result["dispatch"].Number("claimed"));
                Assert.Empty(result["import_summary"]!.AsObject());
            }
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Pump_backend_loss_is_visible_in_heartbeat_work_and_cycle_failure()
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60)); var ct = timeout.Token;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        var work = new SemanticWork(independent: true);
        var pump = new SemanticOutboxPump(runtime, new(true,true,false,false,false,false), "facts-v1", 1, null, new SemanticQueueRate(), ct, work);
        try {
            await pump.Ready;
            Assert.Equal("running", Assert.Single(work.Snapshot()).Text("status"));
            await PostCollectionPostgres.Sql(owner, "select pg_terminate_backend(pid) from pg_stat_activity where usename='sli_semantic_login'", ct);
            while (Assert.Single(work.Snapshot()).Text("status") != "error") await Task.Delay(20, ct);
            await SemanticProduction.Heartbeat(owner, Guid.NewGuid(), "facts-v1", "running", 5, ct, executing: work.Snapshot());
            await using var heartbeat = new NpgsqlCommand("select details_json->'executing'->0->>'status' from runtime_worker_heartbeats where worker_name='semantic'", owner);
            Assert.Equal("error", await heartbeat.ExecuteScalarAsync(ct));
            var error = await Assert.ThrowsAsync<Sli.Server.Hosting.WorkerFailure>(() => pump.StopAsync());
            Assert.Equal("processing_outbox", SemanticProduction.CycleFailure(error)["error"].Text("step"));
        }
        finally { try { await pump.DisposeAsync(); } catch (Sli.Server.Hosting.WorkerFailure) { } }
    }

    [Fact]
    public async Task Lock_wait_retries_do_not_exhaust_job_attempts_or_lose_imported_work()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString);await owner.OpenAsync(ct);
        var (_, events) = await SeedShortAsync(fixture,owner,0,ct);
        await using var control=new NpgsqlConnection(fixture.Pg.ConnectionString);await control.OpenAsync(ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var db=await runtime.OpenAsync(ct);await PostCollectionPostgres.Sql(db,"set lock_timeout='10ms'",ct);
        Assert.Equal(1L,(await SemanticProducerBackfill.RunAsync(db,"facts-v1",1,ct)).Number("queued"));
        await PostCollectionPostgres.Sql(owner,"update semantic_processing_outbox set max_attempts=1",ct);
        var production=new SemanticProduction(runtime,new(true,true,false,false,false,false),"facts-v1",1);
        await using(var blocker=await owner.BeginTransactionAsync(ct)) {
            await using var held=new NpgsqlCommand("select pg_advisory_xact_lock(hashtextextended(@key,0))",owner,blocker);
            held.Parameters.AddWithValue("key",$"semantic_source:{events[0].EventId}");
            await held.ExecuteNonQueryAsync(ct);
            for(int retry=0;retry<2;retry++) {
                var result=await production.ProcessOutbox(db,ct);Assert.Equal(1L,result.Number("claimed"));
                await using var check=new NpgsqlCommand("select status,attempt_count from semantic_processing_outbox",owner,blocker);
                await using(var rows=await check.ExecuteReaderAsync(ct)) {Assert.True(await rows.ReadAsync(ct));Assert.Equal("queued",rows.GetString(0));Assert.Equal(0,rows.GetInt32(1));}
                await PostCollectionPostgres.Sql(control,"update semantic_processing_outbox set available_at=now()",ct);
            }
            await blocker.CommitAsync(ct);
        }
        var completed=await production.ProcessOutbox(db,ct);Assert.Equal(1L,completed.Number("completed"));Assert.Equal(0L,completed.Number("failed"));
    }

    [Fact]
    public async Task Continuous_worker_reports_long_source_while_other_sources_and_import_advance()
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(3));
        var ct=timeout.Token;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString);await owner.OpenAsync(ct);
        var (slowHost, _) = await SeedShortAsync(fixture,owner,0,ct);
        var (otherHost, _) = await SeedShortAsync(fixture,owner,1,ct);
        // Hold one real reader until the test has observed concurrent progress.
        // The replacement retains its admission, native proof, OID, owner and grants.
        const long readerGate = 900006;
        await PostCollectionPostgres.Sql(owner,$"select pg_advisory_lock({readerGate})",ct);
        await using(var definition=new NpgsqlCommand("select pg_get_functiondef('public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure)",owner)) {
            string sql=(string)(await definition.ExecuteScalarAsync(ct))!;
            int begin=sql.IndexOf("\nbegin\n",StringComparison.OrdinalIgnoreCase);Assert.True(begin>0);
            sql=sql.Insert(begin+7,$"    if p_source='{slowHost:D}' then perform pg_advisory_xact_lock({readerGate}); end if;\n");
            await PostCollectionPostgres.Sql(owner,sql,ct);
        }
        var info=NativeProcess(fixture,true,true);info.ArgumentList.Add("--poll-seconds");info.ArgumentList.Add("5");
        using var process=Process.Start(info)!;
        var stdout=process.StandardOutput.ReadToEndAsync(ct);var stderr=process.StandardError.ReadToEndAsync(ct);
        async Task<(JsonObject Heartbeat,JsonObject Reader)> Observe(Func<JsonObject,JsonObject,bool> ready) {
            while(true) {
                Assert.False(process.HasExited,"worker exited before reporting the blocked reader");
                await using var query=new NpgsqlCommand("""
                    select to_jsonb(h)::text,operation::text
                    from runtime_worker_heartbeats h
                    cross join lateral jsonb_array_elements(h.details_json->'executing') as operation
                    where h.worker_name='semantic' and operation->>'query'='read_account_decoy_events'
                        and pg_backend_pid()=any(pg_blocking_pids((operation->>'backend_pid')::int))
                    """,owner);
                await using(var rows=await query.ExecuteReaderAsync(ct)) {
                    while(await rows.ReadAsync(ct)) {
                        var heartbeat=JsonNode.Parse(rows.GetString(0))!.AsObject();
                        var reader=JsonNode.Parse(rows.GetString(1))!.AsObject();
                        if(ready(heartbeat,reader))return (heartbeat,reader);
                    }
                }
                await Task.Delay(50,ct);
            }
        }
        async Task WaitForCheckpoint(Guid host) {
            await using var check=new NpgsqlCommand("select exists(select 1 from semantic_account_decoy_checks where scope_json->>'source_instance_id'=@host)",owner);
            check.Parameters.AddWithValue("host",host.ToString());
            while(await check.ExecuteScalarAsync(ct) is not true) {
                Assert.False(process.HasExited,"worker exited before committing the source checkpoint");
                await Task.Delay(50,ct);
            }
        }
        try {
            var (first,slow)=await Observe((_,_)=>true);
            Assert.NotNull(slow.Text("started_at"));Assert.NotNull(slow.Text("query_started_at"));
            Assert.True(slow.Number("backend_pid")>0);
            var firstHeartbeat=DateTimeOffset.Parse(first.Text("heartbeat_at")!);
            await PostCollectionPostgres.Sql(owner,"set lock_timeout='500ms'",ct);
            var (_, imported) = await SeedShortAsync(fixture,owner,2,ct);
            await using(var read=new NpgsqlCommand("select count(*) from event_hot where event_id=any(@ids)",owner)) {
                read.Parameters.AddWithValue("ids", imported.Select(row => row.EventId).ToArray());
                Assert.Equal((long)imported.Length,await read.ExecuteScalarAsync(ct));
            }
            await WaitForCheckpoint(otherHost);
            await Observe((h,operation)=>operation.Text("operation")==slow.Text("operation") &&
                operation.Text("query_started_at")==slow.Text("query_started_at") &&
                operation.Number("backend_pid")==slow.Number("backend_pid") &&
                DateTimeOffset.Parse(h.Text("heartbeat_at")!)>firstHeartbeat.AddSeconds(4));
            await PostCollectionPostgres.Sql(owner,$"select pg_advisory_unlock({readerGate})",ct);
            await WaitForCheckpoint(slowHost);
            string stop=Path.Combine(fixture.Pg.Root,"runtime","semantic-production-stop.json");Directory.CreateDirectory(Path.GetDirectoryName(stop)!);
            await File.WriteAllTextAsync(stop,new JsonObject{["requested_at_utc"]=DateTimeOffset.UtcNow.ToString("O")}.ToJsonString(),ct);
            await process.WaitForExitAsync(ct);await stdout;string errors=await stderr;
            Assert.Equal(0,process.ExitCode);
            Assert.DoesNotContain("client_timeout",errors);Assert.DoesNotContain("57014",errors);
        }
        finally {if(!process.HasExited){process.Kill(true);await process.WaitForExitAsync(CancellationToken.None);}}
    }

    [Fact]
    public async Task Live_semantic_queries_outlast_old_server_and_client_limits_without_blocking_import()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString);await owner.OpenAsync(ct);
        var factory=new Sli.Server.Infrastructure.PostgresConnectionFactory(new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string,string?> { ["ConnectionStrings:Sli"]=fixture.Pg.ConnectionString }).Build());
        async Task ReadSnapshot()
        {
            await using var session=await new SemanticDatabase(factory).OpenAsync(false,ct);
            var rows=await session.QueryAsync("select true as completed from pg_sleep(31)",ct);
            Assert.True(rows[0].Flag("completed"));await session.CommitAsync(ct);
        }
        await using var db=await runtime.OpenAsync(ct);
        await using var tx=await db.BeginTransactionAsync(ct);
        var sql=new DetectionSql(db,tx);
        var snapshot=ReadSnapshot();
        var reader=sql.Rows("select true as completed from pg_sleep(31)",ct);
        // Observe execution, rather than sleeping and guessing that it started.
        await WaitForSleepAsync(owner,db.ProcessID,reader,ct);
        // Actual short event writes run while the read is alive.
        await PostCollectionPostgres.Sql(owner,"set lock_timeout='500ms'",ct);
        var (_, imported) = await SeedShortAsync(fixture,owner,0,ct);
        Assert.False(reader.IsCompleted);
        await using(var read=new NpgsqlCommand("select count(*) from event_hot where event_id=any(@ids)",owner)) {
            read.Parameters.AddWithValue("ids", imported.Select(row => row.EventId).ToArray());
            Assert.Equal((long)imported.Length,await read.ExecuteScalarAsync(ct));
        }
        Assert.True((await reader)[0].Flag("completed"));await tx.CommitAsync(ct);await snapshot;
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    static async Task WaitForSleepAsync(NpgsqlConnection observer,int pid,Task query,CancellationToken ct)
    {
        while(true) {
            // A failed query (or an already missed sleep) cannot enter PgSleep
            // later. Surface its failure instead of polling an idle/dead backend.
            if(query.IsCompleted) {
                await query;
                Assert.Fail("Query completed before PgSleep was observed");
            }
            await using var activity=new NpgsqlCommand("select wait_event='PgSleep' from pg_stat_activity where pid=@pid",observer);
            activity.Parameters.AddWithValue("pid",pid);
            if(await activity.ExecuteScalarAsync(ct) is true) return;
            await Task.Delay(20,ct);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Finished_query_does_not_leave_sleep_observation_waiting(bool failed)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(ct);
        await using var db=new NpgsqlConnection(pg.ConnectionString);await db.OpenAsync(ct);
        var query=PostCollectionPostgres.Sql(db,failed ? "select 1/0" : "select 1",ct);
        var failure=await Record.ExceptionAsync(()=>query);
        // Cancellation makes a regressed observer terminate too. A finished query
        // must be reported before attempting another observation of its backend.
        using var cancelled=CancellationTokenSource.CreateLinkedTokenSource(ct);cancelled.Cancel();
        var observed=await Record.ExceptionAsync(()=>WaitForSleepAsync(db,db.ProcessID,query,cancelled.Token));
        if(failed) Assert.Same(Assert.IsType<PostgresException>(failure),observed);
        else Assert.Contains("Query completed before PgSleep was observed",Assert.IsAssignableFrom<Xunit.Sdk.XunitException>(observed).Message);
    }

    [Fact]
    public async Task Sleep_observation_can_be_cancelled_while_query_is_blocked()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(ct);
        await using var owner=new NpgsqlConnection(pg.ConnectionString);await owner.OpenAsync(ct);
        await using var reader=new NpgsqlConnection(pg.ConnectionString);await reader.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner,"select pg_advisory_lock(83)",ct);
        var query=PostCollectionPostgres.Sql(reader,"select pg_advisory_lock(83)",ct);
        try {
            Assert.False(query.IsCompleted);
            using var cancelled=CancellationTokenSource.CreateLinkedTokenSource(ct);cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>WaitForSleepAsync(owner,reader.ProcessID,query,cancelled.Token));
            Assert.False(query.IsCompleted);
        }
        finally {
            await PostCollectionPostgres.Sql(owner,"select pg_advisory_unlock(83)",ct);
            await query.WaitAsync(ct);
        }
    }

    [Fact]
    public async Task A_disappearing_semantic_backend_is_reported_as_an_error()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var db=await runtime.OpenAsync(ct);
        await using var command=new NpgsqlCommand("select pg_sleep(60)",db);
        var query=command.ExecuteNonQueryAsync(ct);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString);await owner.OpenAsync(ct);
        await using var kill=new NpgsqlCommand("select pg_terminate_backend(@pid)",owner);kill.Parameters.AddWithValue("pid",db.ProcessID);
        Assert.Equal(true,await kill.ExecuteScalarAsync(ct));
        var error=await Assert.ThrowsAnyAsync<NpgsqlException>(async()=>await query);
        var diagnostic=DetectionDiagnostics.Describe(error,"source");
        Assert.True(diagnostic.Text("sql_state")=="57P01" || diagnostic.Text("reason")=="connection_lost",diagnostic.ToJsonString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Summary320_roundtrip_preserves_clean_and_postgres_owned_tables(bool upgraded)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct, throughVersion: 319);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        async Task<string> Scalar(string sql) {
            await using var q=new NpgsqlCommand(sql,db);return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        string directory=Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations");
        string forward=Path.Combine(directory,"320_semantic_import_summary.sql"),rollback=Path.Combine(directory,"320_semantic_import_summary.rollback.sql");
        Assert.Equal("319",await Scalar("select max(version)::text from schema_migrations"));
        if(upgraded) {
            // Historical owners differ from the clean baseline. Keep the
            // existing runtime reader rights when transferring ownership.
            foreach(string table in new[]{"raw_log_files","events_v2_core","sli_agent_packet_inbox","sli_agent_receipts","normalized_events"})
                await PostCollectionPostgres.Sql(db,$"alter table public.{table} owner to postgres;grant select on public.{table} to adlog_storage_owner",ct);
        }
        const string tables="""
            select jsonb_agg(jsonb_build_array(relname,relowner,relacl::text) order by relname)::text
            from pg_class where oid in ('raw_log_files'::regclass,'events_v2_core'::regclass,
                'sli_agent_packet_inbox'::regclass,'sli_agent_receipts'::regclass,'normalized_events'::regclass,'semantic_t109_seen'::regclass)
            """;
        const string readers="""
            select jsonb_agg(jsonb_build_array(oid,proowner,proacl::text,prosecdef,proconfig,pg_get_functiondef(oid)) order by oid)::text
            from pg_proc where oid in ('t109_detection_sources()'::regprocedure,'default_detection_sources_before_v301()'::regprocedure,
                'read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure,'read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure)
            """;
        string tableAuthority=await Scalar(tables),originalReaders=await Scalar(readers);
        output.WriteLine($"320 owners upgraded={upgraded}: "+tableAuthority);
        await SeedNative(db,ct,canonicalAssignment:true);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        // The staged-upgrade reader must tolerate a predecessor without the summary.
        Assert.Empty(await ReadProgress());
        for(int pass=0;pass<2;pass++) {
            await fixture.Pg.ApplyFileAsync(forward,null,ct);
            Assert.Equal("320",await Scalar("select max(version)::text from schema_migrations"));
            Assert.Equal(tableAuthority,await Scalar(tables));
            Assert.Equal("20",await Scalar("select count(*)::text from pg_trigger where tgname in ('semantic_import_insert320','semantic_import_update320','semantic_import_old320','semantic_import_delete320')"));
            Assert.Equal("3",await Scalar("select count(*)::text from pg_indexes where indexname in ('semantic_seen_scope320','semantic_event_packet320','semantic_event_cursor320')"));
            Assert.Equal("true",await Scalar("""
                select (proowner='adlog_storage_owner'::regrole and prosecdef
                    and proconfig=array['search_path=pg_catalog, pg_temp']
                    and not has_function_privilege('adlog_user',oid,'EXECUTE')
                    and not has_function_privilege('adlog_semantic_worker',oid,'EXECUTE'))::text
                from pg_proc where oid='semantic_import_notify320()'::regprocedure
                """));
            // All statement triggers execute as their restricted definer,
            // including empty transition tables on the historical relations.
            foreach(var (table,key) in new[]{("raw_log_files","id"),("events_v2_core","id"),("sli_agent_packet_inbox","packet_id"),("sli_agent_receipts","sequence"),("normalized_events","source_event_id")})
                await PostCollectionPostgres.Sql(db,$"insert into public.{table}({key}) select {key} from public.{table} where false;update public.{table} set {key}={key} where false;delete from public.{table} where false",ct);
            await PostCollectionPostgres.Sql(worker,"select public.semantic_import_refresh320()",ct);
            await PostCollectionPostgres.Sql(worker,"select public.semantic_default_refresh320()",ct);
            var progress=await ReadProgress();
            Assert.True(progress["bootstrap_done"]!.GetValue<bool>());
            Assert.Equal("3",await Scalar("select count(*)::text from semantic_event_facts320"));
            if(pass==0) {
                await fixture.Pg.ApplyFileAsync(rollback,null,ct);
                Assert.Equal("319",await Scalar("select max(version)::text from schema_migrations"));
                Assert.Equal(tableAuthority,await Scalar(tables));Assert.Equal(originalReaders,await Scalar(readers));
                Assert.Equal("0",await Scalar("select count(*)::text from pg_trigger where tgname like 'semantic_import_%320'"));
                Assert.Equal("0",await Scalar("select count(*)::text from pg_class where relname in ('semantic_seen_scope320','semantic_event_packet320','semantic_event_cursor320')"));
            }
        }
        await fixture.AssertNoSqlErrorsAsync(ct);

        async Task<JsonObject> ReadProgress()
        {
            await using var tx=await worker.BeginTransactionAsync(ct);
            var progress=await DetectionProducer.ReadImportProgress(new DetectionSql(worker,tx),ct);
            await tx.CommitAsync(ct);
            return progress;
        }
    }

    [Fact]
    public void Processing_diagnostics_never_include_untrusted_exception_fields()
    {
        var pg = new PostgresException("event XML password", "ERROR", "ERROR", "42501", detail:"private detail", constraintName:"untrusted constraint");
        var detail = JsonNode.Parse(SemanticProcessingFailure.Describe(new InvalidOperationException("secret", pg), SemanticProcessingStep.SourceRead))!;
        Assert.Equal("source_read", (string?)detail["step"]);
        Assert.Equal("42501", (string?)detail["sql_state"]);
        Assert.Equal(3, detail.AsObject().Count);
        Assert.DoesNotContain("secret", detail.ToJsonString());
        Assert.DoesNotContain("private", detail.ToJsonString());
        Assert.Null(JsonNode.Parse(SemanticProcessingFailure.Describe(new IOException("event XML"), SemanticProcessingStep.Normalize))!["sql_state"]);
    }

    [Fact]
    public async Task Current_schema_processes_short_events_and_publishes_finding_as_semantic_login()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        async Task<string> Scalar(string sql) { await using var c = new NpgsqlCommand(sql, owner); return (string)(await c.ExecuteScalarAsync(ct))!; }
        await using var runtime = PasswordProducerRuntime.Create(name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner,"""
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.file-audit',
                'synthetic-wait','synthetic-generation','synthetic-root','file_audit_observation',md5('synthetic-wait-agent')::uuid
            from semantic_default_installation;
            """,ct);
        var waitingSource = new JsonObject {
            ["scope"] = new JsonObject { ["installation_id"] = await Scalar("select installation_id::text from semantic_default_installation"),
                ["plugin_id"] = "sli.file-audit", ["source_instance_id"] = "synthetic-wait", ["source_generation"] = "synthetic-generation", ["collection_scope_id"] = "synthetic-root" },
            ["agent_id"] = "00000000-0000-4000-8000-000000000001", ["config"] = new JsonObject { ["policy_revision"] = "1" },
            ["ransom_policy"] = new JsonObject { ["state"] = "waiting" }
        };
        await using (var waitingTx = await worker.BeginTransactionAsync(ct)) {
            var session = new SemanticSession(worker,waitingTx);
            var now = DateTimeOffset.UtcNow;
            foreach (int seconds in new[] { 0, 1 }) {
                var outcome = await SemanticProduction.ManagedRansom(session,waitingSource,now.AddSeconds(seconds),ct);
                // Frozen Python explicitly counts both initial and cached waits
                // as failed=1. The owner's conditional instruction preserves it.
                Assert.Equal(1,outcome.Failed); Assert.Equal(1,outcome.Waiting); Assert.Equal(0,outcome.Jobs);
            }
            await waitingTx.RollbackAsync(ct);
        }
        await PostCollectionPostgres.Sql(owner,"delete from finding_evidence_source_bindings where source_instance_id='synthetic-wait'",ct);
        Guid workerId = Guid.NewGuid();
        await SemanticProduction.Heartbeat(worker,workerId,"findings-v1","idle",10,ct,new JsonObject { ["status"]="ok",["findings_created"]=1 });
        await SemanticProduction.Heartbeat(worker,workerId,"findings-v1","running",10,ct);
        await PostCollectionPostgres.Sql(owner,"update runtime_worker_heartbeats set heartbeat_at=now()-interval '10 minutes' where worker_name='semantic'",ct);
        await SemanticProduction.Heartbeat(worker,workerId,"findings-v1","partial",70,ct,new JsonObject { ["status"]="partial",["failed"]=1,["findings_created"]=1,["detections"]=new JsonObject { ["sources"]=2,["failed"]=1 } });
        await SemanticProduction.Heartbeat(worker,workerId,"findings-v1","running",70,ct);
        var heartbeat=JsonNode.Parse(await Scalar("select to_jsonb(h)::text from runtime_worker_heartbeats h where worker_name='semantic'"))!.AsObject();
        Assert.True(Sli.Server.Problems.ProblemPresentation.Runtime(heartbeat,DateTimeOffset.UtcNow).Flag("fresh"));
        Assert.Equal(1L,heartbeat["details_json"]!["result"].Number("findings_created"));
        Assert.Equal(1L,heartbeat["details_json"]!["result"].Number("failed"));
        // Actual cycle cadence includes work plus polling; an active one-minute
        // cycle must not become stale merely because its poll delay is 10s.
        Assert.Equal("active",Sli.Server.Problems.ProblemPresentation.Runtime(heartbeat,DateTimeOffset.UtcNow.AddSeconds(75)).Text("findings_state"));
        heartbeat["status"]="partial";
        Assert.Equal("active",Sli.Server.Problems.ProblemPresentation.Runtime(heartbeat,DateTimeOffset.UtcNow).Text("findings_state"));
        Assert.Equal("active",Sli.Server.Domains.HomeSummaryReaders.Runtime(heartbeat,DateTimeOffset.UtcNow));
        // An old partial from an all-failed cycle is not evidence of activity.
        var allFailed = new JsonObject { ["status"]="partial",["failed"]=2,["detections"]=new JsonObject { ["sources"]=2,["failed"]=2 } };
        Assert.Equal("error",SemanticProduction.CycleStatus(allFailed));
        await SemanticProduction.Heartbeat(worker,workerId,"findings-v1","partial",70,ct,allFailed);
        await SemanticProduction.Heartbeat(worker,workerId,"findings-v1","running",70,ct);
        heartbeat=JsonNode.Parse(await Scalar("select to_jsonb(h)::text from runtime_worker_heartbeats h where worker_name='semantic'"))!.AsObject();
        Assert.Equal("inactive",Sli.Server.Problems.ProblemPresentation.Runtime(heartbeat,DateTimeOffset.UtcNow).Text("findings_state"));
        Assert.Equal("inactive",Sli.Server.Domains.HomeSummaryReaders.Runtime(heartbeat,DateTimeOffset.UtcNow));
        allFailed["detections"]!["file_ransom_status"]=new JsonObject { ["code"]="source_policy_waiting",["sources"]=2 };
        Assert.Equal("partial",SemanticProduction.CycleStatus(allFailed));
        await SemanticProduction.Heartbeat(worker,workerId,"findings-v1","partial",70,ct,allFailed);
        heartbeat=JsonNode.Parse(await Scalar("select to_jsonb(h)::text from runtime_worker_heartbeats h where worker_name='semantic'"))!.AsObject();
        Assert.Equal(2L,heartbeat["details_json"]!["result"].Number("failed"));
        Assert.Equal("active",Sli.Server.Problems.ProblemPresentation.Runtime(heartbeat,DateTimeOffset.UtcNow).Text("findings_state"));
        Assert.Equal("active",Sli.Server.Domains.HomeSummaryReaders.Runtime(heartbeat,DateTimeOffset.UtcNow));
        await SeedShortAsync(fixture,owner,0,ct);
        Assert.Equal(3L,(await SemanticProducerBackfill.RunAsync(worker,"facts-v1",10,ct)).Number("queued"));
        var unavailable = await RunNative(fixture,findings:false,bundle:false,ct);
        Assert.Equal(3L,unavailable["processing"].Number("failed"));
        var errors = JsonNode.Parse(await Scalar("select jsonb_agg(last_error_detail::jsonb)::text from semantic_processing_outbox"))!.AsArray();
        Assert.All(errors, error => { Assert.Equal("bundle_admission",(string?)error!["step"]); Assert.Null(error["sql_state"]); Assert.Equal(3,error.AsObject().Count); });
        await PostCollectionPostgres.Sql(owner,"update semantic_processing_outbox set available_at=now() where status='failed'",ct);
        var result = await RunNative(fixture,findings:true,bundle:true,ct);
        output.WriteLine(result.ToJsonString());
        Assert.True(result["detections"].Number("sources") > 0);
        Assert.True(result["password_producer"].Number("sources") > 1);
        Assert.Equal(0L, result["detections"].Number("failed"));
        Assert.Equal(0L, result["password_producer"].Number("failed"));
        output.WriteLine(await Scalar("select coalesce(jsonb_agg(jsonb_build_object('code',last_error_code,'detail',last_error_detail)),'[]')::text from semantic_processing_outbox where last_error_code is not null"));
        Assert.Equal(3L,result["processing"].Number("completed"));
        Assert.Equal(0L,result.Number("failed"));
        Assert.True(result.Number("findings_created")>0);
        Assert.Equal("3",await Scalar("select count(*)::text from normalized_events"));
        Assert.Equal("1",await Scalar("select count(*)::text from findings where rule_code='semantic.qw.security-log-cleared'"));
        Assert.Equal(1L,result["password_producer"].Number("skipped"));
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_password_checkpoints"));
        await PostCollectionPostgres.Sql(worker,"""
            do $$ declare s jsonb; begin
                select source->'scope' into strict s from public.default_detection_sources();
                if public.password_source_ready_v314(s) is distinct from false then raise exception 'unconfigured_source_was_ready'; end if;
                begin perform public.password_source_ready_v314(s||'{"source_generation":"unbound"}'::jsonb);
                    raise exception 'unbound_source_was_accepted';
                exception when insufficient_privilege then null; end;
            end $$;
            """,ct);
        var again = await RunNative(fixture,findings:true,bundle:true,ct);
        Assert.Equal(0L,again.Number("failed")); Assert.Equal(0L,again.Number("findings_created"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Policy314_roundtrip_preserves_worker_read_authority()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 314);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using var runtime = PasswordProducerRuntime.Create(name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        async Task<string> Scalar(string sql) { await using var c = new NpgsqlCommand(sql, owner); return (string)(await c.ExecuteScalarAsync(ct))!; }
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory,"314_semantic_runtime_readers.sql"), rollback = Path.Combine(directory,"314_semantic_runtime_readers.rollback.sql");
        async Task<string> Policy() { await using var c = new NpgsqlCommand("select public.read_t109_policy()::text", worker); return (string)(await c.ExecuteScalarAsync(ct))!; }
        Assert.Equal("{}", await Policy()); // clean-install path
        await PostCollectionPostgres.Sql(owner, """
            insert into platform_settings(key,value,updated_by) values('security.t109.policy','{"fast_files":12}','synthetic');
            insert into platform_settings(key,value,updated_by) values('security.unrelated','private synthetic setting','synthetic');
            """, ct);
        Assert.Equal(12, JsonNode.Parse(await Policy())!["fast_files"]!.GetValue<int>());
        string authoritySql = "select jsonb_build_object('oid',oid,'owner',proowner,'acl',proacl::text,'definer',prosecdef,'config',proconfig)::text from pg_proc where oid='public.read_t109_policy()'::regprocedure";
        string authority = await Scalar(authoritySql);
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        Assert.Equal(authority, await Scalar(authoritySql));
        string original = await Scalar("select pg_get_functiondef('public.read_t109_policy()'::regprocedure)");
        // Reproduce schema312's permission failure inside a caught subtransaction.
        // Test both historical postgres-owned and fresh adlog_user-owned settings.
        foreach (string settingsOwner in new[] { "postgres", "adlog_user" }) {
            await PostCollectionPostgres.Sql(owner, "alter table platform_settings owner to " + settingsOwner + "; grant select on platform_settings to adlog_user", ct);
            await PostCollectionPostgres.Sql(worker, """
                do $$ begin
                    begin perform public.read_t109_policy(); raise exception 'permission_failure_missing';
                    exception when insufficient_privilege then null; end;
                end $$;
                """, ct);
            await fixture.Pg.ApplyFileAsync(forward, null, ct);
            Assert.Equal(authority, await Scalar(authoritySql));
            Assert.Equal(12, JsonNode.Parse(await Policy())!["fast_files"]!.GetValue<int>());
            Assert.Equal("true", await Scalar("""
                select (not has_table_privilege('adlog_semantic_worker','platform_settings','SELECT')
                    and not has_table_privilege('adlog_storage_owner','platform_settings','SELECT')
                    and not has_table_privilege('adlog_storage_owner','semantic_t109_setting_v314','INSERT,UPDATE,DELETE')
                    and not has_table_privilege('adlog_semantic_worker','semantic_t109_setting_v314','SELECT')
                    and (select count(*)=1 from semantic_t109_setting_v314))::text
                """));
            await fixture.Pg.ApplyFileAsync(rollback, null, ct);
            Assert.Equal(original, await Scalar("select pg_get_functiondef('public.read_t109_policy()'::regprocedure)"));
        }
        await fixture.Pg.ApplyFileAsync(forward, null, ct); // previous maximum312 accepts314
        Assert.Equal("314", await Scalar("select max(version)::text from schema_migrations"));
        Assert.Equal(authority, await Scalar(authoritySql));
        Assert.Equal(12, JsonNode.Parse(await Policy())!["fast_files"]!.GetValue<int>());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Eighteen_admitted_sources_run_real_discovery_and_create_native_findings_without_failures()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        for(int source=0;source<18;source++)await SeedShortAsync(fixture,db,source,ct);
        await PostCollectionPostgres.Sql(db,"update sli_agent_module_bindings set password_detection_domain_id=(select id from domains limit 1)",ct);
        var result=await RunNative(fixture,true,true,ct);output.WriteLine(result.ToJsonString());
        Assert.Equal(18L,result["detections"].Number("sources"));
        Assert.Equal(54L,result["password_producer"].Number("sources"));
        Assert.Equal(0L,result["detections"].Number("failed"));Assert.Equal(0L,result["password_producer"].Number("failed"));
        Assert.Empty(result["detections"]!["failure_reasons"]!.AsObject());
        Assert.Empty(result["password_producer"]!["failure_reasons"]!.AsObject());
        // The existing risk consumer publishes at most 16 jobs per cycle.
        Assert.Equal(16L,result.Number("findings_created"));
        Assert.Equal(16L,result["modes"].Number("enabled")); Assert.Equal(0L,result["modes"].Number("shadow"));
        var remainder=await RunNative(fixture,true,true,ct);
        Assert.Equal(0L,remainder.Number("failed"));
        Assert.Equal(18L,result.Number("findings_created")+remainder.Number("findings_created"));
        Assert.Equal(0L,result["password_producer"].Number("skipped"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Repeated_cycle_exceptions_replace_success_and_remain_failed_during_retry()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString);await owner.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner,"""
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
                values('synthetic-admission',1,'control_health','disabled','{}',sha256('{}'::bytea));
            insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by) values('synthetic-admission',1,false,'synthetic');
            """,ct);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(60));var bounded=timeout.Token;
        var info=NativeProcess(fixture,true,true);info.ArgumentList.Add("--poll-seconds");info.ArgumentList.Add("5");
        using var process=Process.Start(info)!;
        async Task<JsonObject> Heartbeat(Func<JsonObject,bool> ready)
        {
            while(true) {
                await using var command=new NpgsqlCommand("select to_jsonb(h)::text from runtime_worker_heartbeats h where worker_name='semantic'",owner);
                if(await command.ExecuteScalarAsync(bounded) is string text) { var row=JsonNode.Parse(text)!.AsObject();if(ready(row))return row; }
                await Task.Delay(50,bounded);
            }
        }
        try {
            string? first=await process.StandardOutput.ReadLineAsync(bounded);
            Assert.NotNull(first);Assert.Equal("ok",JsonNode.Parse(first).Text("status"));
            var successful=await Heartbeat(h=>h.Text("status")=="idle" && h["details_json"]?["result"].Text("status")=="ok");
            // Only this disposable cluster loses the function grant. The real
            // RunWorker catch must replace its previous successful result.
            await PostCollectionPostgres.Sql(owner,"revoke execute on function expire_semantic_suppressions_v160() from adlog_semantic_worker",bounded);
            DateTimeOffset? previous=null;
            for(int cycle=0;cycle<2;cycle++) {
                string? line=await process.StandardError.ReadLineAsync(bounded);
                Assert.NotNull(line);Assert.StartsWith("semantic_production_cycle_failed:",line);
                var failed=await Heartbeat(h=>h.Text("status")=="error" && h["details_json"]?["result"].Text("status")=="error"
                    && (previous is null || DateTimeOffset.Parse(h.Text("heartbeat_at")!)>previous));
                previous=DateTimeOffset.Parse(failed.Text("heartbeat_at")!);
                Assert.Equal(successful.Text("worker_id"),failed.Text("worker_id"));
                var result=failed["details_json"]!["result"]!;
                Assert.Equal(1L,result.Number("failed"));Assert.Null(result["detections"]);
                Assert.Equal("expire_semantic_suppressions_v160",result["error"].Text("step"));Assert.Equal("42501",result["error"].Text("sql_state"));
                Assert.Equal("inactive",Sli.Server.Problems.ProblemPresentation.Runtime(failed,DateTimeOffset.UtcNow).Text("findings_state"));
                Assert.Equal("inactive",Sli.Server.Domains.HomeSummaryReaders.Runtime(failed,DateTimeOffset.UtcNow));
                await using var runtime=PasswordProducerRuntime.Create(name=>name=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
                await using var db=await runtime.OpenAsync(bounded);
                await SemanticProduction.Heartbeat(db,Guid.Parse(failed.Text("worker_id")!),"findings-v1","running",10,bounded);
                var retry=await Heartbeat(h=>h.Text("status")=="error");
                Assert.True(JsonNode.DeepEquals(result,retry["details_json"]!["result"]));
            }
            string stop=Path.Combine(fixture.Pg.Root,"runtime","semantic-production-stop.json");Directory.CreateDirectory(Path.GetDirectoryName(stop)!);
            await File.WriteAllTextAsync(stop,new JsonObject { ["requested_at_utc"]=DateTimeOffset.UtcNow.ToString("O") }.ToJsonString(),bounded);
            await process.WaitForExitAsync(bounded);Assert.Equal(1,process.ExitCode);
        }
        finally { if(!process.HasExited) { process.Kill(true);await process.WaitForExitAsync(CancellationToken.None); } }
    }

    internal static ProcessStartInfo NativeProcess(SqlPostgresFixture fixture,bool findings,bool bundle)
    {
        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet") {
            UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,
            RedirectStandardOutput=true,RedirectStandardError=true,
            // Installed .NET has no source config in its working directory.
            WorkingDirectory=Path.GetPathRoot(SqlPostgresFixture.Repository())!
        };
        foreach (string name in info.Environment.Keys.Where(k => k.StartsWith("ADLOG_",StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("SLI",StringComparison.OrdinalIgnoreCase) || k.StartsWith("PG",StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("ConnectionStrings",StringComparison.OrdinalIgnoreCase)).ToArray()) info.Environment.Remove(name);
        info.ArgumentList.Add(typeof(Program).Assembly.Location);info.ArgumentList.Add("semantic-production-worker");
        info.Environment["ADLOG_SEMANTIC_WORKER_DSN"]=fixture.Dsn("sli_semantic_login");
        info.Environment["ADLOG_DATA_DIR"]=fixture.Pg.Root;
        foreach (string name in new[]{"PRODUCTION","NORMALIZATION","ASSEMBLY"}) info.Environment["ADLOG_SEMANTIC_"+name+"_ENABLED"]="1";
        foreach (string name in new[]{"CORRELATION","RISK_ENGINE","FINDING_CREATION"}) info.Environment["ADLOG_SEMANTIC_"+name+"_ENABLED"]=findings?"1":"0";
        info.Environment["ADLOG_SEMANTIC_RUNTIME_MODE"]=findings?"findings-v1":"facts-v1";
        if(bundle)info.Environment["SLI_PLUGIN_LOCK_DIR"]=Path.Combine(SqlPostgresFixture.Repository(),"config/plugin_packages/v3");
        return info;
    }
    private static async Task<JsonObject> RunNative(SqlPostgresFixture fixture,bool findings,bool bundle,CancellationToken ct)
    {
        var info=NativeProcess(fixture,findings,bundle);info.ArgumentList.Add("--once");
        using var process = Process.Start(info)!;
        var stdout=process.StandardOutput.ReadToEndAsync(ct);var stderr=process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);string text=await stdout,errors=await stderr;
        Assert.True(errors.Length==0,errors);Assert.Equal(findings?0:1,process.ExitCode);
        return JsonNode.Parse(text.Trim())!.AsObject();
    }

    internal static async Task<(Guid Host, ShortEventRow[] Events)> SeedShortAsync(
        SqlPostgresFixture fixture, NpgsqlConnection db, int source, CancellationToken ct)
    {
        Guid agent = Guid.NewGuid(), host = Guid.NewGuid();
        long server = 900001 + source * 10;
        const long domain = 1;
        string hostName = $"dc{source}.example.test";
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(db,agent,host,server,domain,hostName,"Security",ct);
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(db,ct,registered:(agent,host,server,domain),
            packetId:Guid.NewGuid(),firstRecordId:1+source*10,hostName:hostName);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await PostCollectionPostgres.Sql(db,"""
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
                values('synthetic-admission',1,'control_health','disabled','{}',sha256('{}'::bytea)) on conflict do nothing;
            insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
                values('synthetic-admission',1,false,'synthetic') on conflict do nothing;
            """,ct);
        return (host, rows);
    }

    internal static async Task SeedNative(NpgsqlConnection db,CancellationToken ct,int source=0,bool recent=false,bool canonicalAssignment=false,bool powershell=false)
    {
        var row = new JsonObject {
            ["event_id"]=1102,["record_id"]=1,["time_created"]="2026-11-01T00:00:00Z",
            ["channel"]="Security",["computer_name"]="dc.example.test",
            ["xml"]="<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Eventlog\"/><EventID>1102</EventID><Version>0</Version><EventRecordID>1</EventRecordID><TimeCreated SystemTime=\"2026-11-01T00:00:00Z\"/><Channel>Security</Channel><Computer>dc.example.test</Computer></System><UserData><LogFileCleared xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\"><SubjectUserSid>S-1-5-21-100000001-200000002-300000003-1001</SubjectUserSid></LogFileCleared></UserData></Event>"
        };
        var rows = new JsonArray(row);
        foreach (int code in new[] { 4624,4625 }) {
            var native = row.DeepClone().AsObject(); native["event_id"] = code; native["record_id"] = rows.Count+1;
            native["xml"] = "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/><EventID>"+code+"</EventID><Version>0</Version><EventRecordID>"+(rows.Count+1)+"</EventRecordID><TimeCreated SystemTime=\"2026-11-01T00:00:00Z\"/><Channel>Security</Channel><Computer>dc.example.test</Computer></System><EventData><Data Name=\"TargetUserSid\">S-1-5-21-100000001-200000002-300000003-1001</Data><Data Name=\"TargetUserName\">synthetic-user</Data><Data Name=\"TargetDomainName\">example.test</Data><Data Name=\"TargetLogonId\">0x123</Data><Data Name=\"LogonType\">3</Data><Data Name=\"IpAddress\">192.0.2.1</Data></EventData></Event>";
            rows.Add(native);
        }
        if (powershell) {
            rows = new JsonArray(new JsonObject {
                ["event_id"]=4104,["record_id"]=1,["time_created"]="2026-11-01T00:00:00Z",
                ["channel"]="Microsoft-Windows-PowerShell/Operational",["computer_name"]="dc.example.test",
                ["xml"]="""
                    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
                    <Provider Name="Microsoft-Windows-PowerShell"/><EventID>4104</EventID><EventRecordID>1</EventRecordID>
                    <TimeCreated SystemTime="2026-11-01T00:00:00Z"/><Channel>Microsoft-Windows-PowerShell/Operational</Channel>
                    <Computer>dc.example.test</Computer></System><EventData>
                    <Data Name="ScriptBlockText">vssadmin delete shadows /all /quiet</Data></EventData></Event>
                    """
            });
        }
        var hashes = new JsonObject();
        foreach (var native in rows) hashes[native!["record_id"]!.ToString()] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(native.AsObject()))));
        await using var seed = new NpgsqlCommand("""
            insert into servers(id,domain_id,hostname,role,is_active) select 900001,id,'dc.example.test','domain_controller',true from domains limit 1;
            insert into log_sources(name) values('Security') on conflict do nothing;
            insert into storage_v2_channel(value) values('Security') on conflict do nothing;
            insert into storage_v2_provider(value) values('Microsoft-Windows-Eventlog'),('Microsoft-Windows-Security-Auditing') on conflict do nothing;
            insert into storage_v2_computer(value) values('dc.example.test') on conflict do nothing;
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,assigned_modules)
                values(md5('semantic-agent')::uuid,md5('semantic-host')::uuid,repeat('c',64),'dc.example.test',
                jsonb_build_array(jsonb_build_object('module_id','sli.windows.ad-dc','enabled',true,'config',
                    jsonb_build_object('source_name','dc.example.test','connect_address','dc.example.test','policy_revision','1',
                        'channels',jsonb_build_object('Security',true),'channel_generations',jsonb_build_object('Security',md5('semantic-host')::uuid::text)))));
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
                values(md5('semantic-agent')::uuid,'sli.windows.ad-dc',md5('semantic-host')::uuid::text,'dc.example.test','ad-dc','1.0.0','1');
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                values(md5('semantic-agent')::uuid,'sli.windows.ad-dc',1,md5('semantic-packet')::uuid,repeat('c',64),
                jsonb_build_object('agent_id',md5('semantic-agent')::uuid,'source_instance_id',md5('semantic-host')::uuid::text,
                    'generation',md5('semantic-host')::uuid::text),'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select packet_id,envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security","source":"dc.example.test"}}',
                    @rows::jsonb,now() from sli_agent_receipts where packet_id=md5('semantic-packet')::uuid;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select 900001,900001,id,'agent-packet:'||md5('semantic-packet')::uuid,'jsonl',repeat('c',64) from log_sources where name='Security';
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select 900000+(native.row->>'record_id')::bigint,900001,900001,(select domain_id from servers where id=900001),log_source_id,(native.row->>'event_id')::integer,(native.row->>'record_id')::bigint,
                    (select id from storage_v2_channel where value='Security'),(select id from storage_v2_provider where value=case when native.row->>'event_id'='1102' then 'Microsoft-Windows-Eventlog' else 'Microsoft-Windows-Security-Auditing' end),
                    (select id from storage_v2_computer where value='dc.example.test'),'2026-11-01T00:00:00Z',now(),decode(@hashes::jsonb->>(native.row->>'record_id'),'hex'),decode(@hashes::jsonb->>(native.row->>'record_id'),'hex'),
                    (select version from event_catalog_revisions order by id limit 1) from raw_log_files cross join lateral jsonb_array_elements(@rows::jsonb) native(row) where id=900001;
            insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,idempotency_key,
                source_id,domain_id,partition_key,occurred_at_utc,source_identity_json)
                select md5('semantic-job:'||e.id)::uuid,e.id,'normalize_event',1,'semantic-shadow','1.4+identity-1.0',sha256(('semantic-job:'||e.id)::bytea),
                    e.log_source_id,e.domain_id,e.server_id||':'||e.channel_id,e.time_created_utc,
                    to_jsonb(e)||jsonb_build_object('normalized_hash',encode(e.normalized_hash,'hex'),'channel','Security',
                        'computer','dc.example.test','provider_name',provider.value) from events_v2_core e join storage_v2_provider provider on provider.id=e.provider_id where e.raw_log_file_id=900001;
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
                values('synthetic-admission',1,'control_health','disabled','{}',sha256('{}'::bytea)) on conflict do nothing;
            insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by) values('synthetic-admission',1,false,'synthetic') on conflict do nothing;
            """, db);
        if(powershell)seed.CommandText=seed.CommandText
            .Replace("'Security'","'Microsoft-Windows-PowerShell/Operational'",StringComparison.Ordinal)
            .Replace("\"Security\"","\"Microsoft-Windows-PowerShell/Operational\"",StringComparison.Ordinal)
            .Replace("'Microsoft-Windows-Security-Auditing'","'Microsoft-Windows-PowerShell'",StringComparison.Ordinal)
            .Replace("'Microsoft-Windows-Eventlog'","'Microsoft-Windows-PowerShell'",StringComparison.Ordinal);
        if(canonicalAssignment)seed.CommandText=seed.CommandText
            .Replace("jsonb_build_object('source_name','dc.example.test'","jsonb_build_object('batch_size',128,'allow_event_ids',null,'initial_read_hours','all','source_name','dc.example.test'")
            .Replace("'channels',jsonb_build_object('Security',true)","'channels',jsonb_build_object('Security',true,'System',true,'Directory Service',false)");
        if(source>0) {
            foreach(string key in new[]{"semantic-agent","semantic-host","semantic-packet"})seed.CommandText=seed.CommandText.Replace(key,key+source);
            seed.CommandText=seed.CommandText.Replace("900001",(900001+source*10).ToString()).Replace("900000",(900000+source*10).ToString());
            seed.CommandText=seed.CommandText.Replace("dc.example.test","dc"+source+".example.test");
            foreach(var native in rows) {
                native!["computer_name"]="dc"+source+".example.test";
                native["xml"]=native["xml"]!.GetValue<string>().Replace("dc.example.test","dc"+source+".example.test");
                hashes[native["record_id"]!.ToString()]=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(native.AsObject()))));
            }
        }
        if(recent) {
            string stamp=PasswordJson.Stamp(DateTimeOffset.UtcNow.AddMinutes(-3)).Replace("+00:00","Z");
            seed.CommandText=seed.CommandText.Replace("2026-11-01T00:00:00Z",stamp);
            foreach(var native in rows) {
                native!["time_created"]=stamp;native["xml"]=native["xml"]!.GetValue<string>().Replace("2026-11-01T00:00:00Z",stamp);
                hashes[native["record_id"]!.ToString()]=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(native.AsObject()))));
            }
        }
        seed.Parameters.AddWithValue("rows",rows.ToJsonString()); seed.Parameters.AddWithValue("hashes",hashes.ToJsonString());
        await seed.ExecuteNonQueryAsync(ct);
    }
}
